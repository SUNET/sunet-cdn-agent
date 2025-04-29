package runner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/SUNET/sunet-cdn-agent/pkg/ipvsadm"
	"github.com/SUNET/sunet-cdn-agent/pkg/utils"
	"github.com/SUNET/sunet-cdn-manager/pkg/types"
	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

type config struct {
	Manager    managerSettings
	ConfWriter confWriterSettings
	L4LBNode   l4lbNodeSettings `mapstructure:"l4lb-node"`
}

type managerSettings struct {
	URL      string `validate:"required"`
	Username string `validate:"required"`
	Password string `validate:"required"`
}

type confWriterSettings struct {
	RootDir           string `mapstructure:"root_dir" validate:"required"`
	SystemdSystemDir  string `mapstructure:"systemd_system_dir" validate:"required"`
	SystemdNetworkDir string `mapstructure:"systemd_network_dir" validate:"required"`
	CertDir           string `mapstructure:"cert_dir" validate:"required"`
}

type l4lbNodeSettings struct {
	NetNS        string `mapstructure:"netns"`
	NetNSConfDir string `mapstructure:"netns_conf_dir" validate:"required"`
}

// JSON format from "vcl.list -j" described here: https://varnish-cache.org/docs/trunk/reference/varnish-cli.html#json
//
// [ 2, ["vcl.list", "-j"], 1742022002.443,
//
//	  {
//	    "status": "available",
//	    "state": "auto",
//	    "temperature": "cold",
//	    "busy": 0,
//	    "name": "name0"
//	},
//
//	  {
//	    "status": "active",
//	    "state": "auto",
//	    "temperature": "warm",
//	    "busy": 2,
//	    "name": "name1"
//	}
//
// ]
type vclListContent struct {
	Version    int
	Command    []string
	Time       time.Time
	LoadedVcls []loadedVcl
}

type loadedVcl struct {
	Status      string
	State       string
	Temperature string
	Busy        int64
	Name        string
}

// Implement custom unmarshaller since the JSON structure outputted by
// varnishadm is a list of different types which makes things a bit more
// cumbersome to deal with.
func (vclList *vclListContent) UnmarshalJSON(b []byte) error {
	var tmp []json.RawMessage

	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}

	// A version number for the JSON format (integer)
	if err := json.Unmarshal(tmp[0], &vclList.Version); err != nil {
		return err
	}

	// An array of strings that comprise the CLI command just received
	if err := json.Unmarshal(tmp[1], &vclList.Command); err != nil {
		return err
	}

	// The time at which the response was generated, as a Unix epoch time in seconds with millisecond precision (floating point)
	var tmpFloat float64
	if err := json.Unmarshal(tmp[2], &tmpFloat); err != nil {
		return err
	}
	milliSeconds := int64(tmpFloat * 1000)
	vclList.Time = time.UnixMilli(milliSeconds)

	// The list of loaded VCL configs
	listOffset := 3
	for _, listEntry := range tmp[listOffset:] {
		lv := loadedVcl{}
		if err := json.Unmarshal(listEntry, &lv); err != nil {
			return err
		}

		vclList.LoadedVcls = append(vclList.LoadedVcls, lv)
	}

	return nil
}

//go:embed templates
var templateFS embed.FS

// use a single instance of Validate, it caches struct info
var validate = validator.New(validator.WithRequiredStructEnabled())

func (agt *agent) replaceFile(filename string, uid int, gid int, perm os.FileMode, content string) error {
	tmpFilename := filename + ".tmp"
	tmpFilenameFh, err := os.OpenFile(filepath.Clean(tmpFilename), os.O_RDWR|os.O_CREATE|os.O_TRUNC, perm) // #nosec G304 -- gosec gets upset because perm is passed in as a variable which seems strange, see https://github.com/securego/gosec/issues/1318
	if err != nil {
		agt.logger.Err(err).Str("path", tmpFilename).Msg("unable to create file")
		return err
	}

	_, err = tmpFilenameFh.WriteString(content)
	if err != nil {
		agt.logger.Err(err).Str("path", tmpFilename).Msg("unable to write to file")
		// Attempt cleanup of tmp
		err = tmpFilenameFh.Close()
		if err != nil {
			agt.logger.Err(err).Str("path", tmpFilename).Msg("unable to close temporary file for cleanup")
		}
		// Even if the close failed, still try to cleanup the filename
		err = os.Remove(tmpFilename)
		if err != nil {
			agt.logger.Err(err).Str("path", tmpFilename).Msg("unable to close temporary file for cleanup")
		}
		return err
	}

	// Make sure the contents of the file is written out to disk prior to rename()
	err = tmpFilenameFh.Sync()
	if err != nil {
		agt.logger.Err(err).Str("path", tmpFilename).Msg("unable to sync temporary file to disk")
		err = tmpFilenameFh.Close()
		if err != nil {
			agt.logger.Err(err).Str("path", tmpFilename).Msg("unable to close temporary file after filed sync")
		}
		// Even if the close failed, still try to cleanup the filename
		err = os.Remove(tmpFilename)
		if err != nil {
			agt.logger.Err(err).Str("path", tmpFilename).Msg("unable to remove temporary file after failed sync")
		}
		return err
	}

	err = tmpFilenameFh.Close()
	if err != nil {
		agt.logger.Err(err).Str("path", tmpFilename).Msg("unable to close temporary file")
		err = os.Remove(tmpFilename)
		if err != nil {
			agt.logger.Err(err).Str("path", tmpFilename).Msg("unable to remove temporary file after failed close")
		}
		return err
	}

	// Set the correct owner and group
	err = os.Chown(tmpFilename, uid, gid)
	if err != nil {
		agt.logger.Err(err).Str("src", tmpFilename).Str("dest", filename).Int("uid", uid).Int("gid", gid).Msg("unable to set uid/gid")
		err = os.Remove(tmpFilename)
		if err != nil {
			agt.logger.Err(err).Str("path", tmpFilename).Msg("unable to remove temporary file after failing to set uid/gid")
		}
		return err
	}

	// Rename to real path
	err = os.Rename(tmpFilename, filename)
	if err != nil {
		agt.logger.Err(err).Str("src", tmpFilename).Str("dest", filename).Msg("unable to rename file")
		err = os.Remove(tmpFilename)
		if err != nil {
			agt.logger.Err(err).Str("path", tmpFilename).Msg("unable to remove temporary file for cleanup")
		}
		return err
	}

	return nil
}

func (agt *agent) createOrUpdateFile(filename string, uid int, gid int, perm os.FileMode, content string) (bool, error) {
	modified := false
	fileInfo, err := os.Stat(filename)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			agt.logger.Info().Str("path", filename).Msg("creating file")
			err = agt.replaceFile(filename, uid, gid, perm, content)
			if err != nil {
				return false, err
			}
			modified = true
		} else {
			agt.logger.Err(err).Str("path", filename).Msg("stat failed unexpectedly")
			return false, err
		}
	} else {
		// The file exists, fix uid/gid if needed
		err = agt.chownIfNeeded(filename, fileInfo, uid, gid)
		if err != nil {
			return false, err
		}

		// fix perm if different
		err = agt.chmodIfNeeded(filename, fileInfo, perm)
		if err != nil {
			return false, err
		}

		// update content if it is different
		fileSum, err := sha256SumFile(filename)
		if err != nil {
			agt.logger.Err(err).Str("path", filename).Msg("unable to get sha256 sum for existing file")
			return false, err
		}

		contentSum := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))

		if fileSum != contentSum {
			agt.logger.Info().Str("file_sha256", fileSum).Str("content_sha256", contentSum).Str("path", filename).Msg("file content has changed, replacing file")
			err = agt.replaceFile(filename, uid, gid, perm, content)
			if err != nil {
				return false, err
			}
			modified = true
		}
	}

	return modified, nil
}

func (agt *agent) getL4LBNodeConfig() (types.L4LBNodeConfig, error) {
	u, err := url.Parse(agt.conf.Manager.URL)
	if err != nil {
		return types.L4LBNodeConfig{}, err
	}

	configURL, err := url.JoinPath(u.String(), "api/v1/l4lb-node-configs")
	if err != nil {
		return types.L4LBNodeConfig{}, err
	}

	req, err := http.NewRequest("GET", configURL, nil)
	if err != nil {
		return types.L4LBNodeConfig{}, err
	}

	req.SetBasicAuth(agt.conf.Manager.Username, agt.conf.Manager.Password)

	resp, err := agt.httpClient.Do(req)
	if err != nil {
		return types.L4LBNodeConfig{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return types.L4LBNodeConfig{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	lnc := types.L4LBNodeConfig{}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return types.L4LBNodeConfig{}, err
	}

	err = json.Unmarshal(b, &lnc)
	if err != nil {
		return types.L4LBNodeConfig{}, err
	}

	return lnc, nil
}

func (agt *agent) getCacheNodeConfig() (types.CacheNodeConfig, error) {
	u, err := url.Parse(agt.conf.Manager.URL)
	if err != nil {
		return types.CacheNodeConfig{}, err
	}

	configURL, err := url.JoinPath(u.String(), "api/v1/cache-node-configs")
	if err != nil {
		return types.CacheNodeConfig{}, err
	}

	req, err := http.NewRequest("GET", configURL, nil)
	if err != nil {
		return types.CacheNodeConfig{}, err
	}

	req.SetBasicAuth(agt.conf.Manager.Username, agt.conf.Manager.Password)

	resp, err := agt.httpClient.Do(req)
	if err != nil {
		return types.CacheNodeConfig{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return types.CacheNodeConfig{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	cnc := types.CacheNodeConfig{}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return types.CacheNodeConfig{}, err
	}

	err = json.Unmarshal(b, &cnc)
	if err != nil {
		return types.CacheNodeConfig{}, err
	}

	return cnc, nil
}

type cacheComposeConfig struct {
	SeccompDir      string
	VersionBaseDir  string
	CacheDir        string
	SharedDir       string
	CertsDir        string
	HAProxyStatsDir string
	HAProxyLocalDir string
	CertsPrivateDir string
	HAProxyUID      int64
	VarnishUID      int64
	GID             int64
}

type cacheSystemdServiceConfig struct {
	ComposeFile string
	OrgID       string
	ServiceID   string
}

func generateDummyNetworkConf(tmpl *template.Template, orgIPContainers []orgIPContainer) (string, error) {
	var b strings.Builder

	err := tmpl.Execute(&b, orgIPContainers)
	if err != nil {
		return "", err
	}

	return b.String(), nil
}

func generateSeccomp(tmpl *template.Template) (string, error) {
	var b strings.Builder

	err := tmpl.Execute(&b, nil)
	if err != nil {
		return "", err
	}

	return b.String(), nil
}

func generateCacheCompose(tmpl *template.Template, ccc cacheComposeConfig) (string, error) {
	var b strings.Builder

	err := tmpl.Execute(&b, ccc)
	if err != nil {
		return "", err
	}

	return b.String(), nil
}

func generateCacheSystemdService(tmpl *template.Template, cssc cacheSystemdServiceConfig) (string, error) {
	var b strings.Builder

	err := tmpl.Execute(&b, cssc)
	if err != nil {
		return "", err
	}

	return b.String(), nil
}

type templates struct {
	cacheCompose        *template.Template
	cacheService        *template.Template
	slashSeccompFile    *template.Template
	systemdDummyNetwork *template.Template
}

type agent struct {
	ctx        context.Context
	httpClient *http.Client
	logger     zerolog.Logger
	templates  templates
	conf       config
}

func sha256SumFile(fn string) (string, error) {
	f, err := os.Open(filepath.Clean(fn))
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func (agt *agent) setActiveLink(baseDir string, activeVersionInt int64) (bool, error) {
	modified := false
	activeVersion := strconv.FormatInt(activeVersionInt, 10)

	lnPath := filepath.Join(baseDir, "active")
	lnInfo, err := os.Lstat(lnPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			agt.logger.Info().Str("path", lnPath).Msg("creating active symlink")
			// Create relative link, e.g. path/to/active -> 1, makes sure it is valid even inside a container that is only seeing part of the full path
			err := os.Symlink(activeVersion, lnPath)
			if err != nil {
				agt.logger.Err(err).Str("path", lnPath).Msg("unable to create symlink")
				return false, err
			}
			agt.logger.Info().Str("path", lnPath).Str("link_target", activeVersion).Msg("created active symlink")
			modified = true
		} else {
			agt.logger.Err(err).Msg("stat of active symlink failed")
			return false, err
		}
	} else {
		// Error out if "active" is not actually a symlink
		if lnInfo.Mode()&os.ModeSymlink != os.ModeSymlink {
			agt.logger.Error().Str("mode", lnInfo.Mode().String()).Msg("the 'active' file is not a symlink, this is unexpected")
			return false, err
		}

		lnDest, err := os.Readlink(lnPath)
		if err != nil {
			agt.logger.Err(err).Str("path", lnPath).Msg("unable to get destination of symlink")
			return false, err
		}

		// Verify the version being pointed to is a valid int
		_, err = strconv.ParseInt(lnDest, 10, 64)
		if err != nil {
			agt.logger.Err(err).Str("dest", lnDest).Msg("unable to parse current link destination as int64, this is unexpected")
			return false, err
		}

		if lnDest != activeVersion {
			// We need to replace the symlink, do it atomically by
			// creating a new temporary symlink pointing to the
			// active dir and then rename it to the real "active"
			// link.
			agt.logger.Info().Str("old", lnDest).Str("new", activeVersion).Msg("updating active link")
			lnTmpPath := lnPath + ".tmp"
			agt.logger.Info().Str("dest", activeVersion).Str("path", lnTmpPath).Msg("creating replacement symlink")
			err := os.Symlink(activeVersion, lnTmpPath)
			if err != nil {
				agt.logger.Err(err).Str("path", lnPath).Msg("unable to create temporary symlink")
				return false, err
			}
			err = os.Rename(lnTmpPath, lnPath)
			if err != nil {
				agt.logger.Err(err).Msg("unable to update active symlink")
				return false, err
			}
			agt.logger.Info().Str("src", lnTmpPath).Str("dest", lnPath).Msg("updated active symlink")
			modified = true
		}

		// If the link already exists, make sure it is pointing to the correct version, otherwise update it
	}
	fmt.Println(lnPath, "->", activeVersion)
	return modified, nil
}

func (agt *agent) chownIfNeeded(path string, fileInfo os.FileInfo, uid int, gid int) error {
	if s, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
		chownNeeded := false

		if uid < 0 || int64(uid) > math.MaxUint32 {
			agt.logger.Info().Str("path", path).Uint32("old_uid", s.Uid).Int("new_uid", uid).Msg("new UID does not fit in uint32")
			return fmt.Errorf("uid %d does not fit in uint32", uid)
		}
		// #nosec G115 -- seems gosec still detects this as overflow because of the int64(uid) usage above
		if s.Uid != uint32(uid) {
			agt.logger.Info().Str("path", path).Uint32("old_uid", s.Uid).Int("new_uid", uid).Msg("updating file UID")
			chownNeeded = true
		}

		if gid < 0 || int64(gid) > math.MaxUint32 {
			agt.logger.Info().Str("path", path).Uint32("old_gid", s.Gid).Int("new_gid", gid).Msg("new GID does not fit in uint32")
			return fmt.Errorf("gid %d does not fit in uint32", uid)
		}
		// #nosec G115 -- seems gosec still detects this as overflow because of the int64(gid) usage above
		if s.Gid != uint32(gid) {
			agt.logger.Info().Str("path", path).Uint32("old_gid", s.Gid).Int("new_gid", gid).Msg("updating file GID")
			chownNeeded = true
		}

		if chownNeeded {
			err := os.Chown(path, uid, gid)
			if err != nil {
				agt.logger.Err(err).Str("path", path).Uint32("old_uid", s.Uid).Int("new_uid", uid).Uint32("old_gid", s.Gid).Int("new_gid", gid).Msg("chown failed")
				return err
			}
		}
	} else {
		agt.logger.Error().Str("path", path).Msg("unable to access Uid/Gid of file, not running on linux?")
		return errors.New("unable to access Uid/Gid")
	}
	return nil
}

func (agt *agent) chmodIfNeeded(path string, fileInfo os.FileInfo, perm os.FileMode) error {
	if fileInfo.Mode().Perm() != perm {
		agt.logger.Info().Str("path", path).Str("old_perm", fileInfo.Mode().Perm().String()).Str("new_perm", perm.String()).Msg("updating perm on file")
		err := os.Chmod(path, perm)
		if err != nil {
			return err
		}
	}

	return nil
}

func (agt *agent) createDirPathIfNeeded(path string, uid int, gid int, perm os.FileMode) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			agt.logger.Info().Str("path", path).Msg("creating directory path")
			err := os.Mkdir(path, perm)
			if err != nil {
				return fmt.Errorf("unable to create directory path: %w", err)
			}

			err = os.Chown(path, uid, gid)
			if err != nil {
				return fmt.Errorf("unable to call chown: %w", err)
			}

			// Mkdir() is affected by umask, so trying to set
			// a perm of 0770 will still result in 0750 given a
			// default umask of 0022. Make sure the dir has the
			// expected perm here instead of updating it on the
			// next iteration when the dir already exists.
			err = os.Chmod(path, perm)
			if err != nil {
				return fmt.Errorf("unable to call chmod: %w", err)
			}

		} else {
			return fmt.Errorf("stat failed: %w", err)
		}
	} else {
		// Directory exists, make sure it has the correct uid/gid
		err = agt.chownIfNeeded(path, fileInfo, uid, gid)
		if err != nil {
			return err
		}

		// also check it has the correct perms
		err = agt.chmodIfNeeded(path, fileInfo, perm)
		if err != nil {
			return err
		}
	}
	return nil
}

func (agt *agent) collectIPAddresses(orgs map[string]types.OrgWithServices, orderedOrgs []string) []orgIPContainer {
	allIPAddrs := []orgIPContainer{}
	for _, orgUUID := range orderedOrgs {
		org := orgs[orgUUID]

		orgIPCont := orgIPContainer{
			ID: org.ID,
		}

		orderedServices := []string{}
		for serviceUUID := range org.Services {
			orderedServices = append(orderedServices, serviceUUID)
		}

		slices.Sort(orderedServices)

		for _, serviceUUID := range orderedServices {
			service := org.Services[serviceUUID]
			orgIPCont.ServiceIPContainers = append(
				orgIPCont.ServiceIPContainers,
				serviceIPContainer{
					ID:          service.ID,
					IPAddresses: service.IPAddresses,
				})
		}

		allIPAddrs = append(allIPAddrs, orgIPCont)
	}
	return allIPAddrs
}

func (agt *agent) addCertsToService(modifiedCerts map[string]map[string]struct{}, org types.OrgWithServices, service types.ServiceWithVersions, orderedVersions []int64, certsPrivatePath string, haProxyUID int64) error {
	for _, versionNumber := range orderedVersions {
		version := service.ServiceVersions[versionNumber]

		// Skip service if it requires TLS (has at
		// least one origin with TLS enabled) and we do
		// not have a certificate for the domain name(s)
		// assigned to the version.
		if version.TLS {
			for _, domain := range version.Domains {
				domainDir := filepath.Join(agt.conf.ConfWriter.CertDir, string(domain))
				_, err := os.Stat(domainDir)
				if err != nil {
					agt.logger.Error().Str("path", domainDir).Msg("no cert dir available for domain, skipping service")
					return err
				}
				// Created combined cert file as required by haproxy
				fullChainPath := filepath.Join(domainDir, "fullchain.pem")
				fullChainData, err := os.ReadFile(filepath.Clean(fullChainPath))
				if err != nil {
					agt.logger.Error().Str("path", fullChainPath).Msg("unable to read full chain cert file")
					return err
				}

				privKeyPath := filepath.Join(domainDir, "privkey.pem")
				privKeyData, err := os.ReadFile(filepath.Clean(privKeyPath))
				if err != nil {
					agt.logger.Error().Str("path", privKeyPath).Msg("unable to open private key for reading")
					return err
				}

				haproxyCombinedFile := filepath.Join(certsPrivatePath, string(domain)+".pem")
				tlsContent := string(fullChainData)
				tlsContent += string(privKeyData)
				modified, err := agt.createOrUpdateFile(haproxyCombinedFile, int(haProxyUID), 0, 0o600, tlsContent)
				if err != nil {
					return err
				}

				if modified {
					if _, ok := modifiedCerts[org.ID.String()]; !ok {
						modifiedCerts[org.ID.String()] = map[string]struct{}{
							service.ID.String(): {},
						}
					} else {
						modifiedCerts[org.ID.String()][service.ID.String()] = struct{}{}
					}
				}
			}
		}
	}
	return nil
}

func (agt *agent) loadNewVcl(containerName string) error {
	stdout, stderr, err := utils.RunCommand("docker", "exec", containerName, "varnishadm", "vcl.list", "-j")
	if err != nil {
		agt.logger.Err(err).Str("container_name", containerName).Str("stdout", stdout).Str("stderr", stderr).Msg("unable to call varnishadm vcl.list -j")
		return err
	}

	vlc := vclListContent{}
	err = json.Unmarshal([]byte(stdout), &vlc)
	if err != nil {
		agt.logger.Err(err).Str("container_name", containerName).Msg("unable to parse varnishadm vcl.list -j")
		return err
	}

	usedNames := map[string]struct{}{}

	for _, lv := range vlc.LoadedVcls {
		usedNames[lv.Name] = struct{}{}
	}

	var vclConfigName string

	// Build a name like "sunet-cdn-agent-1742080867-0"
	// where the first number is a unix timestamp and the
	// second number is just a counter in case we somehow
	// try to create more than one version inside the same
	// second. Limit attempts to an upper bound so we dont
	// loop forever if something is broken.
	vclPrefix := "sunet-cdn-agent-"
	baseName := fmt.Sprintf("%s%d", vclPrefix, time.Now().Unix())
	for i := range 1000 {
		tmpName := baseName + fmt.Sprintf("-%d", i)
		if _, ok := usedNames[tmpName]; !ok {
			// Not taken, use it
			vclConfigName = tmpName
			break
		}
	}
	if vclConfigName == "" {
		agt.logger.Error().Str("container_name", containerName).Msg("unable to generate unused varnish vcl name")
		return err
	}

	stdout, stderr, err = utils.RunCommand("docker", "exec", containerName, "varnishadm", "vcl.load", vclConfigName, "/service-versions/active/varnish/default.vcl")
	if err != nil {
		agt.logger.Err(err).Str("container_name", containerName).Str("stdout", stdout).Str("stderr", stderr).Msg("unable to call varnishadm vcl.load")
		return err
	}

	stdout, stderr, err = utils.RunCommand("docker", "exec", containerName, "varnishadm", "vcl.use", vclConfigName)
	if err != nil {
		agt.logger.Err(err).Str("container_name", containerName).Str("stdout", stdout).Str("stderr", stderr).Msg("unable to call varnishadm vcl.use")
		return err
	}

	// Cleanup any unused inactive versions without
	// references. This will leave the "most recently
	// inactived" version behind since we are working on
	// data collected before the most recent version was
	// loaded.
	for _, lv := range vlc.LoadedVcls {
		if strings.HasPrefix(lv.Name, vclPrefix) && lv.Status == "available" && lv.Busy == 0 {
			agt.logger.Info().
				Str("container_name", containerName).
				Str("vcl_name", lv.Name).
				Str("vcl_temp", lv.Temperature).
				Str("vcl_state", lv.State).
				Str("vcl_status", lv.Status).
				Int64("vcl_busy", lv.Busy).
				Msg("discarding unused vcl")
			stdout, stderr, err = utils.RunCommand("docker", "exec", containerName, "varnishadm", "vcl.discard", lv.Name)
			if err != nil {
				agt.logger.Err(err).Str("container_name", containerName).Str("stdout", stdout).Str("stderr", stderr).Msg("unable to call varnishadm vcl.discard")
				return err
			}
		}
	}

	return nil
}

func (agt *agent) reloadHAProxy(containerName string) error {
	// HAProxy in master-worker mode will do a seamless reload if sent SIGUSR2
	// https://docs.haproxy.org/2.9/configuration.html#3.1-master-worker
	stdout, stderr, err := utils.RunCommand("docker", "kill", "--signal", "USR2", containerName)
	if err != nil {
		agt.logger.Err(err).Str("container_name", containerName).Str("stdout", stdout).Str("stderr", stderr).Msg("unable to send SIGUSR2 to haproxy")
		return err
	}

	return nil
}

func (agt *agent) reloadContainerConfigs(modifiedActiveLinks map[string]map[string]struct{}, modifiedCerts map[string]map[string]struct{}) {
	// Find out if there are containers running that need to be told that
	// the active link points to a new version
	// Expected output is something like this:
	// ===
	// sunet-cdn-agent-cache-7ea73f72-12e5-45b9-a687-57f678837b6b_061fa36c-ce3c-46f5-851d-ab765bf34229-haproxy-1
	// sunet-cdn-agent-cache-7ea73f72-12e5-45b9-a687-57f678837b6b_061fa36c-ce3c-46f5-851d-ab765bf34229-varnish-1
	// ===
	stdout, stderr, err := utils.RunCommand("docker", "ps", "--format", "{{.Names}}")
	if err != nil {
		agt.logger.Err(err).Str("stdout", stdout).Str("stderr", stderr).Msg("docker ps failed")
		return
	}

	containerPrefix := "sunet-cdn-agent-cache-"
	uuidLen := 36
	containerNameScanner := bufio.NewScanner(strings.NewReader(stdout))

	containerActiveChanged := map[string]struct{}{}
	containerCertChanged := map[string]struct{}{}
	for containerNameScanner.Scan() {
		containerName := containerNameScanner.Text()
		if !strings.HasPrefix(containerName, containerPrefix) {
			continue
		}

		// Pick out the org and service id strings from the container name
		orgID := containerName[len(containerPrefix) : len(containerPrefix)+uuidLen]
		serviceID := containerName[len(containerPrefix)+uuidLen+1 : len(containerPrefix)+uuidLen*2+1]

		// Record containers for services who have had their active
		// symlink updated, this affects all containers for that service
		if _, ok := modifiedActiveLinks[orgID]; ok {
			if _, ok := modifiedActiveLinks[orgID][serviceID]; ok {
				agt.logger.Info().Str("container_name", containerName).Msg("active symlink changed, updating config")
				containerActiveChanged[containerName] = struct{}{}
			}
		}

		// Record TLS handling containers for services that have had
		// their cert modified
		if _, ok := modifiedCerts[orgID]; ok {
			if _, ok := modifiedCerts[orgID][serviceID]; ok {
				if strings.Contains(containerName, "-haproxy-") {
					agt.logger.Info().Str("container_name", containerName).Msg("cert changed, needs to reload")
					containerCertChanged[containerName] = struct{}{}
				}
			}
		}
	}
	if err := containerNameScanner.Err(); err != nil {
		agt.logger.Err(err).Msg("reading docker ps output failed")
		return
	}

	// Since haproxy is reloaded the same way no matter if it is due to
	// cert change or config symlink change just merge the two lists
	// together here so we only reload haproxy at most once.
	mergedContainers := map[string]struct{}{}

	for containerName := range containerActiveChanged {
		mergedContainers[containerName] = struct{}{}
	}

	for containerName := range containerCertChanged {
		mergedContainers[containerName] = struct{}{}
	}

	// Do updates in sorted order so things are a bit more deterministic
	// and easy to follow
	sortedMergedContainers := []string{}

	for containerName := range mergedContainers {
		sortedMergedContainers = append(sortedMergedContainers, containerName)
	}

	slices.Sort(sortedMergedContainers)

	for _, containerName := range sortedMergedContainers {
		// Do the right thing based on what type of container needs a reload.
		switch {
		case strings.Contains(containerName, "-varnish-"):
			err := agt.loadNewVcl(containerName)
			if err != nil {
				continue
			}
			agt.logger.Info().Str("container_name", containerName).Msg("VCL updated")
		case strings.Contains(containerName, "-haproxy-"):
			err := agt.reloadHAProxy(containerName)
			if err != nil {
				continue
			}
			agt.logger.Info().Str("container_name", containerName).Msg("haproxy reloaded")
		default:
			agt.logger.Info().Str("container_name", containerName).Msg("skipping unhandled container type")
		}
	}
}

type orgIPContainer struct {
	ID                  pgtype.UUID
	ServiceIPContainers []serviceIPContainer
}

type serviceIPContainer struct {
	ID          pgtype.UUID
	IPAddresses []netip.Addr
}

// netns-config JSON expected by
// https://platform.sunet.se/sunet-cdn/cdn-ops/src/branch/main/global/overlay/etc/puppet/modules/cdn/files/l4lb/sunet-l4lb-namespace:
//
//	{
//	 "namespace1": {
//	   "interface1": {
//	     "ipv4": [
//	       "192.168.10.1/31"
//	     ],
//	     "ipv6": [
//	       "2001:db8:1337:74::1/127"
//	     ]
//	   },
//	   "interface2": {
//	     "ipv4": [
//	       "192.168.10.3/31"
//	     ],
//	     "ipv6": [
//	       "2001:db8:1338:75::1/127"
//	     ]
//	   }
//	 }
//	}
type netnsConfig map[string]interfaceConfig

type interfaceConfig map[string]addressConfig

type addressConfig map[string][]string

func (agt *agent) setupNetNS(lnc types.L4LBNodeConfig) error {
	namespaceName := "l4lb"
	interfaceName := "dummy0"
	ipv4Key := "ipv4"
	ipv6Key := "ipv6"

	nsConf := netnsConfig{
		namespaceName: interfaceConfig{
			interfaceName: addressConfig{},
		},
	}

	for _, srvConn := range lnc.Services {
		for _, address := range srvConn.ServiceIPAddresses {
			bits := strconv.Itoa(address.Unmap().BitLen())
			if address.Unmap().Is4() {
				nsConf[namespaceName][interfaceName][ipv4Key] = append(nsConf[namespaceName][interfaceName][ipv4Key], address.Unmap().String()+"/"+bits)
			} else if address.Unmap().Is6() {
				nsConf[namespaceName][interfaceName][ipv6Key] = append(nsConf[namespaceName][interfaceName][ipv6Key], address.Unmap().String()+"/"+bits)
			}
		}
	}

	b, err := json.MarshalIndent(nsConf, "", "  ")
	if err != nil {
		agt.logger.Err(err).Msg("unable to create JSON for netns config")
		return err
	}

	netnsConfFile := filepath.Join(agt.conf.L4LBNode.NetNSConfDir, "netns-sunet-cdn-agent.json")
	netNSModified, err := agt.createOrUpdateFile(netnsConfFile, 0, 0, 0o644, string(b))
	if err != nil {
		agt.logger.Err(err).Str("path", netnsConfFile).Msg("unable to write out netns conf file")
		return err
	}

	if netNSModified {
		args := []string{"systemctl", "restart", "sunet-l4lb-namespace.service"}
		agt.logger.Info().Strs("cmd", args).Msg("running command")
		stdout, stderr, err := utils.RunCommand(args[0], args[1:]...)
		if err != nil {
			agt.logger.Err(err).Str("stdout", stdout).Str("stderr", stderr).Strs("cmd", args).Msg("command failed")
		}
	}

	return nil
}

func (agt *agent) setupIpvsadm(lnc types.L4LBNodeConfig, l4lbConfPath string) error {
	ipvsadmConfPath := filepath.Join(l4lbConfPath, "ipvsadm")
	err := agt.createDirPathIfNeeded(ipvsadmConfPath, 0, 0, 0o700)
	if err != nil {
		agt.logger.Err(err).Str("path", ipvsadmConfPath).Msg("unable to create ipvsadm conf dir")
		return err
	}

	// ipvsadm --save --numeric output:
	// -A -t <service-ipv4>:80 -s mh
	// -a -t <service-ipv4>:80 -r <cache-node-ipv4>:80 -i -w 1 --tun-type ipip
	// -A -t <service-ipv4>:443 -s mh
	// -a -t <service-ipv4>:443 -r <cache-node-ipv4>:443 -i -w 1 --tun-type ipip
	// -A -t [<service-ipv6>]:80 -s mh
	// -a -t [<service-ipv6>]:80 -r [<cache-node-ipv6>]:80 -i -w 1 --tun-type ipip
	// -A -t [<service-ipv6>]:443 -s mh
	// -a -t [<service-ipv6]:443 -r [<cache-node-ipv6>]:443 -i -w 1 --tun-type ipip

	// Store rules in a slice to track ordering
	// newIPVSRules := []string{}
	newIPVSRules := ipvsadm.NewRuleset()

	for _, sip := range lnc.Services {
		for _, serviceAddr := range sip.ServiceIPAddresses {
			unmapServiceAddr := serviceAddr.Unmap()
			if sip.HTTP {
				var port uint16 = 80

				vs, err := ipvsadm.NewVirtualService("tcp", unmapServiceAddr, port, "mh")
				if err != nil {
					return fmt.Errorf("unable to init HTTP virtual service: %w", err)
				}

				err = newIPVSRules.AddVS(vs)
				if err != nil {
					return fmt.Errorf("unable to add HTTP service address to ruleset: %w", err)
				}

				for _, cacheNode := range lnc.CacheNodes {
					weight := 1
					if cacheNode.Maintenance {
						weight = 0
					}

					if unmapServiceAddr.Is4() {
						if cacheNode.IPv4Address != nil {
							rs, err := ipvsadm.NewRealServer("tcp", unmapServiceAddr, port, cacheNode.IPv4Address.Unmap(), port, weight, "ipip")
							if err != nil {
								return fmt.Errorf("unable to init HTTP IPv4 cachenode real-server: %w", err)
							}

							err = newIPVSRules.AddRS(rs)
							if err != nil {
								return fmt.Errorf("unable to add HTTP IPv4 cachenode real-server to ruleset: %w", err)
							}
						}
					}
					if serviceAddr.Unmap().Is6() {
						if cacheNode.IPv6Address != nil {
							rs, err := ipvsadm.NewRealServer("tcp", unmapServiceAddr, port, cacheNode.IPv6Address.Unmap(), port, weight, "ipip")
							if err != nil {
								return fmt.Errorf("unable to init HTTP IPv6 cachenode real-server: %w", err)
							}

							err = newIPVSRules.AddRS(rs)
							if err != nil {
								return fmt.Errorf("unable to add HTTP IPv6 cachenode real-server to ruleset: %w", err)
							}
						}
					}
				}
			}
			if sip.HTTPS {
				var port uint16 = 443

				vs, err := ipvsadm.NewVirtualService("tcp", unmapServiceAddr, port, "mh")
				if err != nil {
					return fmt.Errorf("unable to init HTTPS virtual service: %w", err)
				}

				err = newIPVSRules.AddVS(vs)
				if err != nil {
					return fmt.Errorf("unable to add HTTPS service address to ruleset: %w", err)
				}

				for _, cacheNode := range lnc.CacheNodes {
					weight := 1
					if cacheNode.Maintenance {
						weight = 0
					}
					if unmapServiceAddr.Is4() {
						if cacheNode.IPv4Address != nil {
							rs, err := ipvsadm.NewRealServer("tcp", unmapServiceAddr, port, cacheNode.IPv4Address.Unmap(), port, weight, "ipip")
							if err != nil {
								return fmt.Errorf("unable to init HTTPS IPv4 cachenode real-server: %w", err)
							}

							err = newIPVSRules.AddRS(rs)
							if err != nil {
								return fmt.Errorf("unable to add HTTPS IPv4 cachenode real-server to ruleset: %w", err)
							}
						}
					}
					if unmapServiceAddr.Is6() {
						if cacheNode.IPv6Address != nil {
							rs, err := ipvsadm.NewRealServer("tcp", unmapServiceAddr, port, cacheNode.IPv6Address.Unmap(), port, weight, "ipip")
							if err != nil {
								return fmt.Errorf("unable to init HTTPS IPv6 cachenode real-server: %w", err)
							}

							err = newIPVSRules.AddRS(rs)
							if err != nil {
								return fmt.Errorf("unable to add HTTPS IPv6S cachenode real-server to ruleset: %w", err)
							}
						}
					}
				}
			}
		}
	}

	newIPVSRulesString := newIPVSRules.GenerateRules()

	ipvsadmRestoreFile := filepath.Join(ipvsadmConfPath, "ipvsadm.restore")
	_, err = agt.createOrUpdateFile(ipvsadmRestoreFile, 0, 0, 0o600, newIPVSRulesString)
	if err != nil {
		agt.logger.Err(err).Msg("unable to write out ipvsadm.restore")
		return err
	}

	// Unfortunately "ipvsadm --restore" will not atomically replace what
	// is currently loaded with what is in the restore file.
	// Instead it is more like running ipvsadm in a script by hand: if the
	// rule being loaded already exists ipvsadm will complain but continue with
	// the next rule, and if there are rules loaded which are no longer in
	// the file these will just remain loaded.
	//
	// While we will still write out a new file to disk to handle a reboot,
	// we need to manually figure out what rules should be removed and what
	// rules should be added so we can do this at runtime. The other
	// approach would be to write out the file and then do "ipvsadm
	// --clear" followed by "ipvsadm --restore" but clearing out all
	// existing rules is not great since it would cause a glitch for all
	// services.
	loadedIPVSRules, err := ipvsadm.GetLoadedRules(agt.logger, agt.conf.L4LBNode.NetNS)
	if err != nil {
		return fmt.Errorf("unable to load ipvsadm rules: %w", err)
	}

	updates := ipvsadm.FindRuleUpdates(loadedIPVSRules, newIPVSRules)

	err = ipvsadm.UpdateRules(agt.logger, agt.conf.L4LBNode.NetNS, loadedIPVSRules, newIPVSRules, updates)
	if err != nil {
		return fmt.Errorf("unable to update loaded ipvsadm rules: %w", err)
	}

	return nil
}

func (agt *agent) generateL4LBFiles(lnc types.L4LBNodeConfig) {
	l4lbConfPath := filepath.Join(agt.conf.ConfWriter.RootDir, "l4lb-conf")
	err := agt.createDirPathIfNeeded(l4lbConfPath, 0, 0, 0o700)
	if err != nil {
		agt.logger.Err(err).Msg("unable to create l4lb-conf dir")
		return
	}

	err = agt.setupNetNS(lnc)
	if err != nil {
		return
	}

	err = agt.setupIpvsadm(lnc, l4lbConfPath)
	if err != nil {
		return
	}
}

func (agt *agent) getExistingOrgsAndServices(orgPath string) (map[pgtype.UUID]map[pgtype.UUID]struct{}, error) {
	existingOrgIDs := map[pgtype.UUID]map[pgtype.UUID]struct{}{}
	orgDirEntries, err := os.ReadDir(orgPath)
	if err != nil {
		return nil, err
		//}
	}

	for _, orgDirEntry := range orgDirEntries {
		orgID := new(pgtype.UUID)
		err := orgID.Scan(orgDirEntry.Name())
		if err != nil {
			agt.logger.Info().Str("filename", orgDirEntry.Name()).Msg("skipping cleanup of non-UUID org filename")
			continue
		}

		if !orgID.Valid {
			agt.logger.Info().Str("filename", orgDirEntry.Name()).Msg("skipping cleanup of invalid org UUID filename")
			continue
		}

		existingOrgIDs[*orgID] = map[pgtype.UUID]struct{}{}

		orgIDPath := getOrgIDPath(orgPath, *orgID)
		servicePath := getServicePath(orgIDPath)

		serviceDirEntries, err := os.ReadDir(servicePath)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return nil, err
			}
		}

		for _, serviceDirEntry := range serviceDirEntries {
			serviceID := new(pgtype.UUID)
			err := serviceID.Scan(serviceDirEntry.Name())
			if err != nil {
				agt.logger.Info().Str("filename", serviceDirEntry.Name()).Msg("skipping cleanup of non-UUID service filename")
				continue
			}

			if !serviceID.Valid {
				agt.logger.Info().Str("filename", serviceDirEntry.Name()).Msg("skipping cleanup of invalid service UUID filename")
				continue
			}
			existingOrgIDs[*orgID][*serviceID] = struct{}{}
		}
	}

	return existingOrgIDs, nil
}

func (agt *agent) cleanUpService(orgPath string, orgID pgtype.UUID, serviceID pgtype.UUID) error {
	systemdBaseName, systemdFileName := agt.genSystemdFilenames(orgID, serviceID)

	unitSettings, err := agt.systemctlShow(systemdBaseName)
	if err != nil {
		return err
	}

	loadStateKey := "LoadState"
	loadState, ok := unitSettings[loadStateKey]
	if !ok {
		agt.logger.Error().Str("setting_key", loadStateKey).Msg("unable to locate unit setting")
		return fmt.Errorf("unable to locate unit setting")
	}

	if loadState == "loaded" {
		agt.logger.Info().Str("org_id", orgID.String()).Str("serviceID", serviceID.String()).Str("systemd_basename", systemdBaseName).Msg("removing systemd for service")
		stdout, stderr, err := utils.RunCommand("systemctl", "disable", systemdBaseName)
		if err != nil {
			agt.logger.Err(err).Str("stdout", stdout).Str("stderr", stderr).Str("pattern", systemdBaseName).Msg("systemctl disable failed")
			return err
		}

		stdout, stderr, err = utils.RunCommand("systemctl", "stop", systemdBaseName)
		if err != nil {
			agt.logger.Err(err).Str("stdout", stdout).Str("stderr", stderr).Str("pattern", systemdBaseName).Msg("systemctl stop failed")
			return err
		}

		err = os.Remove(systemdFileName)
		if err != nil {
			agt.logger.Err(err).Str("stdout", stdout).Str("stderr", stderr).Str("filename", systemdFileName).Msg("removal of systemd filename failed")
			return err
		}

		err = agt.systemctlDaemonReload()
		if err != nil {
			return err
		}

		// Not sure we should do this, this will only cleanup things that broke during stop, maybe it is better to leave it so it can be inspected:
		//stdout, stderr, err = utils.RunCommand("systemctl", "reset-failed", systemdBaseName)
		//if err != nil {
		//	agt.logger.Err(err).Str("stdout", stdout).Str("stderr", stderr).Str("pattern", systemdBaseName).Msg("systemctl reset-failed failed")
		//	return err
		//}
	}

	orgIDPath := getOrgIDPath(orgPath, orgID)
	servicePath := getServicePath(orgIDPath)
	serviceIDPath := getServiceIDPath(servicePath, serviceID)

	agt.logger.Info().Str("service_id_path", serviceIDPath).Msg("cleaning up files for removed service")
	err = os.RemoveAll(serviceIDPath)
	if err != nil {
		agt.logger.Err(err).Str("service_id_path", serviceIDPath).Msg("failed cleaning up files for removed service")
	}

	return nil
}

func cmpUUID(a pgtype.UUID, b pgtype.UUID) int {
	switch {
	case a.String() < b.String():
		return -1
	case a.String() > b.String():
		return 1
	}

	return 0
}

func (agt *agent) genSystemdFilenames(orgID pgtype.UUID, serviceID pgtype.UUID) (string, string) {
	systemdBaseName := fmt.Sprintf("sunet-cdn-agent_%s_%s.service", orgID, serviceID)
	systemdFile := filepath.Join(agt.conf.ConfWriter.SystemdSystemDir, systemdBaseName)

	return systemdBaseName, systemdFile
}

func getOrgIDPath(orgPath string, orgID pgtype.UUID) string {
	return filepath.Join(orgPath, orgID.String())
}

func getServicePath(orgIDPath string) string {
	return filepath.Join(orgIDPath, "services")
}

func getServiceIDPath(servicePath string, serviceID pgtype.UUID) string {
	return filepath.Join(servicePath, serviceID.String())
}

func (agt *agent) generateCacheFiles(cnc types.CacheNodeConfig) {
	cacheConfPath := filepath.Join(agt.conf.ConfWriter.RootDir, "cache-conf")
	err := agt.createDirPathIfNeeded(cacheConfPath, 0, 0, 0o700)
	if err != nil {
		agt.logger.Err(err).Msg("unable to create cache-conf dir")
		return
	}

	// Handle things ordered by UUID or version, to make operations
	// carry out in a determinstic order which is easier to follow.
	orderedOrgs := []string{}
	for orgUUID := range cnc.Orgs {
		orderedOrgs = append(orderedOrgs, orgUUID)
	}
	slices.Sort(orderedOrgs)

	slashSeccompContent, err := generateSeccomp(agt.templates.slashSeccompFile)
	if err != nil {
		agt.logger.Err(err).Msg("unable to generate slash seccomp content")
		return
	}

	seccompDir := filepath.Join(cacheConfPath, "seccomp")
	err = agt.createDirPathIfNeeded(seccompDir, 0, 0, 0o700)
	if err != nil {
		agt.logger.Err(err).Msg("unable to create seccomp dir")
		return
	}

	seccompFile := filepath.Join(seccompDir, "varnish-slash-seccomp.json")
	_, err = agt.createOrUpdateFile(seccompFile, 0, 0, 0o600, slashSeccompContent)
	if err != nil {
		agt.logger.Err(err).Msg("unable to create slash seccomp file")
		return
	}

	// Update IP addresses assigned to dummy interface if needed so haproxy
	// can listen to them
	allIPAddresses := agt.collectIPAddresses(cnc.Orgs, orderedOrgs)
	if len(allIPAddresses) > 0 {
		dummyNetworkContent, err := generateDummyNetworkConf(agt.templates.systemdDummyNetwork, allIPAddresses)
		if err != nil {
			agt.logger.Err(err).Msg("unable to generate systemd network config content")
			return
		}

		networkFile := filepath.Join(agt.conf.ConfWriter.SystemdNetworkDir, "10-sunet-cdn-agent-dummy.network")
		modified, err := agt.createOrUpdateFile(networkFile, 0, 0, 0o644, dummyNetworkContent)
		if err != nil {
			agt.logger.Err(err).Str("path", networkFile).Msg("unable to create network file")
			return
		}

		if modified {
			agt.logger.Info().Msg("calling networkctl reload")
			stdout, stderr, err := utils.RunCommand("networkctl", "reload")
			if err != nil {
				agt.logger.Err(err).Str("stdout", stdout).Str("stderr", stderr).Msg("networkctl reload failed")
				return
			}
		}
	}

	modifiedSystemdServices := []string{}

	// This map is a orgIDs -> serviceIDs where the active version changed
	// It is used to know what containers need to be notified that they should
	// reload their config.
	modifiedActiveLinks := map[string]map[string]struct{}{}

	// This map is a orgIDs -> serviceIDs where the active version changed
	// It is used to know what containers need to be notified that they should
	// reload their config.
	modifiedCerts := map[string]map[string]struct{}{}

	// Expected directory structure:
	// /opt/sunet-cdn-agent/conf/orgs/org-uuid/services/service-uuid/volumes/shared/service-versions/1/varnish/default.vcl
	// /opt/sunet-cdn-agent/conf/orgs/org-uuid/services/service-uuid/volumes/shared/service-versions/1/haproxy/haproxy.cfg
	// /opt/sunet-cdn-agent/conf/orgs/org-uuid/services/service-uuid/volumes/shared/service-versions/2/varnish/default.vcl
	// /opt/sunet-cdn-agent/conf/orgs/org-uuid/services/service-uuid/volumes/shared/service-versions/2/haproxy/haproxy.cfg
	// /opt/sunet-cdn-agent/conf/orgs/org-uuid/services/service-uuid/volumes/shared/service-versions/active -> 2
	// /opt/sunet-cdn-agent/conf/orgs/org-uuid/services/service-uuid/volumes/shared/work
	// /opt/sunet-cdn-agent/conf/orgs/org-uuid/services/service-uuid/compose/docker-compose.yml
	//
	// The reason for this specific layout is that we can
	// mount the "shared" directory to all containers
	// belonging to a given service and only change a
	// single symlink (active) atomically and be sure that
	// even in the event of a system crash/power outage all
	// processes related to a given service will use config
	// for the same version when they come up again after
	// reboot.
	orgPath := filepath.Join(cacheConfPath, "orgs")
	err = agt.createDirPathIfNeeded(orgPath, 0, 0, 0o700)
	if err != nil {
		agt.logger.Err(err).Msg("unable to create orgs dir")
		return
	}

	// Find all existing orgs and services
	existingOrgIDs, err := agt.getExistingOrgsAndServices(orgPath)
	if err != nil {
		agt.logger.Err(err).Msg("unable to inventory orgs dir")
		return
	}

	orderedExistingOrgIDs := []pgtype.UUID{}
	for existingOrgID := range existingOrgIDs {
		orderedExistingOrgIDs = append(orderedExistingOrgIDs, existingOrgID)
	}
	slices.SortFunc(orderedExistingOrgIDs, cmpUUID)

	for _, orderedExistingOrgID := range orderedExistingOrgIDs {
		orderedExistingServiceIDs := []pgtype.UUID{}
		for existingServiceID := range existingOrgIDs[orderedExistingOrgID] {
			orderedExistingServiceIDs = append(orderedExistingServiceIDs, existingServiceID)
		}
		slices.SortFunc(orderedExistingServiceIDs, cmpUUID)

		if _, ok := cnc.Orgs[orderedExistingOrgID.String()]; !ok {
			agt.logger.Info().Str("org_id", orderedExistingOrgID.String()).Msg("found orphaned org ID on disk")

			// Remove all services for the org and then the org dir itself
			for _, orderedExistingServiceID := range orderedExistingServiceIDs {
				err = agt.cleanUpService(orgPath, orderedExistingOrgID, orderedExistingServiceID)
				if err != nil {
					agt.logger.Err(err).Str("org_id", orderedExistingOrgID.String()).Str("service_id", orderedExistingServiceID.String()).Msg("unable to cleanup service for orphaned org")
					return
				}
			}

			orgIDPath := getOrgIDPath(orgPath, orderedExistingOrgID)
			agt.logger.Info().Str("org_id_path", orgIDPath).Msg("cleaning up files for orphaned org")
			err = os.RemoveAll(orgIDPath)
			if err != nil {
				agt.logger.Err(err).Str("org_id_path", orgIDPath).Msg("failed cleaning up files for orphaned org")
			}
		} else {
			for _, orderedExistingServiceID := range orderedExistingServiceIDs {
				if _, ok := cnc.Orgs[orderedExistingOrgID.String()].Services[orderedExistingServiceID.String()]; !ok {
					agt.logger.Info().Str("service_id", orderedExistingServiceID.String()).Msg("found orphaned service ID on disk")

					err = agt.cleanUpService(orgPath, orderedExistingOrgID, orderedExistingServiceID)
					if err != nil {
						agt.logger.Err(err).Str("org_id", orderedExistingOrgID.String()).Str("service_id", orderedExistingServiceID.String()).Msg("unable to cleanup service")
						return
					}
				}
			}
		}
	}

	for _, orgUUID := range orderedOrgs {
		org := cnc.Orgs[orgUUID]

		orgIDPath := getOrgIDPath(orgPath, org.ID)
		err = agt.createDirPathIfNeeded(orgIDPath, 0, 0, 0o700)
		if err != nil {
			agt.logger.Err(err).Msg("unable to create orgs ID dir")
			return
		}
		fmt.Println(orgPath)

		orderedServices := []string{}
		for serviceUUID := range org.Services {
			orderedServices = append(orderedServices, serviceUUID)
		}
		slices.Sort(orderedServices)

	serviceLoop:
		for _, serviceUUID := range orderedServices {
			service := org.Services[serviceUUID]

			commonGID := service.UIDRangeFirst
			haProxyUID := service.UIDRangeFirst + 1
			varnishUID := service.UIDRangeFirst + 2

			servicePath := getServicePath(orgIDPath)
			err = agt.createDirPathIfNeeded(servicePath, 0, 0, 0o700)
			if err != nil {
				agt.logger.Err(err).Msg("unable to create service dir")
				return
			}

			serviceIDPath := getServiceIDPath(servicePath, service.ID)
			err = agt.createDirPathIfNeeded(serviceIDPath, 0, int(commonGID), 0o750)
			if err != nil {
				agt.logger.Err(err).Msg("unable to create service ID dir")
				return
			}
			fmt.Println(servicePath)

			orderedVersions := []int64{}
			for versionNumber := range service.ServiceVersions {
				orderedVersions = append(orderedVersions, versionNumber)
			}
			slices.Sort(orderedVersions)

			composePath := filepath.Join(serviceIDPath, "compose")
			err = agt.createDirPathIfNeeded(composePath, 0, 0, 0o700)
			if err != nil {
				agt.logger.Err(err).Msg("unable to create compose dir")
				return
			}

			volumesPath := filepath.Join(serviceIDPath, "volumes")
			err = agt.createDirPathIfNeeded(volumesPath, 0, int(commonGID), 0o750)
			if err != nil {
				agt.logger.Err(err).Msg("unable to create volumes dir")
				return
			}

			sharedPath := filepath.Join(volumesPath, "shared")
			err = agt.createDirPathIfNeeded(sharedPath, 0, int(commonGID), 0o770)
			if err != nil {
				agt.logger.Err(err).Msg("unable to create shared volume dir")
				return
			}

			versionBasePath := filepath.Join(sharedPath, "service-versions")
			err = agt.createDirPathIfNeeded(versionBasePath, 0, int(commonGID), 0o750)
			if err != nil {
				agt.logger.Err(err).Msg("unable to create shared volume dir")
				return
			}

			unixSocketPath := filepath.Join(sharedPath, "unix-sockets")
			err = agt.createDirPathIfNeeded(unixSocketPath, 0, int(commonGID), 0o770)
			if err != nil {
				agt.logger.Err(err).Msg("unable to create shared unix-sockets dir")
				return
			}

			certsPrivatePath := filepath.Join(volumesPath, "certs-private")
			err = agt.createDirPathIfNeeded(certsPrivatePath, int(haProxyUID), 0, 0o700)
			if err != nil {
				agt.logger.Err(err).Str("path", certsPrivatePath).Msg("unable to create certs-private dir")
				return
			}

			haproxyStatsPath := filepath.Join(volumesPath, "haproxy-stats")
			err = agt.createDirPathIfNeeded(haproxyStatsPath, int(haProxyUID), 0, 0o700)
			if err != nil {
				agt.logger.Err(err).Str("path", haproxyStatsPath).Msg("unable to create haproxy-stats dir")
				return
			}

			haproxyLocalPath := filepath.Join(volumesPath, "haproxy-local")
			err = agt.createDirPathIfNeeded(haproxyLocalPath, int(haProxyUID), 0, 0o700)
			if err != nil {
				agt.logger.Err(err).Str("path", haproxyLocalPath).Msg("unable to create haproxy-local dir")
				return
			}

			// Do initial loop over all versions to figure out if
			// TLS is required for any service version origin. If
			// this is the case we need to make sure we have access
			// to the required certs prior to potentiallly updating
			// the "active" link. Otherwise we can end up in a
			// situation where the active link points to a version
			// of the config with references to TLS files that are
			// not present, making things fail to start.
			err := agt.addCertsToService(modifiedCerts, org, service, orderedVersions, certsPrivatePath, haProxyUID)
			if err != nil {
				continue serviceLoop
			}

			serviceIsActive := false
			for _, versionNumber := range orderedVersions {
				version := service.ServiceVersions[versionNumber]
				strVersion := strconv.FormatInt(version.Version, 10)

				versionPath := filepath.Join(versionBasePath, strVersion)
				err = agt.createDirPathIfNeeded(versionPath, 0, int(commonGID), 0o750)
				if err != nil {
					agt.logger.Err(err).Msg("unable to create version path")
					return
				}
				fmt.Println(versionPath)

				haproxyPath := filepath.Join(versionPath, "haproxy")
				err = agt.createDirPathIfNeeded(haproxyPath, int(haProxyUID), 0, 0o700)
				if err != nil {
					agt.logger.Err(err).Msg("unable to create haproxy dir")
					return
				}

				haProxyConfFile := filepath.Join(haproxyPath, "haproxy.cfg")
				_, err = agt.createOrUpdateFile(haProxyConfFile, int(haProxyUID), int(commonGID), 0o600, version.HAProxyConfig)
				if err != nil {
					agt.logger.Err(err).Msg("unable to build HAProxy conf file")
					return
				}

				varnishPath := filepath.Join(versionPath, "varnish")
				err = agt.createDirPathIfNeeded(varnishPath, int(varnishUID), 0, 0o700)
				if err != nil {
					agt.logger.Err(err).Msg("unable to create varnish dir")
					return
				}

				varnishVCLFile := filepath.Join(varnishPath, "default.vcl")
				_, err = agt.createOrUpdateFile(varnishVCLFile, int(varnishUID), 0, 0o600, version.VCL)
				if err != nil {
					agt.logger.Err(err).Msg("unable to build VCL conf file")
					return
				}

				if version.Active {
					activeLinkModified, err := agt.setActiveLink(versionBasePath, version.Version)
					if err != nil {
						agt.logger.Err(err).Msg("unable to set active link")
						return
					}
					serviceIsActive = true

					if activeLinkModified {
						if _, ok := modifiedActiveLinks[org.ID.String()]; !ok {
							modifiedActiveLinks[org.ID.String()] = map[string]struct{}{
								service.ID.String(): {},
							}
						} else {
							modifiedActiveLinks[org.ID.String()][service.ID.String()] = struct{}{}
						}
					}

				}
			}

			cachePath := filepath.Join(volumesPath, "cache")
			err = agt.createDirPathIfNeeded(cachePath, int(varnishUID), 0, 0o700)
			if err != nil {
				agt.logger.Err(err).Str("path", cachePath).Msg("unable to create dir")
				return
			}

			dirsToCreateIfNeeded := []string{}

			certsPath := filepath.Join(volumesPath, "certs")
			dirsToCreateIfNeeded = append(dirsToCreateIfNeeded, certsPath)

			for _, dirToCreate := range dirsToCreateIfNeeded {
				err = agt.createDirPathIfNeeded(dirToCreate, 0, 0, 0o700)
				if err != nil {
					agt.logger.Err(err).Str("path", dirToCreate).Msg("unable to create dir")
					return
				}
			}

			ccc := cacheComposeConfig{
				SeccompDir:      seccompDir,
				VersionBaseDir:  versionBasePath,
				CacheDir:        cachePath,
				SharedDir:       sharedPath,
				CertsDir:        certsPath,
				HAProxyStatsDir: haproxyStatsPath,
				HAProxyLocalDir: haproxyLocalPath,
				CertsPrivateDir: certsPrivatePath,
				HAProxyUID:      haProxyUID,
				VarnishUID:      varnishUID,
				GID:             commonGID,
			}

			cacheCompose, err := generateCacheCompose(agt.templates.cacheCompose, ccc)
			if err != nil {
				agt.logger.Fatal().Err(err).Msg("generating cache compose config failed")
				return
			}

			composeFile := filepath.Join(composePath, "docker-compose.yml")
			_, err = agt.createOrUpdateFile(composeFile, 0, 0, 0o600, cacheCompose)
			if err != nil {
				agt.logger.Err(err).Msg("unable to build compose file")
				return

			}

			// Only create systemd files if the service has an active version
			if serviceIsActive {
				cssc := cacheSystemdServiceConfig{
					ComposeFile: composeFile,
					OrgID:       org.ID.String(),
					ServiceID:   service.ID.String(),
				}

				cacheService, err := generateCacheSystemdService(agt.templates.cacheService, cssc)
				if err != nil {
					agt.logger.Fatal().Err(err).Msg("generating cache systemd service failed")
					return
				}

				systemdBaseName, systemdFile := agt.genSystemdFilenames(org.ID, service.ID)
				modified, err := agt.createOrUpdateFile(systemdFile, 0, 0, 0o644, cacheService)
				if err != nil {
					agt.logger.Err(err).Msg("unable to build compose file")
					return
				}

				if modified {
					modifiedSystemdServices = append(modifiedSystemdServices, systemdBaseName)
				}
			}
		}
	}

	// Reload configs for any containers whose active symlinks were updated.
	// Do this before setting up any new systemd services since in that
	// case we would end up reloading the config of a just created/started
	// container (and there is a larger chance of a race condition if
	// trying to update the config of a container that is still not fully
	// started).
	agt.reloadContainerConfigs(modifiedActiveLinks, modifiedCerts)

	if len(modifiedSystemdServices) > 0 {
		err = agt.systemctlDaemonReload()
		if err != nil {
			return
		}

		for _, systemdBaseName := range modifiedSystemdServices {
			_, err = agt.enableUnitFile(systemdBaseName)
			if err != nil {
				return
			}
		}
	}
}

func (agt *agent) l4lbNodeLoop(wg *sync.WaitGroup) {
	defer wg.Done()

mainLoop:
	for {
		lnc, err := agt.getL4LBNodeConfig()
		if err != nil {
			agt.logger.Err(err).Msg("unable to fetch l4lb node config")
		} else {
			agt.generateL4LBFiles(lnc)
		}
		// Wait for the next time to run the loop, or exit if we are sutting down
		select {
		case <-time.Tick(time.Second * 10):
		case <-agt.ctx.Done():
			break mainLoop
		}
	}
}

func (agt *agent) cacheNodeLoop(wg *sync.WaitGroup) {
	defer wg.Done()

mainLoop:
	for {
		cnc, err := agt.getCacheNodeConfig()
		if err != nil {
			agt.logger.Err(err).Msg("unable to fetch cache node config")
		} else {
			agt.generateCacheFiles(cnc)
		}
		// Wait for the next time to run the loop, or exit if we are sutting down
		select {
		case <-time.Tick(time.Second * 10):
		case <-agt.ctx.Done():
			break mainLoop
		}
	}
}

func newAgent(ctx context.Context, logger zerolog.Logger, c *http.Client, tmpls templates, conf config) agent {
	return agent{
		ctx:        ctx,
		httpClient: c,
		logger:     logger,
		templates:  tmpls,
		conf:       conf,
	}
}

func (agt *agent) systemctlShow(pattern string) (map[string]string, error) {
	unitSettings := map[string]string{}
	stdout, stderr, err := utils.RunCommand("systemctl", "show", pattern)
	if err != nil {
		agt.logger.Err(err).Str("stdout", stdout).Str("stderr", stderr).Msg("systemctl show failed")
		return nil, err
	}

	// Settings look like this, one per line:
	// UnitFileState=disabled
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("expected two parts, got %d: %s", len(parts), parts)
		}
		unitSettings[parts[0]] = parts[1]
	}
	if err := scanner.Err(); err != nil {
		agt.logger.Err(err).Str("pattern", pattern).Msg("reading output from 'systemctl show'")
	}

	return unitSettings, nil
}

func (agt *agent) systemctlDaemonReload() error {
	agt.logger.Info().Msg("calling systemctl daemon-reload")
	stdout, stderr, err := utils.RunCommand("systemctl", "daemon-reload")
	if err != nil {
		agt.logger.Err(err).Str("stdout", stdout).Str("stderr", stderr).Msg("systemctl daamon-reload failed")
		return err
	}

	return nil
}

func (agt *agent) enableUnitFile(name string) (bool, error) {
	modified := false

	unitSettings, err := agt.systemctlShow(name)
	if err != nil {
		return false, err
	}

	unitFileStateKey := "UnitFileState"
	unitFileState, ok := unitSettings[unitFileStateKey]
	if !ok {
		agt.logger.Error().Str("setting_key", unitFileStateKey).Msg("unable to locate unit setting")
		return false, fmt.Errorf("unable to locate unit setting")
	}

	if unitFileState == "disabled" {
		agt.logger.Info().Str("service_name", name).Msg("enabling systemd service")
		stdout, stderr, err := utils.RunCommand("systemctl", "enable", name)
		if err != nil {
			agt.logger.Err(err).Str("stdout", stdout).Str("stderr", stderr).Msg("systemctl enable failed")
			return false, err
		}

		// We only try to start a service initially when it is enabled.
		// For "keeping an existing service alive" lets leave that up
		// to systemd instead of becoming a process monitor ourselves.

		// ActiveState=active
		// SubState=running
		activeStateKey := "ActiveState"
		subStateKey := "SubState"

		activeState, ok := unitSettings[activeStateKey]
		if !ok {
			agt.logger.Error().Str("setting_key", activeStateKey).Msg("unable to locate unit setting")
			return false, fmt.Errorf("unable to locate unit setting")
		}

		subState, ok := unitSettings[subStateKey]
		if !ok {
			agt.logger.Error().Str("setting_key", subStateKey).Msg("unable to locate unit setting")
			return false, fmt.Errorf("unable to locate unit setting")
		}

		if activeState != "active" || subState != "running" {
			agt.logger.Info().Str("service_name", name).Msg("starting systemd service")
			stdout, stderr, err := utils.RunCommand("systemctl", "start", name)
			if err != nil {
				agt.logger.Err(err).Str("stdout", stdout).Str("stderr", stderr).Msg("systemctl start failed")
				return false, err
			}
		}

		modified = true
	}

	return modified, nil
}

func Run(logger zerolog.Logger, cacheNode bool, l4lbNode bool) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Exit gracefully on SIGINT or SIGTERM
	go func(logger zerolog.Logger, cancel context.CancelFunc) {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		s := <-sigCh
		logger.Info().Str("signal", s.String()).Msg("received signal")
		cancel()
	}(logger, cancel)

	var conf config
	err := viper.UnmarshalExact(&conf)
	if err != nil {
		return fmt.Errorf("viper unable to decode into struct: %w", err)
	}

	err = validate.Struct(conf)
	if err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	_, err = os.Stat(conf.ConfWriter.SystemdSystemDir)
	if err != nil {
		return fmt.Errorf("unable to find SystemD system path '%s', this is required for the agent to work", conf.ConfWriter.SystemdSystemDir)
	}

	_, err = os.Stat(conf.ConfWriter.SystemdNetworkDir)
	if err != nil {
		return fmt.Errorf("unable to find SystemD network path '%s', this is required for the agent to work", conf.ConfWriter.SystemdSystemDir)
	}

	c := &http.Client{
		Timeout: 15 * time.Second,
	}

	tmpls := templates{}

	tmpls.cacheCompose, err = template.ParseFS(templateFS, "templates/compose/default.template")
	if err != nil {
		return err
	}

	tmpls.cacheService, err = template.ParseFS(templateFS, "templates/systemd-service/default.template")
	if err != nil {
		return err
	}

	tmpls.slashSeccompFile, err = template.ParseFS(templateFS, "templates/seccomp/varnish-slash-seccomp.json")
	if err != nil {
		return err
	}

	tmpls.systemdDummyNetwork, err = template.ParseFS(templateFS, "templates/systemd-networkd/dummy.network")
	if err != nil {
		return err
	}

	err = os.MkdirAll(conf.ConfWriter.RootDir, 0o700)
	if err != nil {
		return err
	}

	agt := newAgent(ctx, logger, c, tmpls, conf)

	var wg sync.WaitGroup

	if cacheNode {
		wg.Add(1)
		go agt.cacheNodeLoop(&wg)
	}

	if l4lbNode {
		wg.Add(1)
		go agt.l4lbNodeLoop(&wg)
	}

	wg.Wait()

	return nil
}
