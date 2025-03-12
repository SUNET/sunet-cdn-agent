package runner

import (
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

	"github.com/SUNET/sunet-cdn-manager/pkg/types"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

type config struct {
	Manager    managerSettings
	ConfWriter confWriterSettings
}

type managerSettings struct {
	URL      string `validate:"required"`
	Username string `validate:"required"`
	Password string `validate:"required"`
}

type confWriterSettings struct {
	RootDir    string `mapstructure:"root_dir" validate:"required"`
	SystemdDir string `mapstructure:"systemd_dir" validate:"required"`
	CertDir    string `mapstructure:"cert_dir" validate:"required"`
}

//go:embed templates/compose/default.template
var cacheComposeTemplateFS embed.FS

//go:embed templates/seccomp/varnish-slash-seccomp.json
var seccompTemplateFS embed.FS

//go:embed templates/systemd-service/default.template
var cacheServiceTemplateFS embed.FS

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

func (agt *agent) createOrUpdateFile(filename string, uid int, gid int, perm os.FileMode, content string) error {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			agt.logger.Info().Str("path", filename).Msg("creating file")
			err = agt.replaceFile(filename, uid, gid, perm, content)
			if err != nil {
				return err
			}
		} else {
			agt.logger.Err(err).Str("path", filename).Msg("stat failed unexpectedly")
			return err
		}
	} else {
		// The file exists, fix uid/gid if needed
		err = agt.chownIfNeeded(filename, fileInfo, uid, gid)
		if err != nil {
			return err
		}

		// fix perm if different
		err = agt.chmodIfNeeded(filename, fileInfo, perm)
		if err != nil {
			return err
		}

		// update content if it is different
		fileSum, err := sha256SumFile(filename)
		if err != nil {
			agt.logger.Err(err).Str("path", filename).Msg("unable to get sha256 sum for existing file")
			return err
		}

		contentSum := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))

		if fileSum != contentSum {
			agt.logger.Info().Str("file_sha256", fileSum).Str("content_sha256", contentSum).Str("path", filename).Msg("file content has changed, replacing file")
			err = agt.replaceFile(filename, uid, gid, perm, content)
			if err != nil {
				return err
			}
		}
	}

	return nil
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
	CertsPrivateDir string
	HAProxyUID      int64
	VarnishUID      int64
	GID             int64
}

type cacheSystemdServiceConfig struct {
	ComposeFile string
	OrgID       string
	OrgName     string
	ServiceID   string
	ServiceName string
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
	cacheCompose     *template.Template
	cacheService     *template.Template
	slashSeccompFile *template.Template
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

func (agt *agent) setActiveLink(baseDir string, activeVersionInt int64) error {
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
				return err
			}
			agt.logger.Info().Str("path", lnPath).Str("link_target", activeVersion).Msg("created active symlink")
		} else {
			agt.logger.Err(err).Msg("stat of active symlink failed")
		}
	} else {
		// Error out if "active" is not actually a symlink
		if lnInfo.Mode()&os.ModeSymlink != os.ModeSymlink {
			agt.logger.Error().Str("mode", lnInfo.Mode().String()).Msg("the 'active' file is not a symlink, this is unexpected")
			return err
		}

		lnDest, err := os.Readlink(lnPath)
		if err != nil {
			agt.logger.Err(err).Str("path", lnPath).Msg("unable to get destination of symlink")
		}

		// Verify the version being pointed to is a valid int
		_, err = strconv.ParseInt(lnDest, 10, 64)
		if err != nil {
			agt.logger.Err(err).Str("dest", lnDest).Msg("unable to parse current link destination as int64, this is unexpected")
			return err
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
				return err
			}
			err = os.Rename(lnTmpPath, lnPath)
			if err != nil {
				agt.logger.Err(err).Msg("unable to update active symlink")
				return err
			}
			agt.logger.Info().Str("src", lnTmpPath).Str("dest", lnPath).Msg("updated active symlink")
		}

		// If the link already exists, make sure it is pointing to the correct version, otherwise update it
	}
	fmt.Println(lnPath, "->", activeVersion)
	return nil
}

func (agt *agent) chownIfNeeded(path string, fileInfo os.FileInfo, uid int, gid int) error {
	if s, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
		chownNeeded := false

		if uid < 0 || uid > math.MaxUint32 {
			agt.logger.Info().Str("path", path).Uint32("old_uid", s.Uid).Int("new_uid", uid).Msg("new UID does not fit in uint32")
			return fmt.Errorf("uid %d does not fit in uint32", uid)
		}
		if s.Uid != uint32(uid) {
			agt.logger.Info().Str("path", path).Uint32("old_uid", s.Uid).Int("new_uid", uid).Msg("updating file UID")
			chownNeeded = true
		}

		if gid < 0 || gid > math.MaxUint32 {
			agt.logger.Info().Str("path", path).Uint32("old_gid", s.Gid).Int("new_gid", gid).Msg("new GID does not fit in uint32")
			return fmt.Errorf("gid %d does not fit in uint32", uid)
		}
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

func (agt *agent) addCertsToService(service types.ServiceWithVersions, orderedVersions []int64, certsPrivatePath string, haProxyUID int64) error {
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
				err = agt.createOrUpdateFile(haproxyCombinedFile, int(haProxyUID), 0, 0o600, tlsContent)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (agt *agent) generateFiles(cnc types.CacheNodeConfig) {
	confPath := filepath.Join(agt.conf.ConfWriter.RootDir, "conf")
	err := agt.createDirPathIfNeeded(confPath, 0, 0, 0o700)
	if err != nil {
		agt.logger.Err(err).Msg("unable to create conf dir")
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

	seccompDir := filepath.Join(confPath, "seccomp")
	err = agt.createDirPathIfNeeded(seccompDir, 0, 0, 0o700)
	if err != nil {
		agt.logger.Err(err).Msg("unable to create seccomp dir")
		return
	}

	seccompFile := filepath.Join(seccompDir, "varnish-slash-seccomp.json")
	err = agt.createOrUpdateFile(seccompFile, 0, 0, 0o600, slashSeccompContent)
	if err != nil {
		agt.logger.Err(err).Msg("unable to create slash seccomp file")
		return
	}

	// Expected directory structure:
	// /opt/sunet-cdn-agent/conf/orgs/org-uuid/services/service-uuid/volumes/shared/service-versions/1/varnish/varnish.vcl
	// /opt/sunet-cdn-agent/conf/orgs/org-uuid/services/service-uuid/volumes/shared/service-versions/1/haproxy/haproxy.cfg
	// /opt/sunet-cdn-agent/conf/orgs/org-uuid/services/service-uuid/volumes/shared/service-versions/2/varnish/varnish.vcl
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
	for _, orgUUID := range orderedOrgs {
		org := cnc.Orgs[orgUUID]

		orgPath := filepath.Join(confPath, "orgs")
		err = agt.createDirPathIfNeeded(orgPath, 0, 0, 0o700)
		if err != nil {
			agt.logger.Err(err).Msg("unable to create orgs dir")
			return
		}

		orgIDPath := filepath.Join(orgPath, org.ID.String())
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

			servicePath := filepath.Join(orgIDPath, "services")
			err = agt.createDirPathIfNeeded(servicePath, 0, int(commonGID), 0o700)
			if err != nil {
				agt.logger.Err(err).Msg("unable to create service dir")
				return
			}

			serviceIDPath := filepath.Join(servicePath, service.ID.String())
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

			certsPrivatePath := filepath.Join(volumesPath, "certs-private")
			err = agt.createDirPathIfNeeded(certsPrivatePath, int(haProxyUID), 0, 0o700)
			if err != nil {
				agt.logger.Err(err).Str("path", certsPrivatePath).Msg("unable to create certs-private dir")
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
			err := agt.addCertsToService(service, orderedVersions, certsPrivatePath, haProxyUID)
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
				err = agt.createOrUpdateFile(haProxyConfFile, int(haProxyUID), int(commonGID), 0o600, version.HAProxyConfig)
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

				varnishVCLFile := filepath.Join(varnishPath, "varnish.vcl")
				err = agt.createOrUpdateFile(varnishVCLFile, int(varnishUID), 0, 0o600, version.VCL)
				if err != nil {
					agt.logger.Err(err).Msg("unable to build VCL conf file")
					return
				}

				if version.Active {
					err = agt.setActiveLink(versionBasePath, version.Version)
					if err != nil {
						agt.logger.Err(err).Msg("unable to set active link")
						return
					}
					serviceIsActive = true
				}
			}

			dirsToCreateIfNeeded := []string{}

			composeBasePath := filepath.Join(servicePath, "compose")
			dirsToCreateIfNeeded = append(dirsToCreateIfNeeded, composeBasePath)

			cachePath := filepath.Join(volumesPath, "cache")
			dirsToCreateIfNeeded = append(dirsToCreateIfNeeded, cachePath)

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

			composeFile := filepath.Join(composeBasePath, "docker-compose.yml")
			err = agt.createOrUpdateFile(composeFile, 0, 0, 0o600, cacheCompose)
			if err != nil {
				agt.logger.Err(err).Msg("unable to build compose file")
				return

			}

			// Only create systemd files if the service has an active version
			if serviceIsActive {
				cssc := cacheSystemdServiceConfig{
					ComposeFile: composeFile,
					OrgID:       org.ID.String(),
					OrgName:     org.Name,
					ServiceID:   service.ID.String(),
					ServiceName: service.Name,
				}

				cacheService, err := generateCacheSystemdService(agt.templates.cacheService, cssc)
				if err != nil {
					agt.logger.Fatal().Err(err).Msg("generating cache systemd service failed")
					return
				}

				systemdFile := filepath.Join(agt.conf.ConfWriter.SystemdDir, fmt.Sprintf("sunet-cdn-agent_%s_%s.service", org.ID, service.ID))
				err = agt.createOrUpdateFile(systemdFile, 0, 0, 0o600, cacheService)
				if err != nil {
					agt.logger.Err(err).Msg("unable to build compose file")
					return
				}
			}
		}
	}
}

func (agt *agent) loop(wg *sync.WaitGroup) {
	defer wg.Done()

mainLoop:
	for {
		cnc, err := agt.getCacheNodeConfig()
		if err != nil {
			agt.logger.Err(err).Msg("unable to fetch cache node config")
		} else {
			agt.generateFiles(cnc)
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

func Run(logger zerolog.Logger) error {
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

	_, err = os.Stat(conf.ConfWriter.SystemdDir)
	if err != nil {
		return fmt.Errorf("unable to find SystemD path '%s', this is required for the agent to work", conf.ConfWriter.SystemdDir)
	}

	c := &http.Client{
		Timeout: 15 * time.Second,
	}

	tmpls := templates{}

	tmpls.cacheCompose, err = template.ParseFS(cacheComposeTemplateFS, "templates/compose/default.template")
	if err != nil {
		return err
	}

	tmpls.cacheService, err = template.ParseFS(cacheServiceTemplateFS, "templates/systemd-service/default.template")
	if err != nil {
		return err
	}

	tmpls.slashSeccompFile, err = template.ParseFS(seccompTemplateFS, "templates/seccomp/varnish-slash-seccomp.json")
	if err != nil {
		return err
	}

	err = os.MkdirAll(conf.ConfWriter.RootDir, 0o700)
	if err != nil {
		return err
	}

	agt := newAgent(ctx, logger, c, tmpls, conf)

	var wg sync.WaitGroup
	wg.Add(1)
	go agt.loop(&wg)
	wg.Wait()

	return nil
}
