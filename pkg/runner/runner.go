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
}

//go:embed templates/compose/default.template
var cacheComposeTemplateFS embed.FS

//go:embed templates/systemd-service/default.template
var cacheServiceTemplateFS embed.FS

// use a single instance of Validate, it caches struct info
var validate = validator.New(validator.WithRequiredStructEnabled())

func (agt *agent) replaceFile(filename string, uid int, gid int, content string) error {
	tmpFilename := filename + ".tmp"
	tmpFilenameFh, err := os.Create(filepath.Clean(tmpFilename))
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

func (agt *agent) createOrUpdateFile(filename string, uid int, gid int, content string) error {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			agt.logger.Info().Str("path", filename).Msg("creating file")
			err = agt.replaceFile(filename, uid, gid, content)
			if err != nil {
				return err
			}
		} else {
			agt.logger.Err(err).Str("path", filename).Msg("stat failed unexpectedly")
			return err
		}
	} else {
		// The file exists, fix uid/gid if needed
		if s, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
			chownNeeded := false

			if uid < 0 || uid > math.MaxUint32 {
				agt.logger.Info().Str("path", filename).Uint32("old_uid", s.Uid).Int("new_uid", uid).Msg("new UID does not fit in uint32")
				return fmt.Errorf("uid %d does not fit in uint32", uid)
			}
			if s.Uid != uint32(uid) {
				agt.logger.Info().Str("path", filename).Uint32("old_uid", s.Uid).Int("new_uid", uid).Msg("updating file UID")
				chownNeeded = true
			}

			if gid < 0 || gid > math.MaxUint32 {
				agt.logger.Info().Str("path", filename).Uint32("old_gid", s.Gid).Int("new_gid", gid).Msg("new GID does not fit in uint32")
				return fmt.Errorf("gid %d does not fit in uint32", uid)
			}
			if s.Gid != uint32(gid) {
				agt.logger.Info().Str("path", filename).Uint32("old_gid", s.Gid).Int("new_gid", gid).Msg("updating file GID")
				chownNeeded = true
			}

			if chownNeeded {
				err = os.Chown(filename, uid, gid)
				if err != nil {
					agt.logger.Err(err).Str("path", filename).Uint32("old_uid", s.Uid).Int("new_uid", uid).Uint32("old_gid", s.Gid).Int("new_gid", gid).Msg("chown failed")
					return err
				}
			}
		} else {
			agt.logger.Error().Str("path", filename).Msg("unable to access Uid/Gid of filename, not running on linux?")
			return errors.New("unable to access Uid/Gid")
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
			err = agt.replaceFile(filename, uid, gid, content)
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
	HAProxyUID int64
	VarnishUID int64
	GID        int64
}

type cacheSystemdServiceConfig struct {
	ComposeFile string
	OrgID       string
	OrgName     string
	ServiceID   string
	ServiceName string
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
	cacheCompose *template.Template
	cacheService *template.Template
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

func (agt *agent) buildConfFile(baseDir string, dirName string, fileName string, uid int, gid int, content string) error {
	path := filepath.Join(baseDir, dirName)
	_, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			agt.logger.Info().Str("path", path).Msg("creating directory path")
			err := os.Mkdir(path, 0o700)
			if err != nil {
				agt.logger.Err(err).Str("path", path).Msg("unable to create directory")
				return err
			}
		} else {
			agt.logger.Err(err).Str("path", path).Msg("stat failed")
			return err
		}
	}

	filePath := filepath.Join(path, fileName)
	err = agt.createOrUpdateFile(filePath, uid, gid, content)
	if err != nil {
		return err
	}

	return nil
}

func (agt *agent) buildCacheCompose(baseDir string, vcc cacheComposeConfig) (string, error) {
	_, err := os.Stat(baseDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			agt.logger.Info().Str("path", baseDir).Msg("creating directory path")
			err := os.Mkdir(baseDir, 0o700)
			if err != nil {
				agt.logger.Err(err).Str("path", baseDir).Msg("unable to create directory")
				return "", err
			}
		} else {
			agt.logger.Err(err).Str("path", baseDir).Msg("stat failed")
			return "", err
		}
	}

	composeFilePath := filepath.Join(baseDir, "docker-compose.yml")

	cacheCompose, err := generateCacheCompose(agt.templates.cacheCompose, vcc)
	if err != nil {
		agt.logger.Fatal().Err(err).Msg("generating cache compose config failed")
		return "", err
	}

	err = agt.createOrUpdateFile(composeFilePath, int(vcc.VarnishUID), int(vcc.GID), cacheCompose)
	if err != nil {
		return "", err
	}

	return composeFilePath, nil
}

func (agt *agent) buildCacheSystemdService(baseDir string, cssc cacheSystemdServiceConfig, orgID string, serviceID string) error {
	_, err := os.Stat(baseDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			agt.logger.Info().Str("path", baseDir).Msg("creating directory path")
			err := os.Mkdir(baseDir, 0o700)
			if err != nil {
				agt.logger.Err(err).Str("path", baseDir).Msg("unable to create directory")
				return err
			}
		} else {
			agt.logger.Err(err).Str("path", baseDir).Msg("stat failed")
			return err
		}
	}

	baseName := fmt.Sprintf("sunet-cdn-agent_%s_%s.service", orgID, serviceID)

	systemdServiceFilePath := filepath.Join(baseDir, baseName)

	cacheSystemdService, err := generateCacheSystemdService(agt.templates.cacheService, cssc)
	if err != nil {
		agt.logger.Fatal().Err(err).Msg("generating cache systemd service failed")
		return err
	}

	err = agt.createOrUpdateFile(systemdServiceFilePath, 0, 0, cacheSystemdService)
	if err != nil {
		return err
	}

	return nil
}

func (agt *agent) loop(wg *sync.WaitGroup) {
	defer wg.Done()

mainLoop:
	for {
		cnc, err := agt.getCacheNodeConfig()
		if err != nil {
			agt.logger.Err(err).Msg("unable to fetch cache node config")
		} else {
			dirPath := filepath.Join(agt.conf.ConfWriter.RootDir, "conf")

			// Handle things ordered by UUID or version, to make operations
			// carry out in a determinstic order which is easier to follow.
			orderedOrgs := []string{}
			for orgUUID := range cnc.Orgs {
				orderedOrgs = append(orderedOrgs, orgUUID)
			}
			slices.Sort(orderedOrgs)

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
		fileLoop:
			for _, orgUUID := range orderedOrgs {
				org := cnc.Orgs[orgUUID]
				orgPath := filepath.Join(dirPath, "orgs", org.ID.String())
				fmt.Println(orgPath)

				orderedServices := []string{}
				for serviceUUID := range org.Services {
					orderedServices = append(orderedServices, serviceUUID)
				}
				slices.Sort(orderedServices)

				for _, serviceUUID := range orderedServices {
					service := org.Services[serviceUUID]
					servicePath := filepath.Join(orgPath, "services", service.ID.String())
					fmt.Println(servicePath)

					orderedVersions := []int64{}
					for versionNumber := range service.ServiceVersions {
						orderedVersions = append(orderedVersions, versionNumber)
					}
					slices.Sort(orderedVersions)

					commonGID := service.UIDRangeFirst
					haProxyUID := service.UIDRangeFirst + 1
					varnishUID := service.UIDRangeFirst + 2

					for _, versionNumber := range orderedVersions {
						version := service.ServiceVersions[versionNumber]
						strVersion := strconv.FormatInt(version.Version, 10)
						versionBasePath := filepath.Join(servicePath, "volumes/shared/service-versions")
						versionPath := filepath.Join(versionBasePath, strVersion)

						fmt.Println(versionPath)

						_, err := os.Stat(versionPath)
						if err != nil {
							if errors.Is(err, fs.ErrNotExist) {
								agt.logger.Info().Str("path", versionPath).Msg("creating directory path")
								err := os.MkdirAll(versionPath, 0o700)
								if err != nil {
									agt.logger.Err(err).Str("path", versionPath).Msg("unable to create directory path")
									break fileLoop
								}
							} else {
								agt.logger.Err(err).Msg("stat failed")
								break fileLoop
							}
						}

						err = agt.buildConfFile(versionPath, "varnish", "varnish.vcl", int(varnishUID), int(commonGID), version.VCL)
						if err != nil {
							agt.logger.Err(err).Msg("unable to build conf file")
							break fileLoop
						}

						if version.Active {
							err = agt.setActiveLink(versionBasePath, version.Version)
							if err != nil {
								break fileLoop
							}
						}
					}

					ccc := cacheComposeConfig{
						HAProxyUID: haProxyUID,
						VarnishUID: varnishUID,
						GID:        commonGID,
					}

					composeBasePath := filepath.Join(servicePath, "compose")
					composeFile, err := agt.buildCacheCompose(composeBasePath, ccc)
					if err != nil {
						break fileLoop
					}

					cssc := cacheSystemdServiceConfig{
						ComposeFile: composeFile,
						OrgID:       org.ID.String(),
						OrgName:     org.Name,
						ServiceID:   service.ID.String(),
						ServiceName: service.Name,
					}

					err = agt.buildCacheSystemdService(agt.conf.ConfWriter.SystemdDir, cssc, org.ID.String(), service.ID.String())
					if err != nil {
						agt.logger.Fatal().Err(err).Msg("generating service conf failed")
					}
				}
			}
		}

		// Wait for the next time to run the loop, or exit if we are sutting down
		select {
		case <-time.Tick(time.Second * 10):
			continue
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

	err = os.MkdirAll(conf.ConfWriter.RootDir, 0o700)
	if err != nil {
		return err
	}

	a := newAgent(ctx, logger, c, tmpls, conf)

	var wg sync.WaitGroup
	wg.Add(1)
	go a.loop(&wg)
	wg.Wait()

	return nil
}
