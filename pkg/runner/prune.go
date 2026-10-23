package runner

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
)

// staleCertFiles returns the full paths of the regular "<domain>.pem" files
// in certsPrivatePath where <domain> is not in wantedDomains. Anything that
// is not a regular .pem file is ignored, and a missing directory means there
// is nothing to remove.
func staleCertFiles(certsPrivatePath string, wantedDomains map[string]struct{}) ([]string, error) {
	entries, err := os.ReadDir(certsPrivatePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var stale []string
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}

		domain, ok := strings.CutSuffix(entry.Name(), ".pem")
		if !ok {
			continue
		}

		if _, wanted := wantedDomains[domain]; wanted {
			continue
		}

		stale = append(stale, filepath.Join(certsPrivatePath, entry.Name()))
	}

	return stale, nil
}

// parseVersionName parses a version directory or "active" link target name.
// Only a canonical base-10 int64 is accepted, so e.g. "01" is not version 1.
func parseVersionName(name string) (int64, bool) {
	version, err := strconv.ParseInt(name, 10, 64)
	if err != nil || strconv.FormatInt(version, 10) != name {
		return 0, false
	}

	return version, true
}

// activeLinkReceived reports whether the "active" symlink in versionBasePath
// points at one of wantedVersions. A missing link, or one whose target is not
// a version name, is reported as not received.
func activeLinkReceived(versionBasePath string, wantedVersions map[int64]struct{}) (bool, error) {
	activeTarget, err := os.Readlink(filepath.Join(versionBasePath, "active"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}

	version, ok := parseVersionName(activeTarget)
	if !ok {
		return false, nil
	}

	_, received := wantedVersions[version]
	return received, nil
}

// staleVersionDirs returns the full paths of the version directories in
// versionBasePath that are not in wantedVersions. Only directories named as a
// canonical base-10 int64 are considered (so e.g. "01" and "tmp" are left
// alone), and the target of the "active" symlink is never returned.
func (agt *agent) staleVersionDirs(versionBasePath string, wantedVersions map[int64]struct{}) ([]string, error) {
	entries, err := os.ReadDir(versionBasePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	activeTarget, err := os.Readlink(filepath.Join(versionBasePath, "active"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	var stale []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		version, ok := parseVersionName(entry.Name())
		if !ok {
			continue
		}

		if _, wanted := wantedVersions[version]; wanted {
			continue
		}

		// Callers only prune once the "active" link points at a version
		// that was sent, so reaching this means that no longer holds.
		// Keep the target, a running service may depend on it, but
		// make the broken invariant visible.
		if entry.Name() == activeTarget {
			agt.logger.Warn().Str("path", filepath.Join(versionBasePath, entry.Name())).Msg("active link does not point at a version in the cache node config, keeping its target")
			continue
		}

		stale = append(stale, filepath.Join(versionBasePath, entry.Name()))
	}

	return stale, nil
}

// wantedVersionsAndDomains returns the version numbers and domain names the
// manager sent for the service, i.e. everything that should be kept.
func wantedVersionsAndDomains(service cdntypes.ServiceWithVersions) (map[int64]struct{}, map[string]struct{}) {
	wantedVersions := map[int64]struct{}{}
	wantedDomains := map[string]struct{}{}
	for versionNumber, version := range service.ServiceVersions {
		wantedVersions[versionNumber] = struct{}{}
		for _, domain := range version.Domains {
			wantedDomains[string(domain)] = struct{}{}
		}
	}

	return wantedVersions, wantedDomains
}

// pruneService removes the version directories and HAProxy cert files that
// the manager did not send for the service, so that for example a retired
// domain stops having its certificate served. It reports whether any cert
// file was removed, since removing the file does not unload the certificate
// from a running HAProxy and the caller needs to trigger a reload.
//
// A failure to remove one entry does not stop the others from being removed,
// the errors are returned joined.
func (agt *agent) pruneService(service cdntypes.ServiceWithVersions, versionBasePath string, certsPrivatePath string) (bool, error) {
	wantedVersions, wantedDomains := wantedVersionsAndDomains(service)

	var errs []error
	removedCert := false

	staleCerts, err := staleCertFiles(certsPrivatePath, wantedDomains)
	if err != nil {
		errs = append(errs, err)
	}
	for _, certPath := range staleCerts {
		err := os.Remove(certPath)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		agt.logger.Info().Str("path", certPath).Msg("removed cert file not in cache node config")
		removedCert = true
	}

	staleVersions, err := agt.staleVersionDirs(versionBasePath, wantedVersions)
	if err != nil {
		errs = append(errs, err)
	}
	for _, versionPath := range staleVersions {
		err := os.RemoveAll(versionPath)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		agt.logger.Info().Str("path", versionPath).Msg("removed service version dir not in cache node config")
	}

	return removedCert, errors.Join(errs...)
}

// pruneSkippedService is used instead of pruneService for a service that is
// skipped because addCertsToService failed, so the version loop has not
// updated the "active" link. If the link still points at a version that was
// sent, that version's domains are kept and pruning is as safe as on the
// normal path. Otherwise (including when there is no link at all) nothing is
// pruned: emptying certs-private would make the HAProxy reload fail and keep
// the old certs loaded anyway, so only report which stale certs are kept.
func (agt *agent) pruneSkippedService(service cdntypes.ServiceWithVersions, versionBasePath string, certsPrivatePath string) (bool, error) {
	wantedVersions, wantedDomains := wantedVersionsAndDomains(service)

	activeReceived, err := activeLinkReceived(versionBasePath, wantedVersions)
	if err != nil {
		return false, err
	}

	if activeReceived {
		return agt.pruneService(service, versionBasePath, certsPrivatePath)
	}

	staleCerts, err := staleCertFiles(certsPrivatePath, wantedDomains)
	if err != nil {
		return false, err
	}
	for _, certPath := range staleCerts {
		agt.logger.Error().Str("path", certPath).Msg("keeping cert file that may no longer be wanted, service skipped due to cert problem")
	}

	return false, nil
}

// markCertRemoved records that a cert was pruned for the service, so its
// HAProxy must be reloaded to unload it. Unlike the per-pass modifiedCerts
// this survives across reconciliation passes: once the file is gone the
// next pass has nothing left to prune, so a reload that did not happen
// (an early return, docker ps failing, the reload command failing) would
// otherwise never be retried.
//
// It is only kept in memory: if the agent restarts after pruning a cert
// but before the reload, the pending reload is lost and the removed cert
// stays loaded until something else reloads that HAProxy.
func (agt *agent) markCertRemoved(orgID string, serviceID string) {
	if agt.pendingCertReloads == nil {
		agt.pendingCertReloads = map[string]map[string]struct{}{}
	}
	markServiceModified(agt.pendingCertReloads, orgID, serviceID)
}

// clearSettledCertReloads removes from pending every service that no
// longer has a removed cert loaded: those with a running HAProxy that was
// reloaded without error, and those with no running HAProxy at all, which
// loads the pruned certs-private when it starts. running and failed map
// org IDs to service IDs with a running HAProxy container and with a
// failed HAProxy reload.
func clearSettledCertReloads(pending map[string]map[string]struct{}, running map[string]map[string]struct{}, failed map[string]map[string]struct{}) {
	for orgID, services := range pending {
		for serviceID := range services {
			_, isRunning := running[orgID][serviceID]
			_, hasFailed := failed[orgID][serviceID]
			if !isRunning || !hasFailed {
				delete(services, serviceID)
			}
		}
		if len(services) == 0 {
			delete(pending, orgID)
		}
	}
}
