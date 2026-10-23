package runner

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/rs/zerolog"
)

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	err := os.Mkdir(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
}

func mustWriteFile(t *testing.T, path string) {
	t.Helper()
	err := os.WriteFile(path, []byte("x"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target string, link string) {
	t.Helper()
	err := os.Symlink(target, link)
	if err != nil {
		t.Fatal(err)
	}
}

func mustExist(t *testing.T, path string, want bool) {
	t.Helper()
	_, err := os.Lstat(path)
	if want && err != nil {
		t.Errorf("expected %q to exist: %s", path, err)
	}
	if !want && err == nil {
		t.Errorf("expected %q to be gone", path)
	}
}

func TestStaleCertFiles(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "a.example.pem"))
	mustWriteFile(t, filepath.Join(dir, "b.example.pem"))
	mustWriteFile(t, filepath.Join(dir, "notes.txt"))
	mustMkdir(t, filepath.Join(dir, "c.example.pem"))

	got, err := staleCertFiles(dir, map[string]struct{}{"a.example": {}})
	if err != nil {
		t.Fatal(err)
	}

	want := []string{filepath.Join(dir, "b.example.pem")}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestStaleCertFilesMissingDir(t *testing.T) {
	got, err := staleCertFiles(filepath.Join(t.TempDir(), "missing"), map[string]struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestStaleVersionDirs(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"1", "2", "3", "01", "tmp"} {
		mustMkdir(t, filepath.Join(dir, name))
	}
	mustWriteFile(t, filepath.Join(dir, "4"))
	mustSymlink(t, "2", filepath.Join(dir, "active"))

	agt := agent{logger: zerolog.Nop()}
	got, err := agt.staleVersionDirs(dir, map[int64]struct{}{3: {}})
	if err != nil {
		t.Fatal(err)
	}

	want := []string{filepath.Join(dir, "1")}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestPruneService(t *testing.T) {
	base := t.TempDir()
	versionBase := filepath.Join(base, "service-versions")
	certs := filepath.Join(base, "certs-private")
	mustMkdir(t, versionBase)
	mustMkdir(t, certs)
	mustMkdir(t, filepath.Join(versionBase, "1"))
	mustMkdir(t, filepath.Join(versionBase, "3"))
	mustSymlink(t, "3", filepath.Join(versionBase, "active"))
	mustWriteFile(t, filepath.Join(certs, "a.example.pem"))
	mustWriteFile(t, filepath.Join(certs, "b.example.pem"))

	agt := agent{logger: zerolog.Nop()}
	service := cdntypes.ServiceWithVersions{
		ServiceVersions: map[int64]cdntypes.ServiceVersionWithConfig{
			3: {Version: 3, Domains: []cdntypes.DomainString{"a.example"}},
		},
	}

	removedCert, err := agt.pruneService(service, versionBase, certs)
	if err != nil {
		t.Fatal(err)
	}
	if !removedCert {
		t.Fatal("expected a cert to be removed")
	}
	mustExist(t, filepath.Join(versionBase, "1"), false)
	mustExist(t, filepath.Join(certs, "b.example.pem"), false)
	mustExist(t, filepath.Join(versionBase, "3"), true)
	mustExist(t, filepath.Join(certs, "a.example.pem"), true)

	removedCert, err = agt.pruneService(service, versionBase, certs)
	if err != nil {
		t.Fatal(err)
	}
	if removedCert {
		t.Fatal("expected nothing to remove on second call")
	}
}

func TestActiveLinkReceived(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{name: "received", target: "3", want: true},
		{name: "not received", target: "1", want: false},
		{name: "non-canonical", target: "03", want: false},
		{name: "missing link", target: "", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if test.target != "" {
				mustSymlink(t, test.target, filepath.Join(dir, "active"))
			}

			got, err := activeLinkReceived(dir, map[int64]struct{}{3: {}})
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("got %t, want %t", got, test.want)
			}
		})
	}
}

// setupPruneLayout creates a service with version dirs 1 and 3, the
// "active" link pointing at activeTarget, and cert files for a.example and
// b.example. The returned service only sends version 3 with a.example.
func setupPruneLayout(t *testing.T, activeTarget string) (string, string, cdntypes.ServiceWithVersions) {
	t.Helper()
	base := t.TempDir()
	versionBase := filepath.Join(base, "service-versions")
	certs := filepath.Join(base, "certs-private")
	mustMkdir(t, versionBase)
	mustMkdir(t, certs)
	mustMkdir(t, filepath.Join(versionBase, "1"))
	mustMkdir(t, filepath.Join(versionBase, "3"))
	mustSymlink(t, activeTarget, filepath.Join(versionBase, "active"))
	mustWriteFile(t, filepath.Join(certs, "a.example.pem"))
	mustWriteFile(t, filepath.Join(certs, "b.example.pem"))

	service := cdntypes.ServiceWithVersions{
		ServiceVersions: map[int64]cdntypes.ServiceVersionWithConfig{
			3: {Version: 3, Domains: []cdntypes.DomainString{"a.example"}},
		},
	}

	return versionBase, certs, service
}

func TestPruneSkippedServiceActiveReceived(t *testing.T) {
	versionBase, certs, service := setupPruneLayout(t, "3")

	agt := agent{logger: zerolog.Nop()}
	removedCert, err := agt.pruneSkippedService(service, versionBase, certs)
	if err != nil {
		t.Fatal(err)
	}
	if !removedCert {
		t.Fatal("expected a cert to be removed")
	}
	mustExist(t, filepath.Join(versionBase, "1"), false)
	mustExist(t, filepath.Join(certs, "b.example.pem"), false)
	mustExist(t, filepath.Join(versionBase, "3"), true)
	mustExist(t, filepath.Join(certs, "a.example.pem"), true)
}

func TestPruneSkippedServiceActiveNotReceived(t *testing.T) {
	versionBase, certs, service := setupPruneLayout(t, "1")

	var logBuf bytes.Buffer
	agt := agent{logger: zerolog.New(&logBuf)}
	removedCert, err := agt.pruneSkippedService(service, versionBase, certs)
	if err != nil {
		t.Fatal(err)
	}
	if removedCert {
		t.Fatal("expected no cert to be removed")
	}
	mustExist(t, filepath.Join(versionBase, "1"), true)
	mustExist(t, filepath.Join(versionBase, "3"), true)
	mustExist(t, filepath.Join(certs, "a.example.pem"), true)
	mustExist(t, filepath.Join(certs, "b.example.pem"), true)

	if !strings.Contains(logBuf.String(), "b.example.pem") {
		t.Fatalf("expected the kept stale cert to be logged, got: %s", logBuf.String())
	}
}

// TestPruneServiceWarnsActiveNotReceived uses the same layout as
// TestPruneSkippedServiceActiveNotReceived but goes through the normal
// path: there everything is kept, here the active target is kept and
// warned about while the rest is still pruned.
func TestPruneServiceWarnsActiveNotReceived(t *testing.T) {
	versionBase, certs, service := setupPruneLayout(t, "1")

	var logBuf bytes.Buffer
	agt := agent{logger: zerolog.New(&logBuf)}
	removedCert, err := agt.pruneService(service, versionBase, certs)
	if err != nil {
		t.Fatal(err)
	}
	if !removedCert {
		t.Fatal("expected the stale cert to be removed")
	}

	// The active target must survive even though it was not sent.
	mustExist(t, filepath.Join(versionBase, "1"), true)
	mustExist(t, filepath.Join(versionBase, "3"), true)
	mustExist(t, filepath.Join(certs, "a.example.pem"), true)
	mustExist(t, filepath.Join(certs, "b.example.pem"), false)

	if !strings.Contains(logBuf.String(), `"level":"warn"`) {
		t.Fatalf("expected a warning about the active link, got: %s", logBuf.String())
	}
}

func TestMarkServiceModified(t *testing.T) {
	m := map[string]map[string]struct{}{}
	markServiceModified(m, "org1", "svc1")
	markServiceModified(m, "org1", "svc2")
	markServiceModified(m, "org2", "svc3")

	if len(m) != 2 || len(m["org1"]) != 2 || len(m["org2"]) != 1 {
		t.Fatalf("unexpected map: %v", m)
	}
	if _, ok := m["org1"]["svc2"]; !ok {
		t.Fatalf("expected org1/svc2 to be marked: %v", m)
	}
}

func TestMarkCertRemovedPersists(t *testing.T) {
	// A zero agent, as in the other tests, must not panic.
	agt := agent{logger: zerolog.Nop()}
	agt.markCertRemoved("org1", "svc1")
	agt.markCertRemoved("org1", "svc2")

	if _, ok := agt.pendingCertReloads["org1"]["svc1"]; !ok {
		t.Fatalf("expected org1/svc1 to be pending: %v", agt.pendingCertReloads)
	}
	if len(agt.pendingCertReloads["org1"]) != 2 {
		t.Fatalf("unexpected pending reloads: %v", agt.pendingCertReloads)
	}
}

func TestClearSettledCertReloads(t *testing.T) {
	// Every service had a cert removed and is waiting for a reload.
	pending := map[string]map[string]struct{}{
		"org1": {
			// HAProxy is running and was reloaded: cleared.
			"reload-ok": {},
			// HAProxy is running but its reload failed, so the
			// removed cert is still loaded: kept for the next pass.
			"reload-failed": {},
			// No HAProxy is running, so nothing has the cert
			// loaded and a later start loads the pruned
			// certs-private: cleared.
			"not-running": {},
		},
		"org2": {
			// Same as not-running, and the only service in org2:
			// once cleared, the now empty org2 must be removed too.
			"only-service-not-running": {},
		},
	}
	running := map[string]map[string]struct{}{
		"org1": {
			"reload-ok":     {},
			"reload-failed": {},
		},
	}
	failed := map[string]map[string]struct{}{
		"org1": {
			"reload-failed": {},
		},
	}

	clearSettledCertReloads(pending, running, failed)

	want := map[string]map[string]struct{}{
		"org1": {"reload-failed": {}},
	}
	if !reflect.DeepEqual(pending, want) {
		t.Fatalf("got %v, want %v", pending, want)
	}
}
