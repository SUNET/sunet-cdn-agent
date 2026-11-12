package runner

import (
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	alloyTargetsDir      = "/etc/alloy/targets.d"
	alloyTargetsFilename = "sunet-cdn-agent.yaml"
	alloyMetricsPort     = 9090
)

// alloyJob is a set of metrics exposed per service behind the haproxy
// metrics listener on alloyMetricsPort.
type alloyJob struct {
	Name        string
	MetricsPath string
}

var alloyJobs = []alloyJob{
	{Name: "haproxy", MetricsPath: "/haproxy/metrics"},
	{Name: "vinyl", MetricsPath: "/vinyl/metrics"},
}

// alloyTargetGroup is one entry in the file_sd style targets file read
// by Alloy.
type alloyTargetGroup struct {
	Targets []string          `yaml:"targets"`
	Labels  alloyTargetLabels `yaml:"labels"`
}

// alloyTargetLabels is a struct rather than a map to keep the labels in
// a fixed, readable order in the generated file.
type alloyTargetLabels struct {
	Job         string `yaml:"job"`
	MetricsPath string `yaml:"__metrics_path__"`
	Instance    string `yaml:"instance"`
	ListenIPv4  string `yaml:"listen_ipv4,omitempty"`
	ListenIPv6  string `yaml:"listen_ipv6,omitempty"`
	OrgID       string `yaml:"cdn_org_id"`
	ServiceID   string `yaml:"cdn_service_id"`
}

// buildAlloyTargetGroups returns one target group per job for every
// service that has an address to scrape, in the order of
// orgIPContainers. The IPv4 address is scraped if present, otherwise the
// IPv6 address. A service currently has at most one address of each
// family. Addresses are unmapped the same way the manager does when it
// sets up the haproxy listeners, so an IPv4-mapped IPv6 address counts as
// IPv4.
func buildAlloyTargetGroups(instance string, orgIPContainers []orgIPContainer) []alloyTargetGroup {
	groups := []alloyTargetGroup{}
	for _, orgIPCont := range orgIPContainers {
		for _, serviceIPCont := range orgIPCont.ServiceIPContainers {
			var ipv4, ipv6 netip.Addr
			for _, addr := range serviceIPCont.IPAddresses {
				addr = addr.Unmap()
				if addr.Is4() && !ipv4.IsValid() {
					ipv4 = addr
				} else if addr.Is6() && !ipv6.IsValid() {
					ipv6 = addr
				}
			}

			scrapeAddr := ipv4
			if !scrapeAddr.IsValid() {
				scrapeAddr = ipv6
			}
			if !scrapeAddr.IsValid() {
				continue
			}

			for _, job := range alloyJobs {
				labels := alloyTargetLabels{
					Job:         job.Name,
					MetricsPath: job.MetricsPath,
					Instance:    instance,
					OrgID:       orgIPCont.ID.String(),
					ServiceID:   serviceIPCont.ID.String(),
				}
				if ipv4.IsValid() {
					labels.ListenIPv4 = ipv4.String()
				}
				if ipv6.IsValid() {
					labels.ListenIPv6 = ipv6.String()
				}
				groups = append(groups, alloyTargetGroup{
					Targets: []string{netip.AddrPortFrom(scrapeAddr, alloyMetricsPort).String()},
					Labels:  labels,
				})
			}
		}
	}

	return groups
}

func generateAlloyTargets(instance string, orgIPContainers []orgIPContainer) (string, error) {
	var b strings.Builder

	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)

	err := enc.Encode(buildAlloyTargetGroups(instance, orgIPContainers))
	if err != nil {
		return "", err
	}

	err = enc.Close()
	if err != nil {
		return "", err
	}

	return b.String(), nil
}

// setupAlloyTargets writes the Alloy scrape targets for the services on
// this node to targetsDir. Nodes without Alloy are left alone: nothing is
// written unless targetsDir already exists.
func (agt *agent) setupAlloyTargets(instance string, orgIPContainers []orgIPContainer, targetsDir string, uid int, gid int) error {
	_, err := os.Stat(targetsDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			agt.logger.Debug().Str("path", targetsDir).Msg("alloy targets dir does not exist, not writing alloy targets")
			return nil
		}
		return err
	}

	content, err := generateAlloyTargets(instance, orgIPContainers)
	if err != nil {
		return err
	}

	_, err = agt.createOrUpdateFile(filepath.Join(targetsDir, alloyTargetsFilename), uid, gid, 0o644, content)
	if err != nil {
		return err
	}

	return nil
}
