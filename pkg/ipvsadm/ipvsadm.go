package ipvsadm

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/SUNET/sunet-cdn-agent/pkg/utils"
	"github.com/rs/zerolog"
)

type virtualServiceIdentifier struct {
	protocol string
	address  netip.Addr
	port     uint16
}

type virtualServiceSettings struct {
	schedulingMethod string
}

type realServerSettings struct {
	weight           int
	forwardingMethod string
}

type VirtualService struct {
	virtualServiceIdentifier
	virtualServiceSettings
}

type realServerIdentifier struct {
	virtualServiceIdentifier
	address netip.Addr
	port    uint16
}

type RealServer struct {
	realServerIdentifier
	realServerSettings
}

// Will output the equivalent ipvsadm command to add the real-server
func (rs RealServer) String() string {
	// Expected output:
	// -a -t 1.3.3.8:443 -r 10.0.0.1:443 -i -w 1 --tun-type ipip
	// -a -t [2001:db8:1337::1]:80 -r [2001:db8:1338::1]:80 -i -w 1 --tun-type ipip
	var b strings.Builder

	b.WriteString("-a")
	b.WriteString(" ")

	appendRealServer(rs, &b)

	return b.String()
}

func (rs RealServer) deleteString() string {
	// Expected output: -d -t 188.240.152.1:443  -r 192.36.171.94:443
	var b strings.Builder

	b.WriteString("-d")
	b.WriteString(" ")
	switch rs.protocol {
	case "tcp":
		b.WriteString("-t")
		b.WriteString(" ")
	}
	if rs.virtualServiceIdentifier.address.Is6() {
		b.WriteString("[")
	}
	b.WriteString(rs.virtualServiceIdentifier.address.String())
	if rs.virtualServiceIdentifier.address.Is6() {
		b.WriteString("]")
	}
	b.WriteString(":")
	b.WriteString(strconv.Itoa(int(rs.virtualServiceIdentifier.port)))
	b.WriteString(" ")

	b.WriteString("-r")
	b.WriteString(" ")

	if rs.address.Is6() {
		b.WriteString("[")
	}
	b.WriteString(rs.address.String())
	if rs.address.Is6() {
		b.WriteString("]")
	}
	b.WriteString(":")
	b.WriteString(strconv.Itoa(int(rs.port)))
	b.WriteString(" ")

	return b.String()
}

// We can use the same arguments for both adding and editing a real-server
func appendRealServer(rs RealServer, b *strings.Builder) string {
	if rs.protocol == "tcp" {
		b.WriteString("-t")
	}
	b.WriteString(" ")

	if rs.virtualServiceIdentifier.address.Is6() {
		b.WriteString("[")
	}
	b.WriteString(rs.virtualServiceIdentifier.address.String())
	if rs.virtualServiceIdentifier.address.Is6() {
		b.WriteString("]")
	}

	b.WriteString(":")
	b.WriteString(strconv.Itoa(int(rs.virtualServiceIdentifier.port)))
	b.WriteString(" ")

	b.WriteString("-r")
	b.WriteString(" ")

	if rs.address.Is6() {
		b.WriteString("[")
	}
	b.WriteString(rs.address.String())
	if rs.address.Is6() {
		b.WriteString("]")
	}

	b.WriteString(":")
	b.WriteString(strconv.Itoa(int(rs.port)))
	b.WriteString(" ")

	if rs.forwardingMethod == "ipip" {
		b.WriteString("-i")
		b.WriteString(" ")
	}

	b.WriteString("-w")
	b.WriteString(" ")
	b.WriteString(strconv.Itoa(rs.weight))
	b.WriteString(" ")

	if rs.forwardingMethod == "ipip" {
		b.WriteString("--tun-type ipip")
	}

	return b.String()
}

// Will output the equivalent ipvsadm command to edit an existing real-server, same as String() but with -e
func (rs RealServer) editString() string {
	// Expected output:
	// -a -t 1.3.3.8:443 -r 10.0.0.1:443 -i -w 1 --tun-type ipip
	// -a -t [2001:db8:1337::1]:80 -r [2001:db8:1338::1]:80 -i -w 1 --tun-type ipip
	var b strings.Builder

	b.WriteString("-e")
	b.WriteString(" ")

	appendRealServer(rs, &b)

	return b.String()
}

// Will output the equivalent ipvsadm command to edit an existing service
func (vs VirtualService) editString() string {
	// Expected output: -E -t 188.240.152.1:443 -s mh
	var b strings.Builder

	b.WriteString("-E")
	b.WriteString(" ")

	appendVirtualService(vs, &b)

	return b.String()
}

func (vs VirtualService) deleteString() string {
	// Expected output: -D -t 10.0.0.1:443
	var b strings.Builder

	b.WriteString("-D")
	b.WriteString(" ")
	switch vs.protocol {
	case "tcp":
		b.WriteString("-t")
		b.WriteString(" ")
	}
	if vs.address.Is6() {
		b.WriteString("[")
	}
	b.WriteString(vs.address.String())
	if vs.address.Is6() {
		b.WriteString("]")
	}
	b.WriteString(":")
	b.WriteString(strconv.Itoa(int(vs.port)))

	return b.String()
}

// append the virtual-service arguments that are the same between -A and -E
func appendVirtualService(vs VirtualService, b *strings.Builder) {
	if vs.protocol == "tcp" {
		b.WriteString("-t")
	}
	b.WriteString(" ")

	if vs.address.Is6() {
		b.WriteString("[")
	}
	b.WriteString(vs.address.String())
	if vs.address.Is6() {
		b.WriteString("]")
	}
	b.WriteString(":")
	b.WriteString(strconv.Itoa(int(vs.port)))
	b.WriteString(" ")

	b.WriteString("-s")
	b.WriteString(" ")

	b.WriteString(vs.schedulingMethod)
}

// Will output the equivalent ipvsadm command to add the virtual service
func (vs VirtualService) String() string {
	// Expected output: -A -t 10.0.0.1:80 -s mh
	var b strings.Builder

	b.WriteString("-A")
	b.WriteString(" ")

	appendVirtualService(vs, &b)

	return b.String()
}

func NewVirtualService(protocol string, serviceIP netip.Addr, port uint16, schedulingMethod string) (VirtualService, error) {
	if protocol != "tcp" {
		return VirtualService{}, fmt.Errorf("unspported protocol '%s', only 'tcp' is supported", protocol)
	}

	return VirtualService{
		virtualServiceIdentifier: virtualServiceIdentifier{
			protocol: protocol,
			address:  serviceIP,
			port:     uint16(port),
		},
		virtualServiceSettings: virtualServiceSettings{
			schedulingMethod: schedulingMethod,
		},
	}, nil
}

func parseVirtualService(ipvsRule string) (VirtualService, error) {
	// Expected input
	// -A -t 10.0.0.1:80 -s mh
	// -A -t [2001:db8:1337::1]:80 -s mh
	commandFlagOffset := 0
	protocolFlagOffset := 1
	virtualServiceOffset := 2
	schedulingFlagOffset := 3
	schedulingMethodOffset := 4

	ruleFields := strings.Fields(ipvsRule)
	if len(ruleFields) != 5 {
		return VirtualService{}, fmt.Errorf("unexpected number of fields %d: %s", len(ruleFields), ipvsRule)
	}

	expectedCommandFlag := "-A"
	if ruleFields[commandFlagOffset] != expectedCommandFlag {
		return VirtualService{}, fmt.Errorf("unexpected virtual-service command '%s', only '%s' is supported", ruleFields[commandFlagOffset], expectedCommandFlag)
	}

	vsi := virtualServiceIdentifier{}

	switch ruleFields[protocolFlagOffset] {
	case "-t":
		vsi.protocol = "tcp"
	default:
		return VirtualService{}, fmt.Errorf("unexpected virtual-service protocol '%s', only '-t' is supported", ruleFields[protocolFlagOffset])
	}

	addr, port, err := parseHostPort(ruleFields[virtualServiceOffset])
	if err != nil {
		return VirtualService{}, fmt.Errorf("unable to split virtual-service host:port: %w", err)
	}

	vsi.address = addr
	vsi.port = port

	if ruleFields[schedulingFlagOffset] != "-s" {
		return VirtualService{}, fmt.Errorf("virtual-service unexpected content for scheduling flag '%s', only '-s' is expected", ruleFields[schedulingFlagOffset])
	}

	if ruleFields[schedulingMethodOffset] != "mh" {
		return VirtualService{}, fmt.Errorf("virtual-service unexpected scheduling method '%s', only 'mh' is expected", ruleFields[schedulingMethodOffset])
	}

	vss := virtualServiceSettings{
		schedulingMethod: ruleFields[schedulingMethodOffset],
	}

	return VirtualService{
		virtualServiceIdentifier: vsi,
		virtualServiceSettings:   vss,
	}, nil
}

func parseHostPort(hostPort string) (netip.Addr, uint16, error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("unable to split host:port '%s': %w", hostPort, err)
	}

	hostAddr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("unable to parse host address '%s': %w", host, err)
	}

	portInt, err := strconv.ParseInt(portStr, 10, 64)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("unable to parse port '%s': %w", portStr, err)
	}

	if portInt < 0 || portInt > math.MaxUint16 {
		return netip.Addr{}, 0, fmt.Errorf("port '%d' is outside valid port range [%d,%d]", portInt, 0, math.MaxUint16)
	}
	port := uint16(portInt)

	return hostAddr, port, nil
}

func NewRealServer(protocol string, serviceIP netip.Addr, servicePort uint16, serverIP netip.Addr, serverPort uint16, weigth int, forwardingMethod string) (RealServer, error) {
	if protocol != "tcp" {
		return RealServer{}, fmt.Errorf("unspported protocol '%s', only 'tcp' is supported", protocol)
	}

	if forwardingMethod != "ipip" {
		return RealServer{}, fmt.Errorf("unspported forwarding method '%s', only 'ipip' is supported", forwardingMethod)
	}

	return RealServer{
		realServerIdentifier: realServerIdentifier{
			virtualServiceIdentifier: virtualServiceIdentifier{
				protocol: protocol,
				address:  serviceIP,
				port:     uint16(servicePort),
			},
			address: serverIP,
			port:    serverPort,
		},
		realServerSettings: realServerSettings{
			weight:           weigth,
			forwardingMethod: forwardingMethod,
		},
	}, nil
}

func parseRealServer(ipvsRule string) (RealServer, error) {
	// Expected input:
	// -a -t 1.3.3.8:443 -r 10.0.0.1:443 -i -w 1 --tun-type ipip
	// -a -t [2001:db8:1337::1]:80 -r [2001:db8:1338::1]:80 -i -w 1 --tun-type ipip
	commandFlagOffset := 0
	protocolFlagOffset := 1
	virtualServiceOffset := 2
	realServerFlagOffset := 3
	realServerOffset := 4
	forwardingMethodFlagOffset := 5
	weightFlagOffset := 6
	weightOffset := 7
	tunnelTypeFlagOffset := 8
	tunnelTypeOffset := 9

	ruleFields := strings.Fields(ipvsRule)
	if len(ruleFields) != 10 {
		return RealServer{}, fmt.Errorf("unexpected number of fields %d: %s", len(ruleFields), ipvsRule)
	}

	expectedCommandFlag := "-a"
	if ruleFields[commandFlagOffset] != expectedCommandFlag {
		return RealServer{}, fmt.Errorf("unexpected real-server command '%s', only '%s' is supported", ruleFields[commandFlagOffset], expectedCommandFlag)
	}

	rsi := realServerIdentifier{}

	switch ruleFields[protocolFlagOffset] {
	case "-t":
		rsi.protocol = "tcp"
	default:
		return RealServer{}, fmt.Errorf("unexpected virtual-service protocol '%s', only '-t' is supported", ruleFields[protocolFlagOffset])
	}

	serviceAddr, servicePort, err := parseHostPort(ruleFields[virtualServiceOffset])
	if err != nil {
		return RealServer{}, fmt.Errorf("unable to split virtual-service host:port: %w", err)
	}
	rsi.virtualServiceIdentifier.address = serviceAddr
	rsi.virtualServiceIdentifier.port = servicePort

	expectedRealServerFlag := "-r"
	if ruleFields[realServerFlagOffset] != expectedRealServerFlag {
		return RealServer{}, fmt.Errorf("unexpected real-server flag '%s', should be '%s'", ruleFields[realServerFlagOffset], expectedRealServerFlag)
	}

	realServerAddr, realServerPort, err := parseHostPort(ruleFields[realServerOffset])
	if err != nil {
		return RealServer{}, fmt.Errorf("unable to split virtual-service host:port: %w", err)
	}
	rsi.address = realServerAddr
	rsi.port = realServerPort

	rss := realServerSettings{}

	switch ruleFields[forwardingMethodFlagOffset] {
	case "-i":
		rss.forwardingMethod = "ipip"
	default:
		return RealServer{}, fmt.Errorf("real-server unexpected content for forwarding method flag '%s', only '-i' is expected", ruleFields[forwardingMethodFlagOffset])
	}

	if ruleFields[weightFlagOffset] != "-w" {
		return RealServer{}, fmt.Errorf("real-server unexpected weight flag '%s', only '-w' is expected", ruleFields[weightFlagOffset])
	}

	rss.weight, err = strconv.Atoi(ruleFields[weightOffset])
	if err != nil {
		return RealServer{}, fmt.Errorf("unable to parse weight value '%s' as integer: %w", ruleFields[weightOffset], err)
	}

	if ruleFields[tunnelTypeFlagOffset] != "--tun-type" {
		return RealServer{}, fmt.Errorf("unexpeted value '%s' at tunnel type offset, only '--tun-type' is expected", ruleFields[tunnelTypeFlagOffset])
	}

	if ruleFields[tunnelTypeOffset] != "ipip" {
		return RealServer{}, fmt.Errorf("unexpeted value '%s' for tunnel type, only 'ipip' is expected", ruleFields[tunnelTypeOffset])
	}

	return RealServer{
		realServerIdentifier: rsi,
		realServerSettings:   rss,
	}, nil
}

type RuleSet struct {
	virtualServices []VirtualService
	realServers     []RealServer
	ruleMap         map[virtualServiceIdentifier]map[realServerIdentifier]struct{}
}

func NewRuleset() RuleSet {
	return RuleSet{
		ruleMap: map[virtualServiceIdentifier]map[realServerIdentifier]struct{}{},
	}
}

func (rset *RuleSet) AddVS(vs VirtualService) error {
	if _, ok := rset.ruleMap[vs.virtualServiceIdentifier]; ok {
		return errors.New("virtual-service already exists in ruleset")
	}

	rset.ruleMap[vs.virtualServiceIdentifier] = map[realServerIdentifier]struct{}{}
	rset.virtualServices = append(rset.virtualServices, vs)

	return nil
}

func (rset *RuleSet) AddRS(rs RealServer) error {
	if _, ok := rset.ruleMap[rs.virtualServiceIdentifier]; !ok {
		return errors.New("related virtual-service does not exists in ruleset")
	}

	if _, ok := rset.ruleMap[rs.virtualServiceIdentifier][rs.realServerIdentifier]; ok {
		return errors.New("real-server already exists in ruleset")
	}

	rset.ruleMap[rs.virtualServiceIdentifier][rs.realServerIdentifier] = struct{}{}
	rset.realServers = append(rset.realServers, rs)

	return nil
}

func ParseRules(rules string) (RuleSet, error) {
	// Use slices for ordering
	virtualServices := []VirtualService{}
	realServers := []RealServer{}

	// Use map for relations
	ruleMap := map[virtualServiceIdentifier]map[realServerIdentifier]struct{}{}

	scanner := bufio.NewScanner(strings.NewReader(rules))
	for scanner.Scan() {
		ipvsRule := scanner.Text()
		switch {
		case strings.HasPrefix(ipvsRule, "-A "):
			vs, err := parseVirtualService(ipvsRule)
			if err != nil {
				return RuleSet{}, fmt.Errorf("unable to parse virtual-service rule '%s': %w", ipvsRule, err)
			}

			// Verify our String() method produces the same string we parsed
			if ipvsRule != vs.String() {
				return RuleSet{}, fmt.Errorf("virtual-service rule output mismatch, input: '%s', output: '%s'", ipvsRule, vs.String())
			}

			virtualServices = append(virtualServices, vs)

			if _, ok := ruleMap[vs.virtualServiceIdentifier]; !ok {
				ruleMap[vs.virtualServiceIdentifier] = map[realServerIdentifier]struct{}{}
			} else {
				return RuleSet{}, fmt.Errorf("found duplicate virtualServiceIdentifier, this is unexpected, rule: '%s'", ipvsRule)
			}
		case strings.HasPrefix(ipvsRule, "-a "):
			rs, err := parseRealServer(ipvsRule)
			if err != nil {
				return RuleSet{}, fmt.Errorf("unable to parse real-server rule '%s': %w", ipvsRule, err)
			}

			// Verify our String() method produces the same string we parsed
			if ipvsRule != rs.String() {
				return RuleSet{}, fmt.Errorf("real-server rule output mismatch, input: '%s', output: '%s'", ipvsRule, rs.String())
			}
			realServers = append(realServers, rs)

			if _, ok := ruleMap[rs.virtualServiceIdentifier]; !ok {
				return RuleSet{}, fmt.Errorf("not finding virtual service for real-server, this should already be parsed, rule: '%s'", ipvsRule)
			}

			if _, ok := ruleMap[rs.virtualServiceIdentifier][rs.realServerIdentifier]; !ok {
				ruleMap[rs.virtualServiceIdentifier][rs.realServerIdentifier] = struct{}{}
			} else {
				return RuleSet{}, fmt.Errorf("found duplicate real-server identifier, this is unexpected, rule: '%s'", ipvsRule)
			}
		}
	}

	return RuleSet{
		virtualServices: virtualServices,
		realServers:     realServers,
		ruleMap:         ruleMap,
	}, nil
}

type IPVSUpdates struct {
	vsToDelete []virtualServiceIdentifier
	vsToAdd    []virtualServiceIdentifier
	vsToEdit   []virtualServiceIdentifier

	rsToDelete []realServerIdentifier
	rsToAdd    []realServerIdentifier
	rsToEdit   []realServerIdentifier
}

func UpdateRules(logger zerolog.Logger, loadedRuleSet RuleSet, newRuleSet RuleSet, updates IPVSUpdates) error {
	// Delete virtual services first so any related real-servers are also removed
	for _, vsIdent := range updates.vsToDelete {
		for _, loadedVS := range loadedRuleSet.virtualServices {
			if loadedVS.virtualServiceIdentifier == vsIdent {
				logger.Info().Str("ipvsadm_args", loadedVS.deleteString()).Msg("deleting virtual service")
				stdout, stderr, err := utils.RunCommand("ipvsadm", strings.Fields(loadedVS.deleteString())...)
				if err != nil {
					return fmt.Errorf("UpdateRules: unable to delete virtual-service, stdout: '%s', stderr: '%s': %w", stdout, stderr, err)
				}
				break
			}
		}
	}

	// Add any new virtual services
	for _, vsIdent := range updates.vsToAdd {
		for _, newVS := range newRuleSet.virtualServices {
			if newVS.virtualServiceIdentifier == vsIdent {
				logger.Info().Str("ipvsadm_args", newVS.String()).Msg("adding virtual service")
				stdout, stderr, err := utils.RunCommand("ipvsadm", strings.Fields(newVS.String())...)
				if err != nil {
					return fmt.Errorf("UpdateRules: unable to add virtual-service, stdout: '%s', stderr: '%s': %w", stdout, stderr, err)
				}
				break
			}
		}
	}

	// Edit any virtual services
	for _, vsIdent := range updates.vsToEdit {
		for _, newVS := range newRuleSet.virtualServices {
			if newVS.virtualServiceIdentifier == vsIdent {
				logger.Info().Str("ipvsadm_args", newVS.editString()).Msg("editing virtual service")
				stdout, stderr, err := utils.RunCommand("ipvsadm", strings.Fields(newVS.editString())...)
				if err != nil {
					return fmt.Errorf("UpdateRules: unable to edit virtual-service, stdout: '%s', stderr: '%s': %w", stdout, stderr, err)
				}
				break
			}
		}
	}

	// Delete real servers
	for _, rsIdent := range updates.rsToDelete {
		for _, loadedRS := range loadedRuleSet.realServers {
			if loadedRS.realServerIdentifier == rsIdent {
				logger.Info().Str("ipvsadm_args", loadedRS.deleteString()).Msg("deleting real server")
				stdout, stderr, err := utils.RunCommand("ipvsadm", strings.Fields(loadedRS.deleteString())...)
				if err != nil {
					return fmt.Errorf("UpdateRules: unable to delete real-server, stdout: '%s', stderr: '%s': %w", stdout, stderr, err)
				}
				break
			}
		}
	}

	// Add real servers
	for _, rsIdent := range updates.rsToAdd {
		for _, newRS := range newRuleSet.realServers {
			if newRS.realServerIdentifier == rsIdent {
				logger.Info().Str("ipvsadm_args", newRS.String()).Msg("adding real server")
				stdout, stderr, err := utils.RunCommand("ipvsadm", strings.Fields(newRS.String())...)
				if err != nil {
					return fmt.Errorf("UpdateRules: unable to add real-server, stdout: '%s', stderr: '%s': %w", stdout, stderr, err)
				}
				break
			}
		}
	}

	// Edit real servers
	for _, rsIdent := range updates.rsToEdit {
		for _, newRS := range newRuleSet.realServers {
			if newRS.realServerIdentifier == rsIdent {
				logger.Info().Str("ipvsadm_args", newRS.editString()).Msg("editing real server")
				stdout, stderr, err := utils.RunCommand("ipvsadm", strings.Fields(newRS.editString())...)
				if err != nil {
					return fmt.Errorf("UpdateRules: unable to edit real-server, stdout: '%s', stderr: '%s': %w", stdout, stderr, err)
				}
				break
			}
		}
	}

	return nil
}

func FindRuleUpdates(loadedRuleSet RuleSet, newRuleSet RuleSet) IPVSUpdates {
	vsToDelete := []virtualServiceIdentifier{}
	vsToAdd := []virtualServiceIdentifier{}
	vsToEdit := []virtualServiceIdentifier{}

	// Virtual services
	for _, loadedVS := range loadedRuleSet.virtualServices {
		// Loaded virtual services that are not in the new ruleset needs to be deleted
		if _, ok := newRuleSet.ruleMap[loadedVS.virtualServiceIdentifier]; !ok {
			vsToDelete = append(vsToDelete, loadedVS.virtualServiceIdentifier)
			continue
		}
	}

	for _, newVS := range newRuleSet.virtualServices {
		// New virtual services that are not loaded needs to be added
		if _, ok := loadedRuleSet.ruleMap[newVS.virtualServiceIdentifier]; !ok {
			vsToAdd = append(vsToAdd, newVS.virtualServiceIdentifier)
			continue
		}

		// If the new virtual-service identifier already exists, see if we need to modify settings
		for _, loadedVS := range loadedRuleSet.virtualServices {
			if newVS.virtualServiceIdentifier == loadedVS.virtualServiceIdentifier {
				if newVS.virtualServiceSettings != loadedVS.virtualServiceSettings {
					vsToEdit = append(vsToEdit, newVS.virtualServiceIdentifier)
					break
				}
			}
		}
	}

	rsToDelete := []realServerIdentifier{}
	rsToAdd := []realServerIdentifier{}
	rsToEdit := []realServerIdentifier{}

	// Real servers
loadedRealServerLoop:
	for _, loadedRS := range loadedRuleSet.realServers {
		// If a loaded real-server rule is part of a service that is going to be deleted the real-server will be automatically deleted so dont do anything here
		for _, vsIdentifier := range vsToDelete {
			if loadedRS.virtualServiceIdentifier == vsIdentifier {
				// Skipping real-server checks for rule that belongs to virtual service that is going to be deleted anyway
				continue loadedRealServerLoop
			}
		}

		if _, ok := newRuleSet.ruleMap[loadedRS.virtualServiceIdentifier][loadedRS.realServerIdentifier]; !ok {
			rsToDelete = append(rsToDelete, loadedRS.realServerIdentifier)
		}
	}

newRealServerLoop:
	for _, newRS := range newRuleSet.realServers {
		// If a new real-server rule is part of a service that is going
		// to be addded (not yet exists) the real-server will always
		// also need to be added
		for _, vsIdentifier := range vsToAdd {
			if newRS.virtualServiceIdentifier == vsIdentifier {
				// Adding new real server unconditionally as the related virtual-service is also to be added
				rsToAdd = append(rsToAdd, newRS.realServerIdentifier)
				continue newRealServerLoop
			}
		}

		// New real-serverers that are not loaded needs to be added
		if _, ok := loadedRuleSet.ruleMap[newRS.virtualServiceIdentifier][newRS.realServerIdentifier]; !ok {
			rsToAdd = append(rsToAdd, newRS.realServerIdentifier)
			continue
		}

		// If the new real-server identifier already exists, see if we need to modify settings
		for _, loadedRS := range loadedRuleSet.realServers {
			if newRS.realServerIdentifier == loadedRS.realServerIdentifier {
				if newRS.realServerSettings != loadedRS.realServerSettings {
					rsToEdit = append(rsToEdit, newRS.realServerIdentifier)
					break
				}
			}
		}
	}

	return IPVSUpdates{
		vsToAdd:    vsToAdd,
		vsToDelete: vsToDelete,
		vsToEdit:   vsToEdit,
		rsToAdd:    rsToAdd,
		rsToDelete: rsToDelete,
		rsToEdit:   rsToEdit,
	}
}

func (rset RuleSet) GenerateRules() string {
	var b strings.Builder

	// While we probably could just print all virtual servers followed by
	// all real-servers and skip the nested looping this way rules are
	// arranged similarly to how ipvsadm outputs them by default. Ideally
	// we would match "ipvsadm --save" after loading the rule file.
	for _, vs := range rset.virtualServices {
		b.WriteString(vs.String() + "\n")
		for _, rs := range rset.realServers {
			if rs.virtualServiceIdentifier == vs.virtualServiceIdentifier {
				b.WriteString(rs.String() + "\n")
			}
		}
	}

	return b.String()
}
