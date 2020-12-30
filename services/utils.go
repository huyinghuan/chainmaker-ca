package services

import "net"

const (
	defaultCountry            = "CN"
	defaultLocality           = "Beijing"
	defaultProvince           = "Beijing"
	defaultOrganizationalUnit = "ChainMaker"
	defaultOrganization       = "ChainMaker"
	defaultCommonName         = "chainmaker.org"
)

const (
	defaultExpireYear = 10
)

func dealSANS(sans []string) ([]string, []net.IP) {

	var dnsName []string
	var ipAddrs []net.IP

	for _, san := range sans {
		ip := net.ParseIP(san)
		if ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsName = append(dnsName, san)
		}
	}

	return dnsName, ipAddrs
}
