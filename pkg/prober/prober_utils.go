package prober

import (
	"context"
	"math/rand"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	errorx "github.com/pkg/errors"
	"github.com/rs/xid"
	"github.com/wissance/stringFormatter"
)

func asMillis(latency *time.Duration) float64 {
	return float64(latency.Nanoseconds()) / float64(time.Millisecond)
}

func newPrinter(taskURL *url.URL, format *string) probePrinter {
	guid := xid.New().String()
	logName := stringFormatter.Format("projects/{0}/tcpping/{1}", os.Getenv("PROJECT_ID"), guid)

	switch *format {
	default:
		return newJSONProbePrinter(guid, logName, taskURL)
	case "json":
		return newJSONProbePrinter(guid, logName, taskURL)
	}
}

func isIPv4(taskType ProberType) bool {
	switch taskType {
	default:
		return false
	case RAW_IPv4, DNS_IPv4:
		return true
	}
}

func isIPv6(taskType ProberType) bool {
	switch taskType {
	default:
		return false
	case RAW_IPv6, DNS_IPv6:
		return true
	}
}

func selectIP(IPs []netip.Addr) (IP netip.Addr, err error) {
	sizeOfIPs := len(IPs)
	if sizeOfIPs == 0 {
		return IP, errorx.WithMessage(errorUnknownHostname, "IP not found")
	}
	index := 0
	if sizeOfIPs > 1 {
		index = rand.Intn(sizeOfIPs)
	}
	return netip.ParseAddr(IPs[index].Unmap().String())
}

func selectIPv4(IPs []netip.Addr) (IPv4 netip.Addr, err error) {
	defer err2.Handle(&err, "selectIPv4")
	var list []netip.Addr
	for _, IP := range IPs {
		if IP.Is4() {
			list = append(list, IP)
		}
	}
	IPv4 = try.To1(selectIP(list))
	return IPv4, nil
}

func selectIPv6(IPs []netip.Addr) (IPv6 netip.Addr, err error) {
	defer err2.Handle(&err, "selectIPv6")
	var list []netip.Addr
	for _, IP := range IPs {
		if IP.Is6() {
			list = append(list, IP)
		}
	}
	IPv6 = try.To1(selectIP(list))
	return IPv6, nil
}

func resolveHostname(hostname *string, network string) (IPs []netip.Addr, err error) {
	defer err2.Handle(&err, "resolveHostname")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	IPs = try.To1(net.DefaultResolver.LookupNetIP(ctx, network, *hostname))
	if len(IPs) == 0 {
		return nil, errorx.WithMessage(errorUnknownHostname, *hostname)
	}
	return IPs, nil
}

func resolveHostnameToIPv4(taskURL *url.URL) (IPv4 netip.Addr, err error) {
	defer err2.Handle(&err, "resolveHostnameToIPv4")
	hostname := taskURL.Hostname()
	IPv4s := try.To1(resolveHostname(&hostname, "ip4"))
	return try.To1(selectIPv4(IPv4s)), err
}

func resolveHostnameToIPv6(taskURL *url.URL) (IPv4 netip.Addr, err error) {
	defer err2.Handle(&err, "resolveHostnameToIPv6")
	hostname := taskURL.Hostname()
	IPv4s := try.To1(resolveHostname(&hostname, "ip6"))
	return try.To1(selectIPv6(IPv4s)), err
}

func getProberTaskPort(taskURL *url.URL) (port int, err error) {
	defer err2.Handle(&err, "getProberTaskPort")
	return try.To1(strconv.Atoi(taskURL.Port())), err
}

func getProberTaskIP(taskType ProberType, taskURL *url.URL) (IP netip.Addr, err error) {
	defer err2.Handle(&err, "getProberTaskIP")
	switch taskType {
	default:
		IP = try.To1(netip.ParseAddr(taskURL.Hostname()))
	case DNS_IPv4, HTTP_IPv4, HTTPS_IPv4:
		IP = try.To1(resolveHostnameToIPv4(taskURL))
	case DNS_IPv6, HTTP_IPv6, HTTPS_IPv6:
		IP = try.To1(resolveHostnameToIPv6(taskURL))
	}
	return IP, err
}

func getProberTaskType(taskURL *url.URL) (ProberType, error) {
	switch taskURL.Scheme {
	default:
		return 0, errorx.WithMessage(errorUnknownTaskType, taskURL.Scheme)
	case RAW_IPv4_SCHEME:
		return RAW_IPv4, nil
	case RAW_IPv6_SCHEME:
		return RAW_IPv6, nil
	case DNS_IPv4_SCHEME:
		return DNS_IPv4, nil
	case DNS_IPv6_SCHEME:
		return DNS_IPv6, nil
	}
}
