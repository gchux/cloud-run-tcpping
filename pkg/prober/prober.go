package prober

import (
	"container/ring"
	"context"
	"errors"
	"log"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	"github.com/go-toolbelt/jitter"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	errorx "github.com/pkg/errors"
	"gonum.org/v1/gonum/stat"
)

type (
	ProberType  uint8
	taskTypeStr string

	logSizeType = uint16

	proberTaskData struct {
		latency *time.Duration
	}

	proberTaskStats struct {
		TotalProbes          uint64
		TotalSuccessful      uint64
		TotalFailures        uint64
		ConsecutiveSuccesful uint64
		ConsecutiveFailures  uint64
		LastLatency          float64
		DeltaLatency         float64
		OverallMinLatency    float64
		OverallMaxLatency    float64
		MinLatency           float64
		MaxLatency           float64
		AverageLatency       float64
		StandardDeviation    float64
		Skewness             float64
	}

	proberTask struct {
		Raw       string
		URL       *url.URL
		Type      ProberType
		IPv4      bool
		IPv6      bool
		IP        netip.Addr
		Port      uint16
		Target    *netip.AddrPort
		Params    *proberTaskParams
		Stats     *proberTaskStats
		Latencies *ring.Ring
		Printer   *probePrinter
	}

	probePrinter interface {
		printProbe(*proberTask, *uint64, *netip.AddrPort, *time.Duration, error)
		printStats(*proberTask, *logSizeType)
		printDNSUpdate(*proberTask, *time.Duration, *netip.Addr, bool, error)
	}

	Prober interface {
		probe(context.Context, *uint64) (*time.Duration, error)
		printStats()
		interval() *time.Duration
		RawURL() *string
		T() ProberType
	}
)

const (
	RAW_IPv4 ProberType = iota + 1 // EnumIndex = 1
	RAW_IPv6
	DNS_IPv4
	DNS_IPv6
	HTTP_IPv4
	HTTP_IPv6
	HTTPS_IPv4
	HTTPS_IPv6
)

const (
	RAW_IPv4_SCHEME   string = "ipv4"
	RAW_IPv6_SCHEME   string = "ipv6"
	DNS_IPv4_SCHEME   string = "dns+ipv4"
	DNS_IPv6_SCHEME   string = "dns+ipv6"
	HTTP_IPv4_SCHEME  string = "http+ipv4" // HTTP(S) prober always uses DNS
	HTTPS_IPv4_SCHEME string = "https+ipv4"
	HTTP_IPv6_SCHEME  string = "http+ipv6"
	HTTPS_IPv6_SCHEME string = "https+ipv6"
)

var (
	errorUnknownTaskType      = errorx.New("unknown task type")
	errorUnknownHostname      = errorx.New("unknown hostname")
	errorDNSUpdateNotRequired = errorx.New("DNS refresh is not required")
)

var logrotateLogger = log.New(os.Stderr, "logrotate", log.LstdFlags)

func (pt *proberTask) printStats() {
	params := pt.Params
	stats := pt.Stats

	size := params.LogSize
	if stats.TotalProbes <= uint64(size) {
		size = uint16(stats.TotalProbes)
	}
	latencies := make([]float64, size)

	var count logSizeType = 0
	var totalLatency float64 = 0.0
	pt.Latencies.Do(func(rtt any) {
		if rtt == nil {
			return
		}

		latency := rtt.(float64)
		if latency >= stats.MaxLatency {
			stats.MaxLatency = latency
		}
		if latency <= stats.MinLatency {
			stats.MinLatency = latency
		}
		totalLatency += latency

		latencies[count] = latency

		count += 1
		latencies = append(latencies, latency)
	})

	stats.StandardDeviation = stat.StdDev(latencies, nil)
	stats.Skewness = stat.Skew(latencies, nil)
	stats.AverageLatency = totalLatency / float64(count)

	(*pt.Printer).printStats(pt, &count)

	latencies = nil
}

func (pt *proberTask) resolveHostname(ctx context.Context) (netip.Addr, time.Duration, error) {
	network := "ip4"
	if pt.IPv6 {
		network = "ip6"
	}
	hostname := pt.URL.Hostname()

	var IP netip.Addr
	var IPs []netip.Addr
	var err error

	start := time.Now()
	IPs, err = net.DefaultResolver.LookupNetIP(ctx, network, hostname)
	latency := time.Since(start)

	if err != nil {
		return IP, latency, err
	}

	if pt.IPv6 {
		IP, err = selectIPv6(IPs)
	} else {
		IP, err = selectIPv4(IPs)
	}

	if err != nil {
		return IP, latency, err
	}

	return IP, latency, nil
}

func (pt *proberTask) getIPForAttempt(ctx context.Context, attempt *uint64) (IP netip.Addr, latency time.Duration, requiresUpdate bool, err error) {
	att := *attempt

	taskType := pt.Type
	params := pt.Params

	IP = pt.IP
	requiresUpdate = false

	if taskType == RAW_IPv4 || taskType == RAW_IPv6 {
		return IP, 0, false, errorx.WithMessage(errorDNSUpdateNotRequired, "not DNS prober")
	}

	if att <= 1 || att%uint64(params.DNSInterval) != 1 {
		return IP, 0, false, errorx.WithMessage(errorDNSUpdateNotRequired, "IP is still valid")
	}

	IP, latency, err = pt.resolveHostname(ctx)
	return IP, latency, true, err
}

func (pt *proberTask) getTargetForAttempt(ctx context.Context, attempt *uint64) (*netip.AddrPort, error) {
	IP, latency, requiresUpdate, err := pt.getIPForAttempt(ctx, attempt)

	p := (*pt.Printer)

	if requiresUpdate && err == nil {
		p.printDNSUpdate(pt, &latency, &IP, requiresUpdate, err)
		pt.IP = IP
	} else if requiresUpdate && err != nil {
		p.printDNSUpdate(pt, &latency, &IP, requiresUpdate, err)
	}

	target := netip.AddrPortFrom(pt.IP, pt.Port)
	return &target, nil
}

func (pt *proberTask) beforeProbing(ctx context.Context, attempt *uint64) (*netip.AddrPort, error) {
	att := *attempt

	target, err := pt.getTargetForAttempt(ctx, attempt)
	if err != nil {
		return nil, err
	}

	params := pt.Params

	if att > 1 && att%uint64(params.StatsInterval) == 1 {
		pt.printStats()
	}

	pt.Target = target

	return target, nil
}

func (pt *proberTask) afterProbing(ctx context.Context,
	attempt *uint64, target *netip.AddrPort, latency *time.Duration, err error,
) {
	att := *attempt

	timeout := pt.Params.Timeout

	if errors.Is(err, context.DeadlineExceeded) || *latency >= timeout {
		*latency = timeout
	}

	// this is not RTT in the same sence of `ping`
	rtt := asMillis(latency)

	pt.Latencies.Value = rtt
	pt.Latencies = pt.Latencies.Next()

	stats := pt.Stats

	// update last observed latency with current observation
	stats.DeltaLatency = stats.LastLatency - rtt
	stats.LastLatency = rtt

	// update total number of probes performed
	stats.TotalProbes = att

	// upodate overall min/max latencies
	if rtt >= stats.OverallMaxLatency {
		stats.OverallMaxLatency = rtt
	}
	if rtt <= stats.OverallMinLatency {
		stats.OverallMinLatency = rtt
	}

	if err != nil {
		stats.TotalFailures += 1
		stats.ConsecutiveFailures += 1
		stats.ConsecutiveSuccesful = 0
	} else {
		stats.TotalSuccessful += 1
		stats.ConsecutiveSuccesful += 1
		stats.ConsecutiveFailures = 0
	}

	(*pt.Printer).printProbe(pt, attempt, target, latency, err)
}

func (pt *proberTask) interval() *time.Duration {
	return &pt.Params.Interval
}

func (pt *proberTask) RawURL() *string {
	return &pt.Raw
}

func (pt *proberTask) T() ProberType {
	return pt.Type
}

func Probe(ctx context.Context, prober *Prober) uint64 {
	p := *prober
	interval := *p.interval()
	ticker := time.NewTicker(interval)
	var counter atomic.Uint64
	for {
		select {
		case <-ticker.C:
			delay := jitter.Delay(interval, 0.8787)
			time.Sleep(delay)
			attempt := counter.Add(1)
			p.probe(ctx, &attempt)
		case <-ctx.Done():
			ticker.Stop()
			p.printStats()
			return counter.Load()
		}
	}
}

func NewProberFromRawURL(rawTaskURL *string) (prober *Prober, err error) {
	defer err2.Handle(&err, "newProberTaskFromRawURL")

	taskURL := try.To1(url.Parse(*rawTaskURL))
	taskType := try.To1(getProberTaskType(taskURL))
	taskIP := try.To1(getProberTaskIP(taskType, taskURL))
	taskPort := try.To1(getProberTaskPort(taskURL))

	taskTarget := netip.AddrPortFrom(taskIP, uint16(taskPort))

	taskParams := newProberTaskParams(taskURL)

	taskStats := &proberTaskStats{
		0, 0, 0, 0, 0, 0.0, 0.0, math.MaxFloat64, 0.0, math.MaxFloat64, 0.0, 0.0, 0.0, 0.0,
	}

	// max number of observations to keep for statistics
	// |_ between 255 and 500 for low cpu/memory apps
	latencies := ring.New(int(taskParams.LogSize))

	taskProbePrinter := newPrinter(taskURL, &taskParams.OutputFormat)

	task := &proberTask{
		Raw:       *rawTaskURL,
		URL:       taskURL,
		Type:      taskType,
		IPv4:      isIPv4(taskType),
		IPv6:      isIPv6(taskType),
		IP:        taskIP,
		Port:      uint16(taskPort),
		Target:    &taskTarget,
		Params:    taskParams,
		Stats:     taskStats,
		Latencies: latencies,
		Printer:   &taskProbePrinter,
	}

	p := newTCPProberTask(task)
	prober = &p

	return prober, err
}
