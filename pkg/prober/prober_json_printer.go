package prober

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/wissance/stringFormatter"
)

const (
	JSON_OUTPUT_FORMAT = "json"
)

type (
	jsonProbePrinter struct {
		guid, logName string
	}
)

func newJSONProbePrinter(guid, logName string) probePrinter {
	return &jsonProbePrinter{guid, logName}
}

func (p *jsonProbePrinter) newJSON(task *proberTask) *gabs.Container {
	json := gabs.New()
	json.Set(p.guid, "id")
	json.Set(p.logName, "logName")
	json.Set(task.URL.Host, "host")
	return json
}

func (p *jsonProbePrinter) printProbe(task *proberTask,
	attempt *uint64, target *netip.AddrPort,
	latency *time.Duration, rtt *float64, err error,
) {
	json := p.newJSON(task)

	if err != nil {
		json.Set("ERROR", "severity")
		json.Set(err.Error(), "error")
	}

	message := stringFormatter.Format("#:{0} | @:{1}/{2} | latency:{3}",
		*attempt, task.URL.Host, target.String(), *latency)

	json.Set(*attempt, "serial")
	json.Set(target.String(), "target")
	json.Set(*rtt, "latency")
	json.Set(message, "message")

	fmt.Println(json.String())
}

func (p *jsonProbePrinter) printStats(task *proberTask, probesCount *logSizeType) {
	json := p.newJSON(task)

	stats := task.Stats

	json.Set(stats.TotalProbes, "count", "total")
	json.Set(stats.TotalSuccessful, "count", "success")
	json.Set(stats.TotalFailures, "count", "failures")
	json.Set(stats.ConsecutiveSuccesful, "count", "consecutive", "success")
	json.Set(stats.ConsecutiveFailures, "count", "consecutive", "failures")

	json.Set(stats.OverallMinLatency, "latency", "overall", "min")
	json.Set(stats.MinLatency, "latency", "min")
	json.Set(stats.OverallMaxLatency, "latency", "overall", "max")
	json.Set(stats.MaxLatency, "latency", "max")

	json.Set(stats.AverageLatency, "latency", "avg")
	json.Set(stats.StandardDeviation, "latency", "sigma")
	json.Set(stats.Skewness, "latency", "skew")

	message := stringFormatter.Format("[last {0}]: min/max/avg/sigma/skew={1}/{2}/{3}/{4}/{5} | [total: {6}]: min/max={7}/{8}",
		*probesCount,
		stats.MinLatency, stats.MaxLatency,
		stats.AverageLatency, stats.StandardDeviation, stats.Skewness,
		stats.TotalProbes, stats.OverallMinLatency, stats.OverallMaxLatency)

	json.Set(message, "message")

	fmt.Println(json.String())
}

func (p *jsonProbePrinter) printDNSUpdate(
	task *proberTask,
	latency *time.Duration,
	ip *netip.Addr,
	requiresUpdate bool,
	err error,
) {
	json := p.newJSON(task)

	json.Set(requiresUpdate, "required")

	rtt := asMillis(latency)
	json.Set(rtt, "latency")

	hostname := task.URL.Hostname()
	json.Set(hostname, "hostname")

	currentIP := task.IP.String()
	json.Set(currentIP, "IP", "before")

	var message string
	if err == nil {
		newIP := ip.String()
		message = stringFormatter.Format("'{0}' IP mapping updated [ {1} ]: {2} => {3}", hostname, latency, currentIP, newIP)
		json.Set(newIP, "IP", "after")
	} else {
		message = stringFormatter.Format("'{0}' IP mapping update failed: {1}", hostname, err.Error())
		json.Set("ERROR", "severity")
	}
	json.Set(message, "message")

	fmt.Println(json.String())
}
