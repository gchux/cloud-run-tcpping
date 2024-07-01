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
	latency *time.Duration, err error,
) {
	json := p.newJSON(task)

	if err != nil {
		json.Set("ERROR", "severity")
		json.Set(err.Error(), "error")
	}

	json.Set(*attempt, "serial")
	json.Set(target.String(), "target")
	json.Set(task.Stats.LastLatency, "latency")
	json.Set(task.Stats.DeltaLatency, "delta")

	var message string
	if task.Type == RAW_IPv4 || task.Type == RAW_IPv6 {
		message = stringFormatter.Format("#:{0} | @:{1} | latency:{3}", *attempt, target.String(), *latency)
	} else {
		message = stringFormatter.Format("#:{0} | @:{1}/{2} | latency:{3}", *attempt, task.URL.Hostname(), target.String(), *latency)
	}
	json.Set(message, "message")

	fmt.Println(json.String())
}

func (p *jsonProbePrinter) printStats(task *proberTask, probesCount *logSizeType) {
	json := p.newJSON(task)

	stats := task.Stats

	json.Set(stats.TotalProbes, "count", "total")
	json.Set(stats.TotalSuccessful, "count", "ok")
	json.Set(stats.TotalFailures, "count", "ko")
	json.Set(stats.ConsecutiveSuccesful, "count", "consecutive", "ok")
	json.Set(stats.ConsecutiveFailures, "count", "consecutive", "ko")

	json.Set(stats.OverallMinLatency, "latency", "overall", "min")
	json.Set(stats.MinLatency, "latency", "min")
	json.Set(stats.OverallMaxLatency, "latency", "overall", "max")
	json.Set(stats.MaxLatency, "latency", "max")

	json.Set(stats.AverageLatency, "latency", "avg")
	json.Set(stats.StandardDeviation, "latency", "sigma")
	json.Set(stats.Skewness, "latency", "skew")

	message := stringFormatter.Format("{0} | [last {1}]: min/max/avg/sigma/skew={2}/{3}/{4}/{5}/{6} | [total: {7}]: min/max={8}/{9}",
		task.URL.Host, *probesCount,
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
