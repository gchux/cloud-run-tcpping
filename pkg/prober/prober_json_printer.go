package prober

import (
	"io"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/easyCZ/logrotate"
	"github.com/wissance/stringFormatter"
)

const (
	JSON_OUTPUT_FORMAT   = "json"
	JSON_LOG_ROTATE_SECS = 600 /* 10 minutes */
	JSON_LOGGER_MESSAGE  = "configured logger for '{0}' at directory '{1}' using name 'ping_#__{2}.json', rotating every '{3}'"
)

type (
	jsonProbePrinter struct {
		guid, logName, logDir, logFileName *string
		logFilesCounter                    *atomic.Uint64
		logRotateSecs                      time.Duration
		writer                             io.Writer
	}
)

func newJSONProbePrinter(guid, logName string, url *url.URL) probePrinter {
	var logFilesCounter atomic.Uint64

	printer := &jsonProbePrinter{
		guid:            &guid,
		logName:         &logName,
		logFilesCounter: &logFilesCounter,
	}

	params := url.Query()

	// where in the FS should log files be stored
	logDir := params.Get(PARAM_LOGZ_DIR)

	logFileName := params.Get(PARAM_LOGZ_NAME)
	if logDir == "" || logDir == "stdout" || logFileName == "stdout" {
		printer.writer = os.Stdout
		return printer
	}
	printer.logDir = &logDir

	// `name` to be used as part of the log file name pattern `ping_{log_file_number}__{log_name}.json`
	if logFileName == "" {
		// if no `log_name` is provided, default to: `{scheme}__{hostname}__{port}`
		logFileName = stringFormatter.Format("{0}__{1}__{2}", url.Scheme, strings.ReplaceAll(url.Hostname(), ".", "_"), url.Port())
	}
	printer.logFileName = &logFileName

	// rotation will happen on a time basis; default is 10m
	printer.logRotateSecs = JSON_LOG_ROTATE_SECS * time.Second
	logRotateSecs := params.Get(PARAM_LOGZ_ROTATE_SECS)
	if rotateSecs, err := strconv.Atoi(logRotateSecs); err == nil {
		printer.logRotateSecs = time.Duration(rotateSecs) * time.Second
	}

	isFileLoggerSync := true
	if paramLogzSync, err := strconv.ParseBool(params.Get(PARAM_LOGZ_SYNC)); err == nil {
		isFileLoggerSync = paramLogzSync
	}

	if writer, err := logrotate.New(logrotateLogger, logrotate.Options{
		Directory:            *printer.logDir,
		MaximumFileSize:      0,
		MaximumLifetime:      printer.logRotateSecs,
		FileNameFunc:         printer.logFileNameProvider,
		FlushAfterEveryWrite: isFileLoggerSync,
	}); err == nil {
		printer.writer = writer
	} else {
		printer.writer = os.Stdout
	}

	logrotateLogger.Println(stringFormatter.Format(JSON_LOGGER_MESSAGE,
		url.String(), logDir, logFileName, printer.logRotateSecs.String()))

	return printer
}

func (p *jsonProbePrinter) logFileNameProvider() string {
	newLogFileName := stringFormatter.Format("ping_{0}__{1}.json", p.logFilesCounter.Add(1), *p.logFileName)
	logrotateLogger.Printf("created new log file: '%s/%s'\n", *p.logDir, newLogFileName)
	return newLogFileName
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
		message = stringFormatter.Format("#:{0} | @:{1} | latency:{2}", *attempt, target.String(), *latency)
	} else {
		message = stringFormatter.Format("#:{0} | @:{1}/{2} | latency:{3}", *attempt, task.URL.Hostname(), target.String(), *latency)
	}
	json.Set(message, "message")

	io.WriteString(p.writer, json.String()+"\n")
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

	io.WriteString(p.writer, json.String()+"\n")
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

	io.WriteString(p.writer, json.String()+"\n")
}
