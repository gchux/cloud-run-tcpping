package prober

import (
	"net/url"
	"strconv"
	"time"
)

type (
	proberTaskParams struct {
		TLS           bool
		Timeout       time.Duration
		DNSInterval   uint8
		Interval      time.Duration
		LogSize       logSizeType
		StatsInterval uint8
		OutputFormat  string
	}
)

const (
	PARAM_INTERVAL         = "probe_interval" // how often to probe ( seconds )
	PARAM_TIMEOUT          = "probe_timeout"  // how long probes should wait before failing ( Milliseconds )
	PARAM_USE_TLS          = "use_tls"        // probe using TLS
	PARAM_DNS_INTERVAL     = "dns_interval"   // after how many probes FQDNs should be re-resolved ( only applied for `dns+...` )
	PARAM_LOG_SIZE         = "log_size"       // how many probes details to keep for stats
	PARAM_STATS_INTERVAL   = "stats_interval" // after how many probes stats should be printed
	PARAM_OUTPUT_FORMAT    = "output_format"  // how to print probes
	PARAM_LOGZ_DIR         = "logz_dir"
	PARAM_LOGZ_NAME        = "logz_name"
	PARAM_LOGZ_ROTATE_SECS = "logz_rotate_secs"
	PARAM_LOGZ_SYNC        = "logz_sync"
)

const (
	defaultProbeInterval                = 1 * time.Second
	defaultProbeTimeout                 = 5 * time.Second
	defaultProbeDNSInterval uint8       = 10
	defaultStatsInterval                = 10
	defaultLogSize          logSizeType = 255
	defaultOutptFormat                  = JSON_OUTPUT_FORMAT
)

func getProbeInterval(config *url.Values) time.Duration {
	interval, err := strconv.Atoi(config.Get(PARAM_INTERVAL))
	if err != nil {
		return defaultProbeInterval
	}
	return time.Duration(interval) * time.Second
}

func getProbeTimeout(config *url.Values) time.Duration {
	timeout, err := strconv.Atoi(config.Get(PARAM_TIMEOUT))
	if err != nil {
		return defaultProbeTimeout
	}
	return time.Duration(timeout) * time.Millisecond
}

func getProbeDNSInterval(config *url.Values) uint8 {
	dnsInterval, err := strconv.Atoi(config.Get(PARAM_DNS_INTERVAL))
	if err != nil {
		return defaultProbeDNSInterval
	}
	return uint8(dnsInterval)
}

func useTLS(config *url.Values) bool {
	useTLS, err := strconv.ParseBool(config.Get(PARAM_USE_TLS))
	return err == nil && useTLS
}

func getLogSize(config *url.Values) logSizeType {
	logSize, err := strconv.Atoi(config.Get(PARAM_LOG_SIZE))
	if err != nil {
		return defaultLogSize
	}
	return logSizeType(logSize)
}

func getStatsInterval(config *url.Values) uint8 {
	statsInterval, err := strconv.Atoi(config.Get(PARAM_STATS_INTERVAL))
	if err != nil {
		return defaultStatsInterval
	}
	return uint8(statsInterval)
}

func getOutputFormat(config *url.Values) string {
	outputFormat := config.Get(PARAM_OUTPUT_FORMAT)
	if outputFormat == "" {
		return defaultOutptFormat
	}
	return outputFormat
}

func newProberTaskParams(taskURL *url.URL) *proberTaskParams {
	taskParams := taskURL.Query()

	config := &taskParams
	interval := getProbeInterval(config)
	timeout := getProbeTimeout(config)
	useTLS := useTLS(config)
	dnsInterval := getProbeDNSInterval(config)
	logSize := getLogSize(config)
	statsInterval := getStatsInterval(config)
	outputFormat := getOutputFormat(config)

	return &proberTaskParams{
		Interval:      interval,
		Timeout:       timeout,
		TLS:           useTLS,
		DNSInterval:   dnsInterval,
		LogSize:       logSize,
		StatsInterval: statsInterval,
		OutputFormat:  outputFormat,
	}
}
