package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gchux/cloud-run-tcpping/pkg/prober"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/wissance/stringFormatter"
)

const (
	envVarPrefix           = "TCP_PING_"
	invalidTaskURLTemplate = "invalid task URL: %s"
)

func startProbeing(ctx context.Context, wg *sync.WaitGroup, pp *prober.Prober) {
	p := *pp
	start := time.Now()
	count := prober.Probe(ctx, pp)
	executionTime := time.Since(start)
	fmt.Println(stringFormatter.Format("Probed '{0}' {1} times ( {2} )", *p.RawURL(), count, executionTime))
	wg.Done()
}

func provideProbers() (probers []*prober.Prober) {
	var err error
	defer err2.Handle(&err)
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		if strings.HasPrefix(pair[0], envVarPrefix) {
			prober := try.Out1(prober.NewProberFromRawURL(&pair[1])).
				Logf(invalidTaskURLTemplate, pair[1]).Catch(nil)
			if prober != nil {
				probers = append(probers, prober)
			}
		}
	}
	return probers
}

func main() {
	probers := provideProbers()
	if len(probers) == 0 {
		fmt.Println("no prober tasks were configured")
		os.Exit(0)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		cancel()
	}()

	var wg sync.WaitGroup
	for _, task := range probers {
		wg.Add(1)
		go startProbeing(ctx, &wg, task)
	}

	<-ctx.Done()
	wg.Wait()
}
