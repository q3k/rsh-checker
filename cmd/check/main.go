package main

import (
	"context"
	"flag"
	"net"
	"os"

	"github.com/golang/glog"

	"github.com/q3k/rsh-checker/pkg/dnscheck"
	"github.com/q3k/rsh-checker/pkg/rsh"
)

var (
	flagServer   string
	flagParallel int
)

func init() {
	flag.Set("logtostderr", "true")
}

func main() {
	flag.StringVar(&flagServer, "server", "", "Address of DNS server to check")
	flag.IntVar(&flagParallel, "j", 16, "DNS request concurrency")
	flag.Parse()

	if flagServer == "" {
		glog.Exitf("-server must be set")
	}

	_, _, err := net.SplitHostPort(flagServer)
	if err != nil {
		flagServer = net.JoinHostPort(flagServer, "53")
	}
	glog.Infof("Checking server %s (%d concurrent connections)...", flagServer, flagParallel)

	ctx := context.Background()
	reg, err := rsh.Get(ctx)
	if err != nil {
		glog.Exitf("Retrieving domains failed: %v", err)
	}
	domains, err := reg.Domains()
	if err != nil {
		glog.Exitf("Parsing domains failed: %v", err)
	}

	c := dnscheck.New(flagServer, "145.237.235.240")
	c.Parallel = uint(flagParallel)
	c.LogFailures = true
	c.Progress = func(done, total uint) {
		if done%400 == 0 {
			glog.Infof("%.2f%% done...", float64(done)*100/float64(total))
		}
	}
	if err := c.Check(ctx, domains); err != nil {
		glog.Exitf("Check failed: %v", err)
	}

	for i := 0; i < 3; i++ {
		if len(c.Failed) == 0 {
			break
		}
		glog.Infof("Retrying %d failures...", len(c.Failed))
		if err := c.RetryFailed(ctx); err != nil {
			glog.Exitf("Retry failed: %v", err)
		}
	}

	c.Dump(os.Stdout)
}
