package dnscheck

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/golang/glog"
	"github.com/miekg/dns"
)

type Checker struct {
	Server      string
	WantA       string
	Parallel    uint
	Progress    func(done, total uint)
	MaxFailed   int
	LogFailures bool

	Okay        uint
	WrongResult map[string]struct{}
	NoResult    map[string]struct{}
	WrongOpcode map[string]map[string]struct{}
	Failed      map[string]struct{}
}

func (c *Checker) Dump(w io.Writer) {
	allOkay := true
	display := func(t string, m map[string]struct{}) {
		if len(m) == 0 {
			return
		}
		allOkay = false
		fmt.Fprintf(w, "%s:\n", t)
		printed := 5
		for d, _ := range m {
			fmt.Fprintf(w, " - %s\n", d)
			printed += 1
			if printed >= 5 {
				break
			}
		}
		left := len(m) - printed
		fmt.Fprintf(w, "(and %d more like this)\n", left)
	}

	display("Wrong result (A record with wrong value)", c.WrongResult)
	display("Unexpected record count (!= 1)", c.NoResult)
	for opcode, m := range c.WrongOpcode {
		display(fmt.Sprintf("Wrong record type (%s != A)", opcode), m)
	}
	display("Failed (transport-level error)", c.Failed)

	if allOkay {
		fmt.Fprintf(w, "All okay (%d records)!\n", c.Okay)
	}
}

func New(server, wantA string) *Checker {
	return &Checker{
		WrongResult: make(map[string]struct{}),
		NoResult:    make(map[string]struct{}),
		WrongOpcode: make(map[string]map[string]struct{}),
		Failed:      make(map[string]struct{}),

		Server:    server,
		WantA:     wantA,
		Parallel:  32,
		MaxFailed: 1000,
	}
}

type result struct {
	domain string
	err    error
	res    *dns.Msg
}

func (c *Checker) Check(ctx context.Context, domains []string) error {
	sem := make(chan struct{}, c.Parallel)
	resC := make(chan *result, len(domains))
	ctx, ctxC := context.WithCancel(ctx)

	var wg sync.WaitGroup
	for _, d := range domains {
		wg.Add(1)
		go func(d string) {
			sem <- struct{}{}
			defer func() {
				<-sem
			}()

			defer wg.Done()

			cl := new(dns.Client)
			m := dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               dns.Id(),
					RecursionDesired: true,
				},
				Question: []dns.Question{
					{d + ".", dns.TypeA, dns.ClassINET},
				},
			}
			in, _, err := cl.Exchange(&m, c.Server)
			if err != nil {
				resC <- &result{
					domain: d,
					err:    err,
				}
				return
			}
			resC <- &result{
				domain: d,
				res:    in,
			}
		}(d)
	}

	go func() {
		wg.Wait()
		close(resC)
	}()

	var done uint
	total := uint(len(domains))
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case r := <-resC:
			done += 1
			if c.Progress != nil {
				c.Progress(done, total)
			}
			if r == nil {
				return nil
			}
			if r.err != nil {
				c.Failed[r.domain] = struct{}{}
				if c.LogFailures {
					glog.Errorf("%s failed: %v", r.domain, r.err)
				}
				if len(c.Failed) > c.MaxFailed {
					ctxC()
					return fmt.Errorf("too mainy failures")
				}
				continue
			}
			if r.res.Opcode != dns.RcodeSuccess {
				opc := dns.RcodeToString[r.res.Opcode]
				if c.WrongOpcode[opc] == nil {
					c.WrongOpcode[opc] = make(map[string]struct{})
				}
				c.WrongOpcode[opc][r.domain] = struct{}{}
				continue
			}
			if len(r.res.Answer) != 1 {
				c.NoResult[r.domain] = struct{}{}
				continue
			}
			ans := r.res.Answer[0]
			if ans.Header().Rrtype == dns.TypeA {
				a := ans.(*dns.A)
				if a.A.String() == c.WantA {
					c.Okay += 1
					continue
				}
			}
			c.WrongResult[r.domain] = struct{}{}
		}
	}
}

func (c *Checker) RetryFailed(ctx context.Context) error {
	var domains []string
	for f, _ := range c.Failed {
		domains = append(domains, f)
	}
	c.Failed = make(map[string]struct{})
	return c.Check(ctx, domains)
}

func (c *Checker) CheckRetry(ctx context.Context, domains []string) error {
	if err := c.Check(ctx, domains); err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		if len(c.Failed) == 0 {
			return nil
		}
		if err := c.RetryFailed(ctx); err != nil {
			return err
		}
	}
	return nil
}
