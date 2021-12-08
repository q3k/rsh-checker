package rsh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"

	"golang.org/x/net/idna"
)

var (
	flagRegistry string
)

func init() {
	flag.StringVar(&flagRegistry, "registry", "https://hazard.mf.gov.pl/api/Register", "Address of RSH Registry endpoint")
}

type Registry struct {
	XMLName xml.Name        `xml:"Rejestr"`
	Entries []RegistryEntry `xml:"PozycjaRejestru"`
}

func (r *Registry) Domains() ([]string, error) {
	set := make(map[string]struct{})
	for _, entry := range r.Entries {
		addr, err := idna.ToASCII(entry.Address)
		// TODO(q3k): put in metrics, alert, and handle gracefully
		if err != nil {
			return nil, fmt.Errorf("could not convert domain: %w", err)
		}
		set[addr] = struct{}{}
	}
	var res []string
	for v, _ := range set {
		res = append(res, v)
	}
	sort.Slice(res, func(i, j int) bool { return res[i] < res[j] })
	return res, nil
}

func (r *Registry) Hash() (string, error) {
	h := sha256.New()
	fmt.Fprintf(h, "rsh-hash-v0")
	domains, err := r.Domains()
	if err != nil {
		return "", err
	}
	for _, d := range domains {
		fmt.Fprintf(h, ":%q", d)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type RegistryEntry struct {
	Address string `xml:"AdresDomeny"`
}

func Get(ctx context.Context) (*Registry, error) {
	registry := Registry{}

	req, err := http.NewRequestWithContext(ctx, "GET", flagRegistry, nil)
	if err != nil {
		return nil, fmt.Errorf("NewRequest: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("while connecting to registry: %v", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("while downloading registry: %v", err)
	}

	err = xml.Unmarshal([]byte(body), &registry)
	if err != nil {
		return nil, fmt.Errorf("while parsing registry: %v", err)
	}

	if len(registry.Entries) == 0 {
		return nil, fmt.Errorf("zero results in registry")
	}

	return &registry, nil
}
