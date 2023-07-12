package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/miekg/dns"
)

type empty struct{}

func main() {
	var (
		flDomain      = flag.String("domain", "", "the domain to perform guessing against")
		flWordlist    = flag.String("wordlist", "", "the wordlist to use for guessing")
		flWorkerCount = flag.Int("c", 100, "the amount of workers to use")
		flServerAddr  = flag.String("server", "8.8.8.8:53", "the dns server to use")
	)

	flag.Parse()

	if *flDomain == "" || *flWordlist == "" {
		fmt.Println("-domain and -wordlist can not be empty")
		os.Exit(1)
	}

	var results []result

	fqdns := make(chan string, *flWorkerCount)
	gather := make(chan []result)
	tracker := make(chan empty)

	fh, err := os.Open(*flWordlist)
	if err != nil {
		panic(err)
	}
	defer fh.Close()

	scanner := bufio.NewScanner(fh)

	for i := 0; i < *flWorkerCount; i++ {
		go worker(tracker, fqdns, gather, *flServerAddr)
	}

	for scanner.Scan() {
		fqdns <- fmt.Sprintf("%s.%s", scanner.Text(), *flDomain)
	}

	go func() {
		for r := range gather {
			results = append(results, r...)
		}
		var e empty
		tracker <- e
	}()
	close(fqdns)

	// an empty struct is sent on the gather channel after each worker finishes
	// this prevents us from closing the gather channel before the worker finishes
	// sending its result to gather.
	for i := 0; i < *flWorkerCount; i++ {
		<-tracker
	}
	close(gather)

	// I dont know why this is here.
	<-tracker

	w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, ' ', 0)
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%s\n", r.Hostname, r.IPAddress)
	}

	w.Flush()
}

type result struct {
	IPAddress string
	Hostname  string
}

func lookupA(fqdn, serverAddr string) ([]string, error) {
	var m dns.Msg
	var ips []string

	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	in, err := dns.Exchange(&m, serverAddr)
	if err != nil {
		return ips, err
	}

	if len(in.Answer) < 1 {
		return ips, errors.New("no answer")
	}

	for _, answer := range in.Answer {
		if a, ok := answer.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	return ips, nil
}

func lookupCNAME(fqdn, serverAddr string) ([]string, error) {
	var m dns.Msg
	var fqdns []string

	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeCNAME)

	in, err := dns.Exchange(&m, serverAddr)
	if err != nil {
		return fqdns, err
	}

	if len(in.Answer) < 1 {
		return fqdns, errors.New("no answer")
	}

	for _, answer := range in.Answer {
		if c, ok := answer.(*dns.CNAME); ok {
			fqdns = append(fqdns, c.Target)
		}
	}

	return fqdns, nil
}

func lookup(fqdn, serverAddr string) []result {
	var results []result
	var cfqdn = fqdn // do not modify the original.

	for {
		cnames, err := lookupCNAME(cfqdn, serverAddr)
		fmt.Println(cnames)
		if err == nil && len(cnames) > 0 {
			cfqdn = cnames[0]
			continue
		}

		ips, err := lookupA(cfqdn, serverAddr)
		if err != nil {
			break // there are no a records for the hostname.
		}

		for _, ip := range ips {
			results = append(results, result{IPAddress: ip, Hostname: fqdn})
		}
		break
	}

	return results
}

func worker(tracker chan empty, fqdns chan string, gather chan []result, serverAddr string) {
	for fqdn := range fqdns {
		results := lookup(fqdn, serverAddr)
		if len(results) > 0 {
			gather <- results
		}
	}

	var e empty
	tracker <- e
}
