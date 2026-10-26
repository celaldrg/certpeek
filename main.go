package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

var version = "0.1.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("certpeek", flag.ContinueOnError)
	fs.SetOutput(stderr)
	warn := fs.Int("warn", 21, "warn when a certificate expires within this many days")
	crit := fs.Int("crit", 7, "critical when a certificate expires within this many days")
	timeout := fs.Duration("timeout", 8*time.Second, "per-host connect timeout")
	file := fs.String("f", "", "read targets from a file (one per line, # comments allowed; - for stdin)")
	jsonOut := fs.Bool("json", false, "print JSON")
	conc := fs.Int("c", 16, "number of hosts checked in parallel")
	sortBy := fs.String("sort", "days", "sort by: days, target, input")
	showVersion := fs.Bool("version", false, "print version")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "certpeek %s - check TLS certificates and their expiry\n\nUsage: certpeek [flags] host[:port]|URL ...\n\nExit codes: 0 all OK, 1 warnings, 2 critical or errors, 3 usage\n\nFlags:\n", version)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	targets := fs.Args()
	if *file != "" {
		t, err := readTargets(*file)
		if err != nil {
			fmt.Fprintln(stderr, "certpeek:", err)
			return 3
		}
		targets = append(targets, t...)
	}
	if len(targets) == 0 {
		fs.Usage()
		return 3
	}
	if *crit > *warn {
		fmt.Fprintln(stderr, "certpeek: -crit must be <= -warn")
		return 3
	}
	opts := Options{WarnDays: *warn, CritDays: *crit, Timeout: *timeout}
	results := checkAll(targets, opts, *conc)
	sortResults(results, *sortBy)

	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	} else {
		printTable(stdout, results)
	}
	worst := StatusOK
	for _, r := range results {
		if r.Status > worst {
			worst = r.Status
		}
	}
	switch worst {
	case StatusOK:
		return 0
	case StatusWarn:
		return 1
	default:
		return 2
	}
}

func readTargets(path string) ([]string, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

func checkAll(targets []string, o Options, conc int) []Result {
	if conc < 1 {
		conc = 1
	}
	results := make([]Result, len(targets))
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = Check(context.Background(), t, o)
		}(i, t)
	}
	wg.Wait()
	return results
}

func sortResults(rs []Result, by string) {
	switch by {
	case "target":
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].Target < rs[j].Target })
	case "days":
		sort.SliceStable(rs, func(i, j int) bool {
			ei, ej := rs[i].Error != "", rs[j].Error != ""
			if ei != ej {
				return ei
			}
			return rs[i].DaysLeft < rs[j].DaysLeft
		})
	}
}

func printTable(w io.Writer, rs []Result) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tTARGET\tEXPIRES\tDAYS\tISSUER\tTLS\tNOTES")
	for _, r := range rs {
		if r.Error != "" {
			fmt.Fprintf(tw, "%s\t%s\t-\t-\t-\t-\t%s\n", r.Status, r.Target, r.Error)
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n", r.Status, r.Target, r.NotAfter.Format("2006-01-02"), r.DaysLeft, r.Issuer, r.TLSVersion, strings.Join(r.Problems, ", "))
	}
	tw.Flush()
}
