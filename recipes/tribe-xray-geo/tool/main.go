// Command xraygeo cuts a geosite/geoip pair down to a fixed tag set with the Xray core's own
// protobuf types (common/geodata of the pinned amnezia-xray-core) and writes a sha256 manifest.
//
//	xraygeo -site dlc.dat -ip geoip.dat -sites a,b -ips c,d -out DIR
//
// Output: DIR/geosite.dat, DIR/geoip.dat (entries sorted by tag, deterministic encoding, each
// entry byte-identical to the source entry) and DIR/SHA256SUMS. A requested tag missing from the
// source is an error.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"
)

var deterministic = proto.MarshalOptions{Deterministic: true}

func tagSet(csv string) (map[string]bool, error) {
	set := map[string]bool{}
	for _, tag := range strings.Split(csv, ",") {
		tag = strings.ToUpper(strings.TrimSpace(tag))
		if tag == "" {
			continue
		}
		set[tag] = true
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("empty tag list")
	}
	return set, nil
}

func missing(want, have map[string]bool) []string {
	var out []string
	for tag := range want {
		if !have[tag] {
			out = append(out, strings.ToLower(tag))
		}
	}
	sort.Strings(out)
	return out
}

func sameEntry(a, b proto.Message) error {
	x, err := deterministic.Marshal(a)
	if err != nil {
		return err
	}
	y, err := deterministic.Marshal(b)
	if err != nil {
		return err
	}
	if !bytes.Equal(x, y) {
		return fmt.Errorf("entry changed while cutting")
	}
	return nil
}

func cutSites(src string, want map[string]bool) ([]byte, error) {
	raw, err := os.ReadFile(src)
	if err != nil {
		return nil, err
	}
	var full geodata.GeoSiteList
	if err := proto.Unmarshal(raw, &full); err != nil {
		return nil, fmt.Errorf("%s: %w", src, err)
	}
	have := map[string]bool{}
	var cut geodata.GeoSiteList
	for _, entry := range full.Entry {
		code := strings.ToUpper(entry.Code)
		if !want[code] {
			continue
		}
		if have[code] {
			return nil, fmt.Errorf("%s: duplicate tag %s", src, code)
		}
		if len(entry.Domain) == 0 {
			return nil, fmt.Errorf("%s: tag %s is empty", src, code)
		}
		have[code] = true
		cut.Entry = append(cut.Entry, entry)
	}
	if lost := missing(want, have); len(lost) > 0 {
		return nil, fmt.Errorf("%s: tags not found: %s", src, strings.Join(lost, ","))
	}
	sort.Slice(cut.Entry, func(i, j int) bool { return cut.Entry[i].Code < cut.Entry[j].Code })
	out, err := deterministic.Marshal(&cut)
	if err != nil {
		return nil, err
	}
	// Round trip: what the core will read back equals what was selected.
	var back geodata.GeoSiteList
	if err := proto.Unmarshal(out, &back); err != nil {
		return nil, err
	}
	for i := range cut.Entry {
		if err := sameEntry(cut.Entry[i], back.Entry[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func cutIPs(src string, want map[string]bool) ([]byte, error) {
	raw, err := os.ReadFile(src)
	if err != nil {
		return nil, err
	}
	var full geodata.GeoIPList
	if err := proto.Unmarshal(raw, &full); err != nil {
		return nil, fmt.Errorf("%s: %w", src, err)
	}
	have := map[string]bool{}
	var cut geodata.GeoIPList
	for _, entry := range full.Entry {
		code := strings.ToUpper(entry.Code)
		if !want[code] {
			continue
		}
		if have[code] {
			return nil, fmt.Errorf("%s: duplicate tag %s", src, code)
		}
		if len(entry.Cidr) == 0 {
			return nil, fmt.Errorf("%s: tag %s is empty", src, code)
		}
		have[code] = true
		cut.Entry = append(cut.Entry, entry)
	}
	if lost := missing(want, have); len(lost) > 0 {
		return nil, fmt.Errorf("%s: tags not found: %s", src, strings.Join(lost, ","))
	}
	sort.Slice(cut.Entry, func(i, j int) bool { return cut.Entry[i].Code < cut.Entry[j].Code })
	out, err := deterministic.Marshal(&cut)
	if err != nil {
		return nil, err
	}
	var back geodata.GeoIPList
	if err := proto.Unmarshal(out, &back); err != nil {
		return nil, err
	}
	for i := range cut.Entry {
		if err := sameEntry(cut.Entry[i], back.Entry[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func run() error {
	site := flag.String("site", "", "source geosite (v2fly dlc.dat)")
	ip := flag.String("ip", "", "source geoip.dat")
	sites := flag.String("sites", "", "geosite tags to keep, comma separated")
	ips := flag.String("ips", "", "geoip tags to keep, comma separated")
	out := flag.String("out", "", "output directory")
	flag.Parse()
	if *site == "" || *ip == "" || *out == "" {
		return fmt.Errorf("-site, -ip and -out are required")
	}
	wantSites, err := tagSet(*sites)
	if err != nil {
		return fmt.Errorf("-sites: %w", err)
	}
	wantIPs, err := tagSet(*ips)
	if err != nil {
		return fmt.Errorf("-ips: %w", err)
	}
	siteBytes, err := cutSites(*site, wantSites)
	if err != nil {
		return err
	}
	ipBytes, err := cutIPs(*ip, wantIPs)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
	}{{geodata.DefaultGeoIPDat, ipBytes}, {geodata.DefaultGeoSiteDat, siteBytes}}
	var sums strings.Builder
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(*out, f.name), f.data, 0o644); err != nil {
			return err
		}
		digest := sha256.Sum256(f.data)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(digest[:]), f.name)
	}
	return os.WriteFile(filepath.Join(*out, "SHA256SUMS"), []byte(sums.String()), 0o644)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "xraygeo:", err)
		os.Exit(1)
	}
}
