package main

// Gate for the cut pair (run by the recipe with TRIBE_GEO_DIR=<output dir>): every tag loads
// through the core's own asset loader and matchers, known members match, known non-members do
// not, tags outside the set are absent, and SHA256SUMS describes the files.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/platform"
)

var siteMembers = map[string]struct{ in, out []string }{
	"private":     {in: []string{"localhost"}, out: []string{"yandex.ru"}},
	"category-ru": {in: []string{"yandex.ru", "www.gosuslugi.ru", "vk.com"}, out: []string{"www.google.com", "www.tiktok.com"}},
	"tiktok":      {in: []string{"www.tiktok.com", "tiktokcdn.com"}, out: []string{"yandex.ru"}},
	"speedtest":   {in: []string{"www.speedtest.net"}, out: []string{"yandex.ru"}},
	"youtube":     {in: []string{"www.youtube.com", "youtu.be"}, out: []string{"yandex.ru"}},
}

var ipMembers = map[string]struct{ in, out []string }{
	"private": {in: []string{"10.1.2.3", "172.16.5.4", "192.168.1.1", "127.0.0.1", "fd00::1"}, out: []string{"8.8.8.8", "77.88.8.8"}},
	"ru":      {in: []string{"77.88.8.8", "87.250.250.242"}, out: []string{"8.8.8.8", "1.1.1.1", "10.1.2.3"}},
}

func geoDir(t *testing.T) string {
	dir := os.Getenv("TRIBE_GEO_DIR")
	if dir == "" {
		t.Skip("TRIBE_GEO_DIR is not set")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(platform.AssetLocation, abs)
	return abs
}

func TestCutGeoSiteTags(t *testing.T) {
	geoDir(t)
	if len(siteMembers) != 5 {
		t.Fatal("tag list drifted from the recipe")
	}
	for tag, want := range siteMembers {
		rules, err := geodata.ParseDomainRules([]string{"geosite:" + tag}, geodata.Domain_Substr)
		if err != nil {
			t.Fatalf("geosite:%s parse: %v", tag, err)
		}
		matcher, err := geodata.DomainReg.BuildDomainMatcher(rules)
		if err != nil {
			t.Fatalf("geosite:%s does not load: %v", tag, err)
		}
		for _, name := range want.in {
			if !matcher.MatchAny(name) {
				t.Errorf("geosite:%s does not match %s", tag, name)
			}
		}
		for _, name := range want.out {
			if matcher.MatchAny(name) {
				t.Errorf("geosite:%s unexpectedly matches %s", tag, name)
			}
		}
	}
	for _, absent := range []string{"cn", "google", "category-ads-all"} {
		rules, err := geodata.ParseDomainRules([]string{"geosite:" + absent}, geodata.Domain_Substr)
		if err == nil {
			_, err = geodata.DomainReg.BuildDomainMatcher(rules)
		}
		if err == nil {
			t.Errorf("geosite:%s must not be in the cut file", absent)
		}
	}
}

func TestCutGeoIPTags(t *testing.T) {
	geoDir(t)
	for tag, want := range ipMembers {
		rules, err := geodata.ParseIPRules([]string{"geoip:" + tag})
		if err != nil {
			t.Fatalf("geoip:%s parse: %v", tag, err)
		}
		matcher, err := geodata.IPReg.BuildIPMatcher(rules)
		if err != nil {
			t.Fatalf("geoip:%s does not load: %v", tag, err)
		}
		for _, ip := range want.in {
			if !matcher.Match(net.ParseIP(ip)) {
				t.Errorf("geoip:%s does not match %s", tag, ip)
			}
		}
		for _, ip := range want.out {
			if matcher.Match(net.ParseIP(ip)) {
				t.Errorf("geoip:%s unexpectedly matches %s", tag, ip)
			}
		}
	}
	for _, absent := range []string{"cn", "us", "google"} {
		rules, err := geodata.ParseIPRules([]string{"geoip:" + absent})
		if err == nil {
			_, err = geodata.IPReg.BuildIPMatcher(rules)
		}
		if err == nil {
			t.Errorf("geoip:%s must not be in the cut file", absent)
		}
	}
}

func TestCutManifest(t *testing.T) {
	dir := geoDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("SHA256SUMS has %d lines", len(lines))
	}
	for _, line := range lines {
		var sum, name string
		if _, err := fmt.Sscanf(line, "%s %s", &sum, &name); err != nil {
			t.Fatalf("bad line %q", line)
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != sum {
			t.Fatalf("%s: sha256 mismatch", name)
		}
	}
}
