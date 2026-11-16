// scanlab-world: the network around a local end-to-end scan lab (scratch tool, never committed into
// recipes). Everything listens on 127.0.0.1.
//
//   - "edge" fronts: one listener per apparent client address. Each relays HTTP to the local backend and
//     OVERWRITES X-Forwarded-For with its address, the way the production edge does for a backend running
//     with TRUST_FORWARDED_FOR=1. So the backend sees the access network, our own nodes and every provider
//     exit as different addresses although every packet stays on lo0. TLS fronts use a lab CA.
//   - Xray servers (VLESS / VLESS+REALITY / a dialerProxy chain), each one's freedom outbound redirected to
//     its own front (its "exit"). One provider exit goes through a relay that freezes the downlink after
//     -stall bytes (a mobile operator's freeze); one profile points to a closed port (dead).
//   - a subscription server: GET /sub = a JSON array of full Xray client configs (Happ style).
//
// Writes <out>/world.json (ports, client outbounds, the CA path) and logs JSON lines to stdout: every
// request a front relayed (front, method, path without query values except bytes, status, body bytes) and
// every front connection's wire bytes at close.
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtls/xray-core/core"
	confserial "github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

const (
	labUUID    = "6b0e6e1c-0f5b-4e1e-9d1a-2a3b4c5d6e7f"
	labShortID = "b42c9187914b1a52"
)

var (
	logMu  sync.Mutex
	logOut = json.NewEncoder(os.Stdout)
)

func emit(m map[string]any) {
	m["t"] = time.Now().UTC().Format("15:04:05.000")
	logMu.Lock()
	defer logMu.Unlock()
	_ = logOut.Encode(m)
}

// ---- lab CA ----------------------------------------------------------------------------------------------

func makeCA(dir string, names []string) (tls.Certificate, string) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Tribe scan lab CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(7 * 24 * time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(7 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	caPath := filepath.Join(dir, "lab-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		log.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}, caPath
}

// ---- fronts ----------------------------------------------------------------------------------------------

type countConn struct {
	net.Conn
	front    string
	in, out  atomic.Int64
	closeOne sync.Once
}

func (c *countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.in.Add(int64(n))
	return n, err
}

func (c *countConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.out.Add(int64(n))
	return n, err
}

func (c *countConn) Close() error {
	c.closeOne.Do(func() {
		emit(map[string]any{"ev": "conn_close", "front": c.front, "wire_in": c.in.Load(), "wire_out": c.out.Load()})
	})
	return c.Conn.Close()
}

type countListener struct {
	net.Listener
	front string
}

func (l *countListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &countConn{Conn: c, front: l.front}, nil
}

type countWriter struct {
	http.ResponseWriter
	status int
	n      int64
}

func (w *countWriter) WriteHeader(s int) { w.status = s; w.ResponseWriter.WriteHeader(s) }
func (w *countWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(b)
	w.n += int64(n)
	return n, err
}
func (w *countWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

type front struct {
	Name string `json:"name"`
	Port int    `json:"port"`
	TLS  bool   `json:"tls"`
	IP   string `json:"apparent_ip"`
}

func startFront(f front, backend *url.URL, cert *tls.Certificate) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", f.Port))
	if err != nil {
		log.Fatalf("front %s: %v", f.Name, err)
	}
	var l net.Listener = &countListener{Listener: ln, front: f.Name}
	if f.TLS {
		l = tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"}})
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(backend)
			r.Out.Host = r.In.Host
			r.Out.Header.Del("Forwarded")
			r.Out.Header.Set("X-Forwarded-For", f.IP)
			r.Out.Header.Set("X-Forwarded-Proto", map[bool]string{true: "https", false: "http"}[f.TLS])
		},
		FlushInterval: -1,
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t0 := time.Now()
		cw := &countWriter{ResponseWriter: w}
		var reqBody int64
		if r.Body != nil {
			buf, _ := io.ReadAll(r.Body)
			reqBody = int64(len(buf))
			r.Body = io.NopCloser(bytes.NewReader(buf))
		}
		rp.ServeHTTP(cw, r)
		ev := map[string]any{"ev": "req", "front": f.Name, "method": r.Method, "path": r.URL.Path, "status": cw.status,
			"req_body": reqBody, "resp_body": cw.n, "ms": time.Since(t0).Milliseconds()}
		if b := r.URL.Query().Get("bytes"); b != "" {
			ev["q_bytes"] = b
		}
		emit(ev)
	})
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(l) }()
}

// ---- stall relay -------------------------------------------------------------------------------------------

func startStallRelay(target int, after int64) int {
	name := fmt.Sprintf("stall@%d", after)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				s, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", target))
				if err != nil {
					c.Close()
					return
				}
				var once sync.Once
				end := func() { once.Do(func() { c.Close(); s.Close() }) }
				go func() { _, _ = io.Copy(s, c); end() }()
				// Downlink: pass `after` bytes, then stop reading and writing (the flow freezes; the
				// connection stays open until the client gives up).
				n, _ := io.CopyN(c, s, after)
				emit(map[string]any{"ev": "stall", "relay": name, "passed": n})
				if n == after {
					buf := make([]byte, 1)
					_, _ = c.Read(buf) // block until the client closes (uplink copy above gets EOF too)
				}
				end()
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// ---- access-link meter ----------------------------------------------------------------------------------------

// startLinkRelay puts a counting TCP relay in front of a server's inbound: what crosses it is what the device's
// access link would carry for that probe (VLESS / REALITY framing, inner TLS and all). One event per connection.
func startLinkRelay(name string, target int) int {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				t0 := time.Now()
				s, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", target))
				if err != nil {
					c.Close()
					return
				}
				var up, down atomic.Int64
				var wg sync.WaitGroup
				wg.Add(2)
				go func() { n, _ := io.Copy(s, c); up.Store(n); s.Close(); wg.Done() }()
				go func() { n, _ := io.Copy(c, s); down.Store(n); c.Close(); wg.Done() }()
				wg.Wait()
				emit(map[string]any{"ev": "link_close", "server": name, "up": up.Load(), "down": down.Load(),
					"ms": time.Since(t0).Milliseconds()})
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// ---- xray servers ------------------------------------------------------------------------------------------

func freePort() int {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func startCore(cfg map[string]any) *core.Instance {
	raw, _ := json.Marshal(cfg)
	c, err := confserial.LoadJSONConfig(bytes.NewReader(raw))
	if err != nil {
		log.Fatalf("server config: %v\n%s", err, raw)
	}
	inst, err := core.New(c)
	if err != nil {
		log.Fatalf("server core: %v", err)
	}
	if err := inst.Start(); err != nil {
		log.Fatalf("server start: %v", err)
	}
	return inst
}

func freedomTo(port int) map[string]any {
	s := map[string]any{"domainStrategy": "AsIs", "finalRules": []any{map[string]any{"action": "allow"}}}
	if port > 0 {
		s["redirect"] = fmt.Sprintf("127.0.0.1:%d", port)
	}
	return map[string]any{"tag": "out", "protocol": "freedom", "settings": s}
}

func vlessInbound(port int, flow string, stream map[string]any) map[string]any {
	cl := map[string]any{"id": labUUID}
	if flow != "" {
		cl["flow"] = flow
	}
	in := map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "vless",
		"settings": map[string]any{"clients": []any{cl}, "decryption": "none"}}
	if stream != nil {
		in["streamSettings"] = stream
	}
	return in
}

func vlessOutbound(tag string, port int, flow string, stream map[string]any) map[string]any {
	u := map[string]any{"id": labUUID, "encryption": "none"}
	if flow != "" {
		u["flow"] = flow
	}
	ob := map[string]any{"tag": tag, "protocol": "vless", "settings": map[string]any{
		"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{u}}}}}
	if stream != nil {
		ob["streamSettings"] = stream
	}
	return ob
}

type server struct {
	Name      string           `json:"name"`
	Kind      string           `json:"kind"`
	Port      int              `json:"port"`
	Front     string           `json:"front"`
	Outbounds []map[string]any `json:"outbounds"` // client side: the first is the proxy
	// REALITY servers: what the backend's transport profile row publishes (public_config).
	RealityPublicKey string `json:"reality_public_key,omitempty"`
	ShortID          string `json:"short_id,omitempty"`
	ServerName       string `json:"server_name,omitempty"`
}

func main() {
	out := flag.String("out", "", "output dir (world.json, lab-ca.pem)")
	backendURL := flag.String("backend", "http://127.0.0.1:48480", "backend")
	host := flag.String("host", "probe.scanlab.test", "probe / API host name of the lab")
	basePort := flag.Int("port", 48481, "first front port")
	stall := flag.Int64("stall", 16384, "downlink bytes before the freeze of the stalled exit (provD)")
	stall2 := flag.Int64("stall2", 49152, "downlink bytes before the freeze of the second stalled exit (provF)")
	subPort := flag.Int("sub", 0, "subscription server port (0 = free)")
	flag.Parse()
	if *out == "" {
		log.Fatal("-out")
	}
	backend, _ := url.Parse(*backendURL)
	cert, caPath := makeCA(*out, []string{*host})

	fronts := []front{
		{"app", *basePort, false, "192.0.2.10"},     // the app's API calls (VPN off: the access network)
		{"access", *basePort + 1, true, "192.0.2.10"}, // the engine's direct attempts (probe base, base_ips)
		{"own1", *basePort + 2, true, "198.51.100.11"},
		{"own2", *basePort + 3, true, "198.51.100.12"},
		{"provA", *basePort + 4, true, "203.0.113.21"},
		{"provB", *basePort + 5, true, "203.0.113.22"},
		{"provC", *basePort + 6, true, "203.0.113.23"},
		{"provD", *basePort + 7, true, "203.0.113.24"},
		{"provF", *basePort + 8, true, "203.0.113.26"},
	}
	fp := map[string]int{}
	for _, f := range fronts {
		startFront(f, backend, &cert)
		fp[f.Name] = f.Port
	}

	var servers []server
	reality := func(name, frontName string) server {
		priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
		p := freePort()
		startCore(map[string]any{"inbounds": []any{vlessInbound(p, "xtls-rprx-vision", map[string]any{"network": "tcp", "security": "reality",
			"realitySettings": map[string]any{"dest": fmt.Sprintf("127.0.0.1:%d", fp["access"]), "serverNames": []any{*host},
				"privateKey": base64.RawURLEncoding.EncodeToString(priv.Bytes()), "shortIds": []any{labShortID}}})},
			"outbounds": []any{freedomTo(fp[frontName])}})
		pub := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
		link := startLinkRelay(name, p)
		return server{Name: name, Kind: "vless+reality+vision", Port: link, Front: frontName,
			Outbounds: []map[string]any{vlessOutbound("proxy", link, "xtls-rprx-vision",
				map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"serverName": *host,
					"fingerprint": "chrome", "shortId": labShortID, "publicKey": pub}})},
			RealityPublicKey: pub, ShortID: labShortID, ServerName: *host}
	}
	// Own nodes: VLESS + REALITY + Vision, as every Xray listener of ours (the backend issues only that).
	servers = append(servers, reality("own1", "own1"), reality("own2", "own2"))
	// Provider A: plain VLESS/TCP.
	{
		p := freePort()
		startCore(map[string]any{"inbounds": []any{vlessInbound(p, "", nil)}, "outbounds": []any{freedomTo(fp["provA"])}})
		link := startLinkRelay("provA", p)
		servers = append(servers, server{"provA", "vless", link, "provA", []map[string]any{vlessOutbound("proxy", link, "", nil)}, "", "", ""})
	}
	// Provider B: VLESS + REALITY + Vision.
	servers = append(servers, reality("provB", "provB"))
	// Provider C: a chain - the client dials the last server through a hop (sockopt.dialerProxy).
	{
		last := freePort()
		startCore(map[string]any{"inbounds": []any{vlessInbound(last, "", nil)}, "outbounds": []any{freedomTo(fp["provC"])}})
		lastLink := startLinkRelay("provC-last", last)
		hop := freePort()
		startCore(map[string]any{"inbounds": []any{vlessInbound(hop, "", nil)}, "outbounds": []any{freedomTo(0)}})
		hopLink := startLinkRelay("provC", hop)
		px := vlessOutbound("proxy", lastLink, "", map[string]any{"sockopt": map[string]any{"dialerProxy": "hop"}})
		servers = append(servers, server{"provC", "vless chain (dialerProxy)", hopLink, "provC",
			[]map[string]any{px, vlessOutbound("hop", hopLink, "", nil)}, "", "", ""})
	}
	// Provider D: plain VLESS whose exit freezes the downlink after -stall bytes (a mobile operator's freeze);
	// provider F: the same after -stall2 bytes (late enough that the probe body passes the engine's stall threshold).
	stalled := func(name string, after int64) server {
		relay := startStallRelay(fp[name], after)
		p := freePort()
		startCore(map[string]any{"inbounds": []any{vlessInbound(p, "", nil)}, "outbounds": []any{freedomTo(relay)}})
		link := startLinkRelay(name, p)
		return server{name, fmt.Sprintf("vless (exit freezes after %d bytes)", after), link, name, []map[string]any{vlessOutbound("proxy", link, "", nil)}, "", "", ""}
	}
	servers = append(servers, stalled("provD", *stall), stalled("provF", *stall2))
	// Provider E: dead (nothing listens).
	servers = append(servers, server{"provE", "vless (dead: closed port)", freePort(), "", []map[string]any{vlessOutbound("proxy", freePort(), "", nil)}, "", "", ""})

	// Subscription: one full client config per provider profile (Happ style).
	var sub []any
	for _, s := range servers {
		if len(s.Name) < 4 || s.Name[:4] != "prov" {
			continue
		}
		obs := []any{}
		for _, o := range s.Outbounds {
			obs = append(obs, o)
		}
		obs = append(obs, map[string]any{"tag": "direct", "protocol": "freedom"}, map[string]any{"tag": "block", "protocol": "blackhole"})
		sub = append(sub, map[string]any{
			"remarks":   "Lab " + s.Name,
			"log":       map[string]any{"loglevel": "warning"},
			"inbounds":  []any{map[string]any{"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": map[string]any{"udp": true}}},
			"outbounds": obs,
			"routing":   map[string]any{"domainStrategy": "AsIs", "rules": []any{map[string]any{"type": "field", "inboundTag": []any{"socks"}, "outboundTag": "proxy"}}},
		})
	}
	subBody, _ := json.MarshalIndent(sub, "", "  ")
	if *subPort == 0 {
		*subPort = freePort()
	}
	subLn, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", *subPort))
	if err != nil {
		log.Fatal(err)
	}
	var subHits atomic.Int64
	go func() {
		_ = http.Serve(subLn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subHits.Add(1)
			emit(map[string]any{"ev": "sub_fetch", "path": r.URL.Path, "ua": r.UserAgent()})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("profile-update-interval", "1")
			_, _ = w.Write(subBody)
		}))
	}()

	world := map[string]any{"ca": caPath, "host": *host, "fronts": fronts, "servers": servers, "sub_port": *subPort,
		"sub_url": fmt.Sprintf("http://127.0.0.1:%d/sub", *subPort), "uuid": labUUID, "stall_after": *stall}
	wj, _ := json.MarshalIndent(world, "", "  ")
	if err := os.WriteFile(filepath.Join(*out, "world.json"), wj, 0o644); err != nil {
		log.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(*out, "sub.json"), subBody, 0o644)
	emit(map[string]any{"ev": "ready", "world": filepath.Join(*out, "world.json")})

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	emit(map[string]any{"ev": "exit"})
}
