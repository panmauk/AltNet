// Package gateway exposes the DHT + name layer to ordinary HTTP clients.
//
// Running a Gateway lets you point any normal browser at
// http://localhost:9080/@alice/ and have the daemon resolve the name,
// fetch the directory record, fetch the file's chunks, reassemble them,
// and serve the bytes back with a sensible content-type.
//
// This is the cheapest path to "type a domain and see content" without
// shipping a custom browser: a regular browser plus this gateway is
// already a working altnet client.
package gateway

import (
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"mime"
	"net"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"

	"altnet/apps/altca"
	"altnet/apps/files"
	"altnet/apps/sitestats"
	"altnet/core/dht"
	"altnet/core/name"
)

// Defaults for DoS defense. Gateway operators can override via Options.
const (
	// DefaultPerIPRate is the steady-state request rate any single
	// remote IP is allowed to sustain through the gateway.
	DefaultPerIPRate = 20 // requests per second

	// DefaultPerIPBurst is the burst capacity above the steady rate
	// (a fresh IP can fire this many requests immediately before
	// the rate limit kicks in).
	DefaultPerIPBurst = 40

	// DefaultMaxConcurrent caps simultaneous in-flight requests
	// across the whole gateway. Each request can pull chunks from
	// the network, so unbounded concurrency = unbounded uplink fan-out.
	DefaultMaxConcurrent = 256
)

// Options configures a Gateway. Zero values pick defaults.
type Options struct {
	PerIPRate     int // requests per second per remote IP; 0 = default
	PerIPBurst    int // burst capacity per IP; 0 = default
	MaxConcurrent int // total simultaneous requests; 0 = default; -1 = unlimited
}

// Gateway is an HTTP front-end to a DHT instance. It is safe for concurrent
// use; the underlying DHT serializes its own state.
type Gateway struct {
	d *dht.DHT

	limiter *ipRateLimiter
	sem     chan struct{} // semaphore: tokens = MaxConcurrent slots

	// stats is optional; if set, every successful serveName call
	// records the name, remote IP, and bytes served. Both nil-safe
	// at the call site and the package level.
	stats sitestats.Recorder
}

// SetStats wires a stats recorder. Safe to call before Start; not safe
// to swap concurrently with serving.
func (g *Gateway) SetStats(r sitestats.Recorder) { g.stats = r }

// New creates a Gateway bound to a DHT, with default DoS settings.
func New(d *dht.DHT) *Gateway {
	return NewWithOptions(d, Options{})
}

// NewWithOptions creates a Gateway with explicit DoS-defense knobs.
func NewWithOptions(d *dht.DHT, opts Options) *Gateway {
	if opts.PerIPRate == 0 {
		opts.PerIPRate = DefaultPerIPRate
	}
	if opts.PerIPBurst == 0 {
		opts.PerIPBurst = DefaultPerIPBurst
	}
	if opts.MaxConcurrent == 0 {
		opts.MaxConcurrent = DefaultMaxConcurrent
	}

	g := &Gateway{
		d:       d,
		limiter: newIPRateLimiter(opts.PerIPRate, opts.PerIPBurst),
	}
	if opts.MaxConcurrent > 0 {
		g.sem = make(chan struct{}, opts.MaxConcurrent)
	}
	return g
}

// StartTLS is the HTTPS sibling of Start. Same handler, but the
// listener wraps TLS and mints per-SNI certificates from the CA on
// the fly. Browsers see a green padlock for `https://name.alt/` once
// the CA's root cert is in the system trust store.
//
// Concurrency: safe to call alongside Start (the two listen on
// different sockets but share the request handler).
func (g *Gateway) StartTLS(addr string, ca *altca.CA) (*http.Server, error) {
	if ca == nil {
		return nil, fmt.Errorf("gateway StartTLS: nil CA")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", g.handleWithLimits)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// SNI-driven: each new hostname triggers a mint+sign on
			// first connection, then the CA caches it.
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				host := strings.ToLower(strings.TrimSpace(hello.ServerName))
				if host == "" {
					return nil, fmt.Errorf("tls: no SNI host")
				}
				return ca.Issue(host)
			},
		},
	}
	go func() {
		// ListenAndServeTLS with empty cert/key paths makes it use
		// TLSConfig.GetCertificate exclusively, which is what we want.
		_ = srv.ListenAndServeTLS("", "")
	}()
	return srv, nil
}

// Start begins listening on addr. It does not block -- a goroutine serves
// requests, and the returned http.Server can be Shutdown later.
func (g *Gateway) Start(addr string) (*http.Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", g.handleWithLimits)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		// WriteTimeout is intentionally generous: a slow client
		// streaming a large video legitimately holds the response
		// open for a while. We don't want to kill them mid-frame.
		WriteTimeout: 5 * time.Minute,
		IdleTimeout:  120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MiB
	}
	go func() {
		_ = srv.ListenAndServe()
	}()
	return srv, nil
}

// handleWithLimits is the request entrypoint. It enforces per-IP rate
// limits and global concurrency before delegating to handle().
func (g *Gateway) handleWithLimits(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if !g.limiter.allow(ip) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if g.sem != nil {
		select {
		case g.sem <- struct{}{}:
			defer func() { <-g.sem }()
		default:
			http.Error(w, "gateway busy", http.StatusServiceUnavailable)
			return
		}
	}
	g.handle(w, r)
}

// remoteIP pulls just the IP off r.RemoteAddr (which is host:port).
// We don't trust X-Forwarded-For by default -- a Gateway run behind
// a reverse proxy that the operator does trust would need an opt-in.
//
// Uses net.SplitHostPort so IPv6 addresses (`[::1]:8080`,
// `[2001:db8::1]:8080`) round-trip correctly. A naive
// strings.LastIndexByte(":") would split inside the IPv6 itself.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // best effort if format is unexpected
	}
	return host
}

// handle is the single dispatch point.
//
// Primary route (production): the Host header IS the name.
//
//	GET / Host: panmox.alt      -> resolve "panmox.alt", serve index.html
//	GET /styles.css Host: panmox.alt -> resolve "panmox.alt", serve "styles.css"
//
// Fallback routes (for development on a single localhost where the Host
// header is just "127.0.0.1:9080"):
//
//	GET /                       -> landing page
//	GET /n/<name>[/path]        -> explicit name lookup
//	GET /cid/<roothex>[/path]   -> fetch directory by root hash, serve path
func (g *Gateway) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Strip any port from the Host header for hostname matching.
	host := r.Host
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	host = strings.TrimSuffix(host, ".") // DNS sometimes appends a trailing dot

	// If the Host header is a real domain-style name (contains a dot, and
	// is not a localhost loopback), treat it as the name to resolve. This
	// is the primary "type panmox.alt in your browser" path.
	if isResolvableHost(host) {
		g.serveName(w, r, host, strings.TrimPrefix(r.URL.Path, "/"))
		return
	}

	// Otherwise we're being hit at localhost:port -- fall back to path-based
	// routing for development.
	urlPath := strings.TrimPrefix(r.URL.Path, "/")
	if urlPath == "" {
		g.serveLanding(w, r)
		return
	}

	head, rest := splitHead(urlPath)

	switch head {
	case "cid":
		hashPart, subPath := splitHead(rest)
		g.serveCID(w, r, hashPart, subPath)
	case "n":
		nameStr, subPath := splitHead(rest)
		g.serveName(w, r, nameStr, subPath)
	default:
		http.NotFound(w, r)
	}
}

// isResolvableHost decides whether a Host header should be treated as a
// altnet name. We accept anything that has a dot and isn't an IP address
// or "localhost". Loopback addresses fall back to path-based routing.
func isResolvableHost(host string) bool {
	if host == "" || host == "localhost" {
		return false
	}
	// IPv4 / IPv6 literals: skip.
	if host[0] >= '0' && host[0] <= '9' {
		return false // crude but sufficient for IPv4
	}
	if host[0] == '[' {
		return false // IPv6
	}
	// Must look domain-like (have at least one label).
	return strings.Contains(host, ".")
}

// serveName resolves the @name to a root key and serves a file from it.
func (g *Gateway) serveName(w http.ResponseWriter, r *http.Request, name_ string, subPath string) {
	rec, err := name.Resolve(g.d, name_)
	if err != nil {
		http.Error(w, fmt.Sprintf("resolve %s: %v", name_, err), http.StatusNotFound)
		return
	}
	rootKey, err := rec.RootKey()
	if err != nil {
		http.Error(w, "bad root key in record", http.StatusBadGateway)
		return
	}
	// Wrap the writer so we know how many bytes actually went out, then
	// hand that total (plus the resolved name + remote IP) to the stats
	// recorder for the per-site dashboard. nil recorder is fine.
	if g.stats != nil {
		sw := &sizeTrackingWriter{ResponseWriter: w}
		g.serveFromRoot(sw, r, rootKey, subPath)
		g.stats.Record(name_, remoteIP(r), sw.bytes)
		return
	}
	g.serveFromRoot(w, r, rootKey, subPath)
}

// sizeTrackingWriter counts bytes for analytics. Body bytes only (not
// headers) which is what users actually care about as "data served".
type sizeTrackingWriter struct {
	http.ResponseWriter
	bytes int64
}

func (s *sizeTrackingWriter) Write(p []byte) (int, error) {
	n, err := s.ResponseWriter.Write(p)
	s.bytes += int64(n)
	return n, err
}

// serveCID parses a hex root key directly from the URL and serves from it.
func (g *Gateway) serveCID(w http.ResponseWriter, r *http.Request, hexRoot, subPath string) {
	rootKey, err := dht.IDFromHex(hexRoot)
	if err != nil {
		http.Error(w, "bad root hash", http.StatusBadRequest)
		return
	}
	g.serveFromRoot(w, r, rootKey, subPath)
}

// serveFromRoot is the shared bottom half: given a directory root key and
// a path within that directory, fetch and write the file out.
func (g *Gateway) serveFromRoot(w http.ResponseWriter, r *http.Request, rootKey dht.NodeID, subPath string) {
	blob, err := g.d.Get(rootKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("fetch directory: %v", err), http.StatusBadGateway)
		return
	}
	dir, err := files.UnmarshalDirectory(blob)
	if err != nil {
		http.Error(w, "directory record is malformed", http.StatusBadGateway)
		return
	}

	// Default to index.html when no file specified, or when path ends in /.
	if subPath == "" || strings.HasSuffix(subPath, "/") {
		subPath = path.Join(subPath, "index.html")
	}

	// Look up the entry. We compare against the canonical
	// forward-slash form used in directory records.
	var entry *files.DirEntry
	for i := range dir.Entries {
		if dir.Entries[i].Path == subPath {
			entry = &dir.Entries[i]
			break
		}
	}
	if entry == nil {
		// If no exact match and no extension, also try a directory-style
		// listing: render the index.
		http.NotFound(w, r)
		return
	}

	manifestKey, err := dht.IDFromHex(entry.ManifestKey)
	if err != nil {
		http.Error(w, "bad manifest key in directory", http.StatusBadGateway)
		return
	}
	// Stream chunks lazily instead of slurping the whole file into RAM.
	// A 4 GB video served via the gateway used to require 4 GB of
	// memory; with the ChunkReader it's bounded to a single chunk
	// (64 KiB) at a time, even with concurrent fetchers, and Range
	// requests only pull the chunks that overlap the requested span.
	reader, err := files.NewChunkReader(g.d, manifestKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("fetch file: %v", err), http.StatusBadGateway)
		return
	}

	// Sniff content-type from the first chunk if the extension didn't
	// pin it down. We can't pass arbitrary bytes to DetectContentType
	// without consuming the reader, so we Read up to 512 bytes, sniff,
	// then Seek back to the start before handing off to ServeContent.
	ct := mime.TypeByExtension(filepath.Ext(subPath))
	if ct == "" {
		var sniff [512]byte
		n, _ := reader.Read(sniff[:])
		ct = http.DetectContentType(sniff[:n])
		_, _ = reader.Seek(0, io.SeekStart)
	}
	w.Header().Set("Content-Type", ct)

	// Hand off to http.ServeContent: Range / If-None-Match / HEAD all
	// handled. The ETag is the immutable manifest key, so caching
	// works without any modtime.
	w.Header().Set("ETag", `"`+entry.ManifestKey+`"`)
	http.ServeContent(w, r, subPath, time.Time{}, reader)
}

// serveLanding renders a tiny help page so someone hitting / sees something
// useful instead of a 404.
func (g *Gateway) serveLanding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<!DOCTYPE html>
<html>
<head><title>altnet gateway</title></head>
<body style="font-family:sans-serif;max-width:640px;margin:40px auto;line-height:1.5">
<h1>altnet gateway</h1>
<p>This daemon is acting as an HTTP bridge to the altnet DHT.</p>
<p>Try:</p>
<ul>
<li><code>/&#64;name/</code> &mdash; resolves a name to a directory and serves <code>index.html</code></li>
<li><code>/&#64;name/path/to/file</code> &mdash; serves a specific file</li>
<li><code>/cid/&lt;64-char-hex&gt;/</code> &mdash; fetch a directory directly by its root hash</li>
</ul>
<p>Identity of this peer: <code>` + html.EscapeString(g.d.Self().Hex()) + `</code></p>
</body>
</html>`
	_, _ = w.Write([]byte(body))
}

// splitHead returns ("a", "b/c") for input "a/b/c", or ("a", "") for "a".
func splitHead(p string) (string, string) {
	idx := strings.IndexByte(p, '/')
	if idx < 0 {
		return p, ""
	}
	return p[:idx], p[idx+1:]
}
