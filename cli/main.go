// Command altnet runs a single peer node with DHT, naming, HTTP gateway,
// and an optional DNS resolver.
//
// Usage:
//
//	altnet -listen 127.0.0.1:9000 -gateway 127.0.0.1:80 -dns 127.0.0.1:5353
//	altnet -listen 127.0.0.1:9001 -bootstrap 127.0.0.1:9000 -keydir data/keys2
//
// On first run a new identity (Ed25519 keypair) is generated and saved
// under -keydir. On subsequent runs the same identity is loaded so the
// peer keeps the same ID across restarts.
//
// If -gateway is set, an HTTP server is started so any browser can hit
// http://<name>.alt/ to fetch content from the network. The Host header
// is parsed and resolved through the DHT name layer.
//
// If -dns is set, a UDP DNS server is started that returns the gateway IP
// for any name under -tld (default "alt") and forwards everything else
// to -upstream (default 1.1.1.1:53). To browse panmox.alt by typing the
// domain into your browser, set your network's primary DNS to point at
// the daemon's -dns address.
//
// Interactive commands (type at the prompt):
//
//	<anything>          broadcast as a chat message
//	ping                send a ping to all connected peers
//	peers               show how many peers we hold connections to
//	dht                 show contents of the DHT routing table
//	find <id>           look up a peer ID via the DHT
//	put <text>          store text in the DHT; prints the content key
//	get <key>           retrieve a value from the DHT by hex key
//	publish <dir>       publish a directory of files; prints the root hash
//	fetch <key> <dest>  fetch a published directory by root hash into dest
//	register <name> <key>  publish "name -> key" record signed by this peer
//	resolve <name>      look up a name and print its signed record
//	bootstrap <addr>    join the DHT through peer at addr
//	quit                exit
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"net"

	"altnet/apps/altca"
	"altnet/apps/dns"
	"altnet/apps/files"
	"altnet/apps/gateway"
	"altnet/apps/metrics"
	"altnet/apps/registrar"
	"altnet/apps/sitestats"
	"altnet/core/crypto"
	"altnet/core/dht"
	"altnet/core/name"
	"altnet/core/peer"
	"altnet/core/relay"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9000", "address to listen on")
	bootstrap := flag.String("bootstrap", "", "comma-separated addresses of existing DHT peers to join through (optional, falls back through the list)")
	keydir := flag.String("keydir", "data/keys", "directory to store the peer's private key")
	gw := flag.String("gateway", "", "address for the HTTP gateway (e.g. 127.0.0.1:9080); empty = disabled")
	gwTLS := flag.String("gateway-tls", "", "address for the HTTPS gateway (e.g. 127.0.0.1:443); empty = disabled. Requires -ca-dir.")
	caDir := flag.String("ca-dir", "", "directory holding the AltNet local CA (cert + key); empty = <data>/ca. Used by -gateway-tls.")
	dnsAddr := flag.String("dns", "", "address for the DNS resolver (e.g. 127.0.0.1:5353); empty = disabled")
	tld := flag.String("tld", "alt", "TLD to capture in DNS (e.g. 'alt')")
	dnsCaptureIP := flag.String("dns-ip", "127.0.0.1", "IP address returned by DNS for captured names (the gateway's IP)")
	dnsUpstream := flag.String("dns-upstream", dns.DefaultUpstream, "upstream DNS server to forward non-captured queries to")
	regAddr := flag.String("registrar", "", "address for the registrar API (e.g. 127.0.0.1:9090); empty = disabled")
	regToken := flag.String("registrar-token", "", "bearer token for registrar API authentication (required if -registrar is set)")
	dataDir := flag.String("data", "data/store", "directory to persist DHT values and registry; empty = in-memory only (data is lost on restart)")
	storeBudget := flag.Int64("store-budget", dht.DefaultStoreBudgetBytes, "max bytes the local DHT store may use; 0 = unlimited. LRU eviction kicks in when full.")
	perPeerBudget := flag.Int64("per-peer-budget", dht.DefaultPerPeerBudgetBytes, "max bytes any single remote peer can have STORE'd at us; 0 = unlimited. Caps spam from a bad actor.")
	relayAddr := flag.String("relay", "", "comma-separated relays to register with for NAT traversal (e.g. relay1.altnet.example:9100,relay2.altnet.example:9100). Multiple relays = redundancy.")
	relayListen := flag.String("relay-listen", "", "run a relay server on this address so NAT-ed peers can register through us (e.g. 0.0.0.0:9100)")
	public := flag.Bool("public", false, "this peer is directly reachable on the internet (public IP, port-forwarded, etc.). When set, peers prefer dialing us directly over going through any relay we may also be registered with.")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	logFormat := flag.String("log-format", "text", "log format: text (human-readable) or json (machine-parseable for the AltNet app)")
	metricsAddr := flag.String("metrics", "", "address for the metrics HTTP endpoint (e.g. 127.0.0.1:9999); empty = disabled. Serves GET /metrics (JSON) and GET /healthz.")
	exportKey := flag.Bool("export-key", false, "print the local identity's private key in portable form and exit. Save the printed string somewhere safe -- it's how you recover ownership of your domains if this machine dies.")
	importKey := flag.String("import-key", "", "import a previously-exported key string into -keydir, overwriting any existing key, and exit. Use this on a fresh machine to take over the same identity.")
	headless := flag.Bool("headless", false, "run without the interactive REPL; keep all servers alive and block until SIGINT/SIGTERM. Use this when running under systemd, Docker, or any non-interactive supervisor.")
	flag.Parse()

	configureLogging(*logLevel, *logFormat)

	keyPath := filepath.Join(*keydir, "peer.key")

	// Key import: write the supplied key string to keydir and exit.
	// This lets a user recover their identity (and therefore their
	// registered domains) on a fresh machine.
	if *importKey != "" {
		imported, err := crypto.ImportKey(*importKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "import-key: %v\n", err)
			os.Exit(1)
		}
		if err := imported.Save(keyPath); err != nil {
			fmt.Fprintf(os.Stderr, "save imported key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("imported identity %s into %s\n", imported.ID(), keyPath)
		return
	}

	id, err := crypto.LoadOrCreate(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load identity: %v\n", err)
		os.Exit(1)
	}

	// Key export: print the portable form and exit. Don't start the
	// daemon -- exporting is a one-shot operation.
	if *exportKey {
		fmt.Println("# Save this string somewhere safe. Anyone with it can")
		fmt.Println("# act as you on AltNet, including transferring your domains.")
		fmt.Printf("# identity: %s\n", id.ID())
		fmt.Println(id.Export())
		return
	}

	fmt.Printf("identity: %s\n", id.ID())

	p := peer.New(id, *listen)
	p.SetPublic(*public)
	if err := p.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start peer: %v\n", err)
		os.Exit(1)
	}
	defer p.Stop()

	// Optional: run a relay server (for publicly-reachable nodes that
	// want to help NAT-ed peers be reachable).
	if *relayListen != "" {
		relaySrv := relay.NewServer()
		if err := relaySrv.Start(*relayListen); err != nil {
			fmt.Fprintf(os.Stderr, "start relay server: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("relay server listening on %s\n", *relayListen)
		defer relaySrv.Stop()
	}

	// Optional: register with one or more relays so other peers can
	// reach us through them (typical for nodes behind home NAT).
	relayAddrs := splitAndTrim(*relayAddr)
	if len(relayAddrs) > 0 {
		p.UseRelay(relayAddrs...)
	}

	d, err := dht.NewWithFullLimit(p, *dataDir, *storeBudget, *perPeerBudget)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start dht: %v\n", err)
		os.Exit(1)
	}
	if *dataDir != "" {
		budget := "unlimited"
		if *storeBudget > 0 {
			budget = fmt.Sprintf("%d MiB cap", *storeBudget/(1<<20))
		}
		fmt.Printf("data dir: %s (loaded %d value(s), %s)\n",
			*dataDir, d.LocalStoreSize(), budget)
	} else {
		fmt.Println("data dir: <in-memory only>")
	}

	// Load chunk-hash blocklist. data/blocklist.txt is the convention;
	// missing file = empty list (no blocking). One SHA-256 hex hash per
	// line; blank lines and #-comments ignored. Blocked hashes are
	// refused by Store, find_value, and getInner — they behave as if
	// they never existed on the network.
	blocklistPath := "data/blocklist.txt"
	if *dataDir != "" {
		blocklistPath = filepath.Join(*dataDir, "blocklist.txt")
	}
	if bl, err := dht.LoadBlocklistFromFile(blocklistPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to load blocklist %s: %v\n", blocklistPath, err)
	} else {
		d.SetBlocklist(bl)
		if bl.Size() > 0 {
			fmt.Printf("blocklist: loaded %d blocked hash(es) from %s\n", bl.Size(), blocklistPath)
		}
	}

	// Load trusted-revoker pubkeys. One Ed25519 hex pubkey per line;
	// blank lines and #-comments ignored. Any node receiving a
	// dht_revoke signed by one of these keys will purge the listed
	// chunks and forward the revoke. With no keys configured the
	// revoke handler is a no-op (safer default: nothing happens until
	// the operator opts in to trust a specific admin key).
	trustedPath := "data/trusted-revokers.txt"
	if *dataDir != "" {
		trustedPath = filepath.Join(*dataDir, "trusted-revokers.txt")
	}
	tr := dht.NewTrustedRevokers()
	if f, err := os.Open(trustedPath); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if i := strings.Index(line, "#"); i >= 0 {
				line = strings.TrimSpace(line[:i])
			}
			tr.Add(line)
		}
		f.Close()
	}
	d.SetTrustedRevokers(tr)
	if tr.Size() > 0 {
		fmt.Printf("trusted revokers: %d key(s) loaded from %s\n", tr.Size(), trustedPath)
	}

	// Load trusted-registrar pubkeys (permissioned naming). One Ed25519
	// hex pubkey per line. When at least one is configured, this node only
	// resolves .alt names whose record is signed by one of these authority
	// keys — the protocol-level enforcement of admin-approved registration.
	// With no keys configured, naming stays open (any validly-signed record
	// resolves), so existing/open deployments are unaffected.
	regPath := "data/trusted-registrars.txt"
	if *dataDir != "" {
		regPath = filepath.Join(*dataDir, "trusted-registrars.txt")
	}
	var regKeys []string
	if f, err := os.Open(regPath); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if i := strings.Index(line, "#"); i >= 0 {
				line = strings.TrimSpace(line[:i])
			}
			regKeys = append(regKeys, line)
		}
		f.Close()
	}
	name.SetTrustedRegistrars(regKeys)
	if n := name.TrustedRegistrarCount(); n > 0 {
		fmt.Printf("permissioned naming: %d trusted registrar(s) loaded from %s\n", n, regPath)
	}

	bootstrapAddrs := splitAndTrim(*bootstrap)
	if len(bootstrapAddrs) > 0 {
		chosen, err := d.BootstrapAll(bootstrapAddrs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bootstrap: %v\n", err)
		} else {
			fmt.Printf("bootstrapped via %s; routing table now has %d peer(s)\n",
				chosen, d.RoutingTable().Size())
		}
	}

	// Start the background maintenance loop: republish stored values,
	// prune dead peers, and reconnect to bootstraps if we get partitioned.
	maint := d.StartMaintenance(dht.MaintenanceConfig{
		BootstrapPeers: bootstrapAddrs,
	})
	defer maint.Stop()

	// Optional: HTTP metrics endpoint. The AltNet desktop app polls
	// this to drive its node-status UI; ops people can also curl it.
	if *metricsAddr != "" {
		mSrv, err := metrics.New(p, d).Start(*metricsAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "start metrics: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Metrics: http://%s/metrics\n", *metricsAddr)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = mSrv.Shutdown(ctx)
		}()
	}

	// Single per-daemon stats store shared by the gateway (writer) and
	// the registrar (reader). Constructed unconditionally — both
	// services accept a nil recorder/reader but having one means the
	// desktop app's dashboard always has data to render.
	stats := sitestats.New()

	// One Gateway instance shared by the HTTP and HTTPS listeners.
	// SetStats is wired once; both listeners record into the same
	// counters, so the dashboard sees a single combined total per
	// site regardless of which protocol the visitor used.
	var sharedGateway *gateway.Gateway
	if *gw != "" || *gwTLS != "" {
		sharedGateway = gateway.New(d)
		sharedGateway.SetStats(stats)
	}

	if *gw != "" {
		srv, err := sharedGateway.Start(*gw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "start gateway: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("HTTP gateway: http://%s/\n", *gw)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
		}()
	}

	if *gwTLS != "" {
		caPath := *caDir
		if caPath == "" {
			caPath = filepath.Join(*dataDir, "ca")
		}
		ca, err := altca.LoadOrCreate(caPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load/create CA at %s: %v\n", caPath, err)
			os.Exit(1)
		}
		srv, err := sharedGateway.StartTLS(*gwTLS, ca)
		if err != nil {
			fmt.Fprintf(os.Stderr, "start TLS gateway: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("HTTPS gateway: https://%s/  (CA: %s)\n", *gwTLS, ca.CertPath())
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
		}()
	}

	if *dnsAddr != "" {
		ip := net.ParseIP(*dnsCaptureIP)
		if ip == nil || ip.To4() == nil {
			fmt.Fprintf(os.Stderr, "dns-ip must be an IPv4 address, got %q\n", *dnsCaptureIP)
			os.Exit(1)
		}
		r := dns.New([]string{*tld}, ip, *dnsUpstream)
		if err := r.Start(*dnsAddr); err != nil {
			fmt.Fprintf(os.Stderr, "start DNS resolver: %v (try a high port, e.g. 5353)\n", err)
			os.Exit(1)
		}
		fmt.Printf("DNS resolver: udp://%s, capturing .%s -> %s, forwarding else -> %s\n",
			*dnsAddr, *tld, ip, *dnsUpstream)
		defer r.Stop()
	}

	if *regAddr != "" {
		if *regToken == "" {
			fmt.Fprintf(os.Stderr, "registrar-token is required when registrar is enabled\n")
			os.Exit(1)
		}
		reg, err := registrar.NewWithDataDir(d, id, *regToken, *dataDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create registrar: %v\n", err)
			os.Exit(1)
		}
		reg.SetStats(stats)
		regSrv, err := reg.Start(*regAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "start registrar: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Registrar API: http://%s/\n", *regAddr)
		fmt.Printf("  check:      GET  /api/check/<name>\n")
		fmt.Printf("  register:   POST /api/register     (auth required)\n")
		fmt.Printf("  update:     POST /api/update       (auth required)\n")
		fmt.Printf("  domains:    GET  /api/domains      (auth required)\n")
		fmt.Printf("  publish:    POST /api/publish      (auth required)\n")
		fmt.Printf("  stats:      GET  /api/stats/<name> (auth required)\n")
		fmt.Printf("  unregister: POST /api/unregister   (auth required)\n")
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = regSrv.Shutdown(ctx)
		}()
	}

	// When running under a supervisor (systemd, Docker, etc.) there's no
	// one to type REPL commands and stdin is typically /dev/null, so
	// Scan() would return EOF immediately and the process would exit.
	// With -headless we skip the REPL entirely and block until a
	// termination signal, keeping all the background servers (peer, DHT,
	// gateway, relay, registrar) alive.
	if *headless {
		fmt.Println("running headless; waiting for SIGINT/SIGTERM")
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		s := <-sigCh
		fmt.Printf("received %s; shutting down\n", s)
		return
	}

	fmt.Println("type 'help' for the command list, 'stats' for an overview, 'quit' to exit")
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			return
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		switch {
		case line == "quit", line == "exit":
			return
		case line == "peers":
			showPeers(p)
		case line == "ping":
			p.Broadcast(peer.Message{Type: "ping"})
		case line == "dht":
			showRoutingTable(d)
		case line == "relays":
			showRelays(p)
		case line == "stats":
			showStats(p, d)
		case line == "help", line == "?":
			showHelp()
		case strings.HasPrefix(line, "find "):
			runFind(d, strings.TrimSpace(line[len("find "):]))
		case strings.HasPrefix(line, "put "):
			runPut(d, strings.TrimSpace(line[len("put "):]))
		case strings.HasPrefix(line, "get "):
			runGet(d, strings.TrimSpace(line[len("get "):]))
		case strings.HasPrefix(line, "publish "):
			runPublish(d, strings.TrimSpace(line[len("publish "):]))
		case strings.HasPrefix(line, "fetch "):
			runFetch(d, strings.TrimSpace(line[len("fetch "):]))
		case strings.HasPrefix(line, "register "):
			runRegister(d, id, strings.TrimSpace(line[len("register "):]))
		case strings.HasPrefix(line, "resolve "):
			runResolve(d, strings.TrimSpace(line[len("resolve "):]))
		case strings.HasPrefix(line, "bootstrap "):
			addr := strings.TrimSpace(line[len("bootstrap "):])
			if err := d.Bootstrap(addr); err != nil {
				fmt.Printf("bootstrap failed: %v\n", err)
			} else {
				fmt.Printf("bootstrapped via %s; %d peer(s) in DHT\n",
					addr, d.RoutingTable().Size())
			}
		default:
			p.Broadcast(peer.Message{Type: "chat", Payload: line})
		}
	}
}

func showRoutingTable(d *dht.DHT) {
	contacts := d.RoutingTable().All()
	if len(contacts) == 0 {
		fmt.Println("(routing table empty - bootstrap to a peer first)")
		return
	}
	fmt.Printf("%d contact(s) in routing table:\n", len(contacts))
	for _, c := range contacts {
		fmt.Printf("  %s  %s\n", c.ID, c.Address)
	}
}

func runFind(d *dht.DHT, idHex string) {
	target, err := dht.IDFromHex(idHex)
	if err != nil {
		fmt.Printf("not a valid 64-char hex id: %v\n", err)
		return
	}
	results := d.Lookup(target)
	if len(results) == 0 {
		fmt.Println("no peers found")
		return
	}
	fmt.Printf("%d peer(s) closest to %s:\n", len(results), target.String())
	for _, c := range results {
		fmt.Printf("  %s  %s\n", c.ID, c.Address)
	}
}

func runPut(d *dht.DHT, text string) {
	if text == "" {
		fmt.Println("usage: put <text>")
		return
	}
	value := []byte(text)
	key := dht.ContentAddress(value)
	stores, err := d.Store(key, value)
	if err != nil {
		fmt.Printf("store failed: %v\n", err)
		return
	}
	fmt.Printf("stored %d bytes; key = %s (replicated to %d peer(s))\n",
		len(value), key.Hex(), stores)
}

func runGet(d *dht.DHT, keyHex string) {
	key, err := dht.IDFromHex(keyHex)
	if err != nil {
		fmt.Printf("not a valid 64-char hex key: %v\n", err)
		return
	}
	value, err := d.Get(key)
	if err != nil {
		fmt.Printf("get failed: %v\n", err)
		return
	}
	fmt.Printf("got %d bytes: %s\n", len(value), string(value))
}

func runPublish(d *dht.DHT, dir string) {
	if dir == "" {
		fmt.Println("usage: publish <directory>")
		return
	}
	rootKey, manifest, err := files.PublishDir(d, dir)
	if err != nil {
		fmt.Printf("publish failed: %v\n", err)
		return
	}
	fmt.Printf("published %d file(s) from %s\n", len(manifest.Entries), dir)
	fmt.Printf("root key: %s\n", rootKey.Hex())
	fmt.Println("share the root key with anyone you want to fetch the directory.")
}

func runFetch(d *dht.DHT, args string) {
	parts := strings.Fields(args)
	if len(parts) != 2 {
		fmt.Println("usage: fetch <root-key> <dest-directory>")
		return
	}
	rootKey, err := dht.IDFromHex(parts[0])
	if err != nil {
		fmt.Printf("not a valid 64-char hex key: %v\n", err)
		return
	}
	dest := parts[1]
	manifest, err := files.FetchDir(d, rootKey, dest)
	if err != nil {
		fmt.Printf("fetch failed: %v\n", err)
		return
	}
	fmt.Printf("fetched %d file(s) into %s\n", len(manifest.Entries), dest)
}

func runRegister(d *dht.DHT, id *crypto.Identity, args string) {
	parts := strings.Fields(args)
	if len(parts) != 2 {
		fmt.Println("usage: register <name> <root-key>     (e.g. register panmox.alt 9c1f...)")
		return
	}
	rootKey, err := dht.IDFromHex(parts[1])
	if err != nil {
		fmt.Printf("not a valid 64-char hex key: %v\n", err)
		return
	}

	// Use a timestamp-based version so a republish is monotonically newer
	// than the previous one without us needing to track state.
	version := time.Now().UnixNano()

	rec, err := name.Publish(d, id, parts[0], rootKey, version)
	if err != nil {
		fmt.Printf("register failed: %v\n", err)
		return
	}
	fmt.Printf("registered %s -> %s (version %d)\n", rec.Name, rec.Root, rec.Version)
}

func runResolve(d *dht.DHT, n string) {
	if n == "" {
		fmt.Println("usage: resolve <name>     (e.g. resolve panmox.alt)")
		return
	}
	rec, err := name.Resolve(d, n)
	if err != nil {
		fmt.Printf("resolve failed: %v\n", err)
		return
	}
	fmt.Printf("name:    %s\n", rec.Name)
	fmt.Printf("owner:   %s\n", rec.PublicKey)
	fmt.Printf("root:    %s\n", rec.Root)
	fmt.Printf("version: %d (signed at unix=%d)\n", rec.Version, rec.Timestamp)
}

// showHelp prints the interactive command reference.
func showHelp() {
	fmt.Println("commands:")
	fmt.Println("  peers                show connected peers (with address + ID)")
	fmt.Println("  dht                  show routing table contents")
	fmt.Println("  relays               show our active relay registrations")
	fmt.Println("  stats                show node-wide counters")
	fmt.Println("  ping                 ping every connected peer")
	fmt.Println("  find <id>            DHT lookup of a peer ID")
	fmt.Println("  put <text>           store text in the DHT")
	fmt.Println("  get <key>            retrieve a value from the DHT")
	fmt.Println("  publish <dir>        publish a directory; prints root key")
	fmt.Println("  fetch <key> <dest>   fetch a published directory")
	fmt.Println("  register <name> <key>  publish a name -> root mapping")
	fmt.Println("  resolve <name>       look up a name in the DHT")
	fmt.Println("  bootstrap <addr>     join via an existing peer")
	fmt.Println("  help                 show this list")
	fmt.Println("  quit                 exit")
	fmt.Println("  <anything else>      broadcast as a chat message")
}

// showPeers prints a peers table including dedup info.
func showPeers(p *peer.Peer) {
	conns := p.PeerCountByAddr()
	if len(conns) == 0 {
		fmt.Println("(no peers connected)")
		return
	}
	fmt.Printf("%d connection alias(es), %d unique peer(s):\n",
		len(conns), p.UniqueConnCount())
	for addr, id := range conns {
		short := id
		if len(short) > 16 {
			short = short[:16]
		}
		fmt.Printf("  %-50s -> %s\n", addr, short)
	}
}

// showRelays prints our active relay registrations.
func showRelays(p *peer.Peer) {
	relays := p.RelayAddresses
	if len(relays) == 0 {
		fmt.Println("(no relay registrations)")
		return
	}
	fmt.Printf("%d relay registration(s):\n", len(relays))
	for _, r := range relays {
		fmt.Printf("  %s  (dial me at relay://%s/%s)\n",
			r, r, p.Identity.ID())
	}
}

// showStats prints node-wide counters in a quick overview.
func showStats(p *peer.Peer, d *dht.DHT) {
	fmt.Printf("identity:           %s\n", p.Identity.ID())
	fmt.Printf("listen:             %s\n", p.LocalAddr())
	if p.IsPublic() {
		fmt.Println("public:             yes (advertising direct address first)")
	} else {
		fmt.Println("public:             no  (NAT-ed; advertising relays only)")
	}
	advertised := p.AdvertisedAddresses()
	fmt.Printf("advertising %d addr(s):\n", len(advertised))
	for _, a := range advertised {
		fmt.Printf("  %s\n", a)
	}
	fmt.Printf("connections:        %d unique (%d aliases)\n",
		p.UniqueConnCount(), p.PeerCount())
	fmt.Printf("routing table:      %d contact(s)\n", d.RoutingTable().Size())
	fmt.Printf("local store:        %d entries, %d bytes",
		d.LocalStoreSize(), d.LocalStoreBytes())
	if budget := d.LocalStoreBudget(); budget > 0 {
		fmt.Printf(" / %d bytes (%.1f%% full)",
			budget, 100*float64(d.LocalStoreBytes())/float64(budget))
	}
	fmt.Println()
}

// configureLogging installs the default slog handler based on the
// requested level + format. Called once at startup before any other
// code that might log.
//
// Format "text" is human-friendly tab-aligned output for an operator
// watching the daemon. Format "json" emits one JSON object per line,
// which is what the AltNet desktop app will ingest to display
// node activity in its UI.
func configureLogging(level, format string) {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lv}
	var handler slog.Handler
	switch strings.ToLower(format) {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, opts)
	default:
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
}

// splitAndTrim splits s on commas and returns the non-empty trimmed pieces.
// Used to parse comma-separated bootstrap addresses from the -bootstrap flag.
func splitAndTrim(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
