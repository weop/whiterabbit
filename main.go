package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/miekg/dns"
)

const (
	defaultPort = ":5333"
	cacheExpiry = 5 * time.Minute
)

type Server struct {
	db            *badger.DB
	whitelistMode bool
	cache         map[string]cacheEntry
	cacheMutex    sync.RWMutex
	httpClient    *http.Client
}

type cacheEntry struct {
	ip      string
	expires time.Time
}

type DNSResponse struct {
	Status int         `json:"Status"`
	Answer []DNSAnswer `json:"Answer"`
}

type DNSAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

func (s *Server) initDB() error {
	opts := badger.DefaultOptions("whiterabbit.db")
	opts.Logger = nil
	var err error
	s.db, err = badger.Open(opts)
	if err != nil {
		return fmt.Errorf("failed to open badger database: %w", err)
	}

	return s.loadInitialData()
}

func (s *Server) loadInitialData() error {
	if err := s.loadRecordsFromFile("dns_records.txt"); err != nil {
		log.Printf("Warning: failed to load dns_records.txt: %v", err)
	}
	
	if err := s.loadWhitelistFromFile("whitelist.txt"); err != nil {
		log.Printf("Warning: failed to load whitelist.txt: %v", err)
	}
	
	return nil
}

func (s *Server) loadRecordsFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	txn := s.db.NewTransaction(true)
	defer txn.Discard()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		err = txn.Set([]byte("dns:"+fields[0]), []byte(fields[1]))
		if err != nil {
			log.Printf("Failed to insert record %s: %v", fields[0], err)
		}
	}
	if err := txn.Commit(); err != nil {
		return err
	}
	return scanner.Err()
}

func (s *Server) loadWhitelistFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	txn := s.db.NewTransaction(true)
	defer txn.Discard()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		err = txn.Set([]byte("wl:"+line), []byte("1"))
		if err != nil {
			log.Printf("Failed to insert whitelist entry %s: %v", line, err)
		}
	}
	if err := txn.Commit(); err != nil {
		return err
	}
	return scanner.Err()
}

func (s *Server) getDNSRecord(domain string) (string, bool) {
	s.cacheMutex.RLock()
	if entry, exists := s.cache[domain]; exists && time.Now().Before(entry.expires) {
		s.cacheMutex.RUnlock()
		return entry.ip, true
	}
	s.cacheMutex.RUnlock()

	txn := s.db.NewTransaction(false)
	defer txn.Discard()

	item, err := txn.Get([]byte("dns:" + domain))
	if err != nil {
		return "", false
	}

	var ip string
	err = item.Value(func(val []byte) error {
		ip = string(val)
		return nil
	})
	if err != nil {
		return "", false
	}

	s.updateCache(domain, ip)
	return ip, true
}

func (s *Server) addDNSRecord(domain, ip string) error {
	txn := s.db.NewTransaction(true)
	defer txn.Discard()

	err := txn.Set([]byte("dns:"+domain), []byte(ip))
	if err != nil {
		return err
	}

	if err := txn.Commit(); err != nil {
		return err
	}

	s.updateCache(domain, ip)
	return nil
}

func (s *Server) removeDNSRecord(domain string) error {
	txn := s.db.NewTransaction(true)
	defer txn.Discard()

	err := txn.Delete([]byte("dns:" + domain))
	if err != nil {
		return err
	}

	if err := txn.Commit(); err != nil {
		return err
	}

	s.cacheMutex.Lock()
	delete(s.cache, domain)
	s.cacheMutex.Unlock()
	return nil
}

func (s *Server) updateCache(domain, ip string) {
	s.cacheMutex.Lock()
	s.cache[domain] = cacheEntry{
		ip:      ip,
		expires: time.Now().Add(cacheExpiry),
	}
	s.cacheMutex.Unlock()
}

func (s *Server) isWhitelisted(domain string) bool {
	txn := s.db.NewTransaction(false)
	defer txn.Discard()

	_, err := txn.Get([]byte("wl:" + domain))
	if err == nil {
		return true
	}

	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parentDomain := strings.Join(parts[i:], ".")
		_, err := txn.Get([]byte("wl:" + parentDomain))
		if err == nil {
			return true
		}
	}

	return false
}

func (s *Server) addToWhitelist(domain string) error {
	txn := s.db.NewTransaction(true)
	defer txn.Discard()

	err := txn.Set([]byte("wl:"+domain), []byte("1"))
	if err != nil {
		return err
	}

	if err := txn.Commit(); err != nil {
		return err
	}

	return s.appendToWhitelistFile(domain)
}

func (s *Server) appendToWhitelistFile(domain string) error {
	file, err := os.OpenFile("whitelist.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open whitelist.txt: %w", err)
	}
	defer file.Close()

	_, err = file.WriteString(domain + "\n")
	if err != nil {
		return fmt.Errorf("failed to write to whitelist.txt: %w", err)
	}

	return nil
}

func (s *Server) queryExternalDNS(domain string) (string, error) {
	baseURL := "https://dns.google.com/resolve"
	query := url.Values{}
	query.Set("name", domain)

	fullURL := fmt.Sprintf("%s?%s", baseURL, query.Encode())
	resp, err := s.httpClient.Get(fullURL)
	if err != nil {
		return "", fmt.Errorf("failed to query DNS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected HTTP status: %s", resp.Status)
	}

	var dnsResp DNSResponse
	if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
		return "", fmt.Errorf("failed to parse DNS response: %v", err)
	}

	if dnsResp.Status != 0 {
		return "", fmt.Errorf("DNS query failed with status: %d", dnsResp.Status)
	}

	if len(dnsResp.Answer) == 0 {
		return "", fmt.Errorf("no DNS answer found")
	}

	return dnsResp.Answer[0].Data, nil
}

func (s *Server) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	msg.Authoritative = true

	for _, question := range r.Question {
		if question.Qtype != dns.TypeA {
			continue
		}

		domain := strings.ToLower(strings.TrimSuffix(question.Name, "."))
		
		ip, found := s.getDNSRecord(domain)
		if !found {
			isWhitelisted := s.isWhitelisted(domain)
			
			// In whitelist mode, automatically add any requested domain to whitelist
			if s.whitelistMode && !isWhitelisted {
				if err := s.addToWhitelist(domain); err != nil {
					log.Printf("Failed to add %s to whitelist: %v", domain, err)
				} else {
					log.Printf("Auto-whitelisted domain: %s", domain)
					isWhitelisted = true
				}
			}
			
			if isWhitelisted {
				var err error
				ip, err = s.queryExternalDNS(domain)
				if err != nil {
					log.Printf("Failed to query external DNS for %s: %v", domain, err)
					continue
				}
				
				if s.whitelistMode {
					if err := s.addDNSRecord(domain, ip); err != nil {
						log.Printf("Failed to cache DNS record for %s: %v", domain, err)
					}
				} else {
					s.updateCache(domain, ip)
				}
			} else {
				log.Printf("Blocked request for %s", domain)
				continue
			}
		}

		rr, err := dns.NewRR(fmt.Sprintf("%s A %s", question.Name, ip))
		if err != nil {
			log.Printf("Failed to create DNS record for %s: %v", domain, err)
			continue
		}
		msg.Answer = append(msg.Answer, rr)
	}

	w.WriteMsg(&msg)
}

func (s *Server) close() {
	if s.db != nil {
		s.db.Close()
	}
}

func clearCache() error {
	opts := badger.DefaultOptions("whiterabbit.db")
	opts.Logger = nil
	db, err := badger.Open(opts)
	if err != nil {
		return fmt.Errorf("failed to open badger database: %w", err)
	}
	defer db.Close()

	err = db.DropAll()
	if err != nil {
		return fmt.Errorf("failed to clear database: %w", err)
	}

	fmt.Println("Cleared entire cache and database")
	return nil
}

func removeRecord(domain string) error {
	opts := badger.DefaultOptions("whiterabbit.db")
	opts.Logger = nil
	db, err := badger.Open(opts)
	if err != nil {
		return fmt.Errorf("failed to open badger database: %w", err)
	}
	defer db.Close()

	txn := db.NewTransaction(true)
	defer txn.Discard()

	_, err = txn.Get([]byte("dns:" + domain))
	if err == badger.ErrKeyNotFound {
		return fmt.Errorf("record not found: %s", domain)
	}
	if err != nil {
		return fmt.Errorf("failed to check record: %w", err)
	}

	err = txn.Delete([]byte("dns:" + domain))
	if err != nil {
		return fmt.Errorf("failed to remove record: %w", err)
	}

	if err := txn.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	fmt.Printf("Removed DNS record for %s\n", domain)
	return nil
}

func main() {
	var (
		listen        = flag.Bool("listen", false, "Start DNS server in listen mode")
		whitelistMode = flag.Bool("whitelist", false, "Enable auto-adding DNS entries for whitelisted domains")
		rmDomain      = flag.String("rm", "", "Remove DNS record for specified domain")
		reset         = flag.Bool("reset", false, "Clear entire cache and database")
		port          = flag.String("port", defaultPort, "Port to listen on")
	)
	flag.Parse()

	if *reset {
		if err := clearCache(); err != nil {
			log.Fatalf("Error: %v", err)
		}
		return
	}

	if *rmDomain != "" {
		if err := removeRecord(*rmDomain); err != nil {
			log.Fatalf("Error: %v", err)
		}
		return
	}

	if !*listen {
		flag.Usage()
		fmt.Println("\nUse --listen to start the DNS server")
		return
	}

	server := &Server{
		whitelistMode: *whitelistMode,
		cache:         make(map[string]cacheEntry),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
			},
		},
	}
	defer server.close()

	if err := server.initDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	dns.HandleFunc(".", server.handleDNSRequest)

	dnsServer := &dns.Server{
		Addr: *port,
		Net:  "udp",
		UDPSize: 65535,
		ReusePort: runtime.GOOS == "linux",
	}

	mode := "normal"
	if *whitelistMode {
		mode = "whitelist auto-add"
	}
	
	log.Printf("WhiteRabbit DNS server starting on %s (mode: %s)", *port, mode)
	if err := dnsServer.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}