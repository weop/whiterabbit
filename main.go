package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/miekg/dns"
)

const (
	port = ":5353"
)

var dnsRecords = make(map[string]string)

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

func loadRecords(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return fmt.Errorf("invalid record: %s", line)
		}
		dnsRecords[fields[0]] = fields[1]
	}

	return scanner.Err()
}

func checkWhitelist(domain string) bool {
	file, err := os.Open("whitelist.txt")
	if err != nil {
		log.Printf("Failed to open whitelist file: %v", err)
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == domain {
			return true
		}
		//check if domain is a subdomain of a whitelisted domain
		if strings.HasSuffix(domain, line) {
			return true
		}
	}
	return false
}

func askExternalDNS(domain string) (string, error) {
	baseURL := "https://dns.google.com/resolve"
	query := url.Values{}
	query.Set("name", domain)

	fullURL := fmt.Sprintf("%s?%s", baseURL, query.Encode())
	resp, err := http.Get(fullURL)
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

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	msg.Authoritative = true

	for _, question := range r.Question {
		domain := strings.ToLower(question.Name)

		ip, found := dnsRecords[domain]
		if !found {
			if checkWhitelist(domain) {
				var err error
				ip, err = askExternalDNS(domain)
				if err != nil {
					log.Printf("Failed to query external DNS: %v", err)
					continue
				}
				dnsRecords[domain] = ip
			} else {
				writeDeniedLog(domain)
				continue
			}
		}

		rr, err := dns.NewRR(fmt.Sprintf("%s A %s", domain, ip))
		if err != nil {
			log.Printf("Failed to create DNS record: %v", err)
			continue
		}
		msg.Answer = append(msg.Answer, rr)
	}

	w.WriteMsg(&msg)
}

func writeDeniedLog(domain string) {
	file, err := os.OpenFile("denied.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open denied.log: %v", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == domain {
			return
		}
	}

	if _, err := file.WriteString(domain + "\n"); err != nil {
		log.Printf("Failed to write to denied.log: %v", err)
	}
}

func main() {
	err := loadRecords("dns_records.txt")
	if err != nil {
		log.Fatalf("Failed to load DNS records: %v", err)
	}

	dns.HandleFunc(".", handleRequest)

	server := &dns.Server{Addr: port, Net: "udp"}
	log.Printf("DNS resolver server listening on %s", port)
	err = server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
