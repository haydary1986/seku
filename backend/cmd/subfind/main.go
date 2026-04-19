package main

import (
	"fmt"
	"seku/internal/scanner"
)

func main() {
	url := "https://uoturath.edu.iq"
	s := scanner.NewSubdomainScanner()
	results := s.Scan(url)

	for _, r := range results {
		if r.CheckName == "Common Subdomain Enumeration" {
			fmt.Println(r.Details)
			return
		}
	}
}
