package main

import (
	"fmt"
	"os"

	"seku/internal/scanner"
)

func main() {
	url := "https://uoturath.edu.iq"
	if len(os.Args) > 1 {
		url = os.Args[1]
	}

	engine := scanner.NewEngineForPolicy("deep")
	scanners := engine.GetScanners()

	for _, s := range scanners {
		checks := s.Scan(url)
		for _, c := range checks {
			if c.Status == "fail" {
				fmt.Printf("FAIL [%s] %s = %.0f (weight %.1f)\n  Details: %s\n\n",
					c.Category, c.CheckName, c.Score, c.Weight, c.Details)
			}
		}
	}
}
