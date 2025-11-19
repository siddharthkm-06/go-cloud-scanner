package main

import (
	"encoding/json" // New package for JSON handling
	"fmt"
	"os" // New package for file I/O
)

// Asset represents a generic cloud resource we want to scan.
type Asset struct {
	ID              string
	Type            string // e.g., "VM_INSTANCE", "STORAGE_BUCKET"
	Name            string
	IsPublic        bool
	Tags            []string
	ComplianceScore int
	Violations      []Violation // NEW: List of specific issues found
}

// generateMockAssets simulates data returned from a cloud asset inventory API.
func generateMockAssets() []Asset {
	return []Asset{
		{
			ID:              "gcp-001",
			Type:            "STORAGE_BUCKET",
			Name:            "mercad-prod-user-photos",
			IsPublic:        true, // CRITICAL: Publicly exposed bucket
			Tags:            []string{"production", "user_data"},
			ComplianceScore: 0,
		},
		{
			ID:              "gcp-002",
			Type:            "VM_INSTANCE",
			Name:            "mercad-dev-worker-01",
			IsPublic:        false,
			Tags:            []string{"development", "no_pii"},
			ComplianceScore: 0,
		},
		{
			ID:              "gcp-003",
			Type:            "STORAGE_BUCKET",
			Name:            "mercad-logs-archive",
			IsPublic:        false,
			Tags:            []string{"logs", "archived"},
			ComplianceScore: 0,
		},
	}
}

// checkCompliance runs security rules against a single asset.
func checkCompliance(a *Asset) {
	score := 100 // Start with a perfect score

	// Rule 1: CRITICAL - Storage Buckets must NOT be public
	if a.Type == "STORAGE_BUCKET" && a.IsPublic {
		score -= 50
		a.Violations = append(a.Violations, Violation{
			RuleID:      "SEC_R01",
			Description: "Publicly exposed storage bucket.",
			Severity:    "CRITICAL",
		})
	}

	// Rule 2: HIGH - VM Instances must have 'production' tag if they are prod-related
	isProd := false
	for _, tag := range a.Tags {
		if tag == "production" {
			isProd = true
		}
	}
	if a.Type == "VM_INSTANCE" && !isProd { // Assuming all VMs should be tagged for this rule
		score -= 30
		a.Violations = append(a.Violations, Violation{
			RuleID:      "TAG_R02",
			Description: "Missing essential 'production' tag for classification.",
			Severity:    "HIGH",
		})
	}

	a.ComplianceScore = score
}

// Violation holds details about a specific compliance failure.
type Violation struct {
	RuleID      string
	Description string
	Severity    string
}

// generateReport serializes the violations to a JSON file.
func generateReport(assets []Asset) {
	// Find only the failed assets
	var failedAssets []Asset
	for _, a := range assets {
		if a.ComplianceScore < 100 { // We report anything that isn't 100% compliant
			failedAssets = append(failedAssets, a)
		}
	}

	if len(failedAssets) == 0 {
		fmt.Println("No compliance failures found. Clean run!")
		return
	}

	// Marshal the struct into a JSON byte slice
	jsonData, err := json.MarshalIndent(failedAssets, "", "  ")
	if err != nil {
		fmt.Printf("Error marshalling JSON: %v\n", err)
		return
	}

	// Write the JSON data to a file
	err = os.WriteFile("compliance_report.json", jsonData, 0644)
	if err != nil {
		fmt.Printf("Error writing file: %v\n", err)
		return
	}

	fmt.Printf("✅ Detailed report for %d failed assets written to: compliance_report.json\n", len(failedAssets))
}

func main() {
	fmt.Println("Welcome to the Automated Cloud Asset & Compliance Scanner!")
	fmt.Println("Initiating scan for Mercari compliance...")
	fmt.Println("-------------------------------------------------------")

	assets := generateMockAssets()

	fmt.Printf("Scanning %d assets...\n\n", len(assets))

	for i := range assets {
		checkCompliance(&assets[i])
	}

	fmt.Println("\n-------------------------------------------------------")
	fmt.Println("Scan Complete. Summary:")

	// Print final summary report
	for _, a := range assets {
		status := "PASS"
		if a.ComplianceScore < 100 {
			status = "FAIL"
		}
		fmt.Printf("Asset ID: %s | Score: %d | Violations: %d | Status: %s\n",
			a.ID, a.ComplianceScore, len(a.Violations), status)
	}

	fmt.Println("-------------------------------------------------------")

	// Generate the professional JSON report
	generateReport(assets)
}
