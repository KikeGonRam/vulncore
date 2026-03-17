package webhooks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type VulnSummary struct {
	ScanID   string
	Target   string
	Critical int
	High     int
	Medium   int
	Low      int
	Total    int
	ScanType string
}

// Send envía una notificación webhook si hay vulnerabilidades
// con severidad >= VULNCORE_WEBHOOK_MIN_SEVERITY.
func Send(summary VulnSummary) {
	url := os.Getenv("VULNCORE_WEBHOOK_URL")
	if url == "" {
		return
	}

	minSev := os.Getenv("VULNCORE_WEBHOOK_MIN_SEVERITY")
	if minSev == "" {
		minSev = "CRITICAL"
	}

	shouldSend := false
	switch strings.ToUpper(minSev) {
	case "LOW":
		shouldSend = summary.Total > 0
	case "MEDIUM":
		shouldSend = summary.Critical+summary.High+summary.Medium > 0
	case "HIGH":
		shouldSend = summary.Critical+summary.High > 0
	case "CRITICAL":
		shouldSend = summary.Critical > 0
	}

	if !shouldSend {
		return
	}

	var payload map[string]interface{}
	text := buildMessage(summary)

	if strings.Contains(url, "discord.com") {
		payload = map[string]interface{}{"content": text}
	} else {
		// Slack / generic webhook
		payload = map[string]interface{}{
			"text": text,
			"blocks": []map[string]interface{}{
				{"type": "section", "text": map[string]string{"type": "mrkdwn", "text": text}},
			},
		}
	}

	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[webhook] send error: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("[webhook] sent — status %d", resp.StatusCode)
}

func buildMessage(s VulnSummary) string {
	return fmt.Sprintf(
		"🔴 *VulnCore Alert* — Scan completed on `%s`\n"+
			"Scan type: `%s` | Scan ID: `%s`\n\n"+
			"*Vulnerabilities found:*\n"+
			"• 🔴 Critical: %d\n"+
			"• 🟠 High: %d\n"+
			"• 🟡 Medium: %d\n"+
			"• 🟢 Low: %d\n"+
			"*Total: %d*",
		s.Target, s.ScanType, s.ScanID[:8],
		s.Critical, s.High, s.Medium, s.Low, s.Total,
	)
}