package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	keychainService = "Claude Code-credentials"
	usageEndpoint   = "https://api.anthropic.com/api/oauth/usage"
)

// Keychain credentials
type OAuthToken struct {
	AccessToken string `json:"accessToken"`
}

type Credentials struct {
	ClaudeAiOauth OAuthToken `json:"claudeAiOauth"`
}

// API response
type UsageLimit struct {
	Utilization float64 `json:"utilization"`
	ResetsAt    *string `json:"resets_at"`
}

type UsageResponse struct {
	FiveHour *UsageLimit `json:"five_hour"`
	SevenDay *UsageLimit `json:"seven_day"`
}

// Claude Code stdin input
type ContextWindow struct {
	TotalInputTokens     int     `json:"total_input_tokens"`
	TotalOutputTokens    int     `json:"total_output_tokens"`
	ContextWindowSize    int     `json:"context_window_size"`
	UsedPercentage       float64 `json:"used_percentage"`
	RemainingPercentage  float64 `json:"remaining_percentage"`
	CacheReadTokens      int     `json:"cache_read_input_tokens"`
	CacheCreationTokens  int     `json:"cache_creation_input_tokens"`
}

type Model struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
}

type Workspace struct {
	CurrentDir string `json:"current_dir"`
	ProjectDir string `json:"project_dir"`
}

type ClaudeInput struct {
	SessionID      string        `json:"session_id"`
	TranscriptPath string        `json:"transcript_path"`
	Cwd            string        `json:"cwd"`
	Model          Model         `json:"model"`
	Workspace      Workspace     `json:"workspace"`
	ContextWindow  ContextWindow `json:"context_window"`
}

// Session index
type SessionEntry struct {
	SessionID   string `json:"sessionId"`
	CustomTitle string `json:"customTitle"`
	FirstPrompt string `json:"firstPrompt"`
}

// Transcript message for cache stats
type MessageUsage struct {
	CacheReadTokens     int `json:"cache_read_input_tokens"`
	CacheCreationTokens int `json:"cache_creation_input_tokens"`
	InputTokens         int `json:"input_tokens"`
}

type TranscriptMessage struct {
	Message struct {
		Usage MessageUsage `json:"usage"`
	} `json:"message"`
	Type string `json:"type"`
}

type SessionsIndex struct {
	Entries []SessionEntry `json:"entries"`
}

// ANSI colors
const (
	reset   = "\033[0m"
	dim     = "\033[2m"
	red     = "\033[31m"
	yellow  = "\033[33m"
	green   = "\033[32m"
	cyan    = "\033[36m"
	blue    = "\033[34m"
	magenta = "\033[35m"
)

func getColor(pct float64) string {
	switch {
	case pct >= 85:
		return red
	case pct >= 70:
		return yellow
	default:
		return green
	}
}

func getBar(pct float64, width int) string {
	filled := int(pct / (100.0 / float64(width)))
	if filled > width {
		filled = width
	}
	empty := width - filled

	bar := strings.Repeat("▓", filled) + strings.Repeat("░", empty)
	return bar
}

func formatTimeRemaining(resetsAt *string) string {
	if resetsAt == nil {
		return ""
	}

	resetTime, err := time.Parse(time.RFC3339, *resetsAt)
	if err != nil {
		return ""
	}

	remaining := time.Until(resetTime)
	if remaining < 0 {
		return "now"
	}

	hours := int(remaining.Hours())
	mins := int(remaining.Minutes()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh%dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}

func getCredentials() (string, error) {
	cmd := exec.Command("security", "find-generic-password", "-s", keychainService, "-w")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("keychain error: %w", err)
	}

	var creds Credentials
	if err := json.Unmarshal(output, &creds); err != nil {
		return "", fmt.Errorf("parse error: %w", err)
	}

	return creds.ClaudeAiOauth.AccessToken, nil
}

func fetchUsage(token string) (*UsageResponse, error) {
	req, err := http.NewRequest("GET", usageEndpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var usage UsageResponse
	if err := json.NewDecoder(resp.Body).Decode(&usage); err != nil {
		return nil, err
	}

	return &usage, nil
}

func readStdinInput() *ClaudeInput {
	// Check if there's data on stdin (non-blocking)
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return nil // No piped input
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil || len(data) == 0 {
		return nil
	}

	var input ClaudeInput
	if err := json.Unmarshal(data, &input); err != nil {
		return nil
	}

	return &input
}

func findSessionName(sessionID string) string {
	if sessionID == "" {
		return ""
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	projectsDir := filepath.Join(homeDir, ".claude", "projects")
	entries, err := os.ReadDir(projectsDir)
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		indexPath := filepath.Join(projectsDir, entry.Name(), "sessions-index.json")
		data, err := os.ReadFile(indexPath)
		if err != nil {
			continue
		}

		var index SessionsIndex
		if err := json.Unmarshal(data, &index); err != nil {
			continue
		}

		for _, session := range index.Entries {
			if session.SessionID == sessionID {
				if session.CustomTitle != "" {
					return session.CustomTitle
				}
				// Truncate first prompt if too long
				if len(session.FirstPrompt) > 20 {
					return session.FirstPrompt[:20] + "…"
				}
				return session.FirstPrompt
			}
		}
	}

	return ""
}

func getGitBranch(dir string) string {
	if dir == "" {
		return ""
	}

	cmd := exec.Command("git", "-C", dir, "branch", "--show-current")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(output))
}

func shortenPath(cwd, projectDir string) string {
	if cwd == "" {
		return ""
	}

	// If we have a project dir, show path relative to it
	if projectDir != "" && strings.HasPrefix(cwd, projectDir) {
		rel := strings.TrimPrefix(cwd, projectDir)
		rel = strings.TrimPrefix(rel, "/")
		if rel == "" {
			return filepath.Base(projectDir)
		}
		return filepath.Base(projectDir) + "/" + rel
	}

	// Otherwise just show the last component
	return filepath.Base(cwd)
}

func getCacheStats(transcriptPath string) (cacheRead, totalInput int) {
	if transcriptPath == "" {
		return 0, 0
	}

	data, err := os.ReadFile(transcriptPath)
	if err != nil {
		return 0, 0
	}

	lines := strings.Split(string(data), "\n")
	// Read from end to find latest assistant message with usage
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		var msg TranscriptMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}

		usage := msg.Message.Usage
		totalInput := usage.InputTokens + usage.CacheReadTokens + usage.CacheCreationTokens
		if msg.Type == "assistant" && totalInput > 0 {
			return usage.CacheReadTokens, totalInput
		}
	}

	return 0, 0
}

func main() {
	var parts []string

	// Read Claude Code input from stdin
	input := readStdinInput()

	// Directory and git branch
	if input != nil && input.Cwd != "" {
		dir := shortenPath(input.Cwd, input.Workspace.ProjectDir)
		branch := getGitBranch(input.Cwd)

		if branch != "" {
			parts = append(parts, fmt.Sprintf("%s%s%s %s%s%s", dim, dir, reset, magenta, branch, reset))
		} else {
			parts = append(parts, fmt.Sprintf("%s%s%s", dim, dir, reset))
		}
	}

	// Session info
	if input != nil && input.SessionID != "" {
		sessionName := findSessionName(input.SessionID)
		if sessionName != "" {
			parts = append(parts, fmt.Sprintf("%s%s%s", cyan, sessionName, reset))
		} else {
			// Show truncated session ID
			shortID := input.SessionID[:8]
			parts = append(parts, fmt.Sprintf("%s%s%s", dim, shortID, reset))
		}
	}

	// Model info
	if input != nil && input.Model.DisplayName != "" {
		parts = append(parts, fmt.Sprintf("%s%s%s", blue, input.Model.DisplayName, reset))
	}

	// Context window
	if input != nil && input.ContextWindow.ContextWindowSize > 0 {
		pct := input.ContextWindow.UsedPercentage
		color := getColor(pct)
		bar := getBar(pct, 8)
		parts = append(parts, fmt.Sprintf("%sctx %s %.0f%%%s", color, bar, pct, reset))
	}

	// Cache hit rate from transcript
	if input != nil && input.TranscriptPath != "" {
		cacheRead, totalInput := getCacheStats(input.TranscriptPath)
		if totalInput > 0 && cacheRead > 0 {
			cachePct := float64(cacheRead) / float64(totalInput) * 100
			parts = append(parts, fmt.Sprintf("%scache %.0f%%%s", dim, cachePct, reset))
		}
	}

	// Fetch API usage
	token, err := getCredentials()
	if err != nil {
		parts = append(parts, fmt.Sprintf("%s⚠ auth%s", red, reset))
	} else {
		usage, err := fetchUsage(token)
		if err != nil {
			parts = append(parts, fmt.Sprintf("%s⚠ api%s", red, reset))
		} else {
			// 5-hour limit
			if usage.FiveHour != nil {
				pct := usage.FiveHour.Utilization
				color := getColor(pct)
				bar := getBar(pct, 10)
				remaining := formatTimeRemaining(usage.FiveHour.ResetsAt)

				usageStr := fmt.Sprintf("%s5h %s %.0f%%%s", color, bar, pct, reset)
				if remaining != "" {
					usageStr += fmt.Sprintf(" %s(%s)%s", dim, remaining, reset)
				}
				parts = append(parts, usageStr)
			}

			// 7-day limit
			if usage.SevenDay != nil {
				pct := usage.SevenDay.Utilization
				color := getColor(pct)
				parts = append(parts, fmt.Sprintf("%s7d %.0f%%%s", color, pct, reset))
			}
		}
	}

	fmt.Println(strings.Join(parts, " │ "))
}
