package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	prCacheTTL = 90 * time.Second
)

// Rate limits from Claude Code stdin
type RateLimit struct {
	UsedPercentage float64  `json:"used_percentage"`
	ResetsAt       *float64 `json:"resets_at"`
}

type RateLimits struct {
	FiveHour *RateLimit `json:"five_hour"`
	SevenDay *RateLimit `json:"seven_day"`
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
	RateLimits     *RateLimits   `json:"rate_limits"`
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
	orange  = "\033[38;5;208m"
)

func clearToEOL(s string) string {
	return s + "\033[0K"
}

func getColor(pct float64) string {
	switch {
	case pct >= 85:
		return red
	case pct >= 60:
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

func formatTimeRemaining(resetsAt *float64) string {
	if resetsAt == nil {
		return ""
	}

	resetTime := time.Unix(int64(*resetsAt), 0)
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

// CustomTitleEntry represents a rename event in the transcript
type CustomTitleEntry struct {
	Type        string `json:"type"`
	CustomTitle string `json:"customTitle"`
	SessionID   string `json:"sessionId"`
}

func findSessionName(sessionID, transcriptPath string) string {
	if sessionID == "" {
		return ""
	}

	// First: check transcript file for custom-title entries (most up-to-date)
	// Read the LAST one since there can be multiple renames
	if transcriptPath != "" {
		if data, err := os.ReadFile(transcriptPath); err == nil {
			lines := strings.Split(string(data), "\n")
			var latestTitle string
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var entry CustomTitleEntry
				if err := json.Unmarshal([]byte(line), &entry); err != nil {
					continue
				}
				if entry.Type == "custom-title" && entry.SessionID == sessionID && entry.CustomTitle != "" {
					latestTitle = entry.CustomTitle
				}
			}
			if latestTitle != "" {
				return latestTitle
			}
		}
	}

	// Fallback: check sessions-index.json (may be slightly delayed)
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
				// Only return custom title, not firstPrompt
				// Empty string triggers orange UUID display as rename reminder
				return session.CustomTitle
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

// PR info from `gh pr view`
type PRInfo struct {
	Number int    `json:"number"`
	URL    string `json:"url"`
	State  string `json:"state"`
}

type CachedPR struct {
	PR        *PRInfo `json:"pr"`
	FetchedAt int64   `json:"fetched_at"`
}

type PRCacheFile struct {
	Entries map[string]CachedPR `json:"entries"`
}

func prCachePath() string {
	dir := os.TempDir()
	return filepath.Join(dir, fmt.Sprintf("claude-usage-pr-%d.json", os.Getuid()))
}

func readPRCache(key string) (*PRInfo, bool) {
	data, err := os.ReadFile(prCachePath())
	if err != nil {
		return nil, false
	}

	var cache PRCacheFile
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, false
	}

	entry, ok := cache.Entries[key]
	if !ok {
		return nil, false
	}

	if time.Since(time.Unix(entry.FetchedAt, 0)) > prCacheTTL {
		return nil, false
	}

	return entry.PR, true
}

func writePRCache(key string, pr *PRInfo) {
	cache := PRCacheFile{Entries: map[string]CachedPR{}}
	if data, err := os.ReadFile(prCachePath()); err == nil {
		json.Unmarshal(data, &cache)
		if cache.Entries == nil {
			cache.Entries = map[string]CachedPR{}
		}
	}

	cache.Entries[key] = CachedPR{PR: pr, FetchedAt: time.Now().Unix()}

	data, err := json.Marshal(cache)
	if err != nil {
		return
	}
	os.WriteFile(prCachePath(), data, 0600)
}

// getGitPR looks up the PR associated with branch via `gh`. A nil *PRInfo
// (with ok=true) means "looked up, no PR" and is cached to avoid repeat calls.
func getGitPR(dir, branch string) *PRInfo {
	if dir == "" || branch == "" {
		return nil
	}

	key := dir + "@" + branch
	if pr, ok := readPRCache(key); ok {
		return pr
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "gh", "pr", "view", branch, "--json", "number,url,state")
	cmd.Dir = dir
	output, err := cmd.Output()
	if err != nil {
		writePRCache(key, nil) // cache "no PR" until TTL expires
		return nil
	}

	var pr PRInfo
	if err := json.Unmarshal(output, &pr); err != nil {
		writePRCache(key, nil)
		return nil
	}

	writePRCache(key, &pr)
	return &pr
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
	var line1, line2 []string

	// Read Claude Code input from stdin
	input := readStdinInput()

	// === LINE 1: Location & session info ===

	// Model info (first) - use short ID like "opus-4-6 (1m)"
	if input != nil && input.Model.ID != "" {
		// Strip "claude-" prefix for brevity
		shortModel := strings.TrimPrefix(input.Model.ID, "claude-")
		// Extract context suffix like "[1m]" -> "(1m)"
		if idx := strings.Index(shortModel, "["); idx != -1 {
			suffix := shortModel[idx:]
			shortModel = shortModel[:idx]
			suffix = strings.Replace(suffix, "[", "(", 1)
			suffix = strings.Replace(suffix, "]", ")", 1)
			shortModel += " " + suffix
		}
		line1 = append(line1, fmt.Sprintf("%s%s%s", blue, shortModel, reset))
	}

	// Directory and git branch
	if input != nil && input.Cwd != "" {
		dir := shortenPath(input.Cwd, input.Workspace.ProjectDir)
		branch := getGitBranch(input.Cwd)

		if branch != "" {
			seg := fmt.Sprintf("%s%s%s %s%s%s", dim, dir, reset, magenta, branch, reset)
			if pr := getGitPR(input.Cwd, branch); pr != nil {
				// State-based color: open=green, merged=magenta, closed=red
				prColor := green
				switch strings.ToUpper(pr.State) {
				case "MERGED":
					prColor = magenta
				case "CLOSED":
					prColor = red
				}
				// OSC 8 hyperlink: clickable PR number in supporting terminals
				link := fmt.Sprintf("\033]8;;%s\033\\#%d\033]8;;\033\\", pr.URL, pr.Number)
				seg += fmt.Sprintf(" %s%s%s", prColor, link, reset)
			}
			line1 = append(line1, seg)
		} else {
			line1 = append(line1, fmt.Sprintf("%s%s%s", dim, dir, reset))
		}
	}

	// Session info
	if input != nil && input.SessionID != "" {
		sessionName := findSessionName(input.SessionID, input.TranscriptPath)
		if sessionName != "" {
			line1 = append(line1, fmt.Sprintf("%s%s%s", cyan, sessionName, reset))
		} else {
			// Show full UUID in orange as reminder to rename
			line1 = append(line1, fmt.Sprintf("%s%s%s", orange, input.SessionID, reset))
		}
	}

	// === LINE 2: Usage & metrics ===

	// Context window
	if input != nil && input.ContextWindow.ContextWindowSize > 0 {
		pct := input.ContextWindow.UsedPercentage
		color := getColor(pct)
		bar := getBar(pct, 8)
		line2 = append(line2, fmt.Sprintf("%sctx %s %.0f%%%s", color, bar, pct, reset))
	}

	// Rate limits from stdin
	if input != nil && input.RateLimits != nil {
		// 5-hour limit
		if input.RateLimits.FiveHour != nil {
			pct := input.RateLimits.FiveHour.UsedPercentage
			color := getColor(pct)
			bar := getBar(pct, 10)
			remaining := formatTimeRemaining(input.RateLimits.FiveHour.ResetsAt)

			usageStr := fmt.Sprintf("%s5h %s %.0f%%%s", color, bar, pct, reset)
			if remaining != "" {
				usageStr += fmt.Sprintf(" %s(%s)%s", dim, remaining, reset)
			}
			line2 = append(line2, usageStr)
		}

		// 7-day limit
		if input.RateLimits.SevenDay != nil {
			pct := input.RateLimits.SevenDay.UsedPercentage
			color := getColor(pct)
			line2 = append(line2, fmt.Sprintf("%s7d %.0f%%%s", color, pct, reset))
		}
	}

	// Cache hit rate from transcript
	if input != nil && input.TranscriptPath != "" {
		cacheRead, totalInput := getCacheStats(input.TranscriptPath)
		if totalInput > 0 && cacheRead > 0 {
			cachePct := float64(cacheRead) / float64(totalInput) * 100
			line2 = append(line2, fmt.Sprintf("%scache %.0f%%%s", dim, cachePct, reset))
		}
	}

	// Output both lines, padded to terminal width to prevent
	// Claude Code from overlaying indicators on the right side
	if len(line1) > 0 {
		fmt.Println(clearToEOL(strings.Join(line1, " │ ")))
	}
	if len(line2) > 0 {
		fmt.Println(clearToEOL(strings.Join(line2, " │ ")))
	}
}
