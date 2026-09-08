package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Record is a reconstructed hop from STS and optional visor JSONL.
type Record struct {
	Source     string   `json:"source"`
	Timestamp  string   `json:"timestamp"`
	EventType  string   `json:"event_type"`
	ReasonCode string   `json:"reason_code,omitempty"`
	AgentID    string   `json:"agent_id,omitempty"`
	Principal  string   `json:"principal,omitempty"`
	Audience   string   `json:"audience,omitempty"`
	Server     string   `json:"server,omitempty"`
	Tool       string   `json:"tool,omitempty"`
	Decision   string   `json:"policy_decision,omitempty"`
	Hops       []string `json:"hops,omitempty"`
	SessionID  string   `json:"session_id,omitempty"`
	Txn        string   `json:"txn,omitempty"`
}

// TraceTxn scans JSONL files for records whose txn or session_id matches.
func TraceTxn(txn string, paths ...string) ([]Record, error) {
	var out []Record
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		recs, err := scanFile(p, txn)
		if err != nil {
			return nil, err
		}
		out = append(out, recs...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Timestamp < out[j].Timestamp
	})
	return out, nil
}

func scanFile(path, txn string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var recs []Record
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var generic map[string]any
		if err := json.Unmarshal(line, &generic); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		gotTxn, _ := generic["txn"].(string)
		session, _ := generic["session_id"].(string)
		if gotTxn != txn && session != txn {
			continue
		}
		r := Record{Source: path, Txn: gotTxn, SessionID: session}
		r.Timestamp, _ = generic["timestamp"].(string)
		r.EventType, _ = generic["event_type"].(string)
		r.ReasonCode, _ = generic["reason_code"].(string)
		r.AgentID, _ = generic["agent_id"].(string)
		r.Principal, _ = generic["principal"].(string)
		r.Audience, _ = generic["audience"].(string)
		r.Server, _ = generic["server"].(string)
		r.Tool, _ = generic["tool"].(string)
		r.Decision, _ = generic["policy_decision"].(string)
		if hops, ok := generic["hops"].([]any); ok {
			for _, h := range hops {
				if s, ok := h.(string); ok {
					r.Hops = append(r.Hops, s)
				}
			}
		}
		recs = append(recs, r)
	}
	return recs, sc.Err()
}

func FormatTrace(recs []Record) string {
	var b strings.Builder
	for i, r := range recs {
		fmt.Fprintf(&b, "%d. [%s] %s", i+1, r.EventType, r.Timestamp)
		if r.ReasonCode != "" {
			fmt.Fprintf(&b, " reason=%s", r.ReasonCode)
		}
		if r.AgentID != "" {
			fmt.Fprintf(&b, " agent=%s", r.AgentID)
		}
		if r.Principal != "" {
			fmt.Fprintf(&b, " principal=%s", r.Principal)
		}
		if r.Audience != "" {
			fmt.Fprintf(&b, " aud=%s", r.Audience)
		}
		if r.Tool != "" {
			fmt.Fprintf(&b, " tool=%s", r.Tool)
		}
		if r.Decision != "" {
			fmt.Fprintf(&b, " decision=%s", r.Decision)
		}
		if len(r.Hops) > 0 {
			fmt.Fprintf(&b, " hops=%s", strings.Join(r.Hops, " > "))
		}
		b.WriteByte('\n')
	}
	return b.String()
}
