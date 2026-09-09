package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/gateway"
	"github.com/themayursinha/agent-identity-plane/internal/scenario"
	"github.com/themayursinha/agent-identity-plane/internal/sts"
	"github.com/themayursinha/agent-identity-plane/internal/token"
	"github.com/themayursinha/agent-identity-plane/internal/verify"
	"github.com/themayursinha/agent-identity-plane/internal/visoradapter"
	"github.com/themayursinha/agent-identity-plane/internal/visorsession"
)

func cmdDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	strict := fs.Bool("strict", false, "exit non-zero if any expected result fails")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "aip-demo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	log, err := audit.NewLogger(filepath.Join(dir, "sts.jsonl"))
	if err != nil {
		return err
	}
	defer log.Close()

	w, err := scenario.NewWorld(time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC), log)
	if err != nil {
		return err
	}

	var failures int
	report := func(ok bool, line string) {
		fmt.Println(line)
		if !ok {
			failures++
		}
	}

	oncallTok, gwTok, err := w.HappyPath()
	if err != nil {
		report(false, "scenario: allow FAIL "+err.Error())
	} else {
		chain, err := w.Verifier.Verify(gwTok, scenario.Gateway)
		if err != nil {
			report(false, "scenario: allow FAIL verify "+err.Error())
		} else {
			m := visoradapter.FromChain(chain, visoradapter.Options{ShortName: true})
			report(true, fmt.Sprintf("scenario: allow txn=%s hops=%s visor_client_id=%s visor_session_id=%s",
				chain.Txn, strings.Join(chain.Hops, ">"), m.ClientID, m.SessionID))
			if err := verify.RequirePrincipal(chain, scenario.User); err != nil {
				report(false, "scenario: principal FAIL")
			}
			_ = oncallTok
		}
	}

	user, _ := w.UserToken()

	res := w.Exchange("spiffe://example.test/agent/rogue", scenario.WLOncall, user, scenario.Invest, "")
	report(res.ReasonCode == sts.ReasonAgentNotRegistered,
		fmt.Sprintf("attack: unregistered_agent deny reason=%s", res.ReasonCode))

	res = w.Exchange(scenario.Oncall, scenario.WLInvest, user, scenario.Invest, "")
	report(res.ReasonCode == sts.ReasonAgentNotAuthorizedOnWL,
		fmt.Sprintf("attack: wrong_workload deny reason=%s", res.ReasonCode))

	if gwTok != "" {
		_, err := w.Verifier.Verify(gwTok, "https://evil.example")
		report(err != nil, fmt.Sprintf("attack: replay_wrong_audience deny err=%v", err))
	}

	res = w.Exchange(scenario.Oncall, scenario.WLOncall, user, scenario.Invest, "mcp:github:pr secret:exfil")
	report(res.ReasonCode == sts.ReasonScopeWidening,
		fmt.Sprintf("attack: scope_widening deny reason=%s", res.ReasonCode))

	res = w.Exchange(scenario.Oncall, scenario.WLOncall, user, scenario.Gateway, "")
	report(res.ReasonCode == sts.ReasonAudienceNotAllowed,
		fmt.Sprintf("attack: audience_not_allowed deny reason=%s", res.ReasonCode))

	expired, _ := signExpiredUser(w)
	res = w.Exchange(scenario.Oncall, scenario.WLOncall, expired, scenario.Invest, "")
	report(res.ReasonCode == sts.ReasonExpired,
		fmt.Sprintf("attack: expired_token deny reason=%s", res.ReasonCode))

	if oncallTok != "" {
		_, c, _, _ := token.ParseUnverified(oncallTok)
		c.Act = &token.Actor{Sub: "spiffe://example.test/agent/forged"}
		idp, _ := token.SignerFromKeyFile(w.IdPKey)
		forged, _ := idp.SignClaims(c)
		res = w.Exchange(scenario.Invest, scenario.WLInvest, forged, scenario.Gateway, "mcp:github:pr")
		report(res.ReasonCode != sts.ReasonOK,
			fmt.Sprintf("attack: forged_chain deny reason=%s", res.ReasonCode))
	}

	if gwTok != "" {
		chain, _ := w.Verifier.Verify(gwTok, scenario.Gateway)
		recs, err := audit.TraceTxn(chain.Txn, filepath.Join(dir, "sts.jsonl"))
		if err != nil || len(recs) == 0 {
			report(false, "trace: FAIL")
		} else {
			fmt.Print(audit.FormatTrace(recs))
			report(true, fmt.Sprintf("trace: reconstructed hops=%d", len(recs)))
		}
		gwLog, err := audit.NewLogger(filepath.Join(dir, "gateway.jsonl"))
		if err != nil {
			report(false, "visor-session: mapping FAIL "+err.Error())
		} else {
			defer gwLog.Close()
			cfg := &gateway.Config{
				Bind:         "127.0.0.1:0",
				Audience:     scenario.Gateway,
				Verifier:     w.Verifier,
				Audit:        gwLog,
				IdentityOnly: true,
				ProofReplay:  sts.NewReplayCache(func() time.Time { return w.Now }),
			}
			ts := httptest.NewServer(cfg.Handler())
			defer ts.Close()
			m, err := visorsession.Fetch(context.Background(), visorsession.Request{
				GatewayURL: ts.URL + "/session",
				Token:      gwTok,
				ProofKey:   w.WL[scenario.WLInvest],
				Now:        func() time.Time { return w.Now },
			})
			if err != nil {
				report(false, "visor-session: mapping FAIL "+err.Error())
			} else if err := m.Complete(); err != nil {
				report(false, "visor-session: mapping FAIL "+err.Error())
			} else {
				_, args, err := visorsession.Command("mcp-visor", m, []string{"-policy", "policy.yaml"})
				if err != nil {
					report(false, "visor-session: mapping FAIL "+err.Error())
				} else {
					report(true, fmt.Sprintf("visor-session: mapping client_id=%s session_id=%s argv=%s",
						m.ClientID, m.SessionID, visorsession.FormatArgv("mcp-visor", args)))
				}
				_, _, err = visorsession.Command("mcp-visor", m, []string{"-client-id", "spoofed"})
				report(errors.Is(err, visorsession.ErrIdentityArgs),
					fmt.Sprintf("visor-session: typed_client_id deny err=%v", err))
			}
		}
	}

	if *strict && failures > 0 {
		return fmt.Errorf("%d demo checks failed", failures)
	}
	return nil
}

func signExpiredUser(w *scenario.World) (string, error) {
	s, err := token.SignerFromKeyFile(w.IdPKey)
	if err != nil {
		return "", err
	}
	return s.SignClaims(token.Claims{
		Iss: scenario.IdPIssuer,
		Sub: scenario.User,
		Aud: token.Audience{scenario.Oncall},
		Exp: w.Now.Add(-time.Hour).Unix(),
		Iat: w.Now.Add(-2 * time.Hour).Unix(),
	})
}
