package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/themayursinha/agent-identity-plane/internal/audit"
)

func cmdTrace(args []string) error {
	fs := flag.NewFlagSet("trace", flag.ContinueOnError)
	txn := fs.String("txn", "", "transaction id")
	jti := fs.String("jti", "", "minted token jti")
	stsLog := fs.String("audit", "", "STS JSONL audit path")
	visorLog := fs.String("visor", "", "optional mcp-visor JSONL audit path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *stsLog == "" || (*txn == "" && *jti == "") {
		return fmt.Errorf("usage: agent-identity-plane trace [-txn ID] [-jti JTI] -audit sts.jsonl [-visor visor.jsonl]")
	}
	recs, err := audit.Trace(audit.Query{Txn: *txn, JTI: *jti}, *stsLog, *visorLog)
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		if *jti != "" && *txn == "" {
			return fmt.Errorf("no records for jti %s", *jti)
		}
		if *txn != "" {
			return fmt.Errorf("no records for txn %s", *txn)
		}
		return fmt.Errorf("no records")
	}
	_, err = os.Stdout.WriteString(audit.FormatTrace(recs))
	return err
}
