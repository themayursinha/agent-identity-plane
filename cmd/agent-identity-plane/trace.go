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
	stsLog := fs.String("audit", "", "STS JSONL audit path")
	visorLog := fs.String("visor", "", "optional mcp-visor JSONL audit path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *txn == "" || *stsLog == "" {
		return fmt.Errorf("usage: agent-identity-plane trace -txn ID -audit sts.jsonl [-visor visor.jsonl]")
	}
	recs, err := audit.TraceTxn(*txn, *stsLog, *visorLog)
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		return fmt.Errorf("no records for txn %s", *txn)
	}
	_, err = os.Stdout.WriteString(audit.FormatTrace(recs))
	return err
}
