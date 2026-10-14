package spool_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/perplexityai/numbat/internal/spool"
)

func TestSuccessfulQuarantineSurvivesShipperTermination(t *testing.T) {
	const helper = "NUMBAT_QUARANTINE_HELPER"
	const recordBefore = "{\"id\":\"before\"}\n"
	const recordAfter = "{\"id\":\"after\"}\n"
	if path := os.Getenv(helper); path != "" {
		store := spool.New(path)
		batch, err := store.Peek(1)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Quarantine(batch, spool.QuarantineHTTP413); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintln(os.Stdout, "quarantine complete"); err != nil {
			t.Fatal(err)
		}
		_, _ = bufio.NewReader(os.Stdin).ReadByte()
		return
	}
	path := filepath.Join(t.TempDir(), "records.spool")
	store := spool.New(path)
	if err := store.Put([]byte(recordBefore)); err != nil {
		t.Fatal(err)
	}
	if err := store.Put([]byte(recordAfter)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSuccessfulQuarantineSurvivesShipperTermination$")
	cmd.Env = append(os.Environ(), helper+"="+path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "quarantine complete\n" {
		t.Fatalf("child completion: %q, %v, %s", line, err, &stderr)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("terminated shipper exited successfully")
	}
	waited = true
	pending, err := spool.New(path).Peek(1)
	if err != nil || len(pending.Records) != 1 || string(pending.Records[0]) != recordAfter {
		t.Fatalf("pending after termination: %v, %v", pending.Records, err)
	}
	dir := filepath.Join(t.TempDir(), "export")
	summary, err := store.ExportOriginals(dir)
	if err != nil || summary.QuarantinedCount != 1 {
		t.Fatalf("committed quarantine missing: %+v, %v", summary, err)
	}
	got, err := os.ReadFile(filepath.Join(dir, summary.Quarantined[0].File))
	if err != nil || string(got) != recordBefore {
		t.Fatalf("original after termination: %q, %v", got, err)
	}
}
