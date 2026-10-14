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

const (
	spoolCommitHelper = "NUMBAT_SPOOL_COMMIT_HELPER"
	spoolCommitPath   = "NUMBAT_SPOOL_COMMIT_PATH"
	committedRecord   = "{\"record_type\":\"event\",\"event_id\":\"committed\"}\n"
)

func TestSuccessfulPutSurvivesProducerTermination(t *testing.T) {
	if os.Getenv(spoolCommitHelper) == "1" {
		if err := spool.New(os.Getenv(spoolCommitPath)).Put([]byte(committedRecord)); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if _, err := fmt.Fprintln(os.Stdout, "put complete"); err != nil {
			t.Fatalf("report completed Put: %v", err)
		}
		_, _ = bufio.NewReader(os.Stdin).ReadByte()
		return
	}

	path := filepath.Join(t.TempDir(), "records.spool")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSuccessfulPutSurvivesProducerTermination$")
	cmd.Env = append(os.Environ(), spoolCommitHelper+"=1", spoolCommitPath+"="+path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	defer stdin.Close()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start producer: %v", err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "put complete\n" {
		t.Fatalf("producer did not complete Put: line %q, error %v, stderr %q", line, err, stderr.String())
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("terminate producer: %v", err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("terminated producer exited successfully")
	}
	waited = true

	batch, err := spool.New(path).Peek(1 << 20)
	if err != nil {
		t.Fatalf("Peek after producer termination: %v", err)
	}
	if len(batch.Records) != 1 || !bytes.Equal(batch.Records[0], []byte(committedRecord)) {
		t.Fatalf("records after producer termination = %q, want [%q]", batch.Records, committedRecord)
	}
}
