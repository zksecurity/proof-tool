package main

import (
	"strings"
	"testing"
)

func TestPublicReplayRequiresEvidenceButNoSigningIdentity(t *testing.T) {
	args := []string{"replay", "--ceremony", "ceremony.json", "--ceremony-signature", "ceremony.sig", "--coordinator-public-key-file", "coordinator.pub", "--candidate-bundle", "release", "--transcript-root", "transcript"}
	for _, phase := range []string{"phase1", "phase2"} {
		for _, artifact := range []string{"chain", "close", "beacon"} {
			args = append(args, "--"+phase+"-"+artifact, "record.json", "--"+phase+"-"+artifact+"-signature", "record.sig")
		}
	}
	args = append(args, "--phase1-seal", "seal.json", "--phase1-seal-signature", "seal.sig")
	invocation, err := parseInvocation(args)
	if err != nil {
		t.Fatal(err)
	}
	if invocation.Command != CommandReplay {
		t.Fatal(invocation.Command)
	}
	options := invocation.Options.(AuditOptions)
	if options.AuditorSigningKey != "" || options.AuditorID != "" || options.SignatureOutPath != "" {
		t.Fatal("public replay requested signing state")
	}
	for _, flag := range []string{"--auditor-signing-key", "--auditor-id", "--out", "--audit-signature"} {
		if _, err := parseInvocation(append(append([]string{}, args...), flag, "forbidden")); err == nil {
			t.Fatalf("accepted %s", flag)
		}
	}
	if _, err := parseInvocation(args[:len(args)-2]); err == nil || !strings.Contains(err.Error(), "phase1-seal-signature") {
		t.Fatalf("missing seal signature accepted: %v", err)
	}
}
