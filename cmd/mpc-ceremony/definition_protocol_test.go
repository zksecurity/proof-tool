package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	m "proof-tool/internal/mpcceremony"
)

func TestDefinitionProtocolAuthenticatedDispatch(t *testing.T) {
	for _, schema := range []string{m.DefinitionSchemaV1, m.DefinitionSchemaV2, m.DefinitionSchemaV3, m.DefinitionSchemaV4} {
		d, _, key := decisionSignFixture(t)
		d.Schema = schema
		v4 := schema == m.DefinitionSchemaV4
		if schema == m.DefinitionSchemaV1 || schema == m.DefinitionSchemaV2 {
			d.AssurancePolicy = nil
		}
		if schema == m.DefinitionSchemaV1 {
			d.Software.Binaries = nil
			d.Software.GoARM64 = ""
		}
		if v4 {
			d.ReleaseVerification = m.CoordinatorReplayReleaseV1
		}
		var err error
		d.CeremonyID, err = m.ComputeCeremonyID(d)
		if err != nil {
			t.Fatal(err)
		}
		args := writeInspectionTrustFixture(t, t.TempDir(), d, key)
		command := append([]string{"--format", "json", "inspect", "definition-protocol"}, args...)
		var out, stderr bytes.Buffer
		if code := runCLI(context.Background(), command, &out, &stderr, workflowExecutor{}); code != 0 {
			t.Fatalf("%s", stderr.String())
		}
		var result CommandResult
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		p := result.DefinitionProtocolInspection
		want := m.StorageFirstWorkflowV1
		if v4 {
			want = m.StorageFirstWorkflowV2
		}
		if p == nil || p.DefinitionSchema != d.Schema || p.StorageWorkflow != want || p.ReleaseVerification != d.ReleaseVerification || p.Definition.CeremonyID != d.CeremonyID || result.DefinitionInspection != nil {
			t.Fatalf("unexpected projection: %+v", result)
		}
		out.Reset()
		stderr.Reset()
		legacyCommand := append([]string{"--format", "json", "inspect", "definition"}, args...)
		if code := runCLI(context.Background(), legacyCommand, &out, &stderr, workflowExecutor{}); code != 0 || bytes.Contains(out.Bytes(), []byte("definition_protocol_inspection")) {
			t.Fatalf("legacy inspection changed: %s %s", out.String(), stderr.String())
		}
		// A failed authentication emits no format selector for fallback routing.
		for i := range command {
			if command[i] == "--coordinator-public-key-file" {
				command[i+1] += ".missing"
			}
		}
		out.Reset()
		stderr.Reset()
		if code := runCLI(context.Background(), command, &out, &stderr, workflowExecutor{}); code == 0 || bytes.Contains(out.Bytes(), []byte("definition_protocol_inspection")) {
			t.Fatal("failed trust emitted protocol")
		}
	}
}
