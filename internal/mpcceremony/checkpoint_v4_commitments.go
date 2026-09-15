package mpcceremony

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// CheckpointCommitmentsV4 locates coordinator-committed records. It does not
// assert that those records, their signatures or their payloads were re-read.
// The containing inspection binds this index to its exact verified head pair.
type CheckpointCommitmentsV4 struct {
	Enrollments []SignedArtifactRefs `json:"enrollments"`
	Turns       []TurnCommitmentV4   `json:"turns"`
}

type OutboundCommitmentV4 struct {
	CheckpointSequence uint64             `json:"checkpoint_sequence"`
	PublishedAttemptID string             `json:"published_attempt_id"`
	Pair               SignedArtifactRefs `json:"pair"`
}

type AcceptedTurnRecordV4 struct {
	AttemptID string             `json:"attempt_id"`
	Pair      SignedArtifactRefs `json:"pair"`
}

type AcceptedChainCommitmentV4 struct {
	AttemptID            string             `json:"attempt_id"`
	ContributionResultID string             `json:"contribution_result_id"`
	Pair                 SignedArtifactRefs `json:"pair"`
}

type TurnCommitmentV4 struct {
	Scope ContributionScope `json:"scope"`
	// Newest first. PublishedAttemptID records transport history only; a later
	// accepted receipt may acknowledge an older still-valid packet in this list.
	Outbounds     []OutboundCommitmentV4     `json:"outbounds"`
	InputReceipt  *AcceptedTurnRecordV4      `json:"input_receipt,omitempty"`
	AcceptedChain *AcceptedChainCommitmentV4 `json:"accepted_chain,omitempty"`
	ReturnHandoff *SignedArtifactRefs        `json:"return_handoff,omitempty"`
	ReturnReceipt *SignedArtifactRefs        `json:"return_receipt,omitempty"`
}

func collectTurnCommitmentV4(turns map[ContributionScope]*TurnCommitmentV4, c CheckpointV4) error {
	t := c.Transition
	switch t.Kind {
	case CheckpointPhase1OutboundPublished, CheckpointPhase2OutboundPublished, CheckpointPhase1ReceiptAccepted, CheckpointPhase2ReceiptAccepted, CheckpointPhase1CandidateAccepted, CheckpointPhase2CandidateAccepted:
	default:
		return nil
	}
	scope := *t.Scope
	turn := turns[scope]
	if turn == nil {
		if len(turns) >= 2*MaxParticipants {
			return errors.New("turn commitment index exceeds protocol capacity")
		}
		turn = &TurnCommitmentV4{Scope: scope, Outbounds: []OutboundCommitmentV4{}}
		turns[scope] = turn
	}
	switch t.Kind {
	case CheckpointPhase1OutboundPublished, CheckpointPhase2OutboundPublished:
		if len(turn.Outbounds) >= MaxDeliveryAttemptsPerSubmissionV2 {
			return errors.New("outbound commitment index exceeds receipt-attempt limit")
		}
		turn.Outbounds = append(turn.Outbounds, OutboundCommitmentV4{CheckpointSequence: c.Sequence, PublishedAttemptID: t.AttemptID, Pair: *t.Record})
	case CheckpointPhase1ReceiptAccepted, CheckpointPhase2ReceiptAccepted:
		if turn.InputReceipt != nil {
			return errors.New("duplicate accepted receipt commitment")
		}
		turn.InputReceipt = &AcceptedTurnRecordV4{AttemptID: t.AttemptID, Pair: *t.Record}
	case CheckpointPhase1CandidateAccepted, CheckpointPhase2CandidateAccepted:
		if turn.AcceptedChain != nil {
			return errors.New("duplicate candidate commitment")
		}
		resultID, err := t.Contribution.ID()
		if err != nil {
			return err
		}
		turn.AcceptedChain = &AcceptedChainCommitmentV4{AttemptID: t.AttemptID, ContributionResultID: resultID, Pair: *t.Record}
		base := fmt.Sprintf("%s/contributions/%04d/", scope.Phase, scope.Index)
		pair := func(name string) (*SignedArtifactRefs, error) {
			p := SignedArtifactRefs{}
			for _, ref := range t.Evidence {
				if ref.Name == base+name+".json" {
					p.Record = ref
				}
				if ref.Name == base+name+".sig" {
					p.Signature = ref
				}
			}
			if err := p.Validate(); err != nil {
				return nil, err
			}
			return &p, nil
		}
		turn.ReturnHandoff, err = pair("return-handoff")
		if err != nil {
			return err
		}
		turn.ReturnReceipt, err = pair("return-receipt")
		if err != nil {
			return err
		}
	}
	return nil
}

// InspectStoredCheckpointV4 shares the structural verifier's exact ancestry
// read. No loose directory scan or latest-transition heuristic defines facts.
func InspectStoredCheckpointV4(trust TrustPaths, root string, head SignedArtifactRefs) (CheckpointV4, CheckpointCommitmentsV4, error) {
	c, err := openStoredCheckpointV4(trust, root, head)
	if err != nil {
		return CheckpointV4{}, CheckpointCommitmentsV4{}, err
	}
	defer c.reader.root.Close()
	index, err := checkpointCommitmentsV4(c.ancestry)
	return c.ancestry.head, index, err
}

func checkpointCommitmentsV4(a checkpointAncestryV4) (CheckpointCommitmentsV4, error) {
	if len(a.enrollments) > 128 {
		return CheckpointCommitmentsV4{}, errors.New("enrollment commitment index exceeds protocol capacity")
	}
	index := CheckpointCommitmentsV4{Enrollments: sortedSignedRefsV4(a.enrollments), Turns: []TurnCommitmentV4{}}
	for _, turn := range a.turnCommitments {
		index.Turns = append(index.Turns, *turn)
	}
	slices.SortFunc(index.Turns, func(a, b TurnCommitmentV4) int {
		if a.Scope.Phase != b.Scope.Phase {
			return strings.Compare(string(a.Scope.Phase), string(b.Scope.Phase))
		}
		return int(a.Scope.Index) - int(b.Scope.Index)
	})
	return index, nil
}
