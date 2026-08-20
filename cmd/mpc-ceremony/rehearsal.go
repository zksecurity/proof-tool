// Copyright 2026 Midgard Labs
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"

	"proof-tool/internal/mpcceremony"
	"proof-tool/internal/mpcrehearsal"
)

const (
	rehearsalParticipantCount  = 3
	rehearsalBeaconLeadSeconds = 300
)

func executeRehearsalInit(options RehearsalInitOptions) (result CommandResult, err error) {
	if err := mpcrehearsal.Generate(
		options.OutDir,
		rehearsalParticipantCount,
		rehearsalBeaconLeadSeconds,
	); err != nil {
		return CommandResult{}, err
	}
	keepRoot := false
	defer func() {
		if !keepRoot {
			err = errors.Join(err, os.RemoveAll(options.OutDir))
		}
	}()

	configRoot := filepath.Join(options.OutDir, "config")
	keyRoot := filepath.Join(options.OutDir, "keys")
	participantsPath := filepath.Join(configRoot, "participants.json")
	participants, err := mpcceremony.LoadInitParticipants(participantsPath)
	if err != nil {
		return CommandResult{}, err
	}
	result, err = executeInit(InitOptions{
		CreatedAt:             options.CreatedAt,
		KeyVersion:            rehearsalKeyVersion,
		ParticipantsPath:      participantsPath,
		PolicyPath:            filepath.Join(configRoot, "policy.json"),
		CoordinatorKeyID:      participants.Coordinator.KeyID,
		CoordinatorSigningKey: filepath.Join(keyRoot, "coordinator.ed25519.private.hex"),
		OutDir:                filepath.Join(options.OutDir, "public"),
		Mode:                  mpcceremony.ModeRehearsal,
	})
	if err != nil {
		return CommandResult{}, err
	}
	result.Command = CommandRehearsalInit
	result.Summary = "initialized same-host three-participant rehearsal fixture (NOT PRODUCTION)"
	result.Outputs["config_root"] = configRoot
	result.Outputs["environment"] = filepath.Join(configRoot, "environment.json")
	result.Outputs["key_root"] = keyRoot
	result.Outputs["rehearsal_root"] = options.OutDir
	keepRoot = true
	return result, nil
}
