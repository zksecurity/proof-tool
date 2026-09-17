package mpcceremony

import "errors"

// CandidateInvalidError identifies a semantic failure in a complete candidate
// after the caller has authenticated the ceremony, exact turn, and candidate
// directory. It deliberately does not cover missing files, filesystem errors,
// symlink/TOCTOU defenses, or failed trust and predecessor checks: those leave
// the candidate's state uncertain and must be investigated rather than
// rejected as content-invalid.
type CandidateInvalidError struct {
	err error
}

func (e *CandidateInvalidError) Error() string { return e.err.Error() }

func (e *CandidateInvalidError) Unwrap() error { return e.err }

// CandidateInvalid is a marker consumed by the machine-readable command
// boundary. It has no protocol meaning outside candidate inspection.
func (*CandidateInvalidError) CandidateInvalid() {}

// candidateInvalid marks a semantic candidate-validation failure. It is kept
// internal to the ceremony package so callers cannot relabel operational
// failures as invalid candidates.
func candidateInvalid(err error) error {
	if err == nil {
		return nil
	}
	return &CandidateInvalidError{err: err}
}

// IsCandidateInvalid reports whether inspection completed the trust, scope,
// predecessor, and directory-opening stages and then found invalid candidate
// semantics.
func IsCandidateInvalid(err error) bool {
	var invalid *CandidateInvalidError
	return errors.As(err, &invalid)
}
