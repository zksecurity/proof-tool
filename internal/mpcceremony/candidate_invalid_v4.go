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

// candidateArtifactContentError marks bytes that were opened successfully but
// cannot be decoded as the required canonical ceremony artifact. Filesystem,
// path, and short-read failures deliberately remain unmarked.
type candidateArtifactContentError struct {
	err error
}

func (e *candidateArtifactContentError) Error() string { return e.err.Error() }

func (e *candidateArtifactContentError) Unwrap() error { return e.err }

func candidateArtifactContent(err error) error {
	if err == nil {
		return nil
	}
	return &candidateArtifactContentError{err: err}
}

func isCandidateArtifactContent(err error) bool {
	var invalid *candidateArtifactContentError
	return errors.As(err, &invalid)
}

// candidateArtifactDigestMismatchError is narrower than an arbitrary read
// failure: the file was opened and read without changing, but its bytes do not
// match the participant's signed artifact reference.
type candidateArtifactDigestMismatchError struct {
	err error
}

func (e *candidateArtifactDigestMismatchError) Error() string { return e.err.Error() }

func (e *candidateArtifactDigestMismatchError) Unwrap() error { return e.err }

func candidateArtifactDigestMismatch(err error) error {
	if err == nil {
		return nil
	}
	return &candidateArtifactDigestMismatchError{err: err}
}

func isCandidateArtifactDigestMismatch(err error) bool {
	var invalid *candidateArtifactDigestMismatchError
	return errors.As(err, &invalid)
}
