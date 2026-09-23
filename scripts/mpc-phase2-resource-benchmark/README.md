# Phase 2 resource measurement

Build this tool for a disposable Linux container, then pass one read-only public
input directory containing `ceremony.json`, `ceremony.sig`, `coordinator.hex`,
`seal.json`, `seal.sig`, `chain-0000.json`, `chain-0000.sig`, and `commons.bin`.
Never mount signing keys. Use the executable directly as the container entrypoint;
the released role images do not contain a shell.

The tool authenticates the definition, seal and zero-contribution Phase 2 chain,
compiles the exact production circuit, checks the commons digest, and requires the
derived genesis to match both hashes and size in that signed chain. It emits a
JSON result with compilation, input decoding, derivation and total durations,
GOMAXPROCS and cgroup-v2 peak memory. Compilation and input decoding are included
in the peak memory measurement. Gnark compilation logs can precede the JSON line.

Run 2, 4 and 6 CPUs sequentially with matching Docker quota/GOMAXPROCS, the same
6-GiB memory/swap ceiling, GOMEMLIMIT=4GiB and GOGC=25. Keep input and executable
checksums, Docker configuration, exit status and start/end times with each result.
Use a private output directory outside the read-only input mount. Recheck host
capacity before each run. A failed or interrupted run is not a passing result.

This measures one component, not contribution verification, finalization or a
full ceremony. It does not replay Phase 1 or certify the transcript. Results from
a host with other workloads require that qualification when comparing runtimes.
Do not turn a component measurement into a universal resource recommendation.
