# CLAUDE.md

Read `AGENTS.md` first — it is the harness-neutral source of truth and does not override your
active role contract. The import below loads it for Claude Code.

@AGENTS.md

Claude-specific notes:

- Run `bash check.sh go` after every edit — it is gofmt, build, vet, the reference-boundary
  gate and the whole test suite in one command, and it is exactly what CI runs. `bash check.sh`
  adds the parity and release lanes.
- Four shell scripts survive the Go rewrite (`check.sh`, `tests/smoke.sh`, `tools/*.sh`) and
  every one of them is load-bearing; lint them with
  `shellcheck -x check.sh tests/*.sh tools/*.sh` when you touch one.
- The hermetic engine fake means a green suite proves logic, not Docker behavior; say so when
  reporting results that would need a real runtime to fully verify. `bash check.sh acceptance`
  is the lane that needs one, and it is opt-in.
