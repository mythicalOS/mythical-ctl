# CLAUDE.md

Read `AGENTS.md` first — it is the harness-neutral source of truth and does not override your
active role contract. The import below loads it for Claude Code.

@AGENTS.md

Claude-specific notes:

- Run `shellcheck` and the bats suite after every shell edit — shell defects here brick
  installs, and there is no compiler to catch them.
- The hermetic harness means a green suite proves logic, not Docker behavior; say so when
  reporting results that would need a real runtime to fully verify.
