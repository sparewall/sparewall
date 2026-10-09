# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository.

## Orientation

- The design is in `docs/design.md`. Read the relevant section before
  changing behaviour; when code and design disagree, fix one of them in the
  same change and say which.
- Work proceeds by the milestones at the end of the design. Don't build
  later-milestone features into earlier layers speculatively.

## Architecture rules (from the design)

- The coordinator is the **only writer** of daemon configuration. Renderers
  are pure functions from the document (plus node identity) to files; all
  side effects live in `sparewall-core` adapters behind traits so they can
  be faked in tests.
- Collections of named things are maps keyed by name; arrays only for value
  lists. Keep new schema fields consistent with this.
- No secrets in the document — only `secret:<name>` references.
- The coordinator owns the `inet sparewall` nft table and never runs
  `flush ruleset`.
- `sparewall` (CLI) is a thin client: validation, rendering and state belong
  in the coordinator.

## Conventions

- Rust 2024 edition, workspace lints, `cargo fmt`, `cargo clippy -D warnings`.
- Every schema change needs: model update, validation, fixtures in
  `examples/` or tests, and renderer snapshot updates.
- Renderer output is covered by snapshot tests (`insta`); review snapshot
  diffs as carefully as code.
- Tests that need root or real kernel state (nft, netlink) run in an
  unprivileged user+network namespace when available (`unshare -rn`) and
  skip otherwise.
- Commit messages explain why. Sign off commits (`git commit -s`).

## Commands

```shell
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check            # license and advisory gates
```
