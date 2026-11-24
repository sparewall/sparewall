# Contributing to Sparewall

Thanks for your interest. Questions, and ideas that aren't yet feature
requests, belong in
[Discussions](https://github.com/sparewall/sparewall/discussions). Report
security vulnerabilities privately, through a
[security advisory](https://github.com/sparewall/sparewall/security/advisories/new).
Code conventions and the architecture rules are in [AGENTS.md](AGENTS.md),
which applies to people as much as to agents, and the design is in
[docs/design.md](docs/design.md).

## Issues

Issues record work on Sparewall: what's planned, what might be, and what
has been decided against. Search closed issues too before filing.

- **Planned:** an open issue in a milestone, the release it's expected in.
- **Might do:** an open issue with no milestone. The `post-1.0` label marks
  ideas that wait until after 1.0.
- **Decided against:** an issue closed as *not planned* and labelled
  `wontfix`, with the reasons in its body. These stay as the record, so the
  same idea isn't proposed again without them. If something changes, say so
  in a comment on that issue rather than opening a new one.
- **Duplicates** are closed with the `duplicate` label and a link to the
  issue they duplicate.

## Commits and pull requests

- Commit messages explain why. Sign off every commit (`git commit -s`).
- Pull requests are squash-merged once CI passes and review threads are
  resolved.
