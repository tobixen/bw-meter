# Contributing to bw-meter

Contributions are mostly welcome (but do inform about it if you've used AI or other tools).  If the length of this text scares you, then I'd rather want you to skip reading and just produce a pull-request in GitHub.  If you find it too difficult to write test code, etc, then you may skip it and hope the maintainer will fix it.

## What to include

Every submission should ideally include:

- **Test code** covering the new behaviour or bug fix
- **Documentation** updates where relevant
- **A changelog entry** in `CHANGELOG.md` under `[Unreleased]`

## Commit messages

Please follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) and write messages in the imperative mood:

- `fix: handle untagged WireGuard packets in distiller`
- `feat: add rollup command for compacting old buckets`
- `docs: document ptcpdump capture setup`

## Development setup

```
make dev
```

This installs the package in editable mode with dev dependencies.  Pre-commit hooks are configured separately:

```
pre-commit install
pre-commit install --hook-type pre-push
pre-commit install --hook-type commit-msg
```

Run tests with `make test`.
