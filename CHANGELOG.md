# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project scaffold: Hatch build system, ruff, pytest, pre-commit hooks
- `parse_dt()` in `timeutil.py` — flexible datetime parsing via dateparser (+offsets, natural language, ISO 8601)
- CLI skeleton with subcommands: `report`, `top`, `timeline`, `hosts`, `processes`
- All time arguments accept aliases: `--since`/`--from`/`--after`/`--begin`/`--start` and `--until`/`--to`/`--before`/`--end`
