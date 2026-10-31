# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/moq-dev/rind/releases/tag/rind-rcgen-v0.1.0) - 2026-10-31

### Added

- [**breaking**] rind::rand, deviation docs, and the aws-lc-rs API surface audit ([#94](https://github.com/moq-dev/rind/pull/94))
- [**breaking**] signature key pairs bound to algorithm constants ([#89](https://github.com/moq-dev/rind/pull/89))
- [**breaking**] agreement and kem modules with algorithm constants ([#79](https://github.com/moq-dev/rind/pull/79))
- *(rcgen)* add rind-rcgen, an ECDSA P-256 SigningKey for rcgen ([#10](https://github.com/moq-dev/rind/pull/10))

### Other

- attribute every algorithm's source and license ([#88](https://github.com/moq-dev/rind/pull/88))
- follow the move to moq-dev/rind ([#50](https://github.com/moq-dev/rind/pull/50))
- *(cranelift)* build doctests with Cranelift and run the rcgen example ([#37](https://github.com/moq-dev/rind/pull/37))
- one workspace rust-version ([#33](https://github.com/moq-dev/rind/pull/33))
- ctgrind the adapter crates' secret paths ([#19](https://github.com/moq-dev/rind/pull/19))
