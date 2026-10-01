# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->
## [0.5.0] - 2026-10-01

### Changed

* Updated `pyo3` from 0.24.1 to 0.29.2, which adds support for Python 3.14.

### Fixed

* Type hints for `into_client_header_crypto` on `VanillaProofSeed`, `TbcProofSeed`, and `WrathProofSeed` now return the `(proof, crypto)` tuple instead of only the header crypto.
* Add `dynamic = ["version"]` to `pyproject.toml` so that `maturin develop` works with newer maturin versions.
* Type hints for byte array return values now use `bytes` instead of `list[int]`, matching what is returned at runtime.
* Type hints no longer use invalid `(int, int)` tuple syntax, and `__init__` methods now return `None`.
* Type hints for `SrpProof.into_server` and `SrpClientChallenge.verify_server_proof` now include their return types.

## [0.4.0] - 2024-11-12

### Removed

* BREAKING: Removed `SrpClientUser`. This has been replaced by the constructor on `SrpClientChallenge`.

## [0.3.0] - 2023-08-31

### Added

* Type hints for all classes and functions.

### Changed

* BREAKING: Moved types from `vanilla_header`, `tbc_header`, and `wrath_header` modules into main `wow_srp` module.
They are now prefixed with the version, for example `VanillaProofSeed` instead of `vanilla_header.ProofSeed`.
This is in order for everything to work correctly with type hints.

## [0.2.0] - 2023-08-05

### Added

* `vanilla_header`, `tbc_header`, and `wrath_header` modules.

## [0.1.1] - 2023-07-21

### Added

* Documentation to README.

## [0.1.0] - 2023-07-21

### Added

* Initial relase.

<!-- next-url -->
[Unreleased]: https://github.com/gtker/wow_srp/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/gtker/wow_srp/compare/v0.4.0...0.5.0
[0.4.0]: https://github.com/gtker/wow_srp/compare/v0.3.0...0.4.0
[0.3.0]: https://github.com/gtker/wow_srp/compare/v0.2.0...0.3.0
[0.2.0]: https://github.com/gtker/wow_srp/compare/v0.1.1...0.2.0
[0.1.1]: https://github.com/gtker/wow_srp_python/releases/tag/v0.1.1
[0.1.0]: https://github.com/gtker/wow_srp_python/releases/tag/v0.1.0
