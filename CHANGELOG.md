# Changelog

## [0.8.1] - 2026-10-04

- Added: Windows/MSVC CI builds Release and runs non-mutating CTest on every push and pull
  request. It uploads a ZIP with `user-net-lock.exe`, `README.md`, `LICENSE`, and `CHANGELOG.md`,
  plus separate test logs.
- Added: Version tags publish `user-net-lock-v<version>-win64.zip` with changelog notes and
  provenance attestations for the ZIP and executable. Tags must match the binary version.
- Added: GPL-3.0 license text in the repository.
- Changed: `build.ps1 -SkipFormatting` skips source formatting.
- Changed: The Windows Sandbox runner uses the shared `WindowsSandboxTest` module, pinned by
  revision and SHA-256 hash.
- Documented: DNS resolver APIs use the DNS Client service, bypassing the account's WFP filters.
  Queried names and answers can carry data outside the allowed proxy connection.
- Documented: ICMP and ICMPv6 remain unmanaged. Sandbox probes attributed echo requests to
  `SYSTEM`, bypassing experimental per-account filters. See the README and
  `docs/icmp-evidence.md` for evidence and limits.

## [0.8.0] - 2026-09-15

- Added: Managed non-administrators can `list` and `verify` their own WFP policy. Other standard
  accounts cannot inspect it; administrators can inspect any managed account.
- Security: Protected WFP DACLs grant managed accounts read-only status access.
- Fixed: Serialized shared provider and sublayer ACL updates preserve other accounts' status
  access during concurrent policy changes.
- Added: Windows Sandbox tests for concurrent updates, DACL tampering and repair, account
  status access, and real TCP/UDP enforcement.
- Added: Windows executable version metadata from the CMake project version.
