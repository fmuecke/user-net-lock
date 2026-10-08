# Changelog

## [0.10.0] - 2026-10-08

- Changed (breaking): `apply` and `verify` take `--allow <endpoints>` instead of `--port <port>`.
  The value is a comma-separated list of up to 32 endpoints, each `<ipv4>:<port>` or
  `[<ipv6>]:<port>`. The previous `--port 8080` policy is `--allow 127.0.0.1:8080,[::1]:8080`.
  Without `--allow`, all outbound TCP and UDP is blocked.
- Added: `allow --user <account> <endpoints>` and `revoke --user <account> <endpoints>` add
  endpoints to or remove them from an installed policy, then verify it. Both require an existing
  policy; revoking an endpoint that is not installed changes nothing.
- Added: Direct TCP endpoints outside loopback, for example a database server. An IPv4 endpoint
  also permits its IPv4-mapped IPv6 form.
- Changed: `verify` requires the installed filters to match the given allow set exactly,
  regardless of order or repeated entries.
- Changed: `apply` and `remove` replace filters written by 0.9 and earlier; `verify` rejects them
  until the policy is reapplied.
- Changed: Invalid arguments now print the reason after the usage text.
- Documented: `wfp-lock` is configured independently of the `network-sandbox` proxy;
  `agent-win-sandbox` orchestrates both.

## [0.9.0] - 2026-10-07

- Changed: Changed name to `wfp-lock`.

## [0.8.1] - 2026-10-04

- Added: Windows/MSVC CI builds Release and runs non-mutating CTest on every push and pull
  request. It uploads a ZIP with `wfp-lock.exe`, `README.md`, `LICENSE`, and `CHANGELOG.md`,
  plus separate test logs.
- Added: Version tags publish `wfp-lock-v<version>-win64.zip` with changelog notes and
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
