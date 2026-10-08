<!-- Project URL: https://github.com/fmuecke/wfp-lock -->

# wfp-lock [![Windows build](https://github.com/fmuecke/wfp-lock/actions/workflows/build.yml/badge.svg)](https://github.com/fmuecke/wfp-lock/actions/workflows/build.yml)

`wfp-lock.exe` is a small, elevated tool that restricts one Windows account's
outbound network traffic. For that account it creates, verifies, or removes a
persistent WFP policy that:

- permits TCP only to the endpoints given with `--allow`. An IPv4 endpoint also
  covers its IPv4-mapped IPv6 form;
- blocks all other outbound TCP and UDP attributed to that account;
- leaves ICMP and ICMPv6 unmanaged.

It does not read configuration files, install a proxy, download software, or
resolve hostnames. It protects its WFP provider, sublayer, and filters from
modification by every managed account, and gives each managed account read-only
access to its own policy status.

`wfp-lock` is configured independently of other tools. In Agent Sandbox,
`agent-win-sandbox` orchestrates it together with the `network-sandbox` proxy:
it starts the proxy and then applies a policy whose allow set includes the
proxy's loopback endpoints.

## Commands

`apply`, `allow`, `revoke`, and `remove` require an elevated Administrator
session. A managed, non-administrator account may run `verify` and `list` only
for itself. An administrator may inspect any managed account.

```text
wfp-lock apply  --user <account> [--allow <endpoints>]
wfp-lock verify --user <account> [--allow <endpoints>]
wfp-lock allow  --user <account> <endpoints>
wfp-lock revoke --user <account> <endpoints>
wfp-lock remove --user <account>
wfp-lock list   [--user <account>]
```

`<endpoints>` is a comma-separated list without spaces, for example
`127.0.0.1:8080,[::1]:8080,10.1.2.3:5432`. Each endpoint is `<ipv4>:<port>` or
`[<ipv6>]:<port>`. A policy holds up to 32 endpoints; order and repeated
entries do not matter. Hostnames, zone IDs, IPv4-mapped IPv6, unspecified,
multicast, and broadcast addresses are rejected.

`apply` replaces only this tool's existing filters for the selected account
with the given allow set, and verifies the result before reporting success.
Without `--allow`, all of the account's outbound TCP and UDP is blocked.
`verify` succeeds only if the installed filters exactly match the given allow
set.

`allow` adds endpoints to the installed policy and `revoke` removes them; both
verify the result. They require an existing policy, so `allow` cannot create
a policy that lacks the endpoints set by `apply`. Revoking an endpoint that is
not installed changes nothing.

`remove` deletes only this tool's filters for the selected account. `list`
prints those filters, including any left from a different allow set. Without
`--user`, `list` uses the current process account.

A direct endpoint bypasses any proxy, and it is tied to its IP address: if the
service moves, reapply the policy. If the address is shared, for example by a
load balancer, the entry reaches every service there on that port. Windows
Firewall and other WFP providers can still block traffic that this policy
permits.

The status ACL grants the managed account WFP read access and `READ_CONTROL`
only. It grants no filter deletion, policy mutation, ownership, or DACL-change
rights. A narrowly scoped filter-container enumeration ACE is also needed by
the WFP API; enumeration returns only filters that the caller can read.

The WFP `ALE_USER_ID` condition necessarily contains a security descriptor for
the selected account SID; that is the Windows API representation of a
per-user filter, not a configurable ACL feature.

WFP attribution is host-scoped, not a VM or network boundary. Test WSL,
containers, virtual machines, BITS, and other brokered paths in the deployment
that relies on it.

### Known limitation: ICMP echo is not blocked per account

In a Windows Sandbox probe on build 26100, `IcmpSendEcho` and
`Icmp6SendEcho2` still received loopback replies after adding and verifying
SID-scoped ICMP blocks. WFP attributed the requests to `SYSTEM` rather than
the calling account, so the account's filters did not match. A machine-wide
block stopped both test accounts and is outside this tool's per-account
contract. See the [ICMP probe evidence](docs/icmp-evidence.md) for the results
and their limits.

### Known limitation: DNS lookups are not blocked

The policy does not stop the managed account from resolving hostnames
([issue #1](https://github.com/fmuecke/wfp-lock/issues/1)). Windows
resolver APIs such as `GetAddrInfoW` hand the lookup to the DNS Client service
(`Dnscache`), which sends the query as `NT AUTHORITY\NETWORK SERVICE`. WFP
attributes that traffic to the service, so the account's `ALE_USER_ID` filters
never match it. Only DNS sent from the account's own sockets is blocked.

The managed account can therefore send data out in queried names and receive
data in the answers, through whatever resolvers the host is configured to use.
This was reproduced on Windows 11 build 26100 with the policy applied and
verified. A per-user RPC filter on the DNS Client service's resolver interface
was tried and had no effect.

`wfp-lock` has no per-user control for this path. A deployment that needs
it closed has to restrict name resolution for the whole host, for example by
limiting which resolvers the DNS Client service can reach.

## Build

```powershell
.\build.ps1
```

The script builds Release and runs CTest. Use `-Configuration Debug` for a
Debug build, or `-SkipFormatting` to skip automatic source formatting.

### Elevated integration test in Windows Sandbox

The default test run is non-mutating. To exercise real WFP DACL tampering,
use the Windows Sandbox CLI runner. It refuses to attach to an existing
sandbox, starts a fresh unconfigured guest, shares one writable directory,
copies the test executable there, runs it as `SYSTEM`, validates `result.txt`,
and stops the guest:

```powershell
.\tests\Invoke-WfpIntegrationInWindowsSandbox.ps1
```

The test applies and verifies a loopback policy, confirms exactly seven
filters, then removes it and confirms its filters, provider, and sublayer are
gone. It also weakens the provider, sublayer, and filter DACLs, requires
`verify` to fail for each case, and reapplies to prove DACL repair. It proves
repeated apply replaces a user's prior policy and that removing one user's
policy leaves the other's intact. It checks filter counts for direct IPv4 and
IPv6 endpoints and for a block-only policy, that `verify` ignores order and
repeated entries but rejects a missing or extra endpoint, and that `apply`,
`allow`, and `remove` replace filters written by wfp-lock 0.9. It checks that
`allow` and `revoke` change only the given endpoints, that `allow` needs an
existing policy and stops at 32 endpoints, and that revoking a missing endpoint
changes nothing. The WFP changes and test accounts exist only in the Windows
Sandbox guest; no host wfp-lock policy is modified.

The same runner also launches a real traffic-enforcement test as the two
disposable accounts. It proves the target account can use the allowed IPv4 and
IPv6 loopback TCP port and an allowed direct endpoint on a non-loopback
address. It cannot use a different loopback port, another port on the direct
endpoint's address, or UDP to either, while the second account can still reach
the non-loopback TCP and UDP listeners. It also verifies that the target can
list and verify its own installed policy without elevation, while the other
standard account cannot inspect it. It also attempts to weaken the provider
DACL through the target account's direct WFP API call and requires access to be
denied.

The runner downloads the reusable
[`WindowsSandboxTest`](https://gist.github.com/fmuecke/2a53528dba05cd208c2cfbef2c547e2a)
module from GitHub. It pins both the published raw revision and its SHA-256
before importing it. The module stages artifacts in a caller-owned host
directory, runs its callback as `SYSTEM` by default, and stops the fresh guest
afterward.

## License

[GPL-3.0-or-later](LICENSE) © 2026 Florian Mücke
