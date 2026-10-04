# user-net-lock

`user-net-lock.exe` is the small, elevated enforcement primitive for Agent Sandbox.
For one Windows account and one loopback proxy port, it creates, verifies, or
removes a persistent WFP policy:

- permits TCP only to `127.0.0.1:<port>`, `[::1]:<port>`, and the IPv4-mapped
  IPv6 form of the same loopback endpoint;
- blocks all other outbound TCP and UDP attributed to that account;
- leaves ICMP and ICMPv6 unmanaged.

It does not read configuration files, install a proxy, download software,
resolve hostnames, or interpret an allowlist. It protects its WFP provider,
sublayer, and filters from modification by every managed account while granting
each managed account read-only access to its own policy status. The proxy
configurator owns the remaining concerns;
`agent-win-sandbox` calls this tool only after the loopback proxy is running
and healthy.

## Commands

`apply` and `remove` require an elevated Administrator session. A managed,
non-administrator account may run `verify` and `list` only for itself. An
administrator may inspect any managed account.

```text
user-net-lock apply --user <account> --port <port>
user-net-lock verify --user <account> --port <port>
user-net-lock remove --user <account>
user-net-lock list --user <account>
```

`apply` replaces only this tool's existing filters for the selected account,
installs the fixed loopback policy, and verifies it before reporting success.
`remove` deletes only this tool's filters for the selected account. `list`
prints those filters, including any stale loopback policy from a different
port.

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
([issue #1](https://github.com/fmuecke/user-net-lock/issues/1)). Windows
resolver APIs such as `GetAddrInfoW` hand the lookup to the DNS Client service
(`Dnscache`), which sends the query as `NT AUTHORITY\NETWORK SERVICE`. WFP
attributes that traffic to the service, so the account's `ALE_USER_ID` filters
never match it. Only DNS sent from the account's own sockets is blocked.

The managed account can therefore send data out in queried names and receive
data in the answers, through whatever resolvers the host is configured to use.
This was reproduced on Windows 11 build 26100 with the policy applied and
verified. A per-user RPC filter on the DNS Client service's resolver interface
was tried and had no effect.

`user-net-lock` has no per-user control for this path. A deployment that needs
it closed has to restrict name resolution for the whole host, for example by
limiting which resolvers the DNS Client service can reach.

## Build

```powershell
.\build.ps1
```

The script builds Release and runs CTest. Use `-Configuration Debug` for a
Debug build.

### Elevated integration test in Windows Sandbox

The default test run is non-mutating. To exercise real WFP DACL tampering,
use the Windows Sandbox CLI runner. It refuses to attach to an existing
sandbox, starts a fresh unconfigured guest, shares one writable directory,
copies the test executable there, runs it as `SYSTEM`, validates `result.txt`,
and stops the guest:

```powershell
.\tests\Invoke-WfpIntegrationInWindowsSandbox.ps1
```

The test applies and verifies the policy, confirms exactly seven filters, then
removes it and confirms its filters, provider, and sublayer are gone. It also
weakens the provider, sublayer, and filter DACLs, requires `verify` to fail for
each case, and reapplies to prove DACL repair. Finally, it proves repeated
apply replaces a user's prior port policy and that removing one user's policy
leaves the other's intact. The WFP changes and test accounts exist only in the
Windows Sandbox guest; no host user-net-lock policy is modified.

The same runner also launches a real traffic-enforcement test as the two
disposable accounts. It proves the target account can use the configured IPv4
and IPv6 loopback TCP proxy port, cannot use a different loopback port or TCP
and UDP to a non-loopback address, and that the second account can still reach
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
