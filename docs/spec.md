# wfp-lock outbound policy

## Contract

`wfp-lock` is a standalone tool. For one local account it owns exactly one
SID-scoped outbound policy: TCP to an explicit set of endpoints is permitted,
and all other TCP and UDP sent from the account's sockets is blocked. There
are no deny entries; anything not permitted is blocked.

```text
wfp-lock apply  --user AgentSandbox --allow 127.0.0.1:8080,[::1]:8080
wfp-lock verify --user AgentSandbox --allow 127.0.0.1:8080,[::1]:8080
wfp-lock allow  --user AgentSandbox 10.1.2.3:5432
wfp-lock revoke --user AgentSandbox 10.1.2.3:5432
wfp-lock remove --user AgentSandbox
wfp-lock list   [--user AgentSandbox]
```

An endpoint list is comma-separated, without spaces or empty entries. Each
endpoint is a literal IPv4 address, or an IPv6 address in brackets, followed by
a TCP port from 1 through 65535. The tool rejects hostnames, zone IDs,
IPv4-mapped IPv6 addresses (write them as IPv4), unspecified, multicast, and
broadcast addresses. The allow set is unordered, repeated entries count once,
and a policy holds at most 32 endpoints.

`apply` and `verify` take the complete allow set through the optional
`--allow`, which may be given once. With no `--allow`, the account's TCP and
UDP traffic is blocked entirely. `allow` and `revoke` take an endpoint list as
their last argument and change the installed set.

The tool does not accept protocols, address ranges, or policy files, and it
never resolves names.

`apply` first validates the shared provider and sublayer and restores their
administrative DACLs and managed-account read ACEs when necessary. In one
transaction it then removes this tool's prior policy for the account, creates
the provider, sublayer, and filters as needed, and commits. It then verifies
the result. A shared object whose persistence, provider association, or
effective weight is below the policy baseline causes failure before any filter
is changed.

`allow` adds endpoints to the account's installed allow set; `revoke` removes
them. Each reads the set from the installed permit filters, then applies and
verifies the changed set as `apply` does. Both hold the shared-infrastructure
lock from read to commit, so concurrent changes cannot overwrite each other.
Both fail if the account has no policy. `allow` fails if the result would
exceed 32 endpoints. Revoking an endpoint that is not installed changes
nothing; revoking every endpoint leaves a block-only policy.

`verify` succeeds only if the installed filters exactly match the given allow
set. `remove` deletes only this tool's filters for the account. The shared
provider and sublayer are deleted once no filter refers to them. `list` prints
the account's filters, including those left from a different allow set. Without
`--user`, `list` uses the current process token's user SID.

## Filters

All filters go in one sublayer. Inside that sublayer, the matching filter with
the highest weight decides, so the permits take precedence over the blocks.

- Each IPv4 entry adds two high-weight TCP permits for that address and port: one
  at `FWPM_LAYER_ALE_AUTH_CONNECT_V4`, and one for its `::ffff:` mapped form at
  `FWPM_LAYER_ALE_AUTH_CONNECT_V6`, which dual-stack sockets use.
- Each IPv6 entry adds one high-weight TCP permit at
  `FWPM_LAYER_ALE_AUTH_CONNECT_V6`.
- Four lower-weight blocks cover TCP and UDP at both connect layers.

A policy therefore has `4 + 2 × IPv4 entries + IPv6 entries` filters. The old
loopback proxy policy is
`--allow 127.0.0.1:<port>,[::1]:<port>`, which is seven filters. ICMP
and ICMPv6 are out of scope.

Every filter carries an `FWPM_CONDITION_ALE_USER_ID` condition for the target
SID. Windows represents that condition as a security descriptor; the tool
creates and verifies it only to bind the filter to the account. Separately, the
provider, sublayer, and each filter get a protected DACL that grants full
control only to `SYSTEM` and built-in Administrators. Each managed account gets
read-only WFP access (including `READ_CONTROL`) to the shared objects and its
own filters, so it can `list` and `verify` its own policy. The filter container
grants it only the enumeration right needed to list the filters it can read. It
gets no write, delete, ownership, or DACL-change right. The tool does not
inspect directory or configuration-file ACLs.

## Boundaries

`wfp-lock` decides only which TCP endpoints an account may reach from its own
sockets. Other tools are configured separately. The `network-sandbox` proxy
owns its hostname allowlist, loopback binding, lifecycle, and health.
`agent-win-sandbox` orchestrates both tools: it starts the proxy, waits for its
listener to be ready, and then calls `apply` with an allow set that includes
the proxy's loopback endpoints.

A direct entry bypasses any proxy, so the proxy neither sees nor logs that
traffic. An entry is bound to an IP address: if a service moves to another
address, the policy must be reapplied. If the address is shared, for example
by a load balancer or a cloud gateway, the entry reaches every service on that
port.

Permits apply only within this tool's sublayer. Windows Firewall and other WFP
providers evaluate their own sublayers and can still block traffic that this
policy permits.

This is a host-scoped, attribution-dependent control. Validate all brokered
and virtualized networking paths in the actual deployment.

ICMP echo requests through `IcmpSendEcho` and `Icmp6SendEcho2` remained usable
in a Windows build 26100 Sandbox probe, even with additional SID-scoped ICMP
filters installed and verified. The WFP trace attributed the requests to
`SYSTEM` (`S-1-5-18`, PID 4), so the target SID's filters did not match. A
machine-wide block affected both test accounts and does not satisfy this
per-account contract. See [ICMP probe evidence](icmp-evidence.md). The results
cover loopback echo requests only; they do not show complete ICMP coverage or a
working per-user driver solution.

One brokered path is known to be open: DNS lookups delegated to the DNS Client
service (`Dnscache`). The service sends the query as `NT AUTHORITY\NETWORK
SERVICE`, so the target SID's `FWPM_CONDITION_ALE_USER_ID` filters do not match.
The managed account can still resolve arbitrary names and read the answers.
The filters block only DNS sent from the account's own sockets. A per-user
block filter at `FWPM_LAYER_RPC_UM` on the resolver interface does not close
this path. Restricting it is a host-wide deployment concern outside this
tool's contract; see issue #1.

`apply`, `allow`, `revoke`, and `remove` always require elevation. A
non-elevated caller of `verify` or `list` must be the target account;
administrators may inspect any account. This identity check narrows the CLI
surface, while the WFP ACLs remain the enforcement boundary for direct WFP API
callers.
