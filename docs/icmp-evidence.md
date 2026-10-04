# ICMP per-account enforcement probe

On 2026-10-04, probes in fresh Windows Sandbox guests (Windows build
`26100.ge_release.240331-1435`) tested whether the existing per-account WFP
policy could be extended to block IPv4 and IPv6 echo requests. All policy
mutations and disposable accounts stayed inside the guests. The host policy
was not modified, and each guest was stopped after the probe.

## SID-scoped blocks did not stop echo requests

The temporary implementation added persistent protocol-1 (ICMP) and protocol-58
(ICMPv6) block filters at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` and
`FWPM_LAYER_ALE_AUTH_CONNECT_V6`, respectively. Both used the target account's
`FWPM_CONDITION_ALE_USER_ID`. The resulting nine-filter policy installed and
verified; the normal CTest and elevated WFP lifecycle/DACL suite passed.

The traffic probes used `IcmpSendEcho` to `127.0.0.1` and `Icmp6SendEcho2` to
`::1`. They ran under two standard disposable accounts launched using
`CreateProcessWithLogonW`.

| Probe | IPv4 echo | IPv6 echo |
| --- | --- | --- |
| Target account before apply | Reply received | Reply received |
| Target account after apply | Reply received | Reply received |
| Other account while target policy was applied | Reply received | Reply received |

The assertions requiring target echo requests to be blocked failed with both
the existing seven-filter policy and the experimental nine-filter policy.

The WFP capture recorded 12 protocol-1 and 14 protocol-58 allow events, all
with application `System`, user SID `S-1-5-18`, and process ID 4. Representative
request fields were:

| Field | IPv4 request | IPv6 request |
| --- | --- | --- |
| `ipProtocol` | `1` | `58` |
| Remote address | `127.0.0.1` | `::1` |
| `localPort` (ICMP type) | `8` (echo request) | `128` (echo request) |
| `userId` | `S-1-5-18` | `S-1-5-18` |
| `processId` | `4` | `4` |
| Event type | `FWPM_NET_EVENT_TYPE_PUBLIC_CLASSIFY_ALLOW` | `FWPM_NET_EVENT_TYPE_PUBLIC_CLASSIFY_ALLOW` |

These requests were attributed to `SYSTEM`, so the target account's SID
condition could not match them. Successful policy verification therefore did
not demonstrate echo enforcement. The ineffective implementation was reverted.

## Machine-wide comparison

A separate probe installed two temporary dynamic, protocol-only blocks at the
same connect layers, without a user condition. Both accounts received IPv4
and IPv6 echo replies before installation, both were denied while the blocks
were active, and both received replies again after removal. Probe setup and
process-launch failures were distinguished from echo denial. The guest reported
`Machine-wide ICMP probe passed`.

This comparison demonstrates that removing the account condition can stop the
tested requests, but it affects other accounts. Machine-wide blocking is not
acceptable for this tool's per-account contract.

## Evidence and limits

The retained local artifacts are under the ignored `out/` directory:

- `icmp-diagnostics/89eb5b1985f3409c9dd76c63134f68d6/diagnostic.log`,
  `icmp.xml`, and `icmp.etl`: per-account results and WFP attribution capture.
- `icmp-diagnostics/b4cdd6d194ac4912be56c9e597cbf159/diagnostic.log`:
  machine-wide before/during/after results for both accounts.
- `icmp-per-user-attempt.patch`: the experimental filters and echo probes.
- `icmp-machine-probe.cpp`: the temporary machine-wide comparison probe.

These were experimental probes, not tests retained in the normal suite.
They cover loopback echo through the named Windows APIs on the tested build.
Non-loopback destinations, raw sockets, ICMP errors, and IPv6 control traffic
were not acceptance-tested. ALE classifies non-error ICMP messages; errors use
separate layers, as described in [Microsoft's ALE documentation](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-stateful-filtering).

A per-account solution must retain the initiating account's identity at its
enforcement point. No such solution was established by these probes. A WFP
callout driver must not be assumed to recover the missing identity without a
separate feasibility probe.
