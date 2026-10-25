# OPC UA — OIDA capability map

OIDA's OPC UA engine (asyncua) against `opc.tcp` endpoints. This page maps the
`oida opcua` command surface; the per-command detection notes live in the
fingerprint subfolders.

Reference version: OIDA 1.0.6. Default port: `4840`. The target may be a full
URL (`opc.tcp://host:port`) or a host with `-p/--port`.

A plain `oida opcua <target>` is already a **two-connection** run when phase B
runs (anonymous endpoint or supplied credentials):

1. **Pre-auth discovery** — `SecurityPolicy#None`, `HEL/ACK`, `OPN`,
   `GetEndpoints` with a null session token, `CloseSecureChannel`.
2. **Session** — `CreateSession`, `ActivateSession`, BuildInfo read, nine
   diagnostics/security reads, certificate check, endpoint count, close.

The `--get-endpoints` flag adds a third `GetEndpoints` and prints the endpoint
table. The full behaviour is documented in
[`get-endpoint/README.md`](get-endpoint/README.md).

## Contents

| Path | Content |
| --- | --- |
| [`get-endpoint/`](get-endpoint/) | fingerprint for `oida opcua <target> --get-endpoints` |
| [`get-endpoint/README.md`](get-endpoint/README.md) | connection/PDU sequence, secure channel, endpoint map, rule table, validation |
| [`get-endpoint/oida_opcua_get_endpoints.rules`](get-endpoint/oida_opcua_get_endpoints.rules) | Suricata rules, SIDs `9999930`-`9999950` |
| [`get-endpoint/get-endpoints.pcapng`](get-endpoint/get-endpoints.pcapng) | reference capture, 60 packets, 2 TCP streams |

## Command surface

### Target and connection

| Option | Meaning | Default |
| --- | --- | --- |
| positional target | `opc.tcp://host:port` or host | — |
| `-p/--port` | TCP port (a port in the target wins) | `4840` |
| `--timeout` | connect/operation timeout (s) | `2` |

### Security

| Option | Meaning | Default |
| --- | --- | --- |
| `--mode/--security-mode` | `None`, `Sign`, `SignAndEncrypt` | `None` |
| `--policy/--security-policy` | `None`, `Basic128Rsa15`, `Basic256`, `Basic256Sha256` | `None` |
| `--certificate` | client certificate (DER/PEM) | auto-generated for Sign/Encrypt |
| `--privatekey` | client private key | auto-generated for Sign/Encrypt |

`Sign`/`SignAndEncrypt` with `--policy None` is upgraded to `Basic256Sha256`
with a warning. If no client keypair is supplied, OIDA generates one for the
session. The CLI exposes four policy names in 1.0.6; the internal policy map
also contains the AES variants, but they are not selectable through
`--policy`.

### Authentication

| Option | Meaning | Default |
| --- | --- | --- |
| `-u/--username` | username, or a file of usernames | anonymous |
| `-P/--password` | password, or a file of passwords | anonymous |
| `--brute-rate` | delay between credential attempts (s) | `0.5` |
| `--continue-on-success` | keep testing after a valid hit | stop on first hit |

OPC UA does not offer `--credentials`, `--brute`, `--wordlist` or
`--default-creds`: credential testing is driven by passing a file to
`--username` and/or `--password`. An empty password (`-P ''`) is a valid
explicit credential.

### Discovery and mapping

| Option | Capability | Writes |
| --- | --- | --- |
| `--get-endpoints` | list endpoints, policies, modes, levels and user-token types | no |
| `--find-servers` | `FindServers` discovery service | no |
| `--find-servers-on-network` | GDS/LDS `FindServersOnNetwork` | no |
| `--gds-url URL` | GDS endpoint for the network discovery call | — |

### Address space dump

| Option | Capability | Default |
| --- | --- | --- |
| `-d/--dump` | fast dump: names/types | — |
| `-D/--dump-all` | full dump: DataType, access levels | — |
| `--dump-values` | include current values (use with `--dump-all`) | — |
| `--dump-methods` | methods only | — |
| `--dump-write` | writable variables only | — |
| `--dump-namespaces` | namespace table only | — |
| `--dump-examples` | ready-to-run examples (use with `--dump-methods`) | — |
| `--dump-history` | nodes with historizing enabled | — |
| `--dump-files` | `FileType` nodes | — |
| `--max-depth N` | maximum browse depth | `3` |
| `--max-nodes N` | maximum nodes to scan | `1000` |
| `--ns NS` | namespace filter (`2` or `2,3`) | all |
| `--start-node NODE_ID` | start browsing below a node | root |

Dump modes are mutually exclusive; `--dump-namespaces` is exclusive and stops
after the namespace table.

### Node operations

| Option | Capability | Writes |
| --- | --- | --- |
| `--node-id NODE_ID` | read one node's value | no |
| `--node-id NODE_ID --read-attributes` | read all attributes | no |
| `--node-id NODE_ID --write-value VALUE` | write a value | `--confirm` |

### Methods

| Option | Capability | Writes |
| --- | --- | --- |
| `--call-method NODE_ID` | call a method | `--confirm` |
| `--method-args JSON` | JSON array of arguments | — |

### Subscriptions and monitoring

| Option | Capability | Default |
| --- | --- | --- |
| `--subscribe` | subscribe to node value changes | — |
| `--subscribe-events` | subscribe to server events and alarms | — |
| `--subscription-interval MS` | publishing interval | `1000` ms |
| `--duration SECS` | stop after N seconds (`0` = until stopped) | no limit |

`--monitor` and `--interval` are not offered: OPC UA watches values by
subscribing, not by polling.

### Historical data

| Option | Capability | Default |
| --- | --- | --- |
| `--history-read` | read history for `--node-id` | — |
| `--history-start DATETIME` | start time (ISO) | server default |
| `--history-end DATETIME` | end time (ISO) | now |
| `--history-max N` | maximum values | `100` |
| `--history-raw` | raw data points (the only supported mode) | — |

### File transfer (`FileType` nodes)

| Option | Capability | Writes |
| --- | --- | --- |
| `--read-file PATH` | download a file | no |
| `--file-output PATH` | local output for a download | — |
| `--write-file PATH` | upload a file | `--confirm` |
| `--file-data PATH_OR_DATA` | data/path to upload | — |

### Security analysis

| Option | Capability | Writes |
| --- | --- | --- |
| `--test-cert-trust` | does the server trust self-signed application/user certificates? | probe |
| `--test-subscription-limits` | subscription-exhaustion test | `--confirm` |
| `--scan-writable` | find writable nodes via AccessLevel/AccessRestrictions | no |
| `--test-rbac` | compare access across auth methods | auth probes |
| `--rbac-detailed` | per-node permission matrix for the RBAC test | — |

### Fuzzing

| Option | Capability | Default |
| --- | --- | --- |
| `--fuzz` | enable fuzzing (requires `--confirm`) | — |
| `--fuzz-mode` | `nodes`, `methods`, `all` | `nodes` |
| `--fuzz-node NODE_ID` | fuzz one node | — |
| `--fuzz-method NODE_ID` | fuzz one method | — |
| `--fuzz-iterations N` | mutations per target | `10` |
| `--fuzz-max-targets N` | maximum auto-discovered targets | `10` |

## Dangerous operations

These flags change server state or can disrupt it and are refused without
`--confirm`:

- `--write-value`
- `--call-method`
- `--write-file`
- `--test-subscription-limits`
- `--fuzz` (and `--fuzz-node`/`--fuzz-method`)

Read-only or probe operations (`--get-endpoints`, `--find-servers`, `--dump*`,
`--read-attributes`, `--history-read`, `--read-file`, `--scan-writable`,
`--test-cert-trust`, `--test-rbac`, `--subscribe*`) do not require `--confirm`,
although `--test-cert-trust` and `--test-rbac` do authenticate against the
server.

## What a default scan maps

Even without an explicit operation flag, OIDA performs the endpoint/security
mapping when phase B runs (anonymous endpoint or supplied credentials):

- pre-auth `GetEndpoints` → endpoint count, modes, policies, token types,
  certificate;
- `CreateSession` / `ActivateSession` → authentication type;
- BuildInfo (`ns=0;i=2260`) → product, vendor, version, build;
- nine diagnostics/security reads (`2994`, `2269`, `2294`, `2279`, `2287`,
  `2277`, `3707`, `3708`, `3709`) → auditing, RBAC profile, diagnostics leak,
  rejection counters, active sessions, per-session auth data, redundancy;
- post-auth `GetEndpoints` → certificate check and endpoint count.

`--get-endpoints` adds the printed endpoint table (third `GetEndpoints` call).
The full mapping logic is in
[`get-endpoint/README.md`](get-endpoint/README.md).

## Fingerprints

| Command | Subfolder | Detection |
| --- | --- | --- |
| `oida opcua <target> --get-endpoints` | [`get-endpoint/`](get-endpoint/) | 14 rules: pre-auth `GetEndpoints`, FreeOpcUa/asyncua client identity, BuildInfo + nine reads, 3 × `GetEndpoints`, correlation `9999950` |

SIDs `9999930`-`9999950`. The rules are included in the repository-root
[`oida_detection.rules`](../oida_detection.rules), generated by `make rules`.

## References

- [`get-endpoint/README.md`](get-endpoint/README.md) — behaviour, secure
  channel, session, endpoint map, FreeOpcUa/asyncua distinction, rules.
- OIDA source: `src/oida/protocols/opcua/proto_args.py`,
  `cli_runner.py`, `scanner.py`, `mixins/*.py`.
- OPC UA Part 2 (Security Model), Part 4 (Services), Part 6 (Mappings).
- Claroty Team82, *OPC UA Deep Dive (Part 3)* —
  <https://fr.claroty.com/team82/research/opc-ua-deep-dive-part-3-exploring-the-opc-ua-protocol>.
