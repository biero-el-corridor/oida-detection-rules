# OIDA Detection Rules

Suricata rules that detect the **behaviour** of [OIDA](https://getoida.dev)
(`oida-ics`) while it assesses OT/ICS protocols.

OIDA is not detected by a port or a payload signature: it speaks the real
protocol. The rules therefore match the protocol operations OIDA performs, and
correlate several operations that belong to the same scan.

> These rules are for defensive monitoring of authorised assessments. OIDA can
> stop CPUs, write process values and extract credentials. Test only against
> systems you own or have written authorisation to assess.

## Coverage

| Protocol | Folder | Fingerprinted command | Status |
| --- | --- | --- | --- |
| Siemens S7comm | [`s7comm/`](s7comm/) → [`s7 -i/`](s7comm/s7%20-i/) | `oida s7 <IP> -i` | rules + reference capture |
| Modbus TCP | — | — | planned |
| OPC UA | — | — | planned |
| IEC 60870-5-104 | — | — | planned |

Each protocol folder contains:

- a `README.md` with the OIDA capability map for that protocol;
- one subfolder per fingerprinted command, with its own `README.md`, Suricata
  rules, reference capture and output.

## Design

Rules are built in two layers:

1. **Atomic indicators** — one rule per invariant protocol operation. Each rule
   sets an `xbits` flag with `track ip_pair, expire 5` so the flag survives the
   short-lived TCP sessions OIDA opens during discovery.
2. **Correlation** — one rule that fires only when all atomic indicators for the
   same IP pair are present inside the 5-second window. This is what separates
   an OIDA fingerprint from an HMI or engineering station that happens to read
   the same object once.

Conventions:

- SID range `9999900`–`9999999`; SIDs are stable across revisions.
- `classtype:attempted-recon`; priorities 1 (correlated fingerprint), 2
  (dangerous operation), 3 (single recon request).
- Rules are `alert`-only by default. Tune to `drop` or add thresholds for your
  environment after baselining normal PLC traffic.

## Repository layout

```text
.
├── README.md
└── s7comm/
    ├── README.md                         # OIDA S7 capability map
    └── s7 -i/
        ├── README.md                     # -i PDU sequence and detection logic
        ├── oida_s7_-i_detection.rules
        ├── oida_-i_snap7.pcapng
        └── oida_s7_i.png
```

## Validate a rule set

```bash
# replay a capture through the rules
suricata -r request.pcapng \
  -S "s7comm/s7 -i/oida_s7_-i_detection.rules" \
  -l /tmp/oida-rules --runmode single -k none

# show the alerts
cat /tmp/oida-rules/fast.log
```

For the S7 reference capture (`s7comm/s7 -i/oida_-i_snap7.pcapng`, 77 packets,
`oida s7 127.0.0.1 -i -p 10102` against a local mock):

```bash
suricata -r "s7comm/s7 -i/oida_-i_snap7.pcapng" \
  -S "s7comm/s7 -i/oida_s7_-i_detection.rules" \
  -l /tmp/oida-s7 --runmode single -k none
```

Expected: rules `9999901`, `9999902`, `9999903`, `9999905` and `9999920` alert.
See [`s7comm/s7 -i/README.md`](s7comm/s7%20-i/README.md) for the per-rule
result and the reasoning behind each match.

## Adding a protocol

1. Capture one OIDA run against a lab device or mock service.
2. Extract the request sequence (`tshark -Y <protocol>` or the protocol
   dissector fields). Keep only operations that the command always performs.
3. Write one atomic rule per operation; anchor on the protocol header and the
   operation code, not on IP addresses or TCP ports alone.
4. Set a uniquely named `xbits` flag. Use `track ip_pair` when OIDA opens more
   than one TCP session per run.
5. Add a correlation rule that requires all flags; verify it fires on the
   capture, not only the atomic rules.
6. Add a protocol README documenting command, packet sequence, rule table and
   false-positive notes.

## References

- OIDA documentation: <https://getoida.dev>
- OIDA source and protocol implementations: <https://github.com/f0rw4rd/oida>
- S7comm protocol reference: Wireshark `s7comm` dissector and Siemens
  S7-300/400 system software documentation.
