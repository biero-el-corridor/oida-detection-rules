# Siemens S7comm — OIDA capability map

OIDA's classic S7comm engine (Snap7) against TCP/102. This page maps the
`oida s7` command surface; the per-command detection notes live in the
fingerprint subfolders.

Reference version: OIDA 1.0.6. S7comm-plus is not implemented in this version:
S7-1200/1500 targets print `S7CommPlus protocol NOT SUPPORTED` and fall back to
classic Snap7 access.

## Contents

| Path | Content |
| --- | --- |
| [`s7 -i/`](s7%20-i/) | fingerprint for `oida s7 <IP> -i` |
| [`s7 -i/README.md`](s7%20-i/README.md) | PDU sequence, rule table, validation |
| [`s7 -i/oida_s7_-i_detection.rules`](s7%20-i/oida_s7_-i_detection.rules) | Suricata rules |
| [`s7 -i/oida_-i_snap7.pcapng`](s7%20-i/oida_-i_snap7.pcapng) | reference capture, 77 packets |

## Command surface

### Connection

| Option | Meaning | Default |
| --- | --- | --- |
| `-p/--port` | TCP port | `102` |
| `-R/--rack` | PLC rack | `0` |
| `-s/--slot` | PLC slot; omit to auto-scan | auto |
| `-P/--password` | PLC password, or wordlist path to brute-force | — |
| `--connection-type` | `PG`, `OP`, `S7Basic` | `PG` |
| `--pdu-size` | `240`, `480`, `960` | `480` |
| `--timeout` | connect/operation timeout (s) | `2` |

### Discovery and system information

| Option | Capability | Writes |
| --- | --- | --- |
| `-i/--info` | CPU info, run state, order code, firmware, PDU, clock, CP info | no |
| `-e/--enumerate-dbs` | enumerate data blocks | no |
| `-T/--test-memory-areas` | read I/Q/M/C/T access; with `--confirm`, write the same byte back | gated |
| `-F/--full-scan` | sweep all rack/slot combinations | no |
| `-S/--scan-programs` | block counts per type | no |
| `-L/--list-szl` | list advertised SZL IDs | no |
| `-E/--enumerate-szl` | read module ID, protection, communication and diagnostic SZL | no |
| `--read-szl-id ID:INDEX` | read one arbitrary SZL | no |
| `-G/--get-datetime` | read PLC clock | no |

### Memory

| Option | Capability | Writes |
| --- | --- | --- |
| `-I/--read-inputs START:SIZE` | read process inputs | no |
| `-Q/--read-outputs START:SIZE` | read process outputs | no |
| `-M/--read-markers START:SIZE` | read markers | no |
| `--read-timers`, `--read-counters` | read timers/counters (S7-300/400) | no |
| `-r/--read-db DB:START:SIZE` | read a DB range | no |
| `-D/--dump-db NUM` | hex dump a whole DB | no |
| `-w/--write-db DB:START:HEXDATA` | write DB bytes | `--confirm` |
| `--write-markers`, `--write-outputs`, `--write-inputs` | write memory areas | `--confirm` |
| `--write-timers`, `--write-counters` | write timers/counters | `--confirm` |
| `--db-fill DB:BYTE` | fill a DB with one byte | `--confirm` |
| `--test-write` | read a byte and write it back unchanged | `--confirm` |

### Blocks

| Option | Capability | Writes |
| --- | --- | --- |
| `-l/--list-blocks` | per-type block counts (OB/FB/FC/DB/SFB/SFC/SDB) | no |
| `--list-blocks-of-type TYPE` | block numbers of one type | no |
| `-B/--get-block-info TYPE:NUM` | block metadata (MC7/load size, checksum, dates, author) | no |
| `-U/--upload-db NUM` | upload a DB | no |
| `--upload-block TYPE:NUM` | upload a full block with headers | no |
| `-O/--output-file FILE` | save an upload | no |
| `--download-db FILE --db-target NUM` | write a local file into a DB | `--confirm` |
| `--delete-block TYPE:NUM` | delete a block | `--confirm` |

### CPU, clock, monitor

| Option | Capability | Writes |
| --- | --- | --- |
| `--cpu-stop` | stop the CPU | `--confirm` |
| `--cpu-start`, `--cpu-hot-start` | hot start | `--confirm` |
| `--restart` | cold restart | `--confirm` |
| `-K/--copy-ram-to-rom` | persist RAM to ROM | `--confirm` |
| `--compress` | compact PLC memory | `--confirm` |
| `--set-datetime`, `--sync-datetime` | set PLC clock | `--confirm` |
| `--monitor` | poll and log memory changes | no |
| `--monitor-areas` | areas to watch | default `I,Q,M` |
| `--monitor-size` | bytes per area | `16` |
| `--monitor-bits` | log individual bit transitions | no |
| `--interval` | poll interval (s) | `0.5` |
| `--duration` | run time (s); `0` = until stopped | `0` |

### Credentials, audit, fuzzing

| Option | Capability | Writes |
| --- | --- | --- |
| `-n/--null-password` | test empty password | probe |
| `--default-creds` | test Siemens default passwords | `--confirm` |
| `--brute --wordlist FILE` | wordlist brute-force | `--confirm` |
| `-P FILE` | wordlist path used as a smart brute-force | `--confirm` |
| `--brute-rate` | delay between attempts (s) | `0.5` |
| `--continue-on-success` | keep testing after a hit | — |
| `--logout` | log out from the session | — |
| `--audit` | seven-stage audit | `--confirm` |
| `--audit-quick` | audit without password testing | `--confirm` |
| `--fuzz [db\|memory\|all]` | mutate and restore DB/memory values | `--confirm` |
| `--fuzz-db DB:START:SIZE` | target a DB range | — |
| `--fuzz-iterations` | mutations per target | `10` |
| `--fuzz-max-targets` | auto-discovered DB limit | `10` |

`--cpu-start` is a **hot** start; the destructive cold start is `--restart`.
`--audit` stages: device identity, CPU protection, memory access, write probe,
DB enumeration, SZL disclosure, default passwords. `--audit-quick` skips the
last stage.

## Fingerprints

| Command | Subfolder | Detection |
| --- | --- | --- |
| `oida s7 <IP> -i` | [`s7 -i/`](s7%20-i/) | SZL identification reads and correlated sequence |

The `-i` rule set targets four identification requests: all records of SZL
`0x0011`, all records of `0x001C`, index `1` of `0x001C`, and all records of
`0x0131`. See the subfolder README for the exact PDU sequence and SIDs.
