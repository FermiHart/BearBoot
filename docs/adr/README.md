# Architecture Decision Records — Bear Boot Protocol

ADRs capture WHY the protocol is shaped the way it is. Each is immutable once
Accepted; a reversal is a new ADR that supersedes it.

Format: Status / Context / Decision / Consequences.

| #    | Title                                              | Status   |
|------|----------------------------------------------------|----------|
| 0001 | Tag identity: 64-bit UUID = category<<48 \| id      | Accepted |
| 0002 | Integrity primitive: CRC-64/XZ (ECMA-182)          | Accepted |
| 0003 | 16-byte structure magics                           | Accepted |
| 0004 | Defensive parser / hostile-bootloader threat model | Accepted |
| 0005 | HHDM handoff contract (chicken-and-egg)            | Accepted |
| 0006 | Per-reference CRC for out-of-line data (v1.1)      | Accepted |
| 0007 | Post-link header stamping (bbp_stamp)              | Accepted |
| 0008 | Field typing & info_size coupling                  | Accepted |
| 0009 | Optional mapped walk window                        | Accepted |
| 0010 | Host-only BBPC v1 capture container                | Accepted |
| 0011 | Failure-atomic boot-source importers                | Accepted |
| 0012 | Versioned SDK and conformance surfaces             | Accepted |
| 0013 | Keep v2 profiles separate and experimental         | Accepted |
| 0014 | Separate measurement proof from authentication      | Accepted |
| 0015 | Host-only authenticated envelope and rollback state | Accepted |
| 0016 | UEFI loader physical request-pointer contract       | Accepted |
| 0017 | Firmware-independent SECURITY measurement collector | Accepted |
| 0018 | Durable generation and recovery policy              | Accepted |
| 0019 | Experimental v2 SDK surfaces                        | Accepted |
| 0020 | BBP v2 freeze requires executable gates             | Accepted |
