# Network Intrusion Detection
A Python-based network intrusion detection system (NIDS) built incrementally, starting from rule-based detection and evolving toward ML-powered classification.

## Roadmap
### Part 1: Rule Based Detection
> Working detector using rules before moving to the ML
- Parse raw network logs (CSV/PCAP-style)
- Define traffic feature schema (src/dst IP, port, protocol, byte count, duration)
- Implement rule engine: port scanning detection, SYN flood detection, brute force login attempts
- CLI: run detection on a log file, print flagged connections
- Add thresholds config (config.json)
- Unit tests for rule engine

## Attack Categories (NSL-KDD)
 
| Category | Description | Examples |
|----------|-------------|---------|
| DoS | Denial of Service — overwhelm the target | SYN flood, Ping of Death |
| Probe | Surveillance / port scanning | nmap, ipsweep |
| R2L | Remote to Local — unauthorised access | FTP brute force, phf |
| U2R | User to Root — privilege escalation | buffer overflow, rootkit |
 
---