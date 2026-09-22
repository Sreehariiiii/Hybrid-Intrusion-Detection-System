# Suricata Multi-Condition Rule Changelog

This document tracks revisions, syntax adjustments, and rationale for all signatures in `config/custom_rules.rules`.

---

## [Revision 2.0.0] - 2026-09-22

### Fixed & Refactored
- **SID 1000008 (BruteForce-SSH-Patator)**: 
  - *Previous Defect*: Used payload keyword matching `content:"SSH-"` on encrypted protocol traffic.
  - *Fix*: Removed payload dependency. Converted to a purely volumetric behavioral rule matching rapid TCP SYN connection attempts to Port 22 (`flags:S,12; threshold:type both, track by_src, count 5, seconds 5`).
- **SID 1000010 (WebAttack-SQLi)**:
  - Added `nocase` to both `UNION` and `SELECT` tokens to handle casing evasion (`uNiOn sElEcT`).
- **SID 1000011 (WebAttack-XSS)**:
  - Added `nocase` to `<script` and `>` tag boundaries to handle obfuscated casing.
- **SID 1000003 & 1000004 (DoS-Slowloris & DoS-SlowHTTPTest)**:
  - Confirmed separate multi-condition rules with established TCP flow tracking and distinct header starvation signatures.
- **Rule Hot-Reloading Mechanism**:
  - Implemented `load_rules_from_file()` in `src/alert_notifier.py` allowing runtime rule loading and verification without service restart.

---

## [Revision 1.0.0] - 2026-09-21

### Initial Release
- Implemented baseline SIDs 1000001–1000013 covering CIC-IDS2018 / UNSW-NB15 attack patterns.
- Assigned structured classtypes, priorities (Severity 1 and 2), and dataset-to-SID mapping contracts.
