# Automated IP Allowlist Management

A Python script that automates the removal of revoked IP addresses from a corporate access allowlist — reducing the manual error and "permission creep" that come with hand-editing access control lists.

## The Problem

Corporate networks often restrict access to sensitive resources using an IP allowlist. When an employee leaves or a contractor's engagement ends, their IP should be revoked immediately. In practice, this is usually done manually, which means:

- Entries get forgotten and stay active long after they should be removed
- Attack surface grows quietly over time ("permission creep")
- There's no consistent, repeatable process for enforcement

This script solves that by automating the compare-and-remove step, so revocation is accurate and consistent every time it runs.

## How It Works

1. Reads the current allowlist from `allow_list.txt`
2. Compares it against a defined list of IPs to be removed
3. Removes any matching IPs from the allowlist
4. Writes the cleaned list back to `allow_list.txt`

```
Open allow_list.txt → Read IPs into memory → Compare against remove_list
→ Remove matches → Write updated list back to file
```

## Usage

1. Place the IPs you want to keep in `allow_list.txt`, one per line.
2. Edit the `remove_list` in the script with the IPs to revoke.
3. Run:

```bash
python ip_allowlist_manager.py
```

The script overwrites `allow_list.txt` with the cleaned list and prints a summary of what was removed.

## Security Relevance

| Concept | How This Script Applies It |
|---|---|
| Least Privilege | Ensures only currently authorized IPs retain access |
| Access Control | Automated enforcement removes reliance on manual review |
| Permission Creep Prevention | Expired/unauthorized IPs are consistently purged |
| Audit Trail | Extendable with logging to record every removal |

### MITRE ATT&CK Mapping

| Tactic | Technique | Relevance |
|---|---|---|
| Initial Access | Valid Accounts (T1078) | Revokes access tied to expired/terminated accounts |
| Persistence | Account Manipulation (T1098) | Prevents stale IPs from being used to maintain access |

## Planned Enhancements

- **Audit logging** — timestamped log of every IP removed (`logging` module)
- **Last-updated tracking** — record when the allowlist was last modified
- **Threat intel cross-referencing** — flag removed IPs seen in threat feeds
- **Alerting** — notify the security team if a high-risk IP is found in the allowlist
- **Scheduling** — run as a nightly cron job so the allowlist stays current automatically

## Tools & Libraries

- Python 3 (core scripting)
- Built-in file I/O — `open()`, `.read()`, `.write()`
- String methods — `.split()`, `.join()`, `.remove()`
- `logging` module (audit trail enhancement)

## Author

**Kowsalya** - Cyber Security Engineer
