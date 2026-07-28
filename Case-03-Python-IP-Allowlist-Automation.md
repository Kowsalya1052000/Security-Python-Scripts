Case 03 — Python Algorithm: Automated IP Allowlist Management
---
Analyst: Kowsalya  
Date: May 2026  
Language: Python 3  
Category: Security Automation / Access Control  
Skill Demonstrated: Python scripting for security operations
---
Project Overview
Manual management of IP allowlists is prone to human error and "permission
creep" — where access that should be removed is forgotten and left active.
This increases an organisation's attack surface over time.
This project develops a Python automation tool that:
Reads an existing IP allowlist from a file
Compares it against a list of IPs to be removed
Automatically removes unauthorised IPs
Updates the allowlist file with the cleaned list
---
Problem Statement
A corporate network restricts access to sensitive content using an IP
allowlist stored in `allow_list.txt`. Over time, certain IP addresses
that previously had access should be revoked — for example, when employees
leave or contractors finish their engagement.
Manually editing this file creates risk. An automated algorithm ensures
accuracy and consistency every time it runs.
---
Algorithm Design
```
1. Open allow_list.txt
2. Read all IP addresses into memory
3. Convert the string of IPs into a list
4. Loop through each IP in the remove_list
5. If the IP exists in the allowlist → remove it
6. Convert the cleaned list back to a string
7. Write the updated list back to allow_list.txt
```
---
Python Code
```python
# Security Automation: IP Allowlist Management
# Analyst: Kowsalya
# Purpose: Automatically remove revoked IPs from corporate allowlist

# Define the allowlist file and IPs to remove
import_file = "allow_list.txt"

remove_list = [
    "192.168.1.101",
    "192.168.1.205",
    "10.0.0.45"
]

# Step 1 & 2: Open and read the allowlist file
with open(import_file, "r") as file:
    ip_addresses = file.read()

# Step 3: Convert the string into a list
ip_addresses = ip_addresses.split()

# Step 4 & 5: Iterate through remove_list and remove matching IPs
for element in remove_list:
    if element in ip_addresses:
        ip_addresses.remove(element)

# Step 6: Convert the cleaned list back to a string
ip_addresses = "\n".join(ip_addresses)

# Step 7: Write the updated allowlist back to the file
with open(import_file, "w") as file:
    file.write(ip_addresses)

print("Allowlist updated successfully.")
print(f"Removed IPs: {remove_list}")
```
---
Code Explanation
Step	Code Used	Purpose
Open file	`open(import_file, "r")`	Opens allowlist in read mode
Read contents	`.read()`	Reads entire file as one string
Convert to list	`.split()`	Splits string into individual IP addresses
Loop and check	`for element in remove_list`	Iterates through each IP to be removed
Remove IP	`.remove(element)`	Removes matching IP from the list
Rejoin to string	`"\n".join(ip_addresses)`	Converts list back to string for file writing
Write back	`open(import_file, "w")`	Overwrites file with updated allowlist
---
Security Relevance
Concept	Application
Least Privilege	Removing IPs ensures only authorised users retain access
Access Control	Automated enforcement prevents manual error
Permission Creep Prevention	Old/expired IPs are consistently removed
Audit Trail	Script can be extended to log all removals with timestamps
---
Potential Enhancements
```python
# Enhancement 1: Add logging for audit trail
import logging
from datetime import datetime

logging.basicConfig(filename="allowlist_audit.log", level=logging.INFO)

for element in remove_list:
    if element in ip_addresses:
        ip_addresses.remove(element)
        logging.info(f"{datetime.now()} - Removed IP: {element}")

# Enhancement 2: Add timestamp to track when list was last updated
# Enhancement 3: Cross-reference against threat intelligence feeds
# Enhancement 4: Alert security team when specific high-risk IPs are found
```
---
MITRE ATT&CK Relevance
Tactic	Technique	How This Script Helps
Initial Access	Valid Accounts (T1078)	Revokes access from expired/terminated accounts
Persistence	Account Manipulation (T1098)	Prevents unauthorised IPs from maintaining access
---
Lessons Learned
Python's `.split()` and `.join()` methods make file-based list management
clean and efficient
Automation eliminates the risk of human error in access control management
This script can be scheduled as a cron job to run automatically — for
example, nightly — ensuring the allowlist is always current
Adding logging transforms this from a utility script into an auditable
security control
---
Tools & Libraries
Python 3 — core scripting language
Built-in file I/O — open(), read(), write()
String methods — .split(), .join(), .remove()
logging module — for audit trail enhancement
