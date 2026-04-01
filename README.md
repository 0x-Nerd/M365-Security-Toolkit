# M365 Security Toolkit

A collection of PowerShell tools for Microsoft 365 security operations. Built from real-world incident response and security engineering experience across enterprise M365 environments.

---

## Purpose

These tools are designed to support security engineers and administrators responding to incidents, auditing tenant security posture, and hardening Microsoft 365 environments. Each script addresses a specific operational security need encountered in production environments.

---

## Tools

| Script | Description | Category |
|--------|-------------|----------|
| `Invoke-CompromisedAccountResponse.ps1` | Automated response to compromised M365 accounts — disable, revoke sessions, capture forensic data, audit mailbox rules | Incident Response |

*Additional tools added continuously.*

---

## Requirements

- PowerShell 5.1 or later
- Microsoft Graph PowerShell SDK
- Exchange Online Management Module
- Appropriate M365 administrative permissions

---

## Usage

Each script includes inline documentation and parameter definitions. See individual script headers for specific requirements and usage examples.

---

## Structure
```
M365-Security-Toolkit/
├── Incident-Response/
│   └── Invoke-CompromisedAccountResponse.ps1
├── Identity-Auditing/
├── Tenant-Hardening/
└── README.md
```

---

## Disclaimer

These scripts are provided as-is for educational and operational use. Always test in a non-production environment before deploying. Ensure you have appropriate authorization before running any script against an M365 tenant.

---

## Author

Stephen Cothron — Security & Infrastructure Engineer
[LinkedIn](https://www.linkedin.com/in/stephencothron/)
