# SWS202 – Assignment 04 | Active Directory Attacks Lab
## Part A — Theory Questions

---

## Q1. Kerberos Normal Authentication Flow [1 mark]

The Kerberos authentication process follows five distinct steps, each involving specific principals and data exchanges:

**Step 1 — AS-REQ (Client → KDC/AS):**
The client initiates authentication by sending an **Authentication Service Request (AS-REQ)** to the Key Distribution Center (KDC), specifically its Authentication Service (AS) component. The client sends its username and a timestamp encrypted with a key derived from the user's password hash. Nothing sensitive (like the actual password) is transmitted in cleartext.

**Step 2 — AS-REP (KDC/AS → Client):**
The KDC validates the request and, if the user is found in Active Directory, responds with an **AS-REP** containing two items: (a) a **Ticket Granting Ticket (TGT)** encrypted with the KRBTGT account's secret hash (so only the KDC can read it), and (b) a session key encrypted with the user's own key. The TGT contains the user's identity and a copy of the session key, and it is valid for a limited time (typically 10 hours). The client cannot decrypt the TGT itself — it is an opaque token used purely for future requests.

**Step 3 — TGS-REQ (Client → KDC/TGS):**
When the client wants to access a specific service, it sends a **Ticket Granting Service Request (TGS-REQ)** to the TGS component of the KDC. This request includes the TGT obtained in Step 2 and the **Service Principal Name (SPN)** of the target service (e.g., `MSSQLSvc/dbserver.corp.local:1433`). The SPN uniquely identifies the service the client wants to reach.

**Step 4 — TGS-REP (KDC/TGS → Client):**
The KDC decrypts the TGT to verify the client's identity and session key, then issues a **TGS ticket (service ticket)** encrypted with the secret key of the target service account — the account associated with the requested SPN. The client receives this TGS ticket but cannot decrypt it, since it is encrypted with the service account's hash, not the user's.

**Step 5 — AP-REQ (Client → Target Service):**
The client presents the TGS ticket directly to the target service in an **Application Request (AP-REQ)**. The service decrypts the ticket using its own secret key, verifies the client's identity embedded inside, and grants or denies access. Crucially, the KDC is not contacted at this step — the service handles authentication locally using the ticket.

**Summary of roles:**
- **KDC** — issues both TGTs (via AS) and TGS tickets (via TGS); it is the central trust authority.
- **TGT** — a proof-of-identity token; allows the client to request service tickets without re-entering credentials.
- **TGS ticket** — a service-specific access token encrypted with the service account's hash.
- **SPN** — the identifier that maps a service to its associated account in Active Directory.

---

## Q2. Kerberos vs. Kerberoasting Comparison [1 mark]

| Aspect | Kerberos (Protocol) | Kerberoasting (Attack) |
|---|---|---|
| **Type** | Authentication protocol | Offline credential attack |
| **Purpose** | Securely authenticate users and grant access to network services without transmitting passwords | Extract and crack service account password hashes to gain plaintext credentials |
| **Nature** | Legitimate, by-design network authentication mechanism | Exploitation of a legitimate Kerberos feature |
| **Ticket Involved** | TGT (Ticket Granting Ticket) and TGS ticket | TGS ticket (service ticket) specifically |

**Why Kerberoasting is possible:**

Kerberoasting exploits a fundamental design feature of the Kerberos protocol: any authenticated domain user can request a TGS ticket for any SPN registered in Active Directory — no special privileges are required. Because the TGS ticket is encrypted using the password hash of the service account associated with the SPN, an attacker who requests this ticket receives a blob of ciphertext that is directly derived from the service account's password. The attacker can then take this encrypted ticket offline and subject it to brute-force or dictionary attacks (using tools like Hashcat) without ever generating any further network traffic or alerts. The attack is possible because the Kerberos protocol was designed for interoperability and availability, trusting that any authenticated domain user has a legitimate reason to request service tickets — it does not restrict which accounts can be targeted or rate-limit ticket requests.

---

## Q3. Key Active Directory Terms Defined [0.5 marks]

**(a) LDAP — Lightweight Directory Access Protocol**
LDAP is a standardised network protocol used to query and modify directory services, operating on **port 389** (plaintext) or port 636 (LDAPS/TLS). In an Active Directory environment, LDAP is the primary mechanism through which clients, tools, and services read directory objects — users, groups, computers, and SPNs. From an attacker's perspective, LDAP is invaluable during enumeration: tools such as `ldapsearch`, BloodHound, and PowerView use unauthenticated or low-privilege LDAP queries to map the entire domain structure, identify privileged accounts, find Kerberoastable SPNs, and discover misconfigured ACLs — all without triggering typical security alerts.

**(b) SPN — Service Principal Name**
An SPN is a unique identifier that associates a specific network service with the Active Directory account running that service (e.g., `MSSQLSvc/dbserver.corp.local:1433` mapped to the `svc_sql` account). SPNs have no dedicated port number — they are attributes stored within AD objects. In an attack context, SPNs are central to **Kerberoasting**: enumerating accounts with SPNs (via `GetUserSPNs.py` or PowerView) reveals service accounts whose password hashes can be requested as TGS tickets and cracked offline. Service accounts with SPNs often have weak, infrequently rotated passwords, making them high-value targets.

**(c) Domain Controller (DC)**
A Domain Controller is a Windows Server that hosts and manages the Active Directory database (NTDS.dit), handling authentication (Kerberos and NTLM), policy enforcement (Group Policy), and directory replication across the domain. It listens on multiple ports including 88 (Kerberos), 389 (LDAP), 445 (SMB), and 3268 (Global Catalog). In Active Directory attacks, the DC is the ultimate target: compromising it via techniques like DCSync, Golden Ticket forgery, or Pass-the-Ticket grants an attacker complete control over all domain identities. The DC also stores the KRBTGT hash, which is required to forge Golden Tickets.

**(d) BloodHound / SharpHound**
BloodHound is an open-source Active Directory attack path visualisation tool that ingests data collected by its companion collector, **SharpHound** (a C# executable, no dedicated port). SharpHound runs on a domain-joined host and uses LDAP queries and Windows API calls to gather information about users, groups, sessions, ACLs, and trust relationships. BloodHound then graphs this data and uses graph theory to automatically identify the shortest attack paths to Domain Admin. In an attack scenario, BloodHound reveals non-obvious privilege escalation routes — for example, showing that a low-privilege user has `GenericAll` over a group that contains a Domain Admin — which would be nearly impossible to discover manually in large environments.

---

## Q4. Golden Ticket vs. Silver Ticket Comparison [0.5 marks]

| Aspect | Golden Ticket | Silver Ticket |
|---|---|---|
| **Scope** | Domain-wide — grants access to **any** service across the entire domain | Service-specific — grants access to **one specific service** on one host (e.g., CIFS on a single server) |
| **Hash Required** | KRBTGT account's NTLM hash (obtained via DCSync or NTDS.dit dump) | Target **service account's** NTLM hash (e.g., the computer account or a service account hash) |
| **KDC Contact** | None required after forging — the KDC is bypassed entirely for service access | None required — the ticket is presented directly to the target service, bypassing the KDC completely |
| **Stealth Level** | Lower stealth — domain-wide access generates more activity; KRBTGT hash compromise is a critical indicator | Higher stealth — traffic stays between the client and the single target service; no KDC logs are generated |

**Why Silver Tickets are harder to detect:**

A Silver Ticket is significantly harder to detect than a Golden Ticket because it is never validated by the KDC — it is presented directly to the target service, which decrypts it using its own local secret key and grants access without contacting the domain controller at all. This means no Kerberos event logs are generated on the DC (such as Event ID 4768 or 4769), and the forged ticket never appears in any centralised authentication log. A Golden Ticket, while also bypassing the KDC for individual service requests, typically requires broader domain traversal that can trigger anomalous Kerberos ticket-granting events; additionally, KRBTGT compromise is often detected through DCSync alerts or NTDS.dit access logs. Silver Ticket activity, by contrast, is confined to a single service's local event log, which is rarely monitored with the same rigour as domain controllers.

---

## Q5. ACL/ACE Misconfigurations in Active Directory [0.5 marks]

**What is an ACL/ACE Misconfiguration?**

In Active Directory, every object (user, group, GPO, OU) has an **Access Control List (ACL)** — a list of **Access Control Entries (ACEs)** that define which principals (users, groups, computers) have which permissions over that object. An ACL/ACE misconfiguration occurs when excessive or unintended permissions are granted to a principal that should not hold them — for example, granting a standard domain user `GenericAll` rights over a privileged group. These misconfigurations frequently arise from legacy administrative shortcuts, group nesting errors, or delegation gone wrong, and they create invisible privilege escalation paths that BloodHound readily identifies.

---

**Permission 1 — GenericAll**

**(a) What an attacker can do:**
`GenericAll` is the most powerful permission in Active Directory — it grants full control over the target object. If an attacker-controlled account holds `GenericAll` over a **user object**, they can reset that user's password, modify their attributes, or add an SPN to Kerberoast them. If held over a **group object**, the attacker can add any user (including themselves) to that group. If held over a **computer object**, the attacker can perform Resource-Based Constrained Delegation (RBCD) abuse.

**(b) Realistic privilege escalation scenario:**
Suppose a compromised low-privilege user `jdoe` is found (via BloodHound) to have `GenericAll` over the `IT_Admins` group, which contains a Domain Admin. The attacker uses PowerView to add `jdoe` directly to `IT_Admins`:
```
Add-DomainGroupMember -Identity 'IT_Admins' -Members 'jdoe'
```
After re-authenticating, `jdoe` now inherits all privileges of the `IT_Admins` group, granting domain administrator access and completing a full privilege escalation from a standard user to Domain Admin without exploiting any software vulnerability.

---

**Permission 2 — WriteDACL**

**(a) What an attacker can do:**
`WriteDACL` (Write Discretionary Access Control List) allows an attacker to **modify the ACL of the target object** — effectively rewriting the permissions on it. This means the attacker can grant themselves (or any other principal) any permission they choose, including `GenericAll`, `DCSync` rights (`DS-Replication-Get-Changes-All`), or full write access. It turns a limited foothold into arbitrary object control.

**(b) Realistic privilege escalation scenario:**
An attacker has compromised a service account `svc_monitor` and discovers via BloodHound that this account holds `WriteDACL` over the **domain object** itself. The attacker uses PowerView to grant `svc_monitor` DCSync replication rights:
```
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity svc_monitor -Rights DCSync
```
With DCSync rights, the attacker runs Mimikatz (`lsadump::dcsync /user:krbtgt`) to dump the KRBTGT hash and all domain account hashes, effectively achieving full domain compromise — all without ever logging into a domain controller.

---

## Q6. Persistence Techniques After Domain Admin Access [0.5 marks]

**Context:** Once an attacker achieves Domain Admin access, their primary goal shifts from escalation to maintaining that access — even if passwords are reset or incidents are partially remediated. Two powerful techniques for this are **Golden Ticket Persistence** and **DCSync Backdoor via AdminSDHolder**.

---

**Technique 1 — Golden Ticket Persistence**

**(a) How it works:**
After dumping the KRBTGT account's NTLM hash (via Mimikatz `lsadump::dcsync`), an attacker can forge a Golden Ticket at any time — even months later — using that hash offline. The forged TGT contains a self-defined identity (e.g., a non-existent user with Domain Admin group membership) and is encrypted with the stolen KRBTGT key, making it indistinguishable from a legitimately issued ticket from the KDC's perspective.
```
kerberos::golden /user:FakeAdmin /domain:corp.local /sid:S-1-5-21-... /krbtgt:<hash> /ptt
```

**(b) Why it survives incident response:**
Golden Ticket persistence survives password resets on all service and admin accounts because it is not tied to any user account's password — it is tied exclusively to the KRBTGT hash. Even if every domain user's password is reset during incident response, the Golden Ticket remains valid until the KRBTGT account's password is reset **twice** (to invalidate all outstanding tickets). Most incident responders reset user account passwords without performing the dual KRBTGT rotation, leaving the backdoor fully functional.

**(c) How a defender removes it:**
The KRBTGT account password must be reset **twice**, at least 10 hours apart (the default TGT lifetime), to invalidate all forged and legitimate tickets based on the old hash. Microsoft's `New-KrbtgtKeys.ps1` script automates this safely in production environments. Defenders should also monitor for Event ID 4769 with unusual encryption types (RC4 in modern environments) and anomalous TGT lifetimes via Microsoft Defender for Identity or a SIEM.

---

**Technique 2 — DCSync Backdoor via AdminSDHolder**

**(a) How it works:**
**AdminSDHolder** is a special AD container object (`CN=AdminSDHolder,CN=System,DC=...`) whose ACL is used as a template to protect privileged group members. Every 60 minutes, a background process called **SDProp (Security Descriptor Propagator)** copies the AdminSDHolder's ACL onto all members of protected groups (Domain Admins, Enterprise Admins, etc.), overwriting any manual ACL changes made to those accounts. An attacker with Domain Admin access can add a malicious ACE — such as granting a low-privilege account `GenericAll` or DCSync rights — to the AdminSDHolder object itself. SDProp then automatically propagates this backdoor ACE to all protected accounts every hour, permanently.

**(b) Why it survives incident response:**
This technique is extremely resilient: if a defender manually removes the rogue ACE from a protected user object, SDProp will restore it automatically within 60 minutes. Even after the original Domain Admin session is terminated, the compromised low-privilege account retains its elevated permissions. Because AdminSDHolder is an obscure AD internal object, it is rarely checked during standard incident response, and the propagation occurs silently with no user-facing events.

**(c) How a defender removes it:**
The malicious ACE must be removed from the **AdminSDHolder object itself** — not from individual protected accounts — using AD Users and Computers (enable Advanced Features → System → AdminSDHolder → Properties → Security) or PowerShell (`Get-Acl`/`Set-Acl`). After cleaning AdminSDHolder, SDProp will then push the corrected ACL to all protected accounts. Defenders should audit AdminSDHolder permissions regularly using BloodHound or `Get-DomainObjectAcl` and monitor Event ID 4662 for unexpected replication-related permission grants.

---
