# SWS202 – Assignment 04 | Active Directory Attacks Lab
## Part A — Theory Questions

---

## Q1. Kerberos Normal Authentication Flow

Kerberos works in five quick steps:
- Client → AS (AS-REQ): proves identity using a key derived from the user's password.
- AS → Client (AS-REP): returns a TGT and a session key (client can't decrypt the TGT).
- Client → TGS (TGS-REQ): sends the TGT and the target SPN to request a service ticket.
- TGS → Client (TGS-REP): issues a service ticket encrypted with the service account's key.
- Client → Service (AP-REQ): presents the service ticket; the service verifies it locally.

Roles: KDC issues tickets; TGT proves identity; service tickets grant access to specific services; SPN identifies the service.

---

## Q2. Kerberos vs. Kerberoasting Comparison 

- Kerberos: a legitimate auth protocol that issues TGTs and service tickets.
- Kerberoasting: an attack where an attacker requests a service ticket for an SPN and cracks it offline to recover the service account password.

Why it works: any domain user can request a TGS for an SPN, and the returned ticket is encrypted with the service account's hash, so it can be cracked offline.

---

## Q3. Key Active Directory Terms Defined 

- LDAP: directory protocol (ports 389/636). Used to query AD; useful for enumeration.
- SPN: maps a network service to an AD account; central to kerberoasting.
- Domain Controller (DC): hosts AD and handles authentication; a high-value target.
- BloodHound / SharpHound: SharpHound collects AD data; BloodHound visualises attack paths.

---

## Q4. Golden Ticket vs. Silver Ticket Comparison

- Golden Ticket: forged using the KRBTGT hash; gives domain-wide access.
- Silver Ticket: forged with a service account hash; works only for a specific service on a host.

Silver Tickets are quieter because they are validated only by the target service and rarely generate DC logs.

---

## Q5. ACL/ACE Misconfigurations in Active Directory

An ACL/ACE misconfiguration happens when an object has overly permissive entries, creating unintended privilege paths.

- GenericAll: full control over an object. Example: add a user to a privileged group to gain admin rights.
- WriteDACL: lets an attacker change ACLs. Example: grant DCSync rights to a service account and dump hashes.

---

## Q6. Persistence Techniques After Domain Admin Access 

- Golden Ticket: forge TGTs using KRBTGT hash; persists until KRBTGT is rotated twice.
- AdminSDHolder backdoor: add a malicious ACE to AdminSDHolder so SDProp propagates it to protected accounts; remove the ACE from AdminSDHolder to remediate.

---

# HTB Academy — AD Administration: Guided Lab Part I


## Overview

This lab simulates a day as a domain admin at Inlanefreight. The task came in via an email from Bucky Barnes asking the helpdesk to handle some routine AD work — new hires, account cleanup, a locked-out user, a new security group, and a GPO update. I connected via RDP using the provided credentials and used a mix of ADUC (the GUI snap-in) and PowerShell to get everything done.

**Connection:**
```bash
xfreerdp /v:<TARGET_IP> /u:htb-student_adm /p:Academy_student_DA!
```

---

## Task 1 — Manage Users

### Adding New Hires

Three users needed to be created under `INLANEFREIGHT.LOCAL > Corp > Employees > HQ-NYC > IT`. Each needed a full name, display name, email, and the "must change password at logon" flag set.

```powershell
Import-Module -Name ActiveDirectory

New-ADUser -Name "Andromeda Cepheus" -Enabled $true `
  -OtherAttributes @{'title'="Analyst"; 'mail'="a.cepheus@inlanefreight.local"}

New-ADUser -Name "Orion Starchaser" -Enabled $true `
  -OtherAttributes @{'title'="Analyst"; 'mail'="o.starchaser@inlanefreight.local"}

New-ADUser -Name "Artemis Callisto" -Enabled $true `
  -OtherAttributes @{'title'="Analyst"; 'mail'="a.callisto@inlanefreight.local"}
```

For the GUI: right-clicked the IT OU in ADUC, selected **New > User**, filled in first/last name, set logon name as `acepheus`, assigned a temp password (`NewP@ssw0rd123!`), and checked **User must change password at next logon**.

### Removing Old Accounts

Two accounts flagged in an audit needed to go — Mike O'Hare and Paul Valencia:

```powershell
Remove-ADUser -Identity mohare
Remove-ADUser -Identity pvalencia
```

For the GUI: right-clicked the **Employees OU**, hit **Find**, searched by name, then right-clicked the result and selected **Delete**. Confirmed in the popup. Ran the search again to verify they were gone.

### Unlocking Adam Masters

Adam locked himself out after too many wrong password attempts. The helpdesk verified his identity so the ticket was valid. Three things needed to happen: unlock the account, reset the password, force a change at next login.

```powershell
Unlock-ADAccount -Identity amasters

Set-ADAccountPassword -Identity 'amasters' -Reset `
  -NewPassword (ConvertTo-SecureString -AsPlainText "NewP@ssw0rdReset!" -Force)

Set-ADUser -Identity amasters -ChangePasswordAtLogon $true
```

GUI method: found Adam in ADUC, right-clicked, hit **Reset Password**, entered a temp password, and checked both **Unlock the user's account** and **User must change password at next logon**, then OK.

---

## Task 2 — Manage Groups and OUs

### Creating the OU and Security Group

A new OU called **Security Analysts** needed to be created inside the IT hive, then a matching security group inside it.

```powershell
New-ADOrganizationalUnit -Name "Security Analysts" `
  -Path "OU=IT,OU=HQ-NYC,OU=Employees,OU=CORP,DC=INLANEFREIGHT,DC=LOCAL"

New-ADGroup -Name "Security Analysts" -SamAccountName analysts `
  -GroupCategory Security -GroupScope Global `
  -DisplayName "Security Analysts" `
  -Path "OU=Security Analysts,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL" `
  -Description "Members of this group are Security Analysts under the IT OU"
```

For the GUI: right-clicked IT, chose **New > Organizational Unit**, named it `Security Analysts`, left the accidental deletion protection on, hit OK. Then right-clicked the new OU, chose **New > Group**, named it `Security Analysts`, set scope to **Domain local**, type to **Security**.

### Adding Users to the Group

```powershell
Add-ADGroupMember -Identity analysts -Members ACepheus,OStarchaser,ACallisto
```

GUI method: right-clicked each user, chose **Add to a group**, typed `Security Analysts`, confirmed the name resolved (it underlines on a match), and hit OK.

---

## Task 3 — Manage Group Policy Objects

### Duplicating and Linking the GPO

The existing **Logon Banner** GPO was copied and renamed **Security Analysts Control**, then linked to the new OU:

```powershell
Copy-GPO -SourceName "Logon Banner" -TargetName "Security Analysts Control"

New-GPLink -Name "Security Analysts Control" `
  -Target "ou=Security Analysts,ou=IT,OU=HQ-NYC,OU=Employees,OU=Corp,dc=INLANEFREIGHT,dc=LOCAL" `
  -LinkEnabled Yes
```

### Editing the GPO

Opened GPMC from **Server Manager > Tools > Group Policy Management**, right-clicked **Security Analysts Control**, selected **Edit**.

**User Configuration changes:**

| Path | Setting | Value |
|---|---|---|
| `Administrative Templates > System > Removable Storage Access` | All Removable Storage classes: Deny all access | Enabled |
| `Administrative Templates > System` | Prevent access to the command prompt | Disabled |

> Removable media is blocked for security. CMD/PowerShell is explicitly allowed since analysts need it for their daily work.

**Computer Configuration changes:**

Verified the logon banner under `Local Policies > Security Options`:
- **Interactive logon: Message text** — defined with warning text
- **Interactive logon: Message title** — set to `Computer Access Policy`

Password policy under `Account Policies > Password Policy`:

| Setting | Value |
|---|---|
| Minimum password length | 10 characters |
| Password must meet complexity requirements | Enabled |
| Enforce password history | 5 passwords |
| Minimum password age | 7 days |
| Maximum password age | 30 days (auto-set) |

---

## Result

All three tasks completed. New hires are in AD with correct attributes, old accounts removed, and Adam's account is unlocked with a forced password reset. The Security Analysts OU and group exist with the right members. The GPO is linked to the OU, blocks removable media, allows CMD access, and enforces the updated password policy.

# HTB Academy — AD Administration: Guided Lab Part II

---

## Overview

This is the second part of the AD admin lab. The only task here is joining a new workstation to the domain and moving it into the correct OU so that the GPO we set up in Part I applies to it properly.

**Connection:**
```bash
xfreerdp /v:<TARGET_IP> /u:image /p:Academy_student_AD!
```

> Note: This host (`ACADEMY-IAD-W10`) is **not** domain-joined yet. That's the whole point of the task.

---

## Task 4 — Add and Remove Computers to the Domain

### Option A: Join via PowerShell (Remote)

If you're running this from another machine on the network, you can push the join remotely. This uses the local account on the target machine to authenticate to it, then the domain admin account to authorize the join:

```powershell
Add-Computer -ComputerName ACADEMY-IAD-W10 `
  -LocalCredential ACADEMY-IAD-W10\image `
  -DomainName INLANEFREIGHT.LOCAL `
  -Credential INLANEFREIGHT\htb-student_adm `
  -Restart
```

### Option B: Join via PowerShell (Local — on the target machine itself)

If you're already logged into `ACADEMY-IAD-W10`, the command is simpler:

```powershell
Add-Computer -DomainName INLANEFREIGHT.LOCAL `
  -Credential INLANEFREIGHT\HTB-student_adm `
  -Restart
```

The `-Restart` flag is required. The domain join doesn't fully apply until the machine reboots and picks up domain policies.

### Option C: Join via GUI

1. Open **Control Panel > System and Security > System**, click **Change settings** in the Computer name section
2. In the System Properties window, click **Change** next to "rename this computer or change its domain"
3. Under **Member of**, select **Domain** and type `INLANEFREIGHT.LOCAL`, then hit OK
4. When prompted, enter the domain admin credentials: `INLANEFREIGHT\htb-student_adm` / `Academy_student_DA!`
5. If successful, a popup says **Welcome to the INLANEFREIGHT.LOCAL domain**
6. Restart the machine to apply the changes

---

## Moving the Computer to the Correct OU

When a computer joins a domain without a pre-staged AD object, it lands in the default **Computers** container — not the OU we want. We need to move `ACADEMY-IAD-W10` into the **Security Analysts** OU so the GPO from Task 3 takes effect.

### Verify current location first

```powershell
Get-ADComputer -Identity "ACADEMY-IAD-W10" -Properties * | select CN,CanonicalName,IPv4Address
```

The `CanonicalName` field shows the full path like `INLANEFREIGHT.LOCAL/Computers/ACADEMY-IAD-W10`, confirming it's in the wrong place.

### Move via ADUC (GUI)

1. Open **Active Directory Users and Computers**
2. Navigate to the **Computers** container under `INLANEFREIGHT.LOCAL`
3. Right-click `ACADEMY-IAD-W10` and select **Move**
4. In the popup, drill down to `Corp > Employees > HQ-NYC > IT > Security Analysts`
5. Select the **Security Analysts** OU and hit OK

### Move via PowerShell

```powershell
Get-ADComputer -Identity "ACADEMY-IAD-W10" | `
  Move-ADObject -TargetPath "OU=Security Analysts,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
```

After moving, verify by checking the OU contents in ADUC or running:

```powershell
Get-ADComputer -Identity "ACADEMY-IAD-W10" -Properties CanonicalName | select CanonicalName
```

The output should now show the Security Analysts OU path.

---

## Result

`ACADEMY-IAD-W10` is now joined to `INLANEFREIGHT.LOCAL` and sitting in the **Security Analysts** OU. The GPO linked in Part I (**Security Analysts Control**) will apply to it on next Group Policy refresh, enforcing the logon banner, removable media block, and password policy we configured earlier.