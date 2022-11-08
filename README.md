# Arsenal

This repository contains a collection of 3rd party scripts and pre-compiled executables useful for post-exploitation with [Molotov](https://acab.enterprises/dismantl/Molotov).

## Modules

* [ADCollector](https://github.com/dev-2null/ADCollector) - A lightweight tool to quickly extract valuable information from the Active Directory environment. ADCollector is not an alternative to the powerful PowerView, it just automates enumeration to quickly identify juicy information without thinking too much at the early Recon stage. Functions implemented in ADCollector are ideal for enumeration in a large Enterprise environment with lots of users/computers, without generating lots of traffic and taking a large amount of time.
* [BetterSafetyKatz](https://github.com/Flangvik/BetterSafetyKatz) - Fork of SafetyKatz dynamically fetches the latest Mimikatz, runtime patching signatures and PE loads Mimikatz into memory.
* [Group3r](https://github.com/Group3r/Group3r) -  C# tool to find vulnerabilities in AD Group Policy, but do it better than Grouper2 did.
* [JuicyPotatoNG](https://github.com/antonioCoco/JuicyPotatoNG) - Another Windows Local Privilege Escalation from Service Account to System.
* [KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp) - universal no-fix local privilege escalation in windows domain environments where LDAP signing is not enforced.
* [lazagne](https://github.com/AlessandroZ/LaZagne) - Open source Python application used to retrieve lots of passwords stored on a local computer. *NOTE: Does not work with in-memory execution, must be placed on disk*.
* [mimikatz{64,32}](https://github.com/gentilkiwi/mimikatz) - Classic tool for manipulating and extracting Windows credentials from memory.
* [Rubeus](https://github.com/GhostPack/Rubeus) - C# toolset for raw Kerberos interaction and abuses. Useful for AD delegation exploitation.
* [Seatbelt](https://github.com/GhostPack/Seatbelt) - C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives. Useful for, among other things, credential enumeration and privilege escalation.
* [SharpChrome](https://github.com/GhostPack/SharpDPAPI) - Chrome-specific implementation of SharpDPAPI capable of cookies and logins decryption/triage.
* [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) -  C# port of some Mimikatz DPAPI functionality.
* [SharpEDRChecker](https://github.com/PwnDexter/SharpEDRChecker) - Checks for the presence of known defensive products such as AVs, EDRs and logging tools.
* [SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato) - Local privilege escalation from SeImpersonatePrivilege using EfsRpc. Built from SweetPotato by @EthicalChaos and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.
* [SharpHound](https://github.com/BloodHoundAD/SharpHound) - C# data ingestor for [Bloodhound](https://github.com/BloodHoundAD/BloodHound) Active Directory enumeration.
* [SharpKatz64](https://github.com/b4rtik/SharpKatz) - Porting of mimikatz sekurlsa::logonpasswords, sekurlsa::ekeys and lsadump::dcsync commands to C#. Useful if classic Mimikatz is getting flagged by AV/EDR.
* [SharpMove](https://github.com/0xthirteen/SharpMove) -  C# tool for performing lateral movement techniques.
* [SharpNamedPipePTH](https://github.com/S3cur3Th1sSh1t/SharpNamedPipePTH) -  C# tool to use Pass-the-Hash for authentication on a local Named Pipe for user Impersonation. You need a local administrator or SEImpersonate rights to use this.
* [SharpRDP](https://github.com/0xthirteen/SharpRDP) - Remote Desktop Protocol Console Application for Authenticated Command Execution.
* [SharpUp](https://github.com/GhostPack/SharpUp) - C# port of various PowerUp functionality. Useful for privilege escalation.
* [SharpZeroLogon](https://github.com/nccgroup/nccfsas/tree/main/Tools/SharpZeroLogon) - C# exploit for CVE-2020-1472, a.k.a. Zerologon. This allows for an attacker to reset the machine account of a target Domain Controller, leading to Domain Admin compromise.
* [SpoolSample](https://github.com/leechristensen/SpoolSample) - PoC tool to coerce Windows hosts authenticate to other machines via the MS-RPRN RPC interface. Used by the `token-printspoofer` command in Molotov.
* [SweetPotato](https://github.com/CCob/SweetPotato) - Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019.
* [ThunderFox](https://github.com/V1V1/SharpScribbles) - C# Retrieves data (contacts, emails, history, cookies and credentials) from Thunderbird and Firefox.
* [tor{64,32}](https://torproject.org) - Connect to the Tor anonymity network.
* [traitor-amd64](https://github.com/liamg/traitor) - Automatic Linux privesc via exploitation of low-hanging fruit e.g. gtfobins, pwnkit, dirty pipe, +w docker.sock.
* [winPEASx64](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS/winPEASexe) - C# script that search for possible paths to escalate privileges on Windows hosts.

## Scripts

* [ADRecon.ps1](https://github.com/adrecon/ADRecon) - Gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
- amsi.ps1: Disables AMSI by corrupting memory
* [HostRecon.ps1](https://github.com/dafthack/HostRecon) - This function runs a number of checks on a system to help provide situational awareness to a penetration tester during the reconnaissance phase. It gathers information about the local system, users, and domain information. It does not use any 'net', 'ipconfig', 'whoami', 'netstat', or other system commands to help avoid detection.
* [Invoke-Kerberoast.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1) - Requests service tickets for kerberoast-able accounts and returns extracted ticket hashes.
* [Invoke-Nightmare.ps1](https://github.com/calebstewart/CVE-2021-1675) - Pure PowerShell implementation of CVE-2021-1675 Print Spooler Local Privilege Escalation (PrintNightmare).
* [LAPSToolkit.ps1](https://github.com/leoloobeek/LAPSToolkit) - Tool to audit and attack LAPS environments.
* [PowerMad.ps1](https://github.com/Kevin-Robertson/Powermad) - PowerShell MachineAccountQuota and DNS exploit tools.
* [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) - PowerShell tool to gain network situational awareness on Windows domains. It contains a set of pure-PowerShell replacements for various windows "net *" commands, which utilize PowerShell AD hooks and underlying Win32 API functions to perform useful Windows domain functionality.