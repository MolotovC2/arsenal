# Arsenal

This repository contains a collection of 3rd party scripts and pre-compiled executables useful for post-exploitation with [Molotov](https://github.com/MolotovC2/molotov).

## Modules

| Tool | Version | OS | Architecture | Description |
|------|---------|----|--------------|-------------|
| [ADCollector.exe](https://github.com/dev-2null/ADCollector) | 3.0.1 | Windows | Any | A lightweight tool to quickly extract valuable information from the Active Directory environment. ADCollector is not an alternative to the powerful PowerView, it just automates enumeration to quickly identify juicy information without thinking too much at the early Recon stage. Functions implemented in ADCollector are ideal for enumeration in a large Enterprise environment with lots of users/computers, without generating lots of traffic and taking a large amount of time. |
| [BetterSafetyKatz.exe](https://github.com/Flangvik/BetterSafetyKatz) | 03769b5 | Windows | Any | Fork of SafetyKatz dynamically fetches the latest Mimikatz, runtime patching signatures and PE loads Mimikatz into memory. |
| [Group3r.exe](https://github.com/Group3r/Group3r) | 1.0.53 | Windows | Any |  C# tool to find vulnerabilities in AD Group Policy, but do it better than Grouper2 did. |
| [JuicyPotatoNG.exe](https://github.com/antonioCoco/JuicyPotatoNG) | 1.1 | Windows | x64 | Another Windows Local Privilege Escalation from Service Account to System. |
| [KrbRelayUp.exe](https://github.com/Dec0ne/KrbRelayUp) | e919f78 | Windows | Any | universal no-fix local privilege escalation in windows domain environments where LDAP signing is not enforced. |
| [lazagne.exe](https://github.com/AlessandroZ/LaZagne) | 2.4.5 | Windows | x64 | Open source Python application used to retrieve lots of passwords stored on a local computer. *NOTE: Does not work with in-memory execution, must be placed on disk*. |
| [mimikatz64.exe](https://github.com/gentilkiwi/mimikatz) | 2.2.0 20220919 | Windows | x64 | Classic tool for manipulating and extracting Windows credentials from memory. |
| [mimikatz32.exe](https://github.com/gentilkiwi/mimikatz) | 2.2.0 20220919 | Windows | x86 | Classic tool for manipulating and extracting Windows credentials from memory. |
| [mimidrv64.sys](https://github.com/gentilkiwi/mimikatz) | 2.2.0 20220919 | Windows | x64 | Classic tool for manipulating and extracting Windows credentials from memory. (Driver) |
| [mimidrv32.sys](https://github.com/gentilkiwi/mimikatz) | 2.2.0 20220919 | Windows | x86 | Classic tool for manipulating and extracting Windows credentials from memory. (Driver) |
| [Rubeus.exe](https://github.com/GhostPack/Rubeus) | f6685f4 | Windows | Any | C# toolset for raw Kerberos interaction and abuses. Useful for AD delegation exploitation. |
| [Seatbelt.exe](https://github.com/GhostPack/Seatbelt) | 96bd958 | Windows | Any | C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives. Useful for, among other things, credential enumeration and privilege escalation. |
| [SharpChrome.exe](https://github.com/GhostPack/SharpDPAPI) | f75ab5a | Windows | Any | Chrome-specific implementation of SharpDPAPI capable of cookies and logins decryption/triage. |
| [SharpDPAPI.exe](https://github.com/GhostPack/SharpDPAPI) | f75ab5a | Windows | Any |  C# port of some Mimikatz DPAPI functionality.
| [SharpEDRChecker.exe](https://github.com/PwnDexter/SharpEDRChecker) | 1.1 | Windows | Any | Checks for the presence of known defensive products such as AVs, EDRs and logging tools. |
| [SharpEfsPotato.exe](https://github.com/bugch3ck/SharpEfsPotato) | 23c9079 | Windows | Any | Local privilege escalation from SeImpersonatePrivilege using EfsRpc. Built from SweetPotato by @EthicalChaos and SharpSystemTriggers/SharpEfsTrigger by @cube0x0. |
| [SharpHound.exe](https://github.com/BloodHoundAD/SharpHound) | 1.0.4 | Windows | Any | C# data ingestor for [Bloodhound](https://github.com/BloodHoundAD/BloodHound) Active Directory enumeration. |
| [SharpKatz.exe](https://github.com/b4rtik/SharpKatz) | 87e8e66 | Windows | x64 | Porting of mimikatz sekurlsa::logonpasswords, sekurlsa::ekeys and lsadump::dcsync commands to C#. Useful if classic Mimikatz is getting flagged by AV/EDR. |
| [SharpMove.exe](https://github.com/0xthirteen/SharpMove) | eaee0a5 | Windows | Any |  C# tool for performing lateral movement techniques. |
| [SharpNamedPipePTH.exe](https://github.com/S3cur3Th1sSh1t/SharpNamedPipePTH) | 6ab648a | Windows | Any |  C# tool to use Pass-the-Hash for authentication on a local Named Pipe for user Impersonation. You need a local administrator or SEImpersonate rights to use this. |
| [SharpRDP.exe](https://github.com/0xthirteen/SharpRDP) | 545419d | Windows | Any | Remote Desktop Protocol Console Application for Authenticated Command Execution. |
| [SharpUp.exe](https://github.com/GhostPack/SharpUp) | 7e17296 | Windows | Any | C# port of various PowerUp functionality. Useful for privilege escalation. |
| [SharpZeroLogon.exe](https://github.com/nccgroup/nccfsas/tree/main/Tools/SharpZeroLogon) | 0cc0344 | Windows | Any | C# exploit for CVE-2020-1472, a.k.a. Zerologon. This allows for an attacker to reset the machine account of a target Domain Controller, leading to Domain Admin compromise. |
| [SpoolSample.exe](https://github.com/leechristensen/SpoolSample) | 688971e | Windows | x64 | PoC tool to coerce Windows hosts authenticate to other machines via the MS-RPRN RPC interface. |
| [SweetPotato.exe](https://github.com/CCob/SweetPotato) | ffc0afa | Windows | Any | Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019. |
| [ThunderFox.exe](https://github.com/V1V1/SharpScribbles) | c3b56b0 | Windows | Any | C# Retrieves data (contacts, emails, history, cookies and credentials) from Thunderbird and Firefox. |
| [tor-windows-x64.exe](https://torproject.org) | 12.0.4 (tor 0.4.7.13) | Windows | x64 | Connect to the Tor anonymity network. |
| [tor-windows-x86.exe](https://torproject.org) | 12.0.4 (tor 0.4.7.13) | Windows | x86 | Connect to the Tor anonymity network. |
| [tor-linux-x64](https://torproject.org) | 12.0.4 (tor 0.4.7.13) | Linux | x64 | Connect to the Tor anonymity network. |
| [tor-macos-x64](https://torproject.org) | 12.0.4 (tor 0.4.7.13) | MacOS | x64 | Connect to the Tor anonymity network. |
| [tor-macos-arm64](https://torproject.org) | 12.0.4 (tor 0.4.7.13) | MacOS | arm64 | Connect to the Tor anonymity network. |
| [traitor-amd64](https://github.com/liamg/traitor) | 0.0.14 | Linux | x64 | Automatic Linux privesc via exploitation of low-hanging fruit e.g. gtfobins, pwnkit, dirty pipe, +w docker.sock. |
| [winPEASx64.exe](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS/winPEASexe) | 20230409 | Windows | x64 | C# script that search for possible paths to escalate privileges on Windows hosts. |

## Scripts

| Tool | Version | OS | Description |
|------|---------|----|-------------|
| [ADRecon.ps1](https://github.com/adrecon/ADRecon) | ecb2300 | Windows | Gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment. |
| amsi.ps1 | | Windows | Disables AMSI by corrupting memory |
| [HostRecon.ps1](https://github.com/dafthack/HostRecon) | 0208213 | Windows | This function runs a number of checks on a system to help provide situational awareness to a penetration tester during the reconnaissance phase. It gathers information about the local system, users, and domain information. It does not use any 'net', 'ipconfig', 'whoami', 'netstat', or other system commands to help avoid detection. |
| [Invoke-Kerberoast.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1) | cc5de83 | Windows | Requests service tickets for kerberoast-able accounts and returns extracted ticket hashes. |
| [Invoke-Nightmare.ps1](https://github.com/calebstewart/CVE-2021-1675) | ed724e5 | Windows | Pure PowerShell implementation of CVE-2021-1675 Print Spooler Local Privilege Escalation (PrintNightmare). |
| [LAPSToolkit.ps1](https://github.com/leoloobeek/LAPSToolkit) | 4560af7 | Windows | Tool to audit and attack LAPS environments. |
| [Powermad.ps1](https://github.com/Kevin-Robertson/Powermad) | 3ad36e6 | Windows | PowerShell MachineAccountQuota and DNS exploit tools. |
| [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) | f94a5d2 | Windows | PowerShell tool to gain network situational awareness on Windows domains. It contains a set of pure-PowerShell replacements for various windows "net *" commands, which utilize PowerShell AD hooks and underlying Win32 API functions to perform useful Windows domain functionality. |
