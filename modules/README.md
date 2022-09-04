# Arsenal

This repository contains a collection of pre-compiled 3rd party executables useful for post-exploitation with [Molotov](https://acab.enterprises/dismantl/Molotov).

- **[ADCollector.exe](https://github.com/dev-2null/ADCollector)**: A lightweight tool to quickly extract valuable information from the Active Directory environment. ADCollector is not an alternative to the powerful PowerView, it just automates enumeration to quickly identify juicy information without thinking too much at the early Recon stage. Functions implemented in ADCollector are ideal for enumeration in a large Enterprise environment with lots of users/computers, without generating lots of traffic and taking a large amount of time.
- **[lazagne.exe](https://github.com/AlessandroZ/LaZagne)**: Open source Python application used to retrieve lots of passwords stored on a local computer. *NOTE: Does not work with in-memory execution, must be placed on disk*.
- **[mimikatz{64,32}.exe](https://github.com/gentilkiwi/mimikatz)**: Classic tool for manipulating and extracting Windows credentials from memory.
- **[Rubeus.exe](https://github.com/GhostPack/Rubeus)**: C# toolset for raw Kerberos interaction and abuses. Useful for AD delegation exploitation.
- **[Seatbelt.exe](https://github.com/GhostPack/Seatbelt)**: C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives. Useful for, among other things, credential enumeration and privilege escalation.
- **[SharpEDRChecker.exe](https://github.com/PwnDexter/SharpEDRChecker)**: Checks for the presence of known defensive products such as AVs, EDRs and logging tools.
- **[SharpHound.exe](https://github.com/BloodHoundAD/SharpHound)**: C# data ingestor for [Bloodhound](https://github.com/BloodHoundAD/BloodHound) Active Directory enumeration.
- **[SharpKatz64.exe](https://github.com/b4rtik/SharpKatz)**: Porting of mimikatz sekurlsa::logonpasswords, sekurlsa::ekeys and lsadump::dcsync commands to C#. Useful if classic Mimikatz is getting flagged by AV/EDR.
- **[SharpRDP.exe](https://github.com/0xthirteen/SharpRDP)**: Remote Desktop Protocol Console Application for Authenticated Command Execution.
- **[SharpUp.exe](https://github.com/GhostPack/SharpUp)**: C# port of various PowerUp functionality. Useful for privilege escalation.
- **[SharpZeroLogon.exe](https://github.com/nccgroup/nccfsas/tree/main/Tools/SharpZeroLogon)**: C# exploit for CVE-2020-1472, a.k.a. Zerologon. This allows for an attacker to reset the machine account of a target Domain Controller, leading to Domain Admin compromise.
- **[SpoolSample.exe](https://github.com/leechristensen/SpoolSample)**: PoC tool to coerce Windows hosts authenticate to other machines via the MS-RPRN RPC interface. Used by the `token-printspoofer` command in Molotov.
- **[tor{64,32}.exe](https://torproject.org)**: Connect to the Tor anonymity network.
- **[traitor-amd64](https://github.com/liamg/traitor)**: Automatic Linux privesc via exploitation of low-hanging fruit e.g. gtfobins, pwnkit, dirty pipe, +w docker.sock.
- **[winPEASx64.exe](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS/winPEASexe)**: C# script that search for possible paths to escalate privileges on Windows hosts.