# detection-engineering-lab

Detection engineering home lab built on Wazuh with six custom XML rules, each validated by running the attack it detects and documented in its own finding.

## Overview

This repository holds six custom detection rules written for Wazuh, along with a finding documenting each one. Every rule came from running a MITRE ATT&CK technique against the endpoint first, and after watching what the default ruleset did, I would write a rule for whatever it missed or described inaccurately. Each finding is named for the technique it covers. Four of the techniques I ran on the endpoint came from Atomic Red Team. The other two were the brute force in finding 01, which I ran with hydra from the attacking machine, and the encoded PowerShell command in finding 02, which I put together and ran myself.

The findings are ordered to follow an attacker's path through the endpoint rather than the order the rules were written in, and each technique was picked to show a different kind of detection. Finding 01 is initial access, which starts from a brute force against the endpoint and the successful logon that follows it. Finding 02 is an encoded PowerShell command, where the attacker is hiding what they are running. Finding 03 is that idea taken further, with the command built out of environment variable substrings so the string never appears as itself. Finding 04 is an attacker impairing defenses by switching the audit policy off. Findings 05 and 06 both sit under the command and control tactic. One is an outbound connection to an uncommon port and the other is a signed Windows binary pulling a file down from the attacker's machine.

Three of my six rules involve the Kali Linux box acting from outside the endpoint, which are in findings 01, 05, and 06. These are also the rules that do not read a command line, since they work off logon events and network connections instead.

This is a learning project rather than a production ruleset, so the rules were written and tested on one endpoint in a lab with almost no normal traffic. Each of my findings ends with what its rule still cannot see.


## Why I Built This

I started this lab after LetsDefend's SOC Analyst learning path, which came a month after finishing TryHackMe's Cyber Security 101. I took two courses back to back, and what I wanted after them was to challenge myself with a different kind of work rather than another course. The coursework allowed me to learn in a structured environment where the problems were asked by someone else. With this project I had to work through the ambiguity myself, since I am the one asking the questions and deciding what is wrong or right, whether what I wrote is any good, and when it is finished. The idea of building this lab came out of the LetsDefend curriculum itself, because most of what I did there was investigating alerts in a SIEM and writing up what I found, along with some modules on Splunk. This lab is a different flavour of the same work I have done in LetsDefend, as instead of investigating the alerts a SIEM produces, I am writing the rules classifying them as threats. I also built this because it is one of the most fundamental projects a cybersecurity student can do, and it happened to be an extension of the work I had already been doing. 

What I got out of this project was the experience of deploying the software and writing the rules that put those alerts there in the first place. Most importantly, what I have now is a working understanding of how a SIEM gets deployed and navigated and of the concepts underneath it, and I believe most of this knowledge carries over to other SIEMs as well. If I were to build another project like this one it would probably be on a different SIEM, something like Microsoft Sentinel, Splunk, ELK, or QRadar, and I would want to write the rules in Sigma. 


## Lab Environment

<img width="1008" height="469" alt="image" src="https://github.com/user-attachments/assets/f41c338a-8298-4495-8bd2-7f69025020e3" />

The environment is three virtual machines on VMware Workstation, set up to represent a scaled-down version of a Security Operations Center (SOC) deployment. The Wazuh manager, running 4.14.7, is the Security Information and Event Management (SIEM) platform, so this is where the logs arrive, where the detection logic lives and where the alerts are produced, and it is also where I write and fine-tune the rules. The Windows endpoint stands in for a corporate workstation, monitored by a Wazuh agent with the Sysmon config installed on it, and it is where the attacks are run. Kali represents the attacker, and it is where the attacks that come at the endpoint from outside are launched from.

All three machines are sitting on the same host-only network, so there is no traffic going in or out of the lab. I set it up that way to keep the environment as controlled and clean as I could, since it makes everything happening inside it easier to keep track of. All the virtual machines I used have a second adapter configured on VMware's NAT network as well. I set these up earlier on when I was still new to the project and wanted the machines to be able to pull packages and updates if I needed to, and I still have them configured that way. However, when it came to the actual network traffic in the lab, all of it ran over VMnet1, since the IP addresses and the configuration for every device were set on VMnet1.

I had Windows Defender enabled on the endpoint, because a real machine would have it running. For some of the runs I had to turn it off to get the technique to execute at all, because Defender would flag or block the commands before they did anything.


## Repository Contents

- **`detection-findings/`** — contains six writeups with each one covering a technique, and named for the technique it covers.
  
- **`detection-rules/`** — `local_rules.xml`, holding all the finalized versions of the six custom detection rules.
  
- **`wazuh-manager-config/`** — the manager's `ossec.conf`, with anything sensitive stripped out before publishing.
  
- **`windows-endpoint-config/`** — `sysmonconfig.xml`, the sysmon-modular config the endpoint runs.
  
- **`development/`** — `DEVELOPMENT.md`, covers how the project was actually built and the order things happened in.
  
- **`LICENSE`** — CC BY 4.0.


## Detection Rules

| Rule | Level | Technique | Tactic | Detects | Finding |
|---|---|---|---|---|---|
| 100100 | 12 | T1059.001 PowerShell | Execution | A PowerShell command executed with a base64 encoded payload | [02](detection-findings/02-t1059-001-encoded-powershell.md) |
| 100102 | 12 | T1562.001 Disable or Modify Tools | Defense Evasion | `auditpol` used to switch off, clear or restore the audit policy | [04](detection-findings/04-t1562-001-impair-defenses.md) |
| 100103 | 10 | T1027.010 Command Obfuscation, T1059.003 Windows Command Shell | Defense Evasion, Execution | Commands built out of environment variable substring expansion | [03](detection-findings/03-t1027-010-env-var-obfuscation.md) |
| 100104 | 13 | T1110 Brute Force, T1078 Valid Accounts | Credential Access, Initial Access | Failed logons from one address followed by a success inside the timeframe | [01](detection-findings/01-t1110-t1078-brute-force-success.md) |
| 100105 | 10 | T1571 Non-Standard Port | Command and Control | PowerShell opening an outbound TCP connection to a port outside the allow list | [05](detection-findings/05-t1571-non-standard-port.md) |
| 100106 | 10 | T1105 Ingress Tool Transfer | Command and Control | An outbound connection opened by a LOLBin such as certutil or bitsadmin | [06](detection-findings/06-t1105-ingress-tool-transfer.md) |

The rules follow the order I wrote them in, and they split into two groups. My first three rules, which are 100100, 100102 and 100103, work by string matching. They read `win.eventdata.commandLine` and produce an alert when the string sitting in it is one I had already decided was malicious. The second group of rules does not read a command line at all. Instead, they work off logon events, the direction and port of a connection, and the image that opened it. What these rules describe is something that is not supposed to happen rather than something I had decided was malicious.

The severity levels follow Wazuh's scale, and the `email_alert_level` in this lab is 12, so 100100, 100102 and 100104 mail an alert while the other three do not. The rules themselves are in [detection-rules/local_rules.xml](detection-rules/local_rules.xml).


## Methodology

Every finding in this repository follows the same structure, and all of them come after I ran the technique and looked at what Wazuh's default ruleset did with it. The findings are all built around a gap in that ruleset, since the gap is what the rule in each one was written for.

From there each finding runs in the same order. It opens with an overview of the technique and why I picked it. Then I show the attack I used, which is the exact command I ran, and for the atomic tests, anything I changed from the defaults they ship with. The section after that is the baseline alerts, which is what Wazuh produced with only its shipped ruleset active. From there I cover the detection gap the baseline leaves behind. Next is the rule I wrote to cover that gap, where I walk through the design process, followed by the result of loading it and running the same attack again. Most of my findings go through more than one version of the rule from there, where I stress test it and polish one version into the next. Lastly, each finding closes with the coverage limits of my rule.


## Scope and Limitations

I am a cybersecurity student and this is my first home lab, so this project is not meant to represent production-level output. The rules do work as I intended them to, which was to detect the techniques they were written for, and every finding shows them firing. What the limitation comes down to is that they were written and tested inside a controlled lab of three machines with almost no normal traffic on it, which is not what a production environment looks like. They behave cleanly there, but on a network with real users they could be a lot noisier. Any false positive numbers in my findings come from that same environment, which barely produces false positives to begin with.

This repository is more of a learning artifact than anything else, because the findings document the process I went through along with the rules that came out of it. The versions that did not work are in there too, as are the limits I could not get past.


## References

**Frameworks**

- [MITRE ATT&CK](https://attack.mitre.org/) — the framework every technique in this project is mapped to
- [Red Canary — Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — the framework the tests below come from

**Atomic Red Team tests used**

- [T1059.003 — Test 3, Suspicious Execution via Windows Command Shell](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md#atomic-test-3-suspicious-execution-via-windows-command-shell) — finding 03
- [T1562.001 — Impair Defenses: Disable or Modify Tools](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md) — finding 04
- [T1571 — Test 1, Testing usage of uncommonly used port with PowerShell](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) — finding 05
- [T1105 — Test 7, certutil download (urlcache)](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) — finding 06

**Tools and configuration**

- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) — the Sysmon config the endpoint actually runs
- [vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra) — used for the brute force in finding 01

**Documentation and reading**

- [wazuh/wazuh — shipped ruleset](https://github.com/wazuh/wazuh/tree/master/ruleset/rules)  where the default rules my baselines reference are defined
- [Wazuh documentation — rules XML syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html) — the syntax I wrote all six rules in
- [Microsoft — How to enable Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon) — where I read up on Sysmon configs before deciding which one to use
- [Palo Alto Networks — What Are MITRE ATT&CK Techniques](https://www.paloaltonetworks.com/cyberpedia/what-are-mitre-attack-techniques#common-techniques) — where some of my ideas for which techniques to cover came from


## License

Licensed under [CC BY 4.0](LICENSE). Use anything here, just credit this repo.
