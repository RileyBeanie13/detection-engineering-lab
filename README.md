# detection-engineering-lab

Detection engineering home lab built on Wazuh with six custom XML rules, each written for a coverage gap in the default ruleset, validated by running the attack it detects and documented in its own finding. On top of those rules I added LLM-assisted alert triage with a locally hosted Qwen model, measured how well it separates true from false positives, and hardened it against prompt injection from text an attacker can write into the alert data.


## Overview

This repository holds six custom detection rules written for Wazuh, along with a finding documenting each one. Every rule came from running a MITRE ATT&CK technique against the endpoint first, and after watching what the default ruleset did, I would write a rule for whatever it missed or described inaccurately. Four of the techniques came from Atomic Red Team, the brute force in finding 01 was run with hydra from the attacking machine, and the encoded PowerShell command in finding 02 I put together and ran myself.

The findings are ordered to follow an attacker's path through the endpoint rather than the order the rules were written in. They go from initial access with a brute force and the successful logon after it, to hiding what's being run with encoded PowerShell and environment variable substrings, to impairing defenses by switching the audit policy off, and finally to command and control over an uncommon port and a signed Windows binary pulling a file down from the attacker's machine.

On top of the rules, the [llm-assisted-triage](llm-assisted-triage/) folder holds a triage layer that sends every alert from the six rules to a Qwen model running locally through Ollama, which writes an advisory note with a verdict, its reasoning and a suggested next step back into the Wazuh dashboard. I tested every version of it against saved true positive, false positive and prompt injection alerts, and its own README and findings cover how it was built and how it held up.


## Why I Built This

I started this lab after LetsDefend's SOC Analyst learning path, which came a month after finishing TryHackMe's Cyber Security 101. I took two courses back to back, and what I wanted after them was to challenge myself with a different kind of work rather than another course. The coursework allowed me to learn in a structured environment where the problems were asked by someone else. With this project I had to work through the ambiguity myself, since I am the one asking the questions and deciding what is wrong or right, whether what I wrote is any good, and when it is finished. The idea of building this lab came out of the LetsDefend curriculum itself, because most of what I did there was investigating alerts in a SIEM and writing up what I found, along with some modules on Splunk. This lab is a different flavour of the same work I have done in LetsDefend, as instead of investigating the alerts a SIEM produces, I am writing the rules classifying them as threats. I also built this because it is one of the most fundamental projects a cybersecurity student can do, and it happened to be an extension of the work I had already been doing. 

What I got out of this project was the experience of deploying the software and writing the rules that put those alerts there in the first place. Most importantly, what I have now is a working understanding of how a SIEM gets deployed and navigated and of the concepts underneath it, and I believe most of this knowledge carries over to other SIEMs as well. If I were to build another project like this one it would probably be on a different SIEM, something like Microsoft Sentinel, Splunk, ELK, or QRadar, and I would want to write the rules in Sigma. 


## Lab Environment

<img width="1008" height="469" alt="image" src="https://github.com/user-attachments/assets/f41c338a-8298-4495-8bd2-7f69025020e3" />

The environment is three virtual machines on VMware Workstation, set up to represent a scaled-down version of a Security Operations Center (SOC) deployment. The Wazuh manager, running 4.14.7, is the Security Information and Event Management (SIEM) platform, so this is where the logs arrive, where the detection logic lives and where the alerts are produced, and it is also where I write and fine-tune the rules. The Windows endpoint stands in for a corporate workstation, monitored by a Wazuh agent with the Sysmon config installed on it, and it is where the attacks are run. Kali represents the attacker, and it is where the attacks that come at the endpoint from outside are launched from.

All three machines are sitting on the same host-only network, so there is no traffic going in or out of the lab. I set it up that way to keep the environment as controlled and clean as I could, since it makes everything happening inside it easier to keep track of. All the virtual machines I used have a second adapter configured on VMware's NAT network as well. I set these up earlier on when I was still new to the project and wanted the machines to be able to pull packages and updates if I needed to, and I still have them configured that way. However, when it came to the actual network traffic in the lab, all of it ran over VMnet1, since the IP addresses and the configuration for every device were set on VMnet1.

The fourth component of the lab is Qwen, the model behind the LLM-assisted triage layer. It runs through Ollama on my host PC rather than in a virtual machine, since it needs the host's graphics card, an RTX 3070 Ti with 8 GB of memory. The host sits on the same host-only network at 192.168.10.1, and the Wazuh manager sends each alert to it on port 11434, with the Windows firewall only letting the manager reach that port. Because of that, the triage traffic stays inside the lab like everything else.

I had Windows Defender enabled on the endpoint, because a real machine would have it running. For some of the runs I had to turn it off to get the technique to execute at all, because Defender would flag or block the commands before they did anything.


## Repository Contents

- **`detection-findings/`** — contains six writeups with each one covering a technique, and named for the technique it covers.
  
- **`detection-rules/`** — `local_rules.xml`, holding all the finalized versions of the six custom detection rules.
  
- **`wazuh-manager-config/`** — the manager's `ossec.conf`, with anything sensitive stripped out before publishing.
  
- **`windows-endpoint-config/`** — `sysmonconfig.xml`, the sysmon-modular config the endpoint runs.
  
- **`llm-assisted-triage/`** — the LLM-assisted triage layer, with the integration script, the Wazuh config that brings Qwen's notes back into the dashboard, the tests and results, and its own README and findings.
  
- **`development/`** — `development.md`, covers how the project was actually built and the order things happened in.
  
- **`LICENSE`** — CC BY 4.0, except for the triage script, which stays under GPLv2.


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

Every detection finding in this repository follows the same structure, and all of them come after I ran the technique and looked at what Wazuh's default ruleset did with it. The findings are all built around a gap in that ruleset, since the gap is what the rule in each one was written for.

From there each finding runs in the same order. It opens with an overview of the technique and why I picked it. Then I show the attack I used, which is the exact command I ran, and for the atomic tests, anything I changed from the defaults they ship with. The section after that is the baseline alerts, which is what Wazuh produced with only its shipped ruleset active. From there I cover the detection gap the baseline leaves behind. Next is the rule I wrote to cover that gap, where I walk through the design process, followed by the result of loading it and running the same attack again. Most of my findings go through more than one version of the rule from there, where I stress test it and polish one version into the next. Lastly, each finding closes with the coverage limits of my rule.

The LLM-assisted triage findings work differently, since there's no single gap to cover. Instead, they walk through every version of the triage layer in the order I built them. Each version shows what I changed in the prompt or the script, the results on the same set of true positive, false positive and prompt injection alerts, and what I took away from them before planning the next version. The findings close with the limitations of the project and my answer to whether an LLM is safe to put in the loop between the SIEM and the analyst.


## Scope and Limitations

I am a cybersecurity student and this is my first home lab, so this project is not meant to represent production-level output. The rules do work as I intended them to, which was to detect the techniques they were written for, and every finding shows them firing. What the limitation comes down to is that they were written and tested inside a controlled lab of three machines with almost no normal traffic on it, which is not what a production environment looks like. They behave cleanly there, but on a network with real users they could be a lot noisier. Any false positive numbers in my findings come from that same environment, which barely produces false positives to begin with.

This repository is more of a learning artifact than anything else, because the findings document the process I went through along with the rules that came out of it. The versions that did not work are in there too, as are the limits I could not get past. The LLM-assisted triage layer is a proof of concept with its own limits, which are covered at the end of its findings.


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

- [wazuh/wazuh — shipped ruleset](https://github.com/wazuh/wazuh/tree/master/ruleset/rules) — where the default rules my baselines reference are defined
- [Wazuh documentation — rules XML syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html) — the syntax I wrote all six rules in
- [Microsoft — How to enable Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon) — where I read up on Sysmon configs before deciding which one to use
- [Palo Alto Networks — What Are MITRE ATT&CK Techniques](https://www.paloaltonetworks.com/cyberpedia/what-are-mitre-attack-techniques#common-techniques) — where some of my ideas for which techniques to cover came from

**LLM-assisted triage**

- The triage layer has its own references and related work, listed in [its README](llm-assisted-triage/README.md#references), along with the prompt injection and Atomic Red Team sources in [qwen-triage-tests.md](llm-assisted-triage/testing/qwen-triage-tests.md#resources).


## License

Licensed under [CC BY 4.0](LICENSE). Use anything here, just credit this repo.

The one exception is [custom-qwentriage.py](llm-assisted-triage/custom-qwentriage.py), which is adapted from Wazuh's VirusTotal integration and stays under the [GNU General Public License v2](llm-assisted-triage/LICENSE-GPL-2.0), the same license as the Wazuh code it came from.
