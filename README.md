# detection-engineering-lab

Detection engineering home lab built on Wazuh with six custom XML rules, each validated by running the attack it detects and documented in its own finding.


## Why I Built This

I started this lab after LetsDefend's SOC Analyst learning path, which came a month after finishing TryHackMe's Cyber Security 101. I took two courses back to back, and what I wanted after them was to challenge myself with a different kind of work rather than another course. The coursework allowed me to learn in a structured environment where the problems were asked by someone else. With this project I had to work through the ambiguity myself, since I am the one asking the questions and deciding what is wrong or right, whether what I wrote is any good, and when it is finished. The idea of building this lab came out of the LetsDefend curriculum itself, because most of what I did there was investigating alerts in a SIEM and writing up what I found, along with some modules on Splunk. This lab is a different flavour of the same work I've done in LetsDefend, as instead of investigating the alerts a SIEM produces, I am writing the rules classifying them as threats. I also built this because it is one of the most fundamental projects a cybersecurity student can do, and this one happened to be an extension of the work I had already been doing. 

What I got out of this project was deploying the software and writing the rules that put the alerts I was investigating in the first place. Most importantly, what I have now is a working understanding of how a SIEM gets deployed and navigated and of the concepts underneath it, and I believe most of this knowledge carries over to other SIEMs as well. If I were to build another project like this one it would probably be on a different SIEM, something like Microsoft Sentinel, Splunk, ELK, or QRadar, and I would want to write the rules in Sigma. Most importantly, what I have now is a working understanding of how a SIEM gets deployed and navigated and of the concepts underneath it, and I believe most of this knowledge carries over to other SIEMs as well. If I were to build another project like this one it would probably be on a different SIEM, something like Microsoft Sentinel, Splunk, ELK, or QRadar, and I would want to write the rules in Sigma.


## Overview

This repository holds six custom detection rules written for Wazuh, along with a finding documenting each one. Every rule came from running a MITRE ATT&CK technique against the endpoint first, and after watching what the default ruleset did, I would write a rule for whatever it missed or described inaccurately. Each finding is named for the technique it covers. Five of the techniques I used on the endpoint came from Atomic Red Team, and for the sixth rule, the brute force attack in finding 01 was run with hydra from the attacking machine.

The findings are ordered to follow an attacker's path through the endpoint rather than the order the rules were written in, and each technique was picked to show a different kind of detection. Finding 01 is initial access, which starts from a brute force against the endpoint and the successful logon that follows it. Finding 02 is an encoded PowerShell command, where the attacker is hiding what they are running. Finding 03 is that idea taken further, with the command built out of environment variable substrings so the string never appears as itself. Finding 04 is an attacker impairing defenses by switching the audit policy off. Findings 05 and 06 both sit under the command and control tactic, one is an outbound connection to an uncommon port and the other is a signed Windows binary pulling a file down from the attacker's machine.

Three of my six rules involve the Kali Linux box acting from outside the endpoint, which are in findings 01, 05, and 06. These are also the rules that do not read a command line, since they detect off of logon events and network connections instead.

This is a learning project rather than a production ruleset, so the rules were written and tested on one endpoint in a lab with almost no normal traffic. Each of my findings ends with what my rule still cannot see.

















When I first built the lab, I did not have much in mind beyond writing rules for brute force and web attacks like I learned in LetsDefend. These were things like XSS, Command Injection, and SQL injection. The problem is that Wazuh already ships with rules for all of those, and they are rules that have been written many times over already. If all I did was rewrite the same rules as everyone else, I would not be learning anything nor would they be of any real use. That is where Atomic Red Team came in, because it gave me real attack techniques I could run against my endpoint. What mattered was not that it validated my rules at the end, it was that I ran the techniques first to find where Wazuh's default ruleset fell short, and then wrote rules for what I found.

When it came to the work of the lab, it was the same loop for each run. I ran the technique and watched if the default ruleset detected it, if it didn't that would be a gap and I would write a rule for it. If something did fire but described the attack inaccurately, or was so general that it didn't accurately represent the severity level, that was a gap and I would write a rule for that as well.
