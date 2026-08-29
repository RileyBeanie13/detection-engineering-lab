# T1059.001 — Encoded PowerShell Command

## Overview

My first finding was about someone forcing their way in, and finding a way to detect it. I ran hydra against RDP on the Windows endpoint, and rule 100104 correlates a successful logon that follows numerous failures from the same source, so the question my finding answers is whether a brute force attempt actually succeeded. This finding picks up right after that, since the next question is what they do once they're in. At this point the attacker has working credentials and a session on the breached endpoint, which means they can run commands as that user. One of the most common ways for attackers to run commands is through encoded PowerShell. When an attacker puts a blob of base64 following `-EncodedCommand`, it makes it so the actual command never shows up in the command line as readable text so anyone scrolling through process creation events would not see more obvious commands such as `whoami` or `net user` and they would see a wall of base64 instead.\

I think it's worth mentioning that Rule 100100 was the first detection rule I ever wrote. I wrote it early on when I was still getting comfortable with Wazuh's rule syntax, and at the time I thought it worked because it fired when I ran the attack. When I came back to it for this writeup, like the last one I asked where it didn't work. Because of this, I started testing it against variations of the same technique instead of just the one command I originally used, and it turned out there were several ways to run encoded PowerShell that the first iteration of my rule didn't catch at all. There was also a whole category of normal commands it would have alerted on that I hadn't thought about.

My first rule did cover a gap in Wazuh's shipped rules, since when I ran encoded PowerShell from command prompt it slipped under the radar. But this finding also covers the gaps I found when I went back and stress tested that rule, and the three versions it went through before I was satisfied with it.

## Attack Execution

**Version 1 Test**

```powershell
powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAdABlAHMAdAAiAA==
```

The first encoded command I ran was more of a proof of concept. `Write-Host "test"` was encoded to base64, and run with the parameter fully spelled out. All I wanted to know was whether this technique produced a Sysmon event and whether my rule caught it. It did, so I moved on. 



**Version 2 & 3**

```powershell
powershell.exe -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAHQAZQBzAHQAIABkAGUAdABlAGMAdABpAG8AbgAgAHIAdQBsAGUAIAB2AGEAbABpAGQAYQB0AGkAbwBuACAAcwB0AHIAaQBuAGcAIgA=

powershell.exe /enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAHQAZQBzAHQAIABkAGUAdABlAGMAdABpAG8AbgAgAHIAdQBsAGUAIAB2AGEAbABpAGQAYQB0AGkAbwBuACAAcwB0AHIAaQBuAGcAIgA=

powershell.exe -enc "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAHQAZQBzAHQAIABkAGUAdABlAGMAdABpAG8AbgAgAHIAdQBsAGUAIAB2AGEAbABpAGQAYQB0AGkAbwBuACAAcwB0AHIAaQBuAGcAIgA="

powershell.exe -enc dwBoAG8AYQBtAGkA

copy C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe %TEMP%\svchost.exe
%TEMP%\svchost.exe -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAHQAZQBzAHQAIABkAGUAdABlAGMAdABpAG8AbgAgAHIAdQBsAGUAIAB2AGEAbABpAGQAYQB0AGkAbwBuACAAcwB0AHIAaQBuAGcAIgA=
del %TEMP%\svchost.exe

powershell.exe -Command "Get-Process -ErrorAction SilentlyContinue"
```

For Version 2, it came from reading Version 1 and spotting problems on paper, not from testing that showed me it was failing. I re-ran the same command from my first version to confirm the rule still fired after rewriting it, and that was about it. Because I only rewrote the rule after reading it, I only caught problems I already knew how to look for, so I never went looking for cases where it might miss something.

In my last iteration of my rule, this is where my stress-testing actually happened. Instead of running one command that I knew should fire, I went through different ways an attacker could run the same technique. These included the forward slash parameter prefix, quoting the base64 text, a payload short enough to fall under my length requirement, and a renamed copy of the PowerShell binary. I also added a normal command with a long alphanumeric argument, to check whether the rule would fire on something it shouldn't. I ran all of these commands against Version 2 of the rule first, so the results are a before and after rather than what Version 3 happens to catch. 



## Baseline Alerts

<img width="1286" height="868" alt="image" src="https://github.com/user-attachments/assets/bdc47873-6015-4963-b736-7a0e9fb3e383" />

<img width="1288" height="864" alt="image" src="https://github.com/user-attachments/assets/4d86e467-ca10-4084-967c-627e05d42c64" />

```xml
<rule id="92057" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)powershell\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)powershell\.exe.+\-\b(encodedcommand|e|ea|ec|encodeda|encode|en|enco)\b</field>
  <options>no_full_log</options>
  <description>Powershell.exe spawned a powershell process which executed a base64 encoded command</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```

```xml
<rule id="92213" level="15">
  <if_group>sysmon_event_11</if_group>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)[c-z]:\\\\Users\\\\.+\\\\AppData\\\\Local\\\\Temp\\\\.+\.(exe|com|dll|vbs|js|bat|cmd|pif|wsh|ps1|msi|vbe)</field>
  <options>no_full_log</options>
  <description>Executable file dropped in folder commonly used by malware</description>
  <mitre>
    <id>T1105</id>
  </mitre>
</rule>
```

## Detection Gap

<!-- What baseline misses and why. -->

## My Detection Rule

**Version 1**

```xml
  <rule id="100100" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)-e(nc|ncodedcommand)?\s</field>
    <description>Encoded PowerShell command executed</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
```

**Version 2**

```xml
<rule id="100100" level="11">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\(powershell|pwsh)\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\s-e[a-z]*\s+[A-Za-z0-9+/=]{20,}</field>
  <description>Encoded PowerShell command execution</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```


**Version 3**

```xml
<rule id="100100" level="11">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\(powershell|pwsh)\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\s[-/]e[a-z]*\s+[\\"']{0,2}(?:[A-Za-z0-9+/]{4}A[A-Za-z0-9+/]{2}A){2,}</field>
  <description>Encoded PowerShell command execution</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```



## Custom Detection Rule Result

<!-- Evasion test table, v2 vs v3. Screenshots of alerts.

     | Test | v2 | v3 |
     | -enc <long blob>            | fires  | fires  |
     | /enc <blob>                 | evades | fires  |
     | -enc "<blob>" from cmd      | evades | fires  |
     | -enc <16-char blob>         | evades | fires  |
     | renamed powershell.exe      | evades | evades |
     | -Command "... -ErrorAction SilentlyContinue" | silent | silent |

     Two findings worth their own paragraphs:
     - parent shell changes the command line field; PowerShell rebuilds it
       and drops argument-grouping quotes, cmd.exe passes them through
     - Wazuh stores the field with backslash-escaped quotes, so a rule
       written against what you type can miss what the SIEM records -->

## Coverage Limits

<!-- - payloads under 6 ASCII chars evade; dir confirmed silent
     - non-ASCII payloads don't produce the null pattern
     - renamed binaries evade the image anchor; originalFileName stays
       PowerShell.EXE and is the fix, not built, since Wazuh ANDs field
       entries and pwsh's value is untested
     - two other shipped rules caught the rename anyway (get IDs/levels)
     - command lines are attacker-controlled, so this class of rule is
       evadable in principle; ancestry-based detection (T1059.005 chain,
       cmd -> vbs -> wscript) is the durable answer, named not built -->
