# T1027.010 — Environment Variable Obfuscation

## Overview

The technique I will be covering in this finding is T1027.010 otherwise known as Environment Variable Obfuscation. My last finding was about hiding a command from someone reading process creation events. The attacker would run `powershell.exe -enc` followed by a base64 payload, and the command they are actually running never shows up as readable text. This finding is about the same idea, but flipped around. In this case it would be if the attacker hides the name of the program running the command, rather then hiding what the program says.

At this point in the attack chain, the attacker still has working credentials and a session in the endpoint, and they are still trying to run things without it looking obvious. If encoded PowerShell is something that an attacker think might be watched, they will hide a different part of the command. Windows command shell lets you pull a slice out of an environment variable and drop it inline, so the name of the interpreter does not have to be typed.

The syntax for this command would look something like `%VAR:~start,length%`. On my endpoint `%LOCALAPPDATA%` is `C:\Users\WazuhUser\AppData\Local`, so `%LOCALAPPDATA:~-3,1%` starts three characters from the end and takes one ,which gives back `c`. If stick you stick `md` to the end of that, the shell would build `cmd` and run the command. Because of this anyone searching in process creation events for the string `cmd` would not find it, since at the time the command was typed it was not there.

The two findings sit on opposite halves of the command line. In the encoded PowerShell case, the program name is visible but the payload is unreadable. Here, the payload is visible, but the program name is what's not visible. The question this finding answers is whether Wazuh can see the obfuscation itself, or only sees that a command shell ran.


## Attack Execution

I ran this attack against the endpoint with only the shipped Wazuh rules loaded at first, so that the baseline reflects what stock Wazuh rules can detect on their own.

The test is Atomic Red Team T1059.003 test 3, named Suspicious Execution via Windows Command Shell. Atomic Red Team describes it as a "command line executed via suspicious invocation" and cites their 2021 Threat Detection Report by Red Canary as the source.

The command as it appears in the atomic is:

```powershell
%LOCALAPPDATA:~-3,1%md /c echo #{input_message} > #{output_file} & type #{output_file}
```


The one I tested with default inputs filled in is:

```powershell
%LOCALAPPDATA:~-3,1%md /c echo Hello, from CMD! > hello.txt & type hello.txt
```

The payload itself doesn't do anything interesting on purpose, it just writes a line to `hello.txt` and prints the file back. It's only there to prove the shell resolved `cmd` and actually ran something, since what matters is what's at the front of the command line, not the payload. 


## Baseline Alerts

<img width="1321" height="865" alt="image" src="https://github.com/user-attachments/assets/42c31b30-398d-4cae-a43e-229c72eb1ee9" />


```json
{
  "agent": { "name": "Win-10-Endpoint-01", "id": "001" },
  "data": {
    "win": {
      "eventdata": {
        "image": "C:\\Windows\\System32\\cmd.exe",
        "commandLine": "\"cmd.exe\" /c %%LOCALAPPDATA:~-3,1%%md /c echo Hello, from CMD! > hello.txt & type hello.txt",
        "parentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parentCommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"",
        "processId": "4620",
        "parentProcessId": "9976",
        "user": "WIN10-ENDPT-1\\WazuhUser",
        "ruleName": "technique_id=T1059.003,technique_name=Windows Command Shell"
      },
      "system": { "eventID": "1", "eventRecordID": "68944" }
    }
  },
  "rule": {
    "id": "92052",
    "level": 4,
    "description": "Windows command prompt started by an abnormal process",
    "mitre": {
      "id": ["T1059.003"],
      "technique": ["Windows Command Shell"],
      "tactic": ["Execution"]
    }
  }
}
```


```json
{
  "agent": { "name": "Win-10-Endpoint-01", "id": "001" },
  "data": {
    "win": {
      "eventdata": {
        "image": "C:\\Windows\\System32\\cmd.exe",
        "commandLine": "cmd  /c echo Hello, from CMD!",
        "parentImage": "C:\\Windows\\System32\\cmd.exe",
        "parentCommandLine": "\"cmd.exe\" /c %LOCALAPPDATA:~-3,1%md /c echo Hello, from CMD! > hello.txt & type hello.txt",
        "processId": "2096",
        "parentProcessId": "4620",
        "user": "WIN10-ENDPT-1\\WazuhUser",
        "ruleName": "technique_id=T1059.003,technique_name=Windows Command Shell"
      },
      "system": { "eventID": "1", "eventRecordID": "68948" }
    }
  },
  "rule": {
    "id": "92032",
    "level": 3,
    "description": "Suspicious Windows cmd shell execution",
    "mitre": {
      "id": ["T1087", "T1059.003"],
      "technique": ["Account Discovery", "Windows Command Shell"],
      "tactic": ["Discovery", "Execution"]
    }
  }
}
```






## Detection Gap


## My Detection Rule


Version 1

```xml
  <rule id="100103" level="12">
    <if_sid>92031, 61603</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)%[a-zA-Z0-9_]+:~</field>
    <options>no_full_log</options>
    <description>Command obfuscation via environment variable substring expansion</description>
    <mitre>
      <id>T1027.010</id>
      <id>T1059.003</id>
    </mitre>
  </rule>
```


## Custom Detection Rule Result

<img width="1319" height="867" alt="image" src="https://github.com/user-attachments/assets/86ca9cda-959d-4ca0-b5c8-9f73889ab89b" />

```json
{
  "agent": { "name": "Win-10-Endpoint-01", "id": "001" },
  "data": {
    "win": {
      "eventdata": {
        "image": "C:\\Windows\\System32\\cmd.exe",
        "commandLine": "\"cmd.exe\" /c %%LOCALAPPDATA:~-3,1%%md /c echo Hello, from CMD! > hello.txt & type hello.txt",
        "parentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "processId": "4380",
        "parentProcessId": "332",
        "user": "WIN10-ENDPT-1\\WazuhUser"
      },
      "system": { "eventID": "1", "eventRecordID": "70248" }
    }
  },
  "rule": {
    "id": "100103",
    "level": 12,
    "description": "Command obfuscation via environment variable substring expansion",
    "mitre": {
      "id": ["T1027.010", "T1059.003"],
      "technique": ["Command Obfuscation", "Windows Command Shell"],
      "tactic": ["Defense Evasion", "Execution"]
    }
  }
}
```




## Coverage Limits


sudo nano /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
