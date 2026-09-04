# T1027.010 — Environment Variable Obfuscation

## Overview

The technique I will be covering in this finding is T1027.010, Command Obfuscation, specifically the environment variable form of it. My last finding was about hiding a command from someone reading process creation events. The attacker would run `powershell.exe -enc` followed by a base64 payload, and the command they are actually running never shows up as readable text. This finding is about the same idea, but flipped around. In this case it would be if the attacker hides the name of the program running the command, rather than hiding what the program says.

At this point in the attack chain, the attacker still has working credentials and a session on the endpoint, and they're trying to run things without it looking obvious. If encoded PowerShell is something that an attacker thinks might be watched, they will hide a different part of the command. Windows command shell lets you pull a slice out of an environment variable and drop it inline, so the name of the interpreter does not have to be typed.

The syntax for this command would look something like `%VAR:~start,length%`. On my endpoint `%LOCALAPPDATA%` is `C:\Users\WazuhUser\AppData\Local`, so `%LOCALAPPDATA:~-3,1%` starts three characters from the end and takes one, which gives back `c`. If you stick `md` to the end of that, the shell would build `cmd` and run the command. Because of this anyone searching in process creation events for the string `cmd` would not find it, since at the time the command was typed it was not there.

The two findings sit on opposite halves of the command line. In the encoded PowerShell case, the program name is visible but the payload is unreadable. Here, the payload is visible, but the program name is what's not visible. The question this finding answers is whether Wazuh can see the obfuscation itself, or only sees that a command shell ran.


## Attack Execution

I ran this attack against the endpoint with only the shipped Wazuh rules loaded at first, so that the baseline reflects what stock Wazuh rules can detect on their own. I'm running `Invoke-AtomicTest` from a PowerShell session, so that the command shell in this test gets launched by `powershell.exe`. 

The test is Atomic Red Team T1059.003 test 3, named Suspicious Execution via Windows Command Shell. Atomic Red Team describes it as a "command line executed via suspicious invocation" and cites Red Canary's 2021 Threat Detection Report as their source.

The command as it appears in the atomic is:

```cmd
%LOCALAPPDATA:~-3,1%md /c echo #{input_message} > #{output_file} & type #{output_file}
```


The one I tested with default inputs filled in is:

```cmd
%LOCALAPPDATA:~-3,1%md /c echo Hello, from CMD! > hello.txt & type hello.txt
```

The payload itself doesn't do anything interesting on purpose, it just writes a line to `hello.txt` and prints the file back. It's only there to prove the shell expanded `%LOCALAPPDATA:~-3,1%md` into `cmd` and actually ran something, since what matters is what's at the front of the command line, not the payload. 


## Baseline Alerts

<img width="1321" height="865" alt="image" src="https://github.com/user-attachments/assets/42c31b30-398d-4cae-a43e-229c72eb1ee9" />

Wazuh's stock rule alerted on the Atomic Red Team technique I used two times, however none of them pertained to obfuscation which is what I am trying to detect. 


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
The first alert is 92052 at level 4, "Windows command prompt started by an abnormal process," on process 4620. The JSON I've provided above is a trimmed version of the full alert, cut down to the field I think matter here.

This is the event that contains the obfuscated string. As we can see here, `commandLine` holds `"cmd.exe" /c %%LOCALAPPDATA:~-3,1%%md /c echo Hello, from CMD!`, and the rule fired because `parentImage` is `powershell.exe`. The MITRE technique it's tagged with is T1059.003 Windows Command Shell.



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
The second alert is 92032 at level 3, "Suspicious Windows cmd shell execution," on process 2096, whose parent is 4620. I've also provided the JSON for this alert as well in a trimmed version of the full alert. 

In this event the shell has expanded the variable, so `commandLine` reads `cmd /c echo Hello, from CMD!`. The obfuscated string appears only in `parentCommandLine`. This alert is tagged with the MITRE techniques T1087 Account Discovery and T1059.003 Windows Command Shell.


## Detection Gap

Wazuh's shipped ruleset caught the attack technique I used, and it produced two alerts from it. Although the events carrying the techniques were collected and matched, they were quite misleading in a couple ways. 

First of all, the severity of the alert is really low for what the threat is. 92052 came in at level 4 and 92032 at level 3. For context, throughout all of my findings and whenever I run tests for XML rules, I always see 67027 "A process was created alerts" alerts at level 3. It's just normal process telemetry, and because of how often they fire they're basically noise. The fact that both of the alerts responding to an obfuscated command line landing anywhere near the same level as an alert associated with just common noise is pretty low

The descriptions are on point with the command line, but they don't actually mention the obfuscation present in it. The descriptions that were present in the alerts were, "Windows command prompt started by an abnormal process" and "Suspicious Windows cmd shell execution" which are both true of course. However, an analyst that was reading either would not immediately grasp what happened right away, nor understand the obfuscation present in the command line. The information for 92032 is also off, because the alert body doesn't contain the obfuscated string at all. By that event the shell had already expanded the obfuscated string, so `%LOCALAPPDATA:~-3,1%` only shows up one field over in `parentCommandLine`, and nothing in the alert points there.

The MITRE tags are also inaccurate. Both alerts are tagged T1059.003 Windows Command Shell under Execution, which is accurate, but neither carries Defense Evasion. If you triage by tactic, the alert would tell you a command shell ran and nothing about the attempts to hide it. 92032 also carries T1087 Account Discovery, and nothing in this attack enumerates accounts.

The detection gap here is that neither rule could match nor describe the obfuscation correctly. 92052 fired on the parent process being PowerShell, whereas 92032 fired on the cmd spawning cmd. Not to mention that the syntax `%VAR:~` is also sitting in `commandLine` where Sysmon collected it. The evidence exists and was present in all of the alerts, but none of the rules pointed it towards obfuscation.


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

For the first iteration of my rule, I made it so that the regex would match the substring expansion syntax in order to detect it. Rather than trying to make it so that the rule catches the atomic test, I made it so the rule tries to detect the technique by looking for the percent sign, a variable name, and then `:~`. If I only made it so that my rule was looking for `LOCALAPPDATA` or `cmd`, it wouldn't be able to catch something like `%COMSPEC:~-7,3%` which can also build the phrase `cmd` from a different variable and run the same way. 

The `if_sid` chains it to 92031 and 61603, so they only evaluate on Sysmon process creation events. I intentionally put two MITRE tags because T1059.003 (Windows Command Shell) is what actually ran, whereas T1027.010 (Command Obfuscation) is how it was hidden, which also happens to be the part that no shipped rule was tagging. 

As I mentioned in the detection gaps, the severity level of the shipped rules are quite low for a deliberate attempt to hide what was running. They come in at level 3 and 4, which are more indicative of common noise. Because of this, my detection rule started off at level 12, which I believe is a more realistic severity for an attempt to obfuscate the command line.


Version 2

```xml
<rule id="100103" level="10">
  <if_sid>92031, 61603</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">%[\^a-zA-Z0-9_]+:~</field>
  <options>no_full_log</options>
  <description>Command obfuscation via environment variable substring expansion</description>
  <mitre>
    <id>T1027.010</id>
    <id>T1059.003</id>
  </mitre>
</rule>
```

Between my first iteration and final one, there were only two changes.

The first change I made was to the character class, which now allows carets. This is because batch strips a caret wherever it sits inside a variable name, so `%^LOCALAPPDATA:~-3,1%` still gives back `c` and still builds `cmd`. I confirmed that by running it from a command prompt and watching it print `c`. Version 1 needed an alphanumeric character right after the `%` or else it wouldn't match, and the command goes through undetected. The difference was pretty substantial as adding the caret is what separates catching an attacker's obfuscation attempt or missing it completely.
 
Sysmon actually flagged this one on its own. The event that came through was tagged `technique_id=T1027,technique_name=Obfuscated Files or Information` instead of the Windows Command Shell tag every other event in this test carried. The tag comes from a rule in the Sysmon config that matches any command line containing a caret, so it comes off as a broad signal, rather than a real understanding of the technique. It was still sitting in the event, and no shipped Wazuh rule used it.

The second change I made was dropping the severity level from 12 to 10. `email_alert_level` in `ossec.conf` is set to 12, so at the old level every alert this rule produced sent mail. Level 12 was the right severity level for how serious the technique is, but the wrong call once I saw what else fires on this syntax. Because of this I changed it to level 10, which keeps the alert clearly above common noise without sending an email every time it goes off.


## Custom Detection Rule Result

**Version 1 Run**


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
With Version 1, the atomic still produces two alerts, but the first one changes. 92052 does not fir eanymore, since 100103 takes the event instead as it comes in at level 12 and names the technique. 92032 still is untouched at level 3, since that's the child process where the shell already expnaded the variable and there is nothing left to match.

My detection rule didn't cause the alert count to change, it just made it so that the alert says what actually happened now and sits noticeably above the baseline. 


**Version 2 Run**

<img width="1292" height="873" alt="image" src="https://github.com/user-attachments/assets/2cef43a5-8cc6-47da-81ec-eed269cbbc49" />

```json
{
  "agent": { "name": "Win-10-Endpoint-01", "id": "001" },
  "data": {
    "win": {
      "eventdata": {
        "image": "C:\\Windows\\System32\\cmd.exe",
        "commandLine": "\"cmd.exe\" /c %%LOCALAPPDATA:~-3,1%%md /c echo Hello, from CMD! > hello.txt & type hello.txt",
        "parentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "processId": "10924",
        "parentProcessId": "6472",
        "user": "WIN10-ENDPT-1\\WazuhUser"
      },
      "system": { "eventID": "1", "eventRecordID": "73673" }
    }
  },
  "rule": {
    "id": "100103",
    "level": 10,
    "mail": false,
    "description": "Command obfuscation via environment variable substring expansion",
    "mitre": {
      "id": ["T1027.010", "T1059.003"],
      "technique": ["Command Obfuscation", "Windows Command Shell"],
      "tactic": ["Defense Evasion", "Execution"]
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
        "commandLine": "\"C:\\Windows\\system32\\cmd.exe\" /c echo %%^LOCALAPPDATA:~-3,1%%",
        "parentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "processId": "7772",
        "parentProcessId": "6472",
        "user": "WIN10-ENDPT-1\\WazuhUser",
        "ruleName": "technique_id=T1027,technique_name=Obfuscated Files or Information"
      },
      "system": { "eventID": "1", "eventRecordID": "73685" }
    }
  },
  "rule": {
    "id": "100103",
    "level": 10,
    "mail": false,
    "description": "Command obfuscation via environment variable substring expansion",
    "mitre": {
      "id": ["T1027.010", "T1059.003"],
      "technique": ["Command Obfuscation", "Windows Command Shell"],
      "tactic": ["Defense Evasion", "Execution"]
    }
  }
}
```
Version 2 fires on the same atomic at level 10 now, with `mail` now as false so it doesn't send the alert every time it goes off. It also fires on the caret variation that Version 1 missed.


## Coverage Limits

A glaring issue that I was not able to resolve with both the first and final iteration of my rule, is how it fired even on normal commands that had nothing to do with the technique. 

All of the commands I listed below are ones that the rule fired on:

```
cmd /c echo %DATE:~-4,4%%DATE:~-10,2%%DATE:~-7,2%
cmd /c echo %TIME:~0,2%
cmd /c echo %CD:~0,3%
cmd /c echo %USERNAME:~0,2%
cmd /c echo %PATH:~0,10%
```

The first command is the standard way a batch script builds a timestamped filename, which is common in backup and logging scripts. However, these commannds are not attacks, yet my rule cannot tell the difference between them and the atomic technique.

I found that tightening regex does not fix the issue. The difference between the atomic technique and a backup script isn't in the syntax, since both use `%VAR:~` the same way. The difference is what the expanded result ends up getting used as. In the case of the atomic technique, the result becomes a program name and something executes. With something like `echo %DATE:~-4,4%`, it becomes text that gets printed. A field match on `commandLine` cannot see the distinction, because the field records what was typed and not what happened after.

One of the fixes that I thought of implementing was excluding specific variable names like `DATE` and `TIME`. The problem with this is that it becomes a deny list, and it can only cover the cases that I happened to test. Because it's a deny list, it would need constant maintenance to keep up with new legitimate variables. This is not inherently flawed, but it is a limit that I'm acknowledging. Variables like `%CD:~`, `%USERNAME:~`, and anything else a script slices would still fire, and I would end up having a rule that looked clean while only being tested against five commands. Not to mention, excluding `echo` doesn't work either. This is because even though I do use it for my tests, this is something that's quite easy for an attacker to find a workaround for.

The better fix would be matching on the execution context rather than variable name, so that rule only fires when the expansion sits where a program name goes. The atomic's own command line puts the obfuscation in the middle of the arguments rather than at the front, so any anchoring I tried would have to handle nesting, and I would want real traffic to tune against before narrowing a rule this much.

Things like character array reconstruction, base64, and Unicode substitution all can evade my rule without having to use `%VAR:~` at all. There's also the fact that obfuscation inside a `.bat` file is also invisible here, since the command line shows the script path and not its contents.

One thing I could have measured but didn’t was the false positive rate for this endpoint. I only tested five commands that I specifically chose because I expected them to trigger the rule. Because of that, I don’t know how often `%VAR:~` appears in legitimate traffic on this endpoint, so I'm not able to determine the rule's false positive rate.


