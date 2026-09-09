# Finding 04 - T1562.001 Impair Defenses: Disable or Modify Tools

## Overview

The technique I will be covering in this finding in this finding is T1562.001, Impair Defenses: Disable or Modify Tools. My previous techniques were both about an attacker hiding what they were doing. In finding 02, they encoded the payload so the command line could not be read, and in finding 03 they built the name of the interpreter out of an environment variable so the process running it was not visible either. Both of these techniques serve the same purpose in leaving an event behind that is harder to read than it should be. The technique I'm covering is a deliberate attempt from the attacker to stop the record from being written.

The attacker is still in the same position in the attack chain as they were for the last two findings. They have a session on the endpoint and they are running commands out of an elevated shell, which is the same place I was running from when I tested encoded PowerShell and environment variable obfuscation. They don't have have to do anything else to have this technique to become available to them. `auditpol.exe` is the built-in Windows tool for managing the advanced audit policy, and that policy is what decides which events get written to the Security log. It ships with Windows and it can be modified with administrative rights in the computer, in which this case the attacker has. 

The audit policy is what produces the machine's record of who did what on it. It includes things such as logons and logoffs, accounts being created or added to a group, changes to security settings, use of privileged rights, access to files and registry keys, and changes to the audit policy itself, though not all of them are switched on out of the box. Disabling the audit policy does not accomplish anything for the attacker on its own. What it buys them is room for everything they do after, since once a policy is turned off, any actions that would have been alerted happen without producing any records. Because of this the machine looks like it is running normally the whole time, so the only opportunity to catch it is the command that turns the policy off, which is what my rule is written against.


## Attack Execution

A note on the numbering. This technique has been renumbered by Atomic Red Team but the technique itself hasn't changed. In MITRE ATT&CK's framework the technique is T1562.001 for Impair Defenses: Disable or Modify Tools but for Atomic Red Team the ID is T1685.001 Disable or Modify Tools: Disable or Modify Windows Event Logs. 

The test we're going to use is Atomic Red Team test 4 under T1685.001 which disables the Windows audit policy across three categories. Atomic Red Team describes it as disabling the audit policy to prevent key host based telemetry from being written to the event logs, and cites Microsoft's Solorigate reporting as its source.

Solorigate is Microsoft's name for the actor behind the SolarWinds supply chain compromise disclosed in December 2020, the same intrusion that was tracked elsewhere as SUNBURST. Microsoft's writeup on the second stage activation describes the operators switching logging off before doing hands on keyboard work and switching it back on when they were done. That detail is the reason this atomic ships with cleanup commands that re-enable each category. The technique as it was actually used was not to turn auditing off and leave it off, it was to turn it off for exactly as long as it took to do something worth hiding, and then put the policy back the way it was found.

```commandprompt
auditpol /set /category:"Account Logon" /success:disable /failure:disable
auditpol /set /category:"Logon/Logoff" /success:disable /failure:disable
auditpol /set /category:"Detailed Tracking" /success:disable
```

For this test, the commands target categories rather than subcategories, so each line would switch off a whole block of auditing rather than a single event type. Account logon covers credential validation, Logon/Logoff covers the logon and logoff events themselves, and Detailed Tracking covers process creation. Between them they account for most of what the Security Logs would have to say about an account being used on the endpoint.


## Baseline Alerts

<img width="1288" height="866" alt="image" src="https://github.com/user-attachments/assets/57ff8704-b4fb-4280-9e24-391d0954821a" />

For the first figure we can see Wazuh alerting on the test and the bulk of what it produced is rule 60112 at level 8, "Windows Audit Policy changed." The 67027 process creation events at level 3 are just noise. The whole run lands inside about half a second, from 13:29:12.301 to 13:29:12.862. Three commands produced 23 alerts, because each `/category:` I disabled is a container that holds multiple subcategories, and Windows writes a separate audit policy change event for every subcategory that changes. Account Logon, Logon/Logoff and Detailed Tracking come to roughly twenty subcategories between them, so the volume here is the policy being switched off one by one rather than one event repeating.


<img width="1290" height="867" alt="image" src="https://github.com/user-attachments/assets/b22f6fa5-4031-4593-baa2-54a025afc78c" />

For the second figure, this is the first page of the same window, which shows us the end of the run. Alongside more 60112 and 67027 noise, the last alert of the test is 92052 at level 4, "Windows command prompt started by an abnormal process," which is the cmd.exe that Invoke-AtomicTest launched out of my PowerShell session.

The shipped coverage for this test is three rules which is 60112 for the audit policy change at level 8, 92052 for the command prompt at level 4, and 67027 for process creation at level 3.

**Trimmed JSON**

**60112 - Audit Policy Change**

```json
{
  "agent": { "name": "Win-10-Endpoint-01", "id": "001" },
  "data": {
    "win": {
      "eventdata": {
        "subjectUserName": "WazuhUser",
        "subjectDomainName": "WIN10-ENDPT-1",
        "subjectLogonId": "0x15d1c1",
        "category": "Logon/Logoff",
        "subcategory": "Special Logon",
        "auditPolicyChanges": "Success removed, Failure removed",
        "clientProcessId": "10380"
      },
      "system": {
        "eventID": "4719",
        "channel": "Security",
        "eventRecordID": "167529"
      }
    }
  },
  "rule": {
    "id": "60112",
    "level": 8,
    "description": "Windows Audit Policy changed",
    "groups": ["windows", "windows_security", "policy_changed"]
  }
}
```

**92052 - Command Prompt**

```json
{
  "agent": { "name": "Win-10-Endpoint-01", "id": "001" },
  "data": {
    "win": {
      "eventdata": {
        "subjectUserName": "WazuhUser",
        "subjectDomainName": "WIN10-ENDPT-1",
        "subjectLogonId": "0x15d1c1",
        "category": "Logon/Logoff",
        "subcategory": "Special Logon",
        "auditPolicyChanges": "Success removed, Failure removed",
        "clientProcessId": "10380"
      },
      "system": {
        "eventID": "4719",
        "channel": "Security",
        "eventRecordID": "167529"
      }
    }
  },
  "rule": {
    "id": "60112",
    "level": 8,
    "description": "Windows Audit Policy changed",
    "groups": ["windows", "windows_security", "policy_changed"]
  }
}
```


## Detection Gap

The rules that came shipped with Wazuh were able to detect the audit policy being changed and detected it accurately. 60112 fired on every subcategory that was changed, it came in at level 8, and there was no coverage that was actually evaded. The problem is what the alert is actually claiming. "Windows Audit Policy changed" describes something that can happen on a healthy machine all the time. Administrators can change the audit policy, and someone finishing a test can turn the auditing back on, which is what I did myself when I ran the clean up commands. Since the rules fire the same way for all of the commands, the alert can tell me the policy changed but not whether it should have. Because of this, it makes it almost indistinguishable to tell whether it's an attacker changing the audit policy or an administrator doing their job. So the detection gap here is not that Wazuh missed anything. It recorded the command that disabled the policy word for word, but described it as something else.

The information that would settle it was collected, but nothing else would be done with it. Every one of these alerts carries `auditPolicyChanges` reading `Success removed, Failure removed`, and a change in the other direction would say something different. The rule never looks at that field, so it produces the same description and the same level whether auditing was taken away or put back. The alert is also silent about what performed the change. It gives `clientProcessId` 10380 and `subjectUserName` WazuhUser, which is a process number and an account name, and neither of those tells an analyst that the program was auditpol or that the command it ran contained the word disable.

The volume also makes it harder to read rather than easier. Each command targeted a category instead of a subcategory, so Windows recorded a separate change for every subcategory underneath it and Wazuh raised a separate alert for each one. The result is 23 alerts with identical descriptions at identical severity inside half a second, and none of them stating what actually happened, which is that three entire categories of auditing were switched off. The tagging does not help either. 60112 carries PCI, HIPAA, NIST and GDPR mappings and no MITRE technique at all, so an analyst working by tactic would find nothing from this attack sitting under Defense Evasion.

60112 is tuned correctly and I have no issue with it and its severity level. Level 8 for an audit policy change is right, especially when its ambiguous and it can't be known who did it. It does exactly what it says it does, and any higher severity levels would create unnecessary noise. However, the rule that does not add up is 92052, which came in at level 4. In it's `commandLine` field is `auditpol /set /category:"Account Logon" /success:disable /failure:disable` along with the other two commands. The issue with this is that my command came in plain text, it was not encoded nor obfuscated in anyway, and my command was detected. However, all the rule had to say about it was that "Windows command prompt started by an abnormal process." It is describing the parent process, but it says nothing about how the command is an attack itself. 


## My Detection Rule

**Version 1**

```xml
<rule id="100102" level="12">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)auditpol\s+/(set.*disable|clear|remove)</field>
    <options>no_full_log</options>
    <description>Audit policy impaired via auditpol</description>
    <mitre>
        <id>T1562.001</id>
    </mitre>
</rule>
```

The rule is anchored to 61603, Sysmon process creation, and that choice is the entire point of it. The audit policy events on the Security channel do not carry a command line. 4719 gives a category, a subcategory, the subject account and a process ID, and none of that says which program made the change or what it was told to do. The Sysmon event does. `commandLine` holds the whole string, so anchoring to 61603 puts the rule on the only channel where the word disable actually appears.

The field match is a regex written against auditpol's own verbs rather than against the commands in the atomic. `set.*disable` covers switching auditing off for a category or a subcategory, and `clear` and `remove` cover wiping the policy outright. I wrote it that way for the same reason I wrote the obfuscation rule against the syntax instead of the variable name. If I had matched on `/category:"Account Logon"` I would only be catching the test I happened to run that day.

That decision paid off straight away, because the rule catches Atomic Red Team test 5 as well as test 4 without being written for it. Test 5 runs `auditpol /clear /y` and `auditpol /remove /allusers`, which are a completely different pair of commands to the three category disables in test 4, and they hit the `clear` and `remove` branches.  

The regex also gives my rule a direction, which is the thing 60112 could not do. `disable`, `clear` and `remove` are all reductions in auditing, and none of them match the cleanup commands, which use `/success:enable /failure:enable`. So when I put the policy back afterwards, the rule stays quiet. 60112 fired for my attack and for my cleanup at the same level with the same description. This one only fires on one of them.

Level 12 puts it above 60112 at level 8 and well above 92052 at level 4. The description says the audit policy was impaired rather than changed, which is the distinction none of the shipped rules made, and `no_full_log` keeps the alert body clean the way my other rules do.


**Version 2**

```xml
<rule id="100102" level="12">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)auditpol(\.exe)?"?\s+/(set[^&amp;]*disable|clear|remove|restore)</field>
    <options>no_full_log</options>
    <description>Audit policy impaired via auditpol - User: $(win.eventdata.user)</description>
    <mitre>
        <id>T1562.001</id>
    </mitre>
</rule>
```

**Version 2:**

```xml
<rule id="100102" level="12">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)auditpol(\.exe)?"?\s+/(set.*disable|clear|remove|restore)</field>
    <options>no_full_log</options>
    <description>Audit policy impaired via auditpol - User: $(win.eventdata.user)</description>
    <mitre>
        <id>T1562.001</id>
    </mitre>
</rule>
```

Version 1 caught both atomic tests, but it only caught the exact way I happened to invoke auditpol. The pattern required a space and then a slash directly after the word, so anything sitting between the two broke it. `auditpol.exe /clear /y` does not match version 1, and neither does `"C:\Windows\System32\auditpol.exe" /clear /y`, which is the shape a scheduled task or a script would normally use. Adding `(\.exe)?` and an optional quote covers both of those without loosening anything else, since the name of the tool still has to be on the line.

I also added `restore` to the list of verbs. Version 1 covered disabling, clearing and removing, which are the three obvious ways to reduce auditing, but auditpol can write the policy out to a file with `/backup` and read one back in with `/restore`. An attacker can back the policy up, edit the file so everything is switched off, and restore it, and the command line for that contains none of the words my first version was looking for. It provides the same outcome, which is my rule detecting an attempt at impairing audit policy, but through a verb I hadn't thought of before. 

The last change to the pattern was replacing `.*` with `[^&]*` in the set branch. Both atomic tests chain several commands into a single line with `&`, so one command line can hold three separate auditpol invocations. With `.*` the rule could pair a `/set` from one command with the word disable from a different command further along the same line. Restricting it to characters that are not an ampersand keeps each command being judged on its own.

The description is a quality of life change. Version 1 told me the audit policy was impaired and nothing else, so the first thing anybody would ask is who did it. `$(win.eventdata.user)` fills that in straight from the Sysmon event. Like my brute force rule though, the field doing the convenience work is also the field doing the triage as well. This is beacuse an audit policy change is not automatically an attack, and the thing separating an administrator hardening a machine from an attacker blinding one is usually the account it came from, so having it in the alert list means that judgement can start before the alert is even opened.


## Custom Detection Rule Result

**Version 1 Test**

<img width="1293" height="869" alt="image" src="https://github.com/user-attachments/assets/2f99e35f-0df4-44f2-8bc8-ef4a9d863873" />

```json
{
  "agent": { "name": "Win-10-Endpoint-01", "id": "001" },
  "data": {
    "win": {
      "eventdata": {
        "image": "C:\\Windows\\System32\\cmd.exe",
        "commandLine": "\"cmd.exe\" /c auditpol /set /category:\"Account Logon\" /success:disable /failure:disable & auditpol /set /category:\"Logon/Logoff\" /success:disable /failure:disable & auditpol /set /category:\"Detailed Tracking\" /success:disable",
        "parentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parentCommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"",
        "processId": "5196",
        "parentProcessId": "9156",
        "user": "WIN10-ENDPT-1\\WazuhUser",
        "integrityLevel": "High",
        "ruleName": "technique_id=T1059.003,technique_name=Windows Command Shell"
      },
      "system": {
        "eventID": "1",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "eventRecordID": "76708"
      }
    }
  },
  "rule": {
    "id": "100102",
    "level": 12,
    "description": "Audit policy impaired via auditpol",
    "groups": ["sysmon", "local"],
    "mitre": {
      "id": ["T1562.001"],
      "technique": ["Disable or Modify Tools"],
      "tactic": ["Defense Evasion"]
    }
  }
}
```

Rule 100102 fired on test 4 at level 12 with the description "Audit policy impaired via auditpol." It fired once for the whole test rather than once per command, because Invoke-AtomicTest chains all three auditpol commands into a single `cmd.exe` and my rule is matching against that one command line.

The ordering in the dashboard is something I think worth pointing out. My alert lands ahead of the 60112s rather than after them, and that comes directly from what the rule reads. Sysmon writes the process creation event the moment `cmd.exe` starts, which is before the auditpol commands inside it have actually run, while each 60112 only exists once Windows has applied a change to a subcategory. So the alert that names the attack arrives first and the alerts showing its effect come in behind it.

The alert also carries T1562.001 under Defense Evasion, which is the tactic that nothing in the baseline was tagged with at all.

<img width="1289" height="861" alt="image" src="https://github.com/user-attachments/assets/6c214589-cfa9-42fc-97ad-1b8280fe8a13" />

```json
{
  "agent": { "name": "Win-10-Endpoint-01", "id": "001" },
  "data": {
    "win": {
      "eventdata": {
        "image": "C:\\Windows\\System32\\cmd.exe",
        "commandLine": "\"cmd.exe\" /c auditpol /clear /y & auditpol /remove /allusers",
        "parentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parentCommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"",
        "processId": "3868",
        "parentProcessId": "9156",
        "user": "WIN10-ENDPT-1\\WazuhUser",
        "integrityLevel": "High",
        "ruleName": "technique_id=T1059.003,technique_name=Windows Command Shell"
      },
      "system": {
        "eventID": "1",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "eventRecordID": "76790"
      }
    }
  },
  "rule": {
    "id": "100102",
    "level": 12,
    "description": "Audit policy impaired via auditpol",
    "groups": ["sysmon", "local"],
    "mitre": {
      "id": ["T1562.001"],
      "technique": ["Disable or Modify Tools"],
      "tactic": ["Defense Evasion"]
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
        "commandLine": "\"cmd.exe\" /c auditpol /clear /y & auditpol /remove /allusers",
        "parentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parentCommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"",
        "processId": "3868",
        "parentProcessId": "9156",
        "user": "WIN10-ENDPT-1\\WazuhUser",
        "integrityLevel": "High",
        "ruleName": "technique_id=T1059.003,technique_name=Windows Command Shell"
      },
      "system": {
        "eventID": "1",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "eventRecordID": "76790"
      }
    }
  },
  "rule": {
    "id": "100102",
    "level": 12,
    "description": "Audit policy impaired via auditpol",
    "groups": ["sysmon", "local"],
    "mitre": {
      "id": ["T1562.001"],
      "technique": ["Disable or Modify Tools"],
      "tactic": ["Defense Evasion"]
    }
  }
}
```

Test 5 fired the same rule without me changing anything. The command line here is `"cmd.exe" /c auditpol /clear /y & auditpol /remove /allusers`, which has nothing in common with test 4 apart from the name of the tool, and 100102 still caught it at level 12 with the same description and the same Defense Evasion tag.

This is the part I was aiming at when I wrote the regex against auditpol's own verbs instead of the strings in the test I happened to be running. `clear` and `remove` were branches I had never actually exercised until now, and they held up the first time they saw real input.

## Coverage Limits
