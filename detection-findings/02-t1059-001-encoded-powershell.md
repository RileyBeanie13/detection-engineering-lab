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



**Version 2 & 3 Test**

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

**Image 1**

I ran my Version 1 test command, `powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAdABlAHMAdAAiAA==`, twice. The first run was in Powershell and the second was from an administrator command prompt. The PowerShell run produced 92057 at level 12, which correctly identifies base64 encoded command execution. The command prompt run produced nothing that names the technique. Both runs generated 92213 at level 15 and a handful of 67027 process creation alerts at level 3, but neither of those tells an analyst that an encoded command ran. Looking at this alert list, there's no way to tell whether the second command was run at all. 


<img width="1288" height="864" alt="image" src="https://github.com/user-attachments/assets/4d86e467-ca10-4084-967c-627e05d42c64" />

**Image 2**

For the renamed binary test I copied `powershell.exe` to `%TEMP%\svchost.exe` and ran the same encoded command through it. My own rule missed this, since it anchors on the image path and the image reads `svchost.exe`. Good thing that the two shipped rules from Wazuh caught them anyway. As we can see there is a 92151 at level 12 which flagged the binary loading the PowerShell automation library, and 61618 at level 12 flagged the process itself as a suspicious svchost. Neither of these is looking at the command line, which is why the rename that defeats my rule does not defeat them.


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
This rule, provided with Wazuh, checks for two things. It checks that the parent process is `powershell.exe`, and the command line has to contain `powershell.exe` followed by a dash and one of the parameters in the fixed list.

The list of parameter spellings it accepts is `encodedcommand`, `e`, `ea`, `ec`, `encodeda`, `encode`, `en`, and `enco`, with word boundaries on either side so it matches those spellings exactly rather than as part of a longer word.


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

This rule watches Sysmon file creation events and fires on any file that's written under a user's Temp folder with an executable or scripting extension. Level 15 is the highest severity Wazuh uses. The problem is that `.ps1` is in that extension list, and PowerShell writes a temp file named `__PSScriptPolicyTest_<random>.ps1` to that folder when it checks execution policy. That happens on every PowerShell launch, so the rule fires at level 15 every time PowerShell starts regardless of what it's doing. 



## Detection Gap

The biggest gap in 92057 is the parent process condition. Wazuh requires every field in a rule to match, so if the parent process isn't `powershell.exe` the rule would never look at the command line. My first image shows my first two runs, one with PowerShell and the other with Command Prompt after it. They were the same encoded command, and the same payload. The only difference was that only the PowerShell one was detected, and the one ran with Command Prompt wasn't caught. 

The parameter list has a gap too. It accepts `encodedcommand`, `e`, `ea`, `ec`, `encodeda`, `encode`, `en`, and `enco`, but PowerShell accepts any unambiguous abbreviation of the parameter name. `enc` is the most common form and it isn't in the list. Neither are `encod` or `encodedc`. So even with the right parent process, several valid spellings would get past it.


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

This was the first detection rule I ever wrote, so it was mostly me learning the ropes. It looks for `-e`, `-enc`, or `-encodedcommand` followed by whitespace anywhere in the command line, and that's about all it does.

The one thing it got right was what it didn't check, unlike rule 92057. Since there's no parent process condition, it fires on the encoded command whether it came from PowerShell or from a command prompt. That was the gap I was trying to close and it worked. 

However, just about everything else in my first rule is loose. `<if_group>sysmon_event1</if_group>` puts every process creation event on the endpoint in scope, not just PowerShell, so anything at all with `-e` followed by a space in its command line would fire at level 12. There's also nothing requiring a base64 blob to follow the parameter, so the rule never actually confirms an encoded command was run. I also think it's worth mentioning that the three spellings I cover  have the same problem 92057 did. There are many different ways to write the parameter, and the first iteration of my rule catches fewer spellings than 92057 does.


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

Version 2 anchors on the image first, unlike Version 1. `(?i)\\(powershell|pwsh)\.exe` means that the process has to actually be PowerShell, so the rule stops evaluating anything else on the endpoint and create more false positives. That also fixes the scope problem from Version 1, where every process creation event could cause the alert to fire.

The design logic behind the parameter match also changed. Instead of making the list for parameters larger by longer the way Version 1 and 92057 do, I used `-e[a-z]*`, which matches a dash, an e, and then any number of letters after it.

I added a requirement to the blob of base64 as well. `[A-Za-z0-9+/=]{20,}` means at least 20 base64 characters have to follow the parameter, so the rule confirms an encoded command actually ran rather than just matching a parameter name. I also dropped the level from 12 to 11, since I believed that the previous one blew the severity level out of proportion a bit.

I also switched from `<if_group>sysmon_event1</if_group>` to `<if_sid>61603</if_sid>`. Rule 61603 is Sysmon's process creation rule, and it's the rule that puts events into the `sysmon_event1` group in the first place, so both versions are looking at the same events. Pointing at the rule ID directly is just more specific, since a group can pick up other rules later.


**Version 3**

```xml
<rule id="100100" level="12">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\(powershell|pwsh)\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\s[-/]e[a-z]*\s+[\\"']{0,2}(?:[A-Za-z0-9+/]{4}A[A-Za-z0-9+/]{2}A){2,}</field>
  <description>Encoded PowerShell command executed by $(win.eventdata.parentImage)</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```

For the final version I dialed the severity back to 12. Rule 92057 is the shipped rule that detects encoded command lines and it sits at 12. My rule covers a genuine gap because 92057 never fires when encoded PowerShell is run from a command prompt. However, it's still detecting the same technique as 92057. Because it's an extension of that coverage, it should match the severity of the rule it was written against.

This version came out of actually stress testing Version 2 instead of reading it. I ran the forward slash parameter prefix, a quoted base64 payload, a payload short enough to fall under the length requirement, and a renamed copy of the PowerShell binary. I also ran one command that shouldn't fire at all, to check whether the changes I was making would start alerting on normal PowerShell use.

I made three major changes in the command line field. `[-/]` accepts either a dash or a forward slash, since PowerShell takes both. `[\\"']{0,2}` allows an optional quote before the blob, and it allows a backslash too because of how Wazuh stores the command line. And the blob check changed from a plain length requirement to a shape requirement, which I think is the most important part worth explaining. 

Version 2 required at least 20 base64 characters after the parameter. That worked, but it was doing something I didn't intend it to. `whoami` encodes to only 16 characters, so a short command slipped right under the length requirement, and short commands such as `whoami` or `net user` are exactly what an attacker runs first once they authenticate into an endpoint.

The obvious fix was lowering the number, but that opens a different problem. `-e[a-z]*` matches `-ErrorAction`, and `SilentlyContinue` is 16 characters of pure base64 alphabet. If I lowered the floor to 12, it would have made the rule fire on one of the most commonly used parameters in PowerShell. The length requirement wasn't really checking the length, and it accidentally did the work of keeping normal commands out.

Instead of checking how long the payload is, this checks whether it actually looks like UTF-16LE base64. `(?:[A-Za-z0-9+/]{4}A[A-Za-z0-9+/]{2}A){2,}` matches that pattern. Four characters, an `A`, two characters, another `A`, repeated at least twice. That's 16 base64 characters, or six ASCII characters of payload, so `whoami` matches. `SilentlyContinue` doesn't, because splitting it the same way gives `Silently` and `Continue`, with no `A` in either position.

My final edit was the description. 92057 says PowerShell spawned a PowerShell process, which only makes sense because that rule requires a PowerShell parent in the first place. Mine fires no matter what the parent is, so I interpolated `$(win.eventdata.parentImage)` into the description. That way the alert itself shows whether the command came from a command prompt, a service, or PowerShell.


## Custom Detection Rule Result

**Version 1 Testing**

<img width="1314" height="866" alt="image" src="https://github.com/user-attachments/assets/daf3ddcf-1051-4b5d-b32d-d1d77dbe3a18" />


```powershell
powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAdABlAHMAdAAiAA==
```

This is the control command, which is the same one I used to test Version 1 with. I ran this from PowerShell and 92057 catches it at 21:20:14. At 21:20:32, I ran the same command but this time from Command Prompt, which led for my rule 100100 to fire instead of 92057. They both fired at level 12.


**Version 3 Testing**

```powershell
powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAdABlAHMAdAAiAA==
```

<img width="1314" height="866" alt="image" src="https://github.com/user-attachments/assets/409aed71-b436-4512-8d81-6a1481f3f862" />


To keep things consistent, I ran the same control command first with Version 3 like I did with Version 1. When I look at the dashboard it looks like the two rules split the work between them. 92057 fires on the PowerShell run and 100100 fires on the command prompt run, so it reads like each one covers its half. 


<img width="1315" height="861" alt="image" src="https://github.com/user-attachments/assets/30b7170a-5fdc-4d90-be21-a4a88911f08f" />


However upon closer inspection, this is not what happened. Wazuh only fires one rule per event. Both rules match the control command when it's run from PowerShell, but 92057 gets evaluated first and wins, so 100100 never shows up in the alert list. I confirmed this by commenting out 92057 and running the control command again. My rule fired on the PowerShell run too. 

So my rule isn't covering the other half of the technique. It covers everything 92057 covers plus the cases 92057 can't reach, and the only reason it doesn't appear on the PowerShell run is that another rule got there first. That's part of why I put it back at level 12. Which alert an analyst sees depends on evaluation order, and a rule that catches strictly more shouldn't be ranked below the one it's extending.


The commands I am testing below are the ones that I tested Version 2 with and its failure was what allowed me to create Version 3.

**Forward Slash Prefix**

```powershell
powershell.exe /enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAHQAZQBzAHQAIABkAGUAdABlAGMAdABpAG8AbgAgAHIAdQBsAGUAIAB2AGEAbABpAGQAYQB0AGkAbwBuACAAcwB0AHIAaQBuAGcAIgA=
```

PowerShell allows you to use either a hyphen or a forward slash when you're typing the command in cmd.exe. Version 2 only looked for a hyphen, so swapping one character was enough to get past it. 


**Quoted Payload**

```powershell
powershell.exe -enc "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAHQAZQBzAHQAIABkAGUAdABlAGMAdABpAG8AbgAgAHIAdQBsAGUAIAB2AGEAbABpAGQAYQB0AGkAbwBuACAAcwB0AHIAaQBuAGcAIgA="
```

Putting quotes around base64 is normal. Because Version 2 expected base64 characters immediately after the space, a quote sitting in that position can evade the rule.


**Short Payload**

```powershell
powershell.exe -enc dwBoAG8AYQBtAGkA
```

This one is `whoami`, which encodes to 16 characters. Version 2 required at least 20, so short commands slipped underneath the length requirement. Short commands are exactly what someone runs first once they land on a box.


**Renamed Binary**

```powershell
copy C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe %TEMP%\svchost.exe
%TEMP%\svchost.exe -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAHQAZQBzAHQAIABkAGUAdABlAGMAdABpAG8AbgAgAHIAdQBsAGUAIAB2AGEAbABpAGQAYQB0AGkAbwBuACAAcwB0AHIAaQBuAGcAIgA=
del %TEMP%\svchost.exe
```

This test copies PowerShell under a different name and runs it from there. My rule anchors on the image path, so the image reads `svchost.exe` and the rule never matches. This one is still open in Version 3. I could close it by anchoring on `originalFileName` instead, which stays `PowerShell.EXE` even on a renamed copy, but Wazuh requires every `<field>` in a rule to match, so I can't check the image path or the original file name. It would have to be one or the other, and I haven't tested what `pwsh` reports for that field. The other reason I left it is that two shipped rules already caught this on their own, which I get into in Coverage Limits.


**False Positive Test**

```powershell
powershell.exe -Command "Get-Process -ErrorAction SilentlyContinue"
```

This test is not an attack like the others. `-ErrorAction` starts with `-e` and `SilentlyContinue` is 16 characters of base64 alphabet, so this is what would have fired had I 
fix the short payload problem by just lowering the length requirement. 


<img width="1313" height="863" alt="image" src="https://github.com/user-attachments/assets/a4a65d16-bb28-4fbe-84f2-893fbd82eb0b" />

```json
{
  "data.win.eventdata.commandLine": "powershell.exe  /enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAHQAZQBzAHQAIABkAGUAdABlAGMAdABpAG8AbgAgAHIAdQBsAGUAIAB2AGEAbABpAGQAYQB0AGkAbwBuACAAcwB0AHIAaQBuAGcAIgA=",
  "data.win.eventdata.parentImage": "C:\\Windows\\System32\\cmd.exe",
  "rule.id": "100100",
  "rule.level": 12,
  "rule.description": "Encoded PowerShell command executed by C:\\Windows\\System32\\cmd.exe",
  "rule.mitre.id": "T1059.001"
}
```

My rule detected the forward slash prefix test at 22:18:46. Version 2 only looked for a hyphen, so `/enc` can evade it. Version 3 accepts either and fires at level 12, with the parent process shown in the description.


<img width="1313" height="682" alt="image" src="https://github.com/user-attachments/assets/bfbcec56-f5a2-4cf6-a01e-24b762c518c9" />

```json
{
  "data.win.eventdata.commandLine": "powershell.exe  -enc \\\"VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAHQAZQBzAHQAIABkAGUAdABlAGMAdABpAG8AbgAgAHIAdQBsAGUAIAB2AGEAbABpAGQAYQB0AGkAbwBuACAAcwB0AHIAaQBuAGcAIgA=\\\"",
  "data.win.eventdata.parentImage": "C:\\Windows\\System32\\cmd.exe",
  "rule.id": "100100",
  "rule.level": 12,
  "rule.description": "Encoded PowerShell command executed by C:\\Windows\\System32\\cmd.exe",
  "rule.mitre.id": "T1059.001"
}
```

The quoted payload was caught at 22:19:28. Version 2 expected base64 characters right after the space, so a quote in that position was able to evade it. Version 3 allows for an optional quote and fires at level 12.


<img width="1313" height="687" alt="image" src="https://github.com/user-attachments/assets/1fed30e5-d19a-49b8-8999-a34c980dd0d7" />

Because the full document of the JSON from the alert is quite long I provided a trimmed version for the relevant fields.
```
{
  "data.win.eventdata.commandLine": "powershell.exe  -enc dwBoAG8AYQBtAGkA",
  "data.win.eventdata.image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "data.win.eventdata.originalFileName": "PowerShell.EXE",
  "data.win.eventdata.parentImage": "C:\\Windows\\System32\\cmd.exe",
  "rule.id": "100100",
  "rule.level": 12,
  "rule.description": "Encoded PowerShell command executed by C:\\Windows\\System32\\cmd.exe",
  "rule.mitre.id": "T1059.001",
  "rule.mitre.tactic": "Execution"
}
```

Short payload at 22:20:04, caught at level 12. The renamed binary at 22:20:40 shows no 100100, since the rule anchors on the image path and the image reads `svchost.exe`, but 61618 and 92151 both fired on it anyway. The last two runs at 22:21 are the false positive test, and 100100 stays quiet as intended.


## Coverage Limits

Version 3 of my rule anchors on the image path, so copying `powershell.exe` to another name and running it from there gets past the rule entirely. I confirmed this, and the fix is available in the data I already collect. The field `originalFileName` comes from inside the file itself and still reads `PowerShell.EXE` on a renamed copy. I didn't change the anchor because Wazuh requires every field in a rule to match, so I'd have to pick one field or the other, and I haven't tested what `pwsh` reports for `originalFileName`. Two shipped rules caught the rename on their own anyway, which I covered in the results section.

Version 3 needs 16 base64 characters, which works out to six ASCII characters. Anything shorter still gets past it. `dir` encodes to eight characters and could evade my rule. I could drop the requirement to a single block, but eight characters is short enough that I would want to see false positive numbers first.

The shape check I swapped in from the length requirement works because ASCII characters carry a null byte in UTF-16LE, which shows up as a literal `A` in predictable positions. A payload with non-ASCII characters wouldn't produce that pattern, and could possibly evade my rule.

Lastly everything in the final iteration of my rule reads from the command line, and the command line is whatever the attacker types. All of the gaps I closed today were all different ways of writing the same command. Because of that, there are probably more that I did not find. What would be a more robust approach would be to detect the shape of what is happening instead of just the text. For example, Atomic Red Team has a sixth test for T1059.003 that runs `cmd.exe`, writes out a `.vbs` file, and then executes it, and the script spawns another process from there. That gives you a process tree rather than a single command line. The attacker could try to rename the file or rewrite the script, but they can't stop wscript from being the parent of whatever they launch. That relationship survives all the rewriting my rule is vulnerable to.

I haven't built that rule yet though, because it's a different sub-technique, so it wouldn't close the gap in this one. It's a different way of approaching the problem, and it would be the direction I'd go if I wanted detection that doesn't fail when someone types the same command differently.



