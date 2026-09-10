# T1571 - Non-Standard Port

## Overview

The technique I will be covering in this finding is T1571, Non-Standard Port, which sits under Command and Control. The reason I went for this one is that I wanted to write a rule that was fundamentally different from the ones before it, rather than just cover a different technique with the same kind of rule underneath. Findings 02, 03 and 04 are three separate techniques, but all three of the rules I wrote for them do the same thing. An encoded PowerShell command, an interpreter name built out of an environment variable, and auditpol being used to switch the audit policy off are all things that somebody typed, and all three rules come down to reading `win.eventdata.commandLine` and deciding the string sitting in it looks wrong. Of my four findings, three of them were angles on one kind of detection, which was the command line. Once I finished 100103 I wanted to go for a fundamentally different set of rules, and 100104 was the first of them. That is the brute force correlation from finding 01, and it does not read a command line at all. It correlates logon events, and the attack behind it was hydra running on the Kali box rather than anything typed into the endpoint. This finding is the next one in that set, and being able to detect from a different angle is the reason I picked the technique.

T1571 sits at a different part of the attack chain and it is much more on the networking side than anything I have written up so far. The attack is the endpoint reaching out to the Kali box on 192.168.10.52, which is the same machine I ran hydra from in finding 01. What changed is the direction. In finding 01 Kali was the one making the connection and the endpoint was the one receiving it, and here it is the other way around. The endpoint opens the connection outward, Kali sits there with a listener waiting for it, and once the handshake completes the attacker sends commands down a connection that the victim machine established itself. That is command and control, and it runs in that direction because outbound traffic is generally treated as normal and inbound traffic is not. T1571 is the part where the attacker picks which port to run that channel over, and deliberately picks one that is not traditionally used for it. Detection and filtering tend to get built around the ports people expect traffic on, so a port nobody is looking at is a port nobody catches you on.

The difference that makes to the rule is the part I find most interesting about this finding, since unlike my other detection rules, there is no string to match. The attacker never types the port, and there is no way of writing 8081 that looks more suspicious than any other way of writing it, so I cannot describe what they did the way I described an encoded command or an auditpol flag. What I have instead is `win.eventdata.initiated` and `win.eventdata.destinationPort`, and neither of those is something somebody typed. They are facts about a connection that actually happened. That is a different kind of detection to everything else in this project, because the other rules fire on evidence that somebody intended to do something and this one fires on the machine having already done it. It also means the rule cannot describe the attack at all, only what's not supposed to happen. The question this finding answers is whether Wazuh can tell that the endpoint is talking to somewhere it has no business talking to, when nothing about the connection itself is malformed and there is no command line to read.

One thing I think is worth noting is that every rule I had written before this one is the same shape, a `<field>` pointing at `win.eventdata.commandLine` with a regex inside it, so as far as I understood it a Wazuh rule meant string matching. While writing this rule, this is where it clicked to me that the event already carries data describing what happened and that I can reference it directly, which is what `win.eventdata.initiated` and `win.eventdata.destinationPort` are doing here. 

## Attack Execution 

The test I ran is Atomic Red Team test 1 under T1571, "Testing usage of uncommonly used port with PowerShell," with the GUID 21fe622f-8e53-4b31-ba83-6d333c2583f4. Atomic Red Team describes it as testing an uncommonly used port utilizing PowerShell, and according to their description APT33 has been known to attempt telnet over port 8081, which is where the default port in the test comes from. It only supports Windows, and the description notes that on execution it prints details about the successful port check.

```powershell
Test-NetConnection -ComputerName #{domain} -port #{port}
```

The two inputs default to `google.com` and `8081`. The command I actually ran is:

```powershell
Test-NetConnection -ComputerName 192.168.10.52 -port 8081
```

I changed the target and left the port alone, and both of those were deliberate choices. This is because the port is the entire technique, and also it's because I'm not trying to test if my machine can reach Google. I'm trying to test if I can detect an outbound connection between my endpoint and the an attacker's infrastructure. T1571 is an endpoint talking to infrastructure the attacker owns over a port chosen to get through, and 192.168.10.52 is the Kali box I ran hydra from in finding 01. Redirecting it there makes the test the shape of the actual technique, and it means the traffic in this finding and the traffic in finding 01 involve the same two machines with the roles swapped. I had an `nc` listener up on 8081 so the connection was actually accepted on the other end.

One thing worth pointing out about this test is that the command itself is not an attack. `Test-NetConnection` is a built-in PowerShell cmdlet for checking whether a host is reachable on a given port, and administrators use it constantly for exactly that. There is no encoded payload in it, nothing obfuscated, and no unusual binary. Put next to the auditpol command from finding 04, this is the only one of the two that somebody might reasonably type on an ordinary day. 

This is also why writing the rule against `Test-NetConnection` was never really an option. It was the first thing I thought of, because it is the thing sitting in the command line and it is what the atomic runs, but it fails in both directions at the same time. It is far too broad, since `Test-NetConnection` is a normal diagnostic that any administrator might run against any host on any port, and a rule matching the cmdlet name would fire every time somebody checked whether a server was up. It is also far too narrow, because nothing about the technique needs that cmdlet at all. The same connection can be opened with `New-Object System.Net.Sockets.TcpClient`, or with `Invoke-WebRequest`, or by anything else that opens a socket, and none of those contain the string I would have been matching on. Because of that not only would writing a detection rule based on detecting that command in the command line have too many false positives, it also would miss the signal indicating an outbound connection. This is why I went instead for a detection rule that would trigger off a connection event instead.

It also matters that the atomic runs with PowerShell rather than through `cmd /c`. `Test-NetConnection` opens the socket from inside `powershell.exe` itself instead of spawning a child process to do it, so the network connection event Sysmon writes has `powershell.exe` as its image. That is what puts the event in front of the shipped rule my own rule is chained to.

On the Kali side I had a listener running on 8081 so the connection was accepted.

```bash
nc -lvnp 8081
```


## Baseline Alerts

<img width="1280" height="867" alt="image" src="https://github.com/user-attachments/assets/78bbdebe-3614-4834-b6a0-9bb4c9204a87" />

These are the alerts produced by Wazuh's default shipped ruleset upon running the atomic test. The window runs from 14:40:00 to 14:43:13 and holds 19 alerts, and none of them are about the connection.

Most of the volume is 67027 at level 3, "A process was created," which is the same noise floor that shows up in every finding I have run. 60642 and 92154 are in there too and neither has anything to do with the test.

Two alerts belong to the run and they land together at 14:42:30. 92027 at level 4, "Powershell process spawned powershell instance," is Invoke-AtomicTest launching the test out of my session. It carries the full command line, `"powershell.exe" & {Test-NetConnection -ComputerName 192.168.10.52 -port 8081}`, and describes it as a parent and child process relationship. Then 92213 at level 15, "Executable file dropped in folder commonly used by malware," which is the `__PSScriptPolicyTest`. This mainly happened because I was installing and importing the Atomic Test modules to test the rule. It's a false positive and it doesn't say anything about the attack itself.

The connection produced nothing. 92101 is the rule that matches PowerShell making a TCP connection, and it ships at level 0, which in Wazuh means it never alerts on its own. It is a grouping construct for other rules to chain off, and the only two that do are 92102 for port 135 and 92103 for port 389. My connection went to 8081, so it matched the parent, fell through both children, and stopped there.


## Detection Gap

This is the biggest detection gap that I have observed across all of my findings, because nothing in the shipped ruleset detected the attack.

The closest alert that actually describes the attack is 92027, and all it says is that a PowerShell process spawned another PowerShell process. The command line is right there in the alert, so the address and the port were both collected and both sitting in front of me, but the rule is describing a parent and child relationship and nothing else. It does not know a connection was made, it does not know where it went, and it would have said exactly the same thing if the command had been anything else. It is also tagged T1059.001 under Execution, which is true of the shell that ran and says nothing about what the shell did. However, it has no read on the underlying tactic which is Command and Control.

The rule that should have covered this is 92101, which matches PowerShell making a TCP connection. It ships at level 0, so it never alerts on its own. It is a grouping construct for other rules to chain off, and the only two that do are 92102 for port 135 and 92103 for port 389. My connection went to 8081, matched the parent, fell through both children, and stopped there.

I do not think 92101 being level 0 is wrong. A rule that alerted on every TCP connection PowerShell makes would be unusable in a production environment. The rule is simply set up so that other rules can chain off it and decide which connections are actually worth alerting on, and Wazuh only ships two of those, one for port 135 and one for port 389. The gap is that on a default install there is almost nothing chained to it, so any port outside those two goes through undetected.

That also makes this a different kind of gap to the last three findings. In finding 04 the gap was that Wazuh recorded the command word for word and then described it as something else. In this scenario nothing got described wrong, because nothing got described at all. The event was collected and it was evaluated, and the rule that would've matched it was made to stay quiet. That is also why my rule chains onto 92101 instead of replacing anything. There was no rule doing this job badly, there just was not one doing it.


## My Detection Rule

**Version 1**

```xml
  <rule id="100105" level="10">
    <if_sid>92101</if_sid>
    <field name="win.eventdata.initiated">^true$</field>
    <field name="win.eventdata.destinationPort" type="pcre2">^(?!(80|443|135|389|5985|5986)$)\d+$</field>
    <description>PowerShell outbound TCP to uncommon port $(win.eventdata.destinationIp):$(win.eventdata.destinationPort)</description>
    <mitre>
      <id>T1571</id>
    </mitre>
  </rule>
```
Starting with the severity. Level 10 is where I put this one and I think it is the right place for it. An outbound connection to an uncommon port could be an indicator of an attack and it is not something that should be happening often, but it is not self explanatory the way something like a brute force attack is. With 100104 the alert is telling you what happened, because twenty failed logons followed by a successful one from the same address is not ambiguous. This one is not that, it is telling me something uncommon happened and that somebody should go and look at it, which is what level 10 is for. It also keeps the rule underneath the `email_alert_level` of 12 in `ossec.conf`, so it is not mailing me every time it fires, and that matters more here than on my other rules because this is the one most likely to catch something ordinary.
`<if_sid>92101</if_sid>` chains the rule onto the shipped rule for PowerShell making a TCP connection, so mine only ever gets evaluated on events 92101 has already matched. That is what makes "PowerShell outbound TCP" in my description something the rule genuinely checks rather than something I am asserting, because 92101 has already constrained both the process and the protocol before my own fields are looked at. It also means this rule sits next to 92102 and 92103 as another thing chained onto that parent, rather than replacing anything.

`win.eventdata.initiated` being `^true$` is what makes this a command and control rule rather than just a network rule. Sysmon sets that field to true on connections the endpoint opened itself, and false on connections that came in to it, so requiring that it's true means the rule only ever matches outbound connections. That matters for the technique, because the whole point of C2 is that the victim is the one making the connection, which is how the channel gets through a firewall that would never have allowed that connection in the other direction. Because of that it also means the hydra traffic from finding 01 would not fire this rule. It came in to the endpoint on 3389, and 3389 is not on my list, so without the direction check my brute force finding would be setting off my C2 rule.

`win.eventdata.destinationPort` is where the framing of this rule is fundamentally different from my other ones. 100100, 100102 and 100103 all sit quiet until a specific string turns up, and that string is the thing I decided was bad. This one is an allow list. `^(?!(80|443|135|389|5985|5986)$)\d+$` is a negative lookahead, so it matches when the field is not one of those six and then requires the whole thing to be digits. Six ports are fine and everything else alerts, which means anything I did not think of gets flagged rather than getting through. The character doing the work is the `$` inside the lookahead group. Without it the lookahead would reject anything that merely starts with one of those numbers, so 8080, 8000 and 4433 would be excluded alongside 80. With it in there only an exact match on one of the six is excluded, so 8080 fires and 80 does not. The six themselves are the set I decided a Windows endpoint has a reason to open outward on, which is 80 and 443 for HTTP and HTTPS, 135 for the RPC endpoint mapper, 389 for LDAP, and 5985 and 5986 for WinRM. I also believed here that, an allow list is easier to justify here than it would have been in any of my other findings, because of what this rule is actually claiming. It is not saying an attack happened. It is saying an outbound TCP connection went somewhere uncommon, and that is a far easier call to make than deciding whether a command line is malicious. It does make this rule noisier than my others, and I think that is the right trade.

Finding 03 is what made me frame it this way. In that finding, I wanted to stop my obfuscation rule firing on backup scripts, and the fix I considered was excluding variable names like `DATE` and `TIME`. However, I didn't do it because a deny list can only ever cover the cases I happened to test, and I would have had no way of knowing what it was missing. The allow list was also far easier to actually build. There are 65,535 ports, so going the other way would have meant sitting down and trying to list every uncommon one an attacker might pick, and missing even one of them leaves a port the rule cannot see. Writing the allow list meant deciding on six and letting everything else alert. 

The description is doing something I have ended up doing in the final version of most of my rules, which is pulling a field into the alert text so it says something useful before anybody has to open it. I felt like this rule needed the destination to be readable more than any of the others did, because detecting suspicious outbound connections is the whole point of it, and the first question anybody asks about one is where it went. `$(win.eventdata.destinationIp)` and `$(win.eventdata.destinationPort)` put that straight into the alert list, so that question is answered in the list itself. An alert telling me an uncommon port was used without telling me which port, or which address it went to, would not be much use. The MITRE tag is T1571, which puts the alert under Command and Control. 

**Version 1.5**

```json
  <rule id="100105" level="10">
    <if_sid>92101</if_sid>
    <field name="win.eventdata.initiated">^true$</field>
    <field name="win.eventdata.destinationPort" type="pcre2">^(?!(80|443|135|389|5985|5986)$)\d+$</field>
    <options>no_full_log</options>
    <description>PowerShell outbound TCP to uncommon port $(win.eventdata.destinationIp):$(win.eventdata.destinationPort)</description>
    <mitre>
      <id>T1571</id>
    </mitre>
  </rule>
```
I am calling this version 1.5 rather than version 2 because there is only one change in it and it is not a detection change at all. `no_full_log` is something I do across all of my rules and this one did not have it, which meant the alert was carrying the entire event in its body when it did not need to. I didn't make any other changes to what the rule matched on.

I didn't change the port pattern itself either, and this was a deliberate decision I made. This is because I did not think tuning it any further would actually get me much. If I tightened it by taking ports off the allow list, the rule would get more sensitive and start alerting on connections that were fine, so I would just be adding noise. If I loosened it by allowing more ports, I would definitely be losing coverage, because a port I allow is a port this rule can never see. Either direction would cost me something and neither one gives much back, so the port pattern remained unchanged.

There was a much bigger change I tried before settling on this one, which was chaining the rule to 61605 instead of 92101 so that it would cover every process making an outbound connection rather than only PowerShell. It did not work, and the reason it did not work is worth explaining properly, so I have written it up in Coverage Limits.


## Custom Detection Rule Result

**Version 1 Test**

<img width="1278" height="818" alt="image" src="https://github.com/user-attachments/assets/eed01473-815e-4940-a266-47779058e30e" />

```json
{
  "agent": { "name": "Win-10-Endpoint-01", "ip": "192.168.10.51", "id": "001" },
  "data": {
    "win": {
      "eventdata": {
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "user": "WIN10-ENDPT-1\\WazuhUser",
        "processId": "3896",
        "protocol": "tcp",
        "initiated": "true",
        "sourceIp": "192.168.10.51",
        "sourcePort": "55447",
        "destinationIp": "192.168.10.52",
        "destinationPort": "8081",
        "ruleName": "technique_id=T1059.001,technique_name=PowerShell"
      },
      "system": {
        "eventID": "3",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "eventRecordID": "79821"
      }
    }
  },
  "rule": {
    "id": "100105",
    "level": 10,
    "description": "PowerShell outbound TCP to uncommon port 192.168.10.52:8081",
    "groups": ["sysmon", "local"],
    "mitre": {
      "id": ["T1571"],
      "technique": ["Non-Standard Port"],
      "tactic": ["Command and Control"]
    }
  }
}
```

100105 fired once at level 10, as expected, with the description "PowerShell outbound TCP to uncommon port 192.168.10.52:8081". Both fields were filled in, so the address and the port are readable straight off the alert list without opening anything. 

The alert is tagged T1571, Non-Standard Port, under Command and Control. Nothing in the baseline carried that tactic at all, so this is the only thing in the run an analyst would find if they went looking by tactic.

The event behind it is Sysmon Event 3. `initiated` is true, `protocol` is tcp, and the connection runs from 192.168.10.51 on source port 55447 out to 192.168.10.52 on 8081. Those are the fields the rule read, and it did so without the attacker typing them.

`mail` was false, because level 10 sits under the `email_alert_level` of 12 in `ossec.conf`. Again, this was intentional because although this could be an indicator of compromise it alone is not certain of one.


## Coverage Limits

The first thing I think is worth covering here is the second iteration of my rule that did not work, because it failed for a reason that had nothing to do with whether the idea was right. What I wanted was for the rule to stop being PowerShell specific. T1571 is about the port an attacker picks and not about which program opens the connection, so I believed that chaining the rule to 61605 instead of 92101 should have put my rule in front of every outbound connection the endpoint makes. I still think that reasoning is correct and I would make the same call again.

What I did not account for was where each rule ends up sitting in the rule tree. 61605 is the base Sysmon Event 3 rule and it carries the group `sysmon_event3`. 92101 attaches itself to that group, and my rule was attaching to 61605 by ID, so instead of sitting underneath 92101 the way version 1 did, the two of them ended up as siblings under the same parent. Wazuh takes the first child that matches and then stops, and the shipped rules load before `local_rules.xml`, so on any PowerShell connection over TCP 92101 matched first. 92101 is level 0, which means it produces no alert at all, and its only children are 92102 for port 135 and 92103 for port 389, neither of which my traffic matched. The event clearly matched, my rule was write line for line in what it detected, but it still wouldn't fire because of this. Because of this, I kept Version 1 simply for the reason that it  fired and Version 2 wouldn't.

I was able to confirm this when I was testing out the rule. There are two Sysmon Event 3s on the endpoint at 10:52:30 and 10:54:06, both were TCP, both with `initiated` set to true, both going to 192.168.10.52 on port 8081, and both of them after I had loaded version 2. However neither would produce an alert.

Because I reverted to chaining on 92101, the rule only ever sees connections that PowerShell makes, which happens to be the biggest limit of this rule. 

An attacker who opens the channel with anything other than PowerShell is invisible to this rule no matter which port they use, and the technique does not require PowerShell at any point. This could be things such as a LOLBin, a different interpreter, or any program the attacker brought onto the machine themselves could all get past it.
Fixing this rule properly would mean overwriting 92101, or writing a second rule chained to 61605 to cover everything else. This means that there is no version of 100105 that can close the detection gap on its own, I would have to write another rule.

The allow list is the other obvious weakness, and 443 is the worst of it. Any channel that runs over one of the six ports I allow goes straight past this rule, and 443 is where real C2 lives precisely because everything allows it outbound. So the rule is deliberately blind to the most common case in exchange for catching an attacker who picked something unusual. T1571 is specifically the attacker choosing not to do the obvious thing, and a rule written against that technique only ever catches the ones who made that choice.

There is a collection limit underneath all of this as well, and I found it by accident while debugging version 2. I ran `curl.exe` to 192.168.10.52 on 8081 as a test, the connection completed and the listener on Kali printed the request, and Sysmon never wrote a network connection event for it at all. That is the same shape of problem I ran into in finding 04, where Sysmon was only logging process creation for a curated set of binaries. I want to be clear that this one is not a limit of my rule, it is a limit of what my Sysmon config is collecting. No pattern I could write would ever match an event that was not created in the first place, so there is no change to 100105 that fixes this, and closing it would mean changing what Sysmon is told to log instead. What makes it worth flagging anyway is that from the manager side the two are indistinguishable, because a rule that did not match and an event that never arrived both look like nothing.

On false positives, I finally have a number, which is something I could not give at the end of most of my findings. Over 24 hours this endpoint produced 51 outbound connections that were not on my allow list. 49 of them were svchost doing mDNS on UDP 5353 and the other 2 were my own test connections to 8081. Since 92101 restricts the rule to TCP, none of the mDNS ever reaches it, so the rule produced no false positives at all in that window. I want to be careful about what that number actually proves though. This is a controlled environment without many moving parts, running on a host only network with very few network services configured, so a false positive rate measured here does not say much about how this rule would perform in a production environment.

The `ruleName` field on the connection event is worth noting too, and like the collection gap it is about the Sysmon config rather than my rule. It reads `technique_id=T1059.001,technique_name=PowerShell`, so the config has labelled an actual T1571 connection as PowerShell execution. The tag describes which program opened the connection rather than what the connection was doing. This is the second time I have run into that, since in finding 03 a caret anywhere in a command line was enough to get an event tagged T1027. I have never anchored a rule to that field, but it does mean the tags coming out of Sysmon are not something I can lean on when I am working out what a connection was actually for.

Finally, and like all of my rules this is a detection and it prevents nothing. It tells an analyst that the endpoint reached out somewhere unusual, but it does not tell them whether the person who caused it was supposed to, and there is no field in a network connection event that could.

