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
The first thing to say about this rule is that it is built the opposite way round to every other rule I have written. 100100, 100102 and 100103 are all allow by default. They sit quiet until a specific string turns up, and that string is the thing I decided was bad. This rule is deny by default. It fires on every outbound connection except the six ports I decided were fine, so everything I did not think of would be alerted, rather than everything I did not think of getting through.

That is a direct response to the problem I ran into in finding 03. In that one I wanted to stop my obfuscation rule from firing on backup scripts, and the fix I considered was excluding variable names like `DATE` and `TIME`. I talked myself out of it because it was a deny list that could only ever cover the cases I happened to test, and it would need maintaining forever as new legitimate variables turned up. This rule has the mirror image of that problem and it is a better problem to have. My list of six ports is incomplete in exactly the same way, but being incomplete makes the rule noisier rather than blinder. A port I forgot produces a false positive I will see. A variable name I forgot produced a miss I would never have known about.

`initiated` being `^true$` is what makes this a command and control rule rather than a network rule. Sysmon sets that field on connections the endpoint originated, so requiring it true throws away everything connecting inward and leaves only the machine calling out. That matters for the technique, because the whole point of C2 is that the victim initiates, which is how the channel gets through a firewall that would never have allowed the connection in the other direction. It also happens to mean the hydra traffic from finding 01 does not fire this rule. That came in to the endpoint on 3389, and 3389 is not in my allowed list, so without the direction check my brute force finding would be setting off my C2 rule.

The port match is the part I want to explain properly, because the regex is doing something less obvious than it looks. `^(?!(80|443|135|389|5985|5986)$)\d+$` is a negative lookahead, so it matches when what follows is not one of those six, and then requires the whole field to be digits. The character that makes it work is the `$` inside the lookahead group. Without it, the lookahead would fail on anything that merely starts with one of those numbers, so 80 would be excluded and so would 8080, 8000 and 4433. With the `$` in there the lookahead only fails when the entire field is exactly one of the six, which means 8080 fires and 80 does not. That is the difference between a rule that covers the alternate HTTP ports attackers actually use and one that has a hole sitting exactly where they would put the channel.

The six ports are the set I decided a Windows endpoint has a reason to open outward on. 80 and 443 are HTTP and HTTPS, 135 is the RPC endpoint mapper, 389 is LDAP, and 5985 and 5986 are WinRM over HTTP and HTTPS. That list is short because my lab is small, which I get into in Coverage Limits, and it is the part of the rule that is really being tuned rather than the regex around it.

Level 10 is the same call I made on 100103 and for the same reason. `email_alert_level` in `ossec.conf` is 12, so anything at 12 or above sends mail every time it fires, and this is not a rule I want mailing me. It is deny by default on a field the machine touches constantly, so it is the rule of mine most likely to fire on something ordinary. 10 keeps the alert well clear of the level 3 process creation noise without treating every unusual port as a confirmed compromise.

The description is doing the same job as the ones in 100102 and 100106, where I interpolated a field so the alert says something useful before anybody opens it. I felt like this rule needed the destination to be readable more than either of those did, because detecting suspicious outbound connections is the whole point of it, and an outbound connection is defined by where it went. `$(win.eventdata.destinationIp)` and `$(win.eventdata.destinationPort)` put that straight into the alert list, so the first thing anybody wants to know about a connection alert is answered in the list itself. An alert telling me an uncommon port was used without telling me which port, or which address it went to, would not be much use.

## Custom Detection Rule Result

**Version 1**

<img width="1278" height="818" alt="image" src="https://github.com/user-attachments/assets/eed01473-815e-4940-a266-47779058e30e" />

```json
```

100105 fired at level 10 as expected, with the description "PowerShell outbound TCP to uncommon port 192.168.10.52:8081", so both the IP address and the port used could be seen. I feel like this rule definitely needed the destination to be more readable than my other findings, because it needed the destination to be more readable than them. This is because the whole point

The alert is tagged T1571, Non-Standard Port, under Command and Control. Nothing in the baseline carried that tactic at all.

The event behind it is Sysmon Event 3. `initiated` is true, `protocol` is tcp, and the connection runs from 192.168.10.51 on source port 55447 out to 192.168.10.52 on 8081. Those are the fields the rule read, and the attacker typed none of them.

`mail` is false, because level 10 sits under the `email_alert_level` of 12 in `ossec.conf`. That was the reason I picked 10.

One thing carried over from the baseline is the `ruleName` tag, which still reads `technique_id=T1059.001,technique_name=PowerShell`. That is on the network connection event itself now, so the Sysmon config is labelling the actual T1571 connection as PowerShell execution. It describes the binary that opened the socket rather than what the socket was for, which is why I have never anchored a rule to that field.


## Coverage Limits



