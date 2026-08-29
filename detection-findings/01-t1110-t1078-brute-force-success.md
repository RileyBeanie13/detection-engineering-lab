# T1110 / T1078: Detecting Successful Brute Force

## Overview

This finding covers two techniques found in the MITRE ATT&CK Framework. T1110 Brute Force sits under Credential Access, an attacker guessing credentials until something works, such as running through a password list against an account until it authenticates. T1078 Valid Accounts sits under Initial Access, the use of legitimate credentials to access a system, logging in as a real user rather than exploiting anything. In practice they are one sequence. The first technique produces the credentials, and the second one logs in with them.  

I started with the technique brute force because it is one of the most well known attack methods used to break into accounts. Because of that, I already expected Wazuh to come shipped with rules to detect it. Rule 60204 fired correctly on failed attempts, and I did not write anything to replace it. Since the rule already existed, instead of trying to reinvent the wheel the question I asked myself is what could I meaningfully add to it, or what does it currently not do? 

What the shipped coverage does not answer is whether or not the attack was successful. The rule reports that someone tried, and the successful logon was reported too, albeit at a lower severity and not linked to the attempts preceding it. Because of this, the analyst gets a wall of failed alerts, then an alert that summarizes those failures as a brute force attack, and then a subsequent quiet alert that is the only one that actually matters. It is good that the SIEM catches the attack already. But the question that actually matters is whether the address sending all of those failures ever got in.

T1078 is a technique that is hard to detect on its own, mainly because the attacker is not doing anything suspicious. They sign on with real credentials, and generate a real authentication event, so on its own that logon is indistinguishable from a legitimate user. There's nothing in it to anchor a rule to. Because of this, the only window is the moment of transition before they blend in as a regular user, when the successful logon can still be linked to the brute force failures that came before it.

So the rule in this finding does not add visibility, because everything it needs was already being collected. What it adds is the correlation, and one alert that says a brute force attack from this address succeeded.


## Attack Execution

```
Lab Setup

Attacker Machine: Kali Linux, 192.168.10.52

Target Machine: Win-10-Endpoint-01, 192.168.10.51, Windows 10 with Sysmon 

Manager Machine: Ubuntu Server 24.04, 192.168.10.50, stock rules only

Service: RDP, TCP 3389

Account: testuser, local account

Password: Password123

Wordlist: test-passwords.txt, 21 entries, correct password last

Tool: hydra

Network: VMnet1, host-only
```

<img width="1103" height="915" alt="image" src="https://github.com/user-attachments/assets/350ab812-e31c-415b-b0e5-b16c75fd50ed" />


I used RDP as the target service here because it's the native remote access protocol on Windows and one of the most common initial access points in real intrusions. Although SSH would be a more familiar choice for a brute force test, it wouldn't be realistic since Windows doesn't expose it by default. 

`testuser` is a local account I created with a weak password as a brute force target. It exists only for the purpose of this lab.

The word list is 21 entries with the correct password last, so the run can produce 20 failures before it succeeds. I did this on purpose because Wazuh's brute force rule needs 8 failures from the same source address within 240 seconds, so if the password lands too early in the list, or if the list is too short, the alert doesn't fire and there's nothing we can build a correlation rule on. 

```bash
hydra -l testuser -P ~/test-passwords.txt rdp://192.168.10.51 -t 1 -V
```

`-t 1` tells hydra to try one password at a time instead of several at once. This is because RDP doesn't handle multiple simultaneous login attempts well and `hydra` warns you about it, so running single-threaded keeps the attempts in order. `-V` prints every username and password as it tries them, which helps make the run more readable.


## Baseline Alerts

Wazuh detected the failed attempts and it detected the successful logon as well. Each password guess produced a 60122 for the logon failure and a 60104 for the audit failure event, both occurring at level 5. After 8 failures, 60204 fired at level 10 with "Multiple Windows Logon Failures." When the last password worked, 92657 fired at level 6 with "Successful Remote Logon Detected."

<img width="1287" height="860" alt="image" src="https://github.com/user-attachments/assets/cefef8af-12b0-4370-bfa8-2e9963a2618a" />


The dashboard shows the 40 alerts the attack generated, filtered to the 40 second window it ran in. Most of the volume comes from the attempts, since each password creates two alerts. 60122 comes from the logon failure, and 60104 for the audit failure. The histogram shows this as a steady rate of two alerts per second across the entire run, then a spike at the end. The spike is the successful logon at 12:58:26 with three process creation events and the logoff that follows it. 

We can also see here, there was an alert of 60602 at level 9, a Windows application error caused by hydra dropping an RDP connection. 



<img width="1298" height="870" alt="image" src="https://github.com/user-attachments/assets/e9f1a645-4490-45eb-a56b-713f473c595a" />

*Figure 2*

The shows the second page of the same window with 60204 firing at 12:58:15.7. It fired once at 12:57:59.8 and again here, as failures racked up past the rule's threshold in the same 240 second window. The gap between this second alert and the successful logon was about 10 seconds.


```xml
  <rule id="60204" level="10" frequency="$MS_FREQ" timeframe="240">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_field>win.eventdata.ipAddress</same_field>
    <description>Multiple Windows Logon Failures</description>
    <options>no_full_log</options>
<group>authentication_failures,pci_dss_10.2.4,pci_dss_10.2.5,pci_dss_11.4,gdpr_IV_35.7.d,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_SI.4,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

```

This is the shipped rule that produced these alerts. `$MS_FREQ` is a variable that was defined at the top of the same file, where it's set to 8. This means that 60204 needs 8 authentication failures from the same source address within 240 seconds before it fires. This correlates on `win.eventdata.ipAddress`, which is the same field my own rule uses later. The long group list is Wazuh's compliance framework mapping, and not really used for detection.

## Detection Gap

Wazuh detected everything that it needed to. Where it fell short was that it didn't correlate any of the alerts together, which leaves the analyst to work out whether the logon at the end was the attack succeeding. Of the 40 alerts in the dashboard, 39 of them described the part of the attack that failed. The alert describing the attacker getting in is 92657, at level 6. This also happens to be the second lowest severity in the entire dashboard, beaten by 60602 at level 9, even though it's only hydra dropping a connection.

The severity of the rule is not wrong on its own though since a successful RDP logon is a normal event, and in a real environment it can happen constantly. 92657 scoring low is the correct behavior for a standalone rule, when it's not correlated with the alerts that came before it. However, when it's following twenty failures from the same address by 10 seconds, it is not a normal logon. 

To analyze the alerts and then figure out from them that the host is compromised, an analyst would have to notice the 60204, take the source address from it, search for successful logons from the source address, and then confirm that the timestamps line up. None of that is difficult for an analyst who is already looking at the alert. The problem is that this level 6 alert is buried among other level 6 alerts, so nobody looks at it in the first place.

What's needed is one alert that ties the successful logon back to the failures before it, so that the analyst already has the connection rather than having to build it themselves.



## My Detection Rule

**Version 1:**
```xml
<rule id="100104" level="13" timeframe="45">
  <if_group>authentication_success</if_group>
  <if_matched_sid>60204</if_matched_sid>
  <same_field>win.eventdata.ipAddress</same_field>
  <options>no_full_log</options>
  <description>Brute force attack was successful</description>
  <mitre>
    <id>T1110</id>
    <id>T1078</id>
  </mitre>
</rule>
```
This was the base version of my rule and the first iteration. I branched it off of `authentication_success` and required that it follows a 60204. This is because I'm trying to chain a successful logon to rule 60204, which fires when there are multiple failed logon attempts, and the `same_field` line makes sure the successful logon comes from the same address as those attempts. I set this rule at level 13 because this isn't an alert that needs more investigation, because it already tells you what happened based on multiple login failures. My first description was minimal but it covered the gap I pointed out whether or not the attack was successful.


**Version 2:**
```xml
<rule id="100104" level="13" timeframe="45">
  <if_group>authentication_success</if_group>
  <if_matched_sid>60204</if_matched_sid>
  <same_field>win.eventdata.ipAddress</same_field>
  <options>no_full_log</options>
  <description>Brute force attack was successful - User: $(win.eventdata.targetUserName) - Source IP: $(win.eventdata.ipAddress)</description>
  <mitre>
    <id>T1110</id>
    <id>T1078</id>
  </mitre>
</rule>
```

A brute force attack being flagged as successful is useful on its own, but at level 13 it needs more information. Version 1 of my alert pages someone and all it says is that a brute force attack worked. The first question anyone would ask is who did this, and from where?

I wrote the description to show both the user and the source IP as a quality of life change first, but looking at it again it does more than that. This is because it can help an analyst quickly determine upon triaging the alert if, it's a true or false positive.

The username displayed by the rule in the description is usually going to be someone recognized, since attackers brute force accounts that exist. The address is the thing that separates them. If the failures and success both come from the machine the user normally works on, it is probably them locking themselves out and getting it right on the final try. If the source address comes from somewhere that has no business authenticating as that account, that's the compromise.

I tested this on the endpoint itself by guessing passwords at the login screen, and also running hydra with Kali Linux. When I ran hydra from Kali Linux, the alert showed the source address as `192.168.10.52`, which is the attacking machine. When I guessed passwords at the endpoint's login screen, the rule fired again and the address came back as `127.0.0.1`. So my description tells you that a brute force attack succeeded, but also whether it came from another machine on the network or from someone sitting at their keyboard.



**Version 3:**
```xml
<rule id="100104" level="13" timeframe="600">
  <if_group>authentication_success</if_group>
  <if_matched_sid>60204</if_matched_sid>
  <same_field>win.eventdata.ipAddress</same_field>
  <options>no_full_log</options>
  <description>Brute force attack was successful - User: $(win.eventdata.targetUserName) - Source IP: $(win.eventdata.ipAddress)</description>
  <mitre>
    <id>T1110</id>
    <id>T1078</id>
  </mitre>
</rule>
```

I came back to this a day later after Version 2. Version 1 and version 2 were both about the rule working, whereas Version 3 is asking where it doesn't.

`45` seconds works for what I tested, since hydra runs at full speed until it gets in. From my dashboard, I noticed roughly a 10 second gap between the 60204 firing and the successful logon, at least for my attack. I set `45` seconds to cover that with room to spare. In hindsight though, `45` seconds only answered my attack specifically. It did not answer what happens if the brute force and the logon are further apart. 

Because of this, I extended the time frame to 600 seconds. Widening the time frame is safe here because `same_field` means the rule only looks at logons from the address that failed eight times, so a longer window would not pull in unrelated activity such as from another IP address. It only extends how long that one address is paid attention to.

The tradeoff between extending the time frame and narrowing it is not symmetrical. If I shorten the window it gains me almost nothing and costs me detections. However, if I lengthen it up to a certain point, it makes the rule stronger, and the only real risk I have is correlating a logon that had nothing to do with the attack, which `same_field` already makes unlikely. My timeframe of 600 seconds covers attacks running at machine speed, and slower ones too, including someone who's a bit more patient.




## Custom Detection Rule Result

<img width="1311" height="593" alt="image" src="https://github.com/user-attachments/assets/05409453-be2e-4229-83bf-c009773f0059" />

Version 1 of my rule fired at level 13 with the description reading "Brute force attack was successful." The correlation worked, what it did not say was who or where it was from, which is the gap version 2 closed.


<img width="1293" height="606" alt="image" src="https://github.com/user-attachments/assets/5a563814-08cb-42da-91f5-8c06c5fb0c00" />

Version 2 of my rule fired with the description reading `Brute force attack was successful - User: testuser - Source IP: 192.168.10.52`. The compromised account and the source address are both in the alert list now, so the analyst knows what they're dealing with before they open it.


<img width="1281" height="866" alt="image" src="https://github.com/user-attachments/assets/7cd97e9a-b7fe-43d1-877d-bfeaf6bd1891" />

Version 3 fires identically to version 2 on this test, since the attack completes in well under ten minutes either way. The change only shows up in cases the 45 second window would have missed, which this test does not produce.


<img width="1270" height="689" alt="image" src="https://github.com/user-attachments/assets/68098da0-4383-4736-bad7-b3c814d5fad8" />

Although I tested this later, Version 3 shows the same rule firing on the local test. I guessed the passwords directly at the endpoint's login screen until I got in, and the alert came back with the source address as `127.0.0.1` instead of a network address. This is the same rule, with the same description, but I used a different attack path to generate the alert.



## Coverage Limits

First and foremost, this is a detection rule and it does not prevent anything. Wazuh can do that through active response, which runs a script when an alert fires and can block a source address at the firewall, but I have not configured it yet. By the time my detection rule fires, the attacker has already authenticated into the account.

The next limit within my rules is the 600 second window. If an attacker cracks the passcode and waits eleven minutes to get in, my rule won't fire. I know I can keep raising the number, and a larger window would make it less likely, but past a point there's no reasoning behind the value anymore. It just becomes a numbers game. Actually closing this in an efficient and reasonable manner would mean persisting the source address instead of relying on a time window, such as using a CDB list populated when 60204 fires. That's a bigger change than editing a number, and while I'm aware of it, I haven't built it yet.

My rule also depends entirely on 60204 firing first. That rule needs 8 failures from the same source address within 240 seconds, so if an attacker guesses correctly on the seventh try, or spaces their attempts out over hours, it would never produce the parent alert, leaving my rule with nothing to correlate against. My technique would miss password spraying for the same reason, since the failures are spread across different accounts instead of against one address fast enough. There's no change I can make to 100104 that would fix this, because the limitation lives in the parent rule mine is written from.

Correlating on the source address has limits in both directions. An attacker who brute forces from one machine and then logs in from another produces two events my rule would never connect. In an environment with NAT, many hosts can share the same address, so matching on the source address no longer means matching the same machine. That is not a problem in a host-only lab like mine, where every address maps to exactly one host.

The `127.0.0.1` case only tells you the attempt was local, and not anything else. Someone with physical access to the endpoint could produce the same address as a user who forgot their own password. The address separates local from remote, not an attack from an accident.

Lastly, I have only tested this against RDP and the local login screen. SMB and WinRM should reach the same group anchor since they also produce successful authentication events, but I have not run those tests so I will not claim coverage I have not validated.
