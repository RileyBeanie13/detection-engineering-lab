# T1110 / T1078: Detecting Successful Brute Force

## Overview

This finding covers two techniques found in the MITRE ATT&CK Framework. T1110 Brute Force sits under Credential Access, an attacker guessing credentials until something works, such as running through a password list against an account until it authenticates. T1078 Valid Accounts sits under Initial Access, the use of legitimate credentials to access a system, logging in as a real user rather than exploiting anything. In practice they are one sequence as the first technique produces the credentials, and the second one logs in with them.  

I started with the technique brute force because it is one of the most well known attack methods used to break into accounts. Because of that, I already expected that Wazuh to come shipped with rules to detect it. Rule 60204 fired correctly on failed attempts, and I did not write anything to replace it. Since the rule already existed, instead of trying to reinvent the wheel the question I asked myself is what could I meaningfully add to it, or what does it currently not do? 

What the shipped coverage does not answer is whether or not the attack was successful. The rule reports that someone tried, and the successful logon was reported too, albeit at a lower severity and not linked to the attempts preceding it. Because of this, the analyst gets a wall of failed alerts, then an alert that summarizes those failures as a brute force attack, and then a subsequent quiet alert that is the only one that actually matters. It is good that the SIEM catches the attack already. But the question that actually matters is whether the address sending all of those failures ever got in.

T1078 is a technique that is hard to detect on its own, mainly because the attacker is not doing anything suspicious. They sign on with real credentials, and generate a real authentication event, so on its own that logon is indistinguishable from a legitimate user. There's nothing in it to anchor a rule to. Because of this, the only window is the moment of transition before they blend in as a regular user, when the successful logon can still be linked to the brute force failures that came before it.

So the rule in this finding does not add visibility, because everything it needs was already being collected. What it adds is the correlation, and one alert that says a brute force attack from this address succeeded.


## Attack Execution

**Lab Setup**

Attacker Machine: Kali Linux, 192.168.10.52

Target Machine: Win-10-Endpoint-01, 192.168.10.51, Windows 10 with Sysmon 

Manager Machine: Ubuntu Server 24.04, 192.168.10.50, stock rules only

Service: RDP, TCP 3389

Account: testuser, local account

Password: Password123

Wordlist: test-passwords.txt, 21 entries, correct password last

Tool: hydra

Network: VMnet1, host-only


<img width="1103" height="915" alt="image" src="https://github.com/user-attachments/assets/350ab812-e31c-415b-b0e5-b16c75fd50ed" />


I used RDP as the target service here because it's the native remote access protocol on Windows and one of the most common initial access points in real intrusions. Although SSH would be a more familiar choice for a brute force test, it wouldn't be realistic since Windows doesn't expose it by default. 

`testuser` is a local account, I created with a weak password as a brute force target. It exists only for the purpose of this lab.

The word list is 21 entries with the correct password last, so the run can produce 20 failures before it succeeds. I did this on purpose because Wazuh's brute force rule needs 8 failures from the same source address within 240 seconds, so if the password lands too early in the list, or if the list is too short, the alert doesn't fire and there's nothing we can  build a correlation rule on. 


`hydra -l testuser -P ~/test-passwords.txt rdp://192.168.10.51 -t 1 -V`

`-t 1` tells hydra to try one password at a time instead of several at once. This is because RDP doesn't handle multilpe simultaneous login attempts well and `hydra` warns you about it, so running single-threaded keeps the attempts in order. `-V` prints every username and password as it tries them, which helps make the run more readable.


## Baseline Alerts

Wazuh detected the failed attempts and it also detected the successful logon as well. Each password guess produced a 60122 for the logon failure and a 60104 for the audit failure event, both occurring at level 5. After 8 failures, 60204 fired at level 10 with "Multiple Windows Logon Failures." When the last password worked, 92657 fired at level 6 with "Successful Remote Logon Detected."

<img width="1287" height="860" alt="image" src="https://github.com/user-attachments/assets/cefef8af-12b0-4370-bfa8-2e9963a2618a" />

<img width="1298" height="870" alt="image" src="https://github.com/user-attachments/assets/e9f1a645-4490-45eb-a56b-713f473c595a" />

<img width="1303" height="745" alt="image" src="https://github.com/user-attachments/assets/56814c14-c161-4dbc-a3dd-d46ebd1a75d4" />



```
  <rule id="60204" level="10" frequency="$MS_FREQ" timeframe="240">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_field>win.eventdata.ipAddress</same_field>
    <description>Multiple Windows Logon Failures</description>
    <options>no_full_log</options
<group>authentication_failures,pci_dss_10.2.4,pci_dss_10.2.5,pci_dss_11.4,gdpr_IV_35.7.d,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_SI.4,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

```


## Detection Gap


## My Detection Rule


## Custom Detection Rule Result

<img width="1311" height="593" alt="image" src="https://github.com/user-attachments/assets/05409453-be2e-4229-83bf-c009773f0059" />


<img width="1293" height="606" alt="image" src="https://github.com/user-attachments/assets/5a563814-08cb-42da-91f5-8c06c5fb0c00" />



## Coverage Limits
