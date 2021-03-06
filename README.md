Double-MITM-Target
==================

Security researchers have discovered a new type of "Man-in-the-Middle" (MitM) attack in the wild targeting smartphone and tablets users on devices running either iOS or Android around the world.
The MitM attack, dubbed DoubleDirect, enables an attacker to redirect a victim’s traffic of major websites such as Google, Facebook and Twitter to a device controlled by the attacker. Once done, cyber crooks can steal victims’ valuable personal data, such as email IDs, login credentials and banking information as well as can deliver malware to the targeted mobile device.
San Francisco-based mobile security firm Zimperium detailed the threat in a Thursday blog post, revealing that the DoubleDirect technique is being used by attackers in the wild in attacks against the users of web giants including Google, Facebook, Hotmail, Live.com and Twitter, across 31 countries, including the U.S., the U.K. and Canada.
DoubleDirect makes use of ICMP (Internet Control Message Protocol) redirect packets in order to change the routing tables of a host — used by routers to announce a machine of a better route for a certain destination.
In addition to iOS and Android devices, DoubleDirect potentially targets Mac OSX users as well. However, users of Windows and Linux are immune to the attack because their operating systems don't accept ICMP re-direction packets that carry the malicious traffic.

"An attacker can also use ICMP Redirect packets to alter the routing tables on the victim host, causing the traffic to flow via an arbitrary network path for a particular IP," Zimperium warned. "As a result, the attacker can launch a MitM attack, redirecting the victim’s traffic to his device."
"Once redirected, the attacker can compromise the mobile device by chaining the attack with an additional Client Side vulnerability (e.g.: browser vulnerability), and in turn, provide an attack with access to the corporate network."
The security firm tested the attack and it works on the latest versions of iOS, including version 8.1.1; most Android devices, including Nexus 5 and Lollipop; and also on OS X Yosemite. The firm also showed users how to manually disable ICMP Redirect on their Macs to remediate the issue.
"Zimperium is releasing this information at this time to increase awareness as some operating system vendors have yet to implement protection at this point from ICMP Redirect attacks as there are attacks in-the-wild," the post reads.

The company has provided a complete Proof-of-Concept (PoC) for the DoubleDirect Attack, users can downloaded it from the web. It demonstrates the possibility of a full-duplex ICMP redirect attack by predicting the IP addresses the victim tries to connect to, by sniffing the DNS traffic of the target; the next step consists of sending an ICMP redirect packet to all IP addresses.
