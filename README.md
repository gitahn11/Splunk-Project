# Splunk-Project
This is a walkthrough of a Splunk Project

 ### [YouTube Demonstration](https://youtu.be/7eJexJVCqJo)

<h2>Languages and Utilities Used</h2>

- <b>Splunk</b> 
- <b>Google Search</b>

<h2>Environments Used </h2>

- <b>Linux</b> (21H2)

<h2>Program walk-through:</h2>

<h3>Description</h3>
A Big corporate organization Wayne Enterprises has recently faced a cyber-attack where the attackers broke into their network, found their way to their web server, and have successfully defaced their website http://www.imreallynotbatman.com. Their website is now showing the trademark of the attackers with the message "YOUR SITE HAS BEEN DEFACED":
<br />

<p align="center">
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/1.png" height="50%" width="50%" alt="Disk Sanitization Steps"/>
  </p>

<h3> Incident Response Process </h3>
<p align="center">
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture2.png" height="50%" width="50%" alt="Disk Sanitization Steps"/>
  </p>
<ol> 
  <li> Preparation: A strong plan must be in place to support your team. To successfully address security events, these features should be included in an incident response plan: </li>
  <ul>
    <li> Develop and Document IR Policies: Establish policies, procedures, and agreements for incident response management. </li>
    <li> Incorporate Threat Intelligence Feeds: Perform ongoing collection, analysis, and synchronization of your threat intelligence feeds. </li>
    <li> Assess Your Threat Detection Capability: Assess your current threat detection capability and update risk assessment and improvement programs. </li>
  </ul> 
 
  <b> <li> Detection & Analysis: The focus of this phase is to monitor security events in order to detect, alert, and report on potential security incidents. Resources should be utilized to collect data from tools and systems for further analysis and to identify indicators of compromise </li>
  <ul>
    <li> Monitor, Detect. and Alert: Monitor security events in your environment using firewalls, intrusion prevention systems, and data loss prevention. Detect potential security incidents by correlating alerts within a SIEM solution. Analysts create an incident ticket, document initial findings, and assign an initial incident classification. </li>
    <li> Endpoint Analysis: Determine what tracks may have been left behind by the threat actor. Gather the artifacts needed to build a timeline of activities. </li>
    <li> Binary Analysis: Investigate malicious binaries or tools leveraged by the attacker and document the functionalities of those programs. </li>
    <li> Enterprise Hunting: Analyze existing systems and event log technologies to determine the scope of compromise. </li>
  </ul>
      </b>
  
  <b> <li> Containment and Neutralization: This is one of the most critical stages of incident response. The strategy for containment and neutralization is based on the intelligence and indicators of compromise gathered during the analysis phase. After the system is restored and security is verified, normal operations can resume.
•	Coordinated Shutdown: Once you have identified all systems within the environment that have been compromised by a threat actor, perform a coordinated shutdown of these devices. </li>
  <ul>
    <li> Wipe and Rebuild: Wipe the infected devices and rebuild the operating system from the ground up. Change passwords of all compromised accounts. </li>
    <li> Coordinated Shutdown: Once you have identified all systems within the environment that have been compromised by a threat actor, perform a coordinated shutdown of these devices.  </li>
  </ul>
  </b>
  
  <b> <li> Post-Incident Activity: There is more work to be done after the incident is resolved. Be sure to properly document any information that can be used to prevent similar occurrences from happening again in the future. </li>
  </b>
</ol> 


<h3> Cyber Kill Chain </h3>
<p align="center">
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture3.png" height="50%" width="50%" alt="Disk Sanitization Steps"/>
  </p>
<ol> 
  <li> Reconnaissance: Involves researching potential targets before carrying out any penetration testing. The reconnaissance stage may include identifying potential targets and finding their vulnerabilities that can be exploited. This can be performed both online or offline.  </li>
  <li> Weaponization: The weaponization stage, the attacker creates malware to be used against an identified target. Weaponization can include creating new types of malware or modifying existing tools to use in a cyberattack.  </li>
  <li> Delivery: In the delivery stage tools are used to infiltrate a target’s network and reach users. Delivery may involve sending phishing emails containing malware attachments with subject lines that prompt users to click through.  </li>
  <li> Exploitation: In the exploitation step of the Cyber Kill Chain, attackers take advantage of the vulnerabilities they have discovered in previous stages to further infiltrate a target’s network. </li>
  <li> Installation: After cybercriminals have exploited their target’s vulnerabilities to gain access to a network, they begin the installation stage by attempting to install malware onto the target to take control of the systems and exfiltrate valuable data.</li>
  <li> Command and Control: In the C2 stage, cybercriminals communicate with the malware they’ve installed onto a target’s network to instruct malware to carry out their objectives. </li>
  <li> Actions on Objectives: After cybercriminals have compromised installed a target and taken control of their target’s network, they begin the final stage by carrying out their objective which can include Denial of Service, Data Exfiltration, and Ransomware. </li>
</ol> 



<h3> Splunk Incident Response Lab: Splunk Logs </h3>

<p align="center">
Launch the utility: <br/>
<img src="https://i.imgur.com/62TgaWL.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Select the disk:  <br/>
<img src="https://i.imgur.com/tcTyMUE.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
</p>

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
