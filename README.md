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
A Big corporate organization Wayne Enterprises has recently faced a cyber-attack where the attackers broke into their network, found their way to their web server, and have successfully defaced their website http://www.imreallynotbatman.com. <br/>
<br> Their website is now showing the trademark of the attackers with the message "YOUR SITE HAS BEEN DEFACED":
<br />

<p align="center">
 <br/> Defaced Website <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/1.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
  </p>
  
  <h3>Splunk Logs:</h3>
Wayne Enterprises have Splunk SIEM already in place, so we have got all the event logs related to the attacker's activities captured. We need to explore the records and find how the attack got into their network and what actions they performed.<br/>
<br> Logs are being ingested from webserver/firewall/Suricata/Sysmon etc. In the data summary tab, we can explore the log sources showing visibility into both network-centric and host-centric activities. 
<p align="center"> <br/>
 Splunk Sources <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture4.png" height="50%" width="50%" alt="Disk Sanitization Steps"/><img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture5.png" height="50%" width="50%" alt="Disk Sanitization Steps"/>
  </p>
  
 <h3>Splunk Analysis: Recon </h3>
We will start our analysis by examining any reconnaissance attempt against the webserver imreallynotbatman.com Let's start by searching for the domain in the search head and see which log source includes the traces of our domain. <br/>
<p align="center"> <br/>
 Splunk Query <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture6.png" height="50%" width="50%" alt="Disk Sanitization Steps"/>
  </p> 
  
In the sourcetype field, we saw that the following log sources contain the traces of this search term.
<ul>
 <li> Suricata </li>
 <li> Stream:http </li>
 <li> Fortigate_utm </li>
 <li> iis </li>
</ul>
 
 <p align="center">
 Splunk Log Sorces <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture7.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
  </p> 
 
Our first task is to identify the IP address attempting to perform reconnaissance activity on our web server. <br/>
Let us begin looking at the log source stream:http, which contains the http traffic logs, and examine the src_ip field from the left panel. Src_ip field contains the source IP address it finds in the logs. <br/> We have found two IPs in the src_ip field 40.80.148.42 and 23.22.63.114. The first IP seems to contain a high percentage of the logs as compared to the other IP, which could be the answer. <br/> 

 <p align="center">
 Splunk Query <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture8.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
  </p>

 <p align="center">
 IP Addresses found <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture9.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
  </p>

 <p align="center">
 Activity associated with IP 40.80.148.42 <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture10.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
  </p>
  
It appears that the IP was performing some scanning on the web server and we can further verify this activity by reviewing logs from Suricata that are being ingested in Splunk. Suricata is a Intrusion Detection System that will pick up any network activity that appears suspicious or malicious. 

<p align="center">
 Splunk Query <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture11.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
  </p>

 <p align="center">
 Suricata Logs <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture12.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
  </p>
  
  

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
