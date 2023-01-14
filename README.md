# Splunk-Project
This is a walkthrough of a Splunk Project

<h2>Languages and Utilities Used</h2>

- <b>Splunk</b> 
- <b>Google Search</b>

<h2>Environments Used </h2>

- <b>Linux Virtual Machine</b> 

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
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture6.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
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
<br/> Let us begin looking at the log source stream:http, which contains the http traffic logs, and examine the src_ip field from the left panel. Src_ip field contains the source IP address it finds in the logs. <br/> <br/> We have found two IPs in the src_ip field 40.80.148.42 and 23.22.63.114. The first IP seems to contain a high percentage of the logs as compared to the other IP, which could be the answer. <br/> 

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
  
 <h3>Splunk Analysis: Exploitation </h3>
The attacker needs to exploit the vulnerability to gain access to the system/server. We will look at the potential exploitation attempt from the attacker against our web server and see if the attacker got successful in exploiting or not. we will narrow down the result to show requests sent to our web server, which has the IP 192.168.250.70 <br/>
<p align="center"> <br/>
 Splunk Query <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture13.png" height="50%" width="50%" alt="Disk Sanitization Steps"/>
  </p> 
 <p align="center">
 Source IPs <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture14.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
  </p>
 
 Another interesting field, http_method will give us information about the HTTP Methods observed during these HTTP communications. 
 
  <p align="center">
 Http Method <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture15.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
  </p>
  
The term Joomla is associated with the webserver found in a couple of fields like uri, uri_path, http_referrer, etc. This means our webserver is using Joomla CMS (Content Management Service) in the backend. A little search on the internet for the admin login page of the Joomla CMS will show as -> /joomla/administrator/index.php. We can narrow down our search to see the requests sent to the login portal using this information.
  
<p align="center"> <br/>
 Splunk Query <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture16.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
  </p> 
 <p align="center">
Events associated with login page <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture17.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
  </p>  
  
form_data The field contains the requests sent through the form on the admin panel page, which has a login page. 
  
  <p align="center">
Form Data <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture18.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
  </p>
  
If we keep looking at the results, we will find two interesting fields username that includes the single username admin in all the events and another field passwd that contains multiple passwords in it, which shows the attacker from the IP 23.22.63.114 Was trying to guess the password by brute-forcing and attempting numerous passwords. let's use Regex.  rex field=form_data "passwd=(?<creds>\w+)" To extract the passwd values only.  
  
 <p align="center"> <br/>
 rex forumula <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture19.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
  </p> 
 <p align="center">
 passwords used <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture20.png" height="70%" width="70%"  alt="Disk Sanitization Steps"/>
  </p>
 
We have extracted the passwords being used against the username admin on the admin panel of the webserver. If we examine the fields in the logs, we will find two values against the field http_user_agent as shown below. <br/>

The first value clearly shows attacker used a python script to automate the brute force attack against our server. But one request came from a Mozilla browser.

  <p align="center"> <br/>
 user agent <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture21.png" height="70%" width="70%"  alt="Disk Sanitization Steps"/>
  </p> 
 <p align="center">
 Mozilla Browser <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture22.png" height="70%" width="70%"  alt="Disk Sanitization Steps"/>
  </p>
  

 <h3>Splunk Analysis: Installation Phase</h3>
Once the attacker has successfully exploited the security of a system, he will try to install a backdoor or an application for persistence or to gain more control of the system. This activity comes under the installation phase. <br/>
 
<br/> In the previous Exploitation phase, we found evidence of the webserver iamreallynotbatman.com getting compromised via brute-force attack by the attacker using the python script to automate getting the correct password. The attacker used the IP" for the attack and the IP to log in to the server. This phase will investigate any payload / malicious program uploaded to the server from any attacker's IPs and installed into the compromised server. <br/>
 
 <br/> We first would narrow down any http traffic coming into our server 192.168.250.70 containing the term ".exe."
 
<p align="center"> <br/>
 Splunk Query <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture24.png" height="70%" width="70%"  alt="Disk Sanitization Steps"/>
  </p> 
  
 <p align="center"> <br/>
 Executable<br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture25.png" height="70%" width="70%"  alt="Disk Sanitization Steps"/>
  </p> 

Observing the interesting fields and values, we can see the field part_filename{} contains the two file names. an executable file 3791.exe and a PHP file agent.php. We have found that file 3791.exe was uploaded on the server. The question that may come to our mind would be, was this file executed on the server? We need to narrow down our search query to show the logs from the host-centric log sources to answer this question.
 
 <p align="center"> <br/>
 Splunk Query <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture26.png" height="70%" width="70%"  alt="Disk Sanitization Steps"/>
  </p> 
  
 <p align="center"> <br/>
Log Sources <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture27.png" height="70%" width="70%"  alt="Disk Sanitization Steps"/>
  </p> 
  
 Following the Host-centric log, sources were found to have traces of the executable 3791. exe.
<ul> 
 <li> Sysmon </li>
 <li> WinEventlog </li>
 <li> fortigate_utm </li>
 </ul>
 
<br/>  For the evidence of execution, we can leverage sysmon and look at the EventCode=1 for program execution.
  <p align="center"> <br/>
 Splunk Query <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture28.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
  </p> 
  
 <p align="center"> <br/>
Event Code = 1 <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture29.png" height="70%" width="70%" " alt="Disk Sanitization Steps"/>
  </p> 
 
Looking at the output, we can clearly say that this file was executed on the compromised server. We can also look at other host-centric log sources to confirm the result.
 
 <h3>Splunk Analysis: Action on Objective </h3>
As the website was defaced due to a successful attack by the adversary, it would be helpful to understand better what ended up on the website that caused defacement.  We will start our investigation by examining the Suricata log source and the IP addresses communicating with the webserver 192.168.250.70.  Here we see three external IPs towards which our web server initiates the outbound traffic. There is a large chunk of traffic going to these external IP addresses, which could be worth checking. <br/>
  
<p align="center"> <br/>
 Splunk Query <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture30.png" height="70%" width="70%"  alt="Disk Sanitization Steps"/>
  </p> 
  
<p align="center"> <br/>
Suricata Log <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture31.png" height="70%" width="70%"  alt="Disk Sanitization Steps"/>
  </p> 
 
 Pivot into the destination IPs one by one to see what kind of traffic/communication is being carried out.
 
 <p align="center"> <br/>
URLs that were visited <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture32.png" height="70%" width="70%"  alt="Disk Sanitization Steps"/>
  </p> 
 
This jpeg file looks interesting. Let us change the search query and see where this jpeg file came from. The end result clearly shows a suspicious jpeg poisonivy-is-coming-for-you-batman.jpeg was downloaded from the attacker's host prankglassinebracket.jumpingcrab.com that defaced the site.
 <p align="center"> <br/>
Host Name associated with URL <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture33.png" height="70%" width="70%"  alt="Disk Sanitization Steps"/>
  </p> 
 
 <h3>Splunk Analysis: Command and Control Phase </h3>
The attacker uploaded the file to the server before defacing it. While doing so, the attacker used a Dynamic DNS to resolve a malicious IP. Our objective would be to find the IP that the attacker decided the DNS.

 <br/> To investigate the communication to and from the adversary's IP addresses, we will be examining the network-centric log sources mentioned above. We will first pick fortigate_utm to review the firewall logs and then move on to the other log sources.
 <br/>
  
<p align="center"> <br/>
 Splunk Query <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture34.png" height="70%" width="70%"  alt="Disk Sanitization Steps"/>
  </p> 
 
 <p align="center"> <br/>
Fortigate Firewall Log <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture35.png" height="70%" width="70%"  alt="Disk Sanitization Steps"/>
  </p> 
 
 
Looking into the Fortinet firewall logs, we can see the src IP, destination IP, and URL. Look at the fields on the left panel and the field url contains the FQDN (Fully Qualified Domain Name).

 <p align="center"> <br/>
URL Value <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture36.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
  </p> 
 
 
  <h3>Splunk Analysis: Weaponization Phase </h3>
In the weaponization phase, the adversaries would create Malware / Malicious document to gain initial access / evade detection etc. We have found some domains / IP addresses associated with the attacker during the investigations. This task will mainly look into OSINT sites to see what more information we can get about the adversary. <br/>
 
 We have found a domain prankglassinebracket.jumpingcrab.com associated with this attack. Our first task would be to find the IP address tied to the domains that may potentially be pre-staged to attack Wayne Enterprise. <br/> 
 
 Robtex is a Threat Intel site that provides information about IP addresses, domain names, etc. Search for the domain on the robtex site and we will get the IP addresses associated with this domain. <br/> 
 
  <p align="center"> <br/>
Robtex <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture37.png" height="70%" width="70%"  alt="Disk Sanitization Steps"/>
  </p> 
 
 Virustotal is an OSINT site used to analyze suspicious files, domains, IP, etc. Search for the IP address on the virustotal site. We notice that the IP address is associated with several domains similar to the Wayne Enterprise Company. In the domain list, we saw the domain that is associated with the attackerwww.po1s0n1vy.com
 
<p align="center"> <br/>
Virus Total<br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture38.png" height="70%" width="70%"  alt="Disk Sanitization Steps"/>
  </p> 
 
<h3>Splunk Analysis: Delivery Phase </h3>
Attackers create malware and infect devices to gain initial access or evade defenses and find ways to deliver it through different means. We have identified various IP addresses, domains and Email addresses associated with this adversary. Our task is to use the information we have about the adversary and use various Threat Hunting platforms and OSINT sites to find any malware linked with the adversary.  <br/>
 
 We start our investigation by looking for the IP 23.22.63.114 on the Threat Intel site ThreatMiner. We identified three files associated with this IP, from which one file with the hash value  c99131e0169171935c5ac32615ed6261 seems to be malicious and something of interest.
 
  <p align="center"> <br/>
ThreatMiner <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture38.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
  </p> 
 
<p align="center"> <br/>
ThreatMiner <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture39.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
  </p> 
 
 Hybrid Analysis is a beneficial site that shows the behavior Analysis of any malware. Here you can look at all the activities performed by this Malware after being executed.
 
<p align="center"> <br/>
Hybrid Analysis <br/>
<img src="https://github.com/gitahn11/Splunk-Project/blob/main/Uploads/Picture40.png" height="70%" width="70%" alt="Disk Sanitization Steps"/>
  </p> 
 
 <h3>Splunk Analysis: Conclusion  </h3>
 
 <h4> Reconnaissance Phase: <h4> 
 
We first looked at any reconnaissance activity from the attacker to identify the IP address and other details about the adversary. We identified the IP Address 40.80.148.42 was found to be scanning our webserver and the attacker was using Acunetix as a web scanner.
 
<h4> Exploitation Phase: <h4> 
  We then looked into the traces of exploitation attempts and found brute-force attacks against our server, which were successful. The Brute force attack originated from IP 23.22.63.114.The IP address used to gain access: 40.80.148.42
  
<h4> Installation Phase: <h4> 

 Next, we looked at the installation phase to see any executable from the attacker's IP Address uploaded to our server. A malicious executable file 3791.exe was observed to be uploaded by the attacker. We looked at the sysmon logs and found the MD5 hash of the file.
    
<h4> Action On Objective Phase: <h4> 
 
 After compromising the web server, the attacker defaced the website. We examined the logs and found the file name used to deface the webserver. The file was a jpeg named  poisonivy-is-coming-for-you-batman.jpeg 
 
<h4> Weaponization Phase: <h4> 
  
We used various threat Intel platforms to find the attacker's infrastructure based on the following information we obtained from performing the earlier activities including the domain prankglassinebracket.jumpingcrab.com, the IP Address: 23.22.63.114. Multiple masquerading domains were found associated with the attacker's IPs. An email of the user Lillian.rose@po1s0n1vy.com was also found associated with the attacker's IP address.
 
<h4> Delivery Phase: <h4> 

In this phase, we again leveraged online Threat Intel sites to find malware associated with the adversary's IP address, which appeared to be a secondary attack vector if the initial compromise failed. Findings included a malware with the name MirandaTateScreensaver.scr.exe was found associated with the adversary and the MD5 of the malware was c99131e0169171935c5ac32615ed6261
    
  
  

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
