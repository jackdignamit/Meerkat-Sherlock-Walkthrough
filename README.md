# Meerkat Sherlock | HackTheBox Walkthrough
> ## Analyzing Bonitasoft Server Compromise Using Wireshark PCAPs and Log Data

### [>>GOOGLE DOC VERSION <<](https://docs.google.com/document/d/1ZtUvfwmuX1UEr5ZJ6oK2zr_UHzvrzhYLuybwrSNTD70/edit?usp=sharing) (Originally posted on Medium.com)

*Completed 10/25/2025* -- *Jack Dignam*

- - - 
<p align="center"> <img width="300" height="300" alt="1_hi15No2vNm9jsyhkeM3BPQ" src="https://github.com/user-attachments/assets/b9c8e8d7-90b2-4ecf-b43c-cff8d80f0fe8"/>
<p align="center"> https://app.hackthebox.com/sherlocks/552

# Introduction
My second [Hack The Box](https://app.hackthebox.com/home) walkthrough is the [Meerkat](https://app.hackthebox.com/sherlocks/552) Sherlock! 
This lab is the fifth challenge from the **Intro to Blue Team** track that focuses on **Wireshark, MITRE ATT&CK Frameworks, brute force attacks** and parsing **Zeek JSON logs** with **JQ**.

If you find this walkthrough helpful, please feel free to drop a follow. Thank you for your consideration, now let's do this investigation!

---

# Challenge Scenario
> As a fast-growing startup, Forela has been utilizing a business management platform.
> Unfortunately, our documentation is scarce, and our administrators aren't the most security aware.
> As our new security provider we'd like you to have a look at some PCAP and log data we have exported to confirm if we have (or have not) been compromised.

In this challenge, we are the new security provider for Forela, a fast-growing startup. This startup is running an insecure business management software, which is yet to be revealed to us (but we will discover later). 
The business provides us with a **PCAP (Wireshark Packet Capture)** and a **Zeek JSON log file** to determine if this software was compromised.

This exercise tests your ability to analyze Wireshark network captures and logs for signs of compromise, apply the [MITRE ATT&CK](https://attack.mitre.org/) framework, and recognize brute-force techniques in use. These are all fundamental skills for real-world cybersecurity roles, demonstrating a clear understanding of how to discover and safeguard critical business systems from compromise.

---

# Setup the Lab Environment:
As a good rule of thumb before any simulated investigation, it is a smart idea to use a **virtual machine**. 
This ensures the environment is completely isolated and safe. We will be using Parrot Security OS for this lab. 
If you need instructions on installing a virtual machine of your own, you can follow this tutorial: 

[![pHrhvmUe694-HQ](https://github.com/user-attachments/assets/77d59aef-195e-4deb-bcd9-19a31428af02)](https://youtu.be/pHrhvmUe694?si=THsiczCnkAi-RzWE)

https://youtu.be/pHrhvmUe694?si=f0ex0YEJMTJyeZgC

From your virtual machine, download the Hack the Box file and unzip it (password is `hacktheblue`) onto your desktop. 
From there, we will install **jq**, an open source command-line tool for filtering JSON formatted data. Open a new terminal and enter:

``` sudo apt install jq ```

<img width="816" height="408" alt="1_5AHn09-TU5MjYrz9buhZkQ" src="https://github.com/user-attachments/assets/a6f391dc-9e54-4b13-bd7a-f5a15c83f141" />

If an error occurs attempting to install, enter one of these troubleshooting commands:

```

sudo apt update
sudo apt install jq --fix-missing

```

For convenience, we can make it easier to navigate the alerts log by removing the outer JSON list and then piping it into the *less* command:

```
jq '.[]' meerkat-alerts.json | less
```

From there, simply open the pcap file into Wireshark on your VM and we can begin the investigation!

--- 

# Walkthrough
## Task 1: We believe our Business Management Platform server has been compromised. Please can you confirm the name of the application running?
The first task states that Forela's business management platform has been compromised and we need to discover what it is. To begin, we can use a **jq filter** on the `meerkat-alerts.json` file.

In a new terminal, change directories to where the file is located. We will use the **'.[].alert.signaure'** filter to display alert names from the log.

```
cd (file location)
jq '.[].alert.signature' meerkat-alerts.json
```

**A quick breakdown of the filter command:** We are telling `jq` to look through each object in the JSON array ( [] ), then print the value of the field `.alert.signature` from each object. This displays all the alert names within the log. To learn more about jq filtering, visit the Zeek website for documentation: 

https://docs.zeek.org/en/master/log-formats.html

<img width="1000" height="988" alt="1_aLYJlU4OG01bktT1GDJItQ" src="https://github.com/user-attachments/assets/45737688-86b1-488f-9d03-f4c524dd0fdb" />

Each line of the output represents one alert signature with a short description of the detection. For example:

**```ET EXPLOIT BonitaSoft Authorization Bypass M1 (CVE-2022–25237)```**

**ET** means this alert is an emerging threat, in particular, an exploit of the **BonitaSoft Authorization Bypass M1 vulnerability**. The CVE value is listed as **CVE-2022–25237**. Therefore, the answer is **BonitaSoft**.

<img width="1000" height="144" alt="1_6Sx6XVNucmPcLq6_BFjsgw" src="https://github.com/user-attachments/assets/432fb17c-f8b0-459b-a21b-d4850062e8f2" />

--- 

## Task 2: We believe the attacker may have used a subset of the brute forcing attack category - what is the name of the attack carried out?
To determine which subset of brute forcing occurred, we can use the Wireshark capture file to analyze how the intrusion was conducted.

Begin by filtering for http traffic to see the exploit attempts on Bonita:

<img width="1000" height="450" alt="1_8n_7dlpNSXH_xl88lSfLDw" src="https://github.com/user-attachments/assets/c109a368-a273-43d6-aadc-064c888f1c28" />

To view the individual conversations that were ongoing at the time of the intrusion, navigate to the `Statistics > Conversations` menu and click the **TCP tab**.

<img width="1000" height="466" alt="1_0kPf8A1UWn36NkHzkVVD1g" src="https://github.com/user-attachments/assets/edf969be-43b4-4938-b447-a9cb294f9811" />

Most of the conversations on the Wireshark capture are between `138.199.59.221` and `172.31.6.44` on port `8080`. The **"Follow Stream"** tab allows us to view the contents of the conversation and what is being accessed.

<img width="742" height="608" alt="1_bp3UEwcPypFZsgkEp_IoXQ" src="https://github.com/user-attachments/assets/acb4a477-ea5c-4449-8a67-5ee7e0918fd0" />

**HTTP** (*TCP Port 80*) is an unsecure protocol that does not encrypt its data. Because of this, we can view the username and password attempts for this particular conversation. To determine which form of brute forcing is being conducted, lets use the Brute Force framework provided by [MITRE ATT&CK](https://attack.mitre.org/techniques/T1110/):

<img width="497" height="392" alt="1_kkTaJle4nbio6slktP_4jQ" src="https://github.com/user-attachments/assets/dc8eee82-74aa-40c4-b694-37633fdd2d24" />

- **Password Guessing**: using common values for usernames and passwords.
- **Password Cracking**: utilizing offline obtained password hashes to crack or expose plaintext passwords.
- **Password Spraying**: attempting a small set of common passwords across many accounts rather than one account
- **Credential Stuffing**: using previously leaked usernames and password combinations from other sites on a target site.

Comparing each conversation in Wireshark shows that many different valid usernames are being tested with uncommon passwords. 
This type of brute force is most similar to **Credential Stuffing**. 
The attacker likely gained access to a large database of usernames and passwords from a credential breach online, hoping that users reuse those credentials across multiple sites.

<img width="1000" height="142" alt="1_qyniy1XVccuvZmEARNul7g" src="https://github.com/user-attachments/assets/bb91152f-e345-4dd4-8776-d1283b0d4206" />

--- 

## Task 3: Does the vulnerability exploited have a CVE assigned - and if so, which one?
Referring back to Task 1, we discovered that the business management platform is Bonita. The output also revealed that the CVE value was **CVE-2022–25237**.

To learn more about a particular vulnerability, utilize a **CVE database** such as [cvedetails.com](https://www.cvedetails.com/cve/CVE-2022-25237/) or [cve.org](https://www.cve.org/CVERecord?id=CVE-2022-25237):

<img width="1000" height="615" alt="1_2Q2_pa7aAcK5q5XbS73Fkg" src="https://github.com/user-attachments/assets/b90c73c9-bc7f-4cb7-8b7d-ae1b39ad781f" />

<img width="1000" height="603" alt="1_sCa8DuVdmDRJZ7bEHrZrwQ" src="https://github.com/user-attachments/assets/f4bbd230-88db-4ce9-a860-29b3f7db49fb" />

<img width="1000" height="142" alt="1_P0Kq1v0Vb-CblNq4vDa6Ng" src="https://github.com/user-attachments/assets/3d6c8486-e8e7-4357-a6db-a7edf65ddb6f" />

--- 

## Task 4: Which string was appended to the API URL path to bypass the authorization filter by the attacker's exploit?
[CVEdetails](https://www.cvedetails.com/cve/CVE-2022-25237/) stated that the **RestAPIAuthorizationFilter** on **Bonita Web 2021.2** is *overly broad* and therefore can be exploited:

> Bonita Web 2021.2 is affected by a authentication/authorization bypass vulnerability due to an overly broad exclude pattern used in the RestAPIAuthorizationFilter. 
> By appending ;i18ntranslation or /../i18ntranslation/ to the end of a URL, users with no privileges can access privileged API endpoints. 
> This can lead to remote code execution by abusing the privileged API actions.

By utilizing **'i18ntranslation'** in a http URL, users can remotely execute commands completely unauthenticated with privileged REST API endpoints. 
In Wireshark, we can see this exact exploit being utilized by viewing a http stream like before:

<img width="735" height="252" alt="1_iadtwynB5jO4U778mKDkMA" src="https://github.com/user-attachments/assets/dc416933-448b-4687-9d95-e706f026c492" />

<img width="1000" height="143" alt="1_IFXzbiTbVq5S9nXCXZEOfA" src="https://github.com/user-attachments/assets/27da4b36-8899-475a-8561-d488adda030a" />

--- 

## Task 5: How many combinations of usernames and passwords were used in the credential stuffing attack?
We can use a CLI version of Wireshark called **Tshark** to filter for the number of combinations of usernames and passwords used in the attack. In the terminal enter:

```
tshark -Y '(http.request.uri == "/bonita/loginservice") &&
(http.user_agent == "python-requests/2.28.1")' -r meerkat.pcap -T
json | jq '.[]._source.layers.http."http.file_data"' | sort | uniq
| wc -l
```

This command filters the `meerkat.pcap` capture for HTTP requests to `/bonita/loginservice` made by `python-requests/2.28.1` user agent. It extracts the output in JSON format and counts how many requests were made using `| sort | uniq | wc -l`.

<img width="1000" height="62" alt="1_52slVumUyDjUcIcl7A4Z6A" src="https://github.com/user-attachments/assets/f9115cb7-ef53-4421-9991-096aa534adc4" />

The output lists 57 total combinations were used. 
The actual answer is **56**, as you may have noticed in each packet the exploit uses the default credential of `install:install`. 
This means that we can subtract 1 from the total as it wasn't intended to be part of the credential stuffing attack.

<img width="587" height="352" alt="1_q3IUQ7u2sWP_dmwjgELRWA" src="https://github.com/user-attachments/assets/c4791e3c-e126-4bfc-bcf6-7d48e4723150" />

<img width="1000" height="143" alt="1_Frrb599Hl9zZdSrTEBB8mA" src="https://github.com/user-attachments/assets/9fe0ec9d-423e-4537-98b9-85be3310b1e8" />

--- 

## Task 6: Which username and password combination was successful?
On Wireshark, we can filter using the endpoint that we know was successfully targeted: `http.request.uri == "/bonita/loginservice"`

<img width="397" height="85" alt="1_eXYsnL2KVYyccC9JGbZFaQ" src="https://github.com/user-attachments/assets/91ff2ba3-22d7-402d-8445-94bf03219c27" />

This outputs all the packets involved with the exploit. From here, open the Conversation menu and **sort by total packets**.

<img width="139" height="438" alt="1_j8Dl-pRU5g-V4uWUwWwEkA" src="https://github.com/user-attachments/assets/d374c82b-7eb8-4423-934f-34efcbd5d264" />

**The more packets for a particular conversation, the longer the attacker performed the exploit.**
This means the higher the packet number is, the more likely it was to be the successful exploit.

Click on follow stream and view the conversation with the most amount of total packets (*58*). At the bottom of the http stream, lists the username and password that worked.

<img width="683" height="72" alt="1_D9CYCTTyxUX8nOj3qteCpA" src="https://github.com/user-attachments/assets/ebbafd55-e65a-4270-bb5d-2ba4e5dcdbc4" />

*HTTP requests are URL-encoded*, so we must decode the username before we can submit our answer. Visiting [urldecoder.org](https://www.urldecoder.org/) and inputting the username reveals the `%40` was actually an `@` symbol.

<img width="449" height="520" alt="1_8u5CN0lQi1rKHmj_ZYFXXg" src="https://github.com/user-attachments/assets/e97e4a8e-aa6e-4dd2-b4dc-d24d6f14a0e4" />

Therefore, the answer is: **seb.broom@forela.co.uk:g0vernm3nt**

<img width="1000" height="139" alt="1_-wkyyopQKuXqDXV6zec30A" src="https://github.com/user-attachments/assets/c9bfbd2e-34ed-48d7-b45b-34847ca878b7" />

--- 

## Task 7: If any, which text sharing site did the attacker utilize?
The attacker has successfully accessed credentials and begins **remote code execution (RCE)**.

<img width="1000" height="121" alt="1_TuAE_fZxBtz_FEe-rvHd2g" src="https://github.com/user-attachments/assets/10065add-ad81-49e1-8d43-630ab255124d" />

The attacker sends a **crafted request to Bonita's API** with the command `cmd=cat%20/etc/passwd` to test for command execution on the target server of **forela.co.uk** on port **8080**.

On Wireshark, we can view more GET request details to see what other commands were used by navigating to Statistics > HTTP > Requests.

<img width="824" height="778" alt="1_3bWnl8lvcCYBiDs2HsnKyA" src="https://github.com/user-attachments/assets/3fa47da1-59a9-4700-a9f8-d109fc98af35" />

<img width="875" height="532" alt="1_Mt4xZg95SqIB6DxLH2nMhQ" src="https://github.com/user-attachments/assets/a60be450-f31e-4503-93e3-6c6d16fa0cd8" />

From here, we see that the attacker downloaded a file from **pastes.io**.

<img width="1000" height="146" alt="1_xk_r_yzBkuAGpDeZF_HAnQ" src="https://github.com/user-attachments/assets/3726be28-0ad7-4bd0-b691-0f8d28cc293b" />

--- 

## Task 8: Please provide the filename of the public key used by the attacker to gain persistence on our host.
The attacker downloaded the file from a link on pastes.io, which can be directly accessed using a web browser.

Enter https://pastes.io/raw/bx5gcr0et8 into your VM web browser to see the contents of the file.

<img width="600" height="208" alt="1_IXvC6yV173MxBLBzkoGczQ" src="https://github.com/user-attachments/assets/23b0f936-32ec-4324-9787-a0922873f721" />

The attacker's payload on pastes.io copies the contents of the file **hffgra4unv** into the authorized key file on the host.

<img width="1000" height="147" alt="1_T5mg2v0dlBNT8mzgjmSHQg" src="https://github.com/user-attachments/assets/b73ce8ac-1ec1-462b-ac3d-cacd9c64d70a" />

--- 

## Task 9: Can you confirm the file modified by the attacker to gain persistence?
Just like in task 8, we can confirm the file modified by the attacker by entering https://pastes.io/raw/hffgra4unv into our web browser.

The contents of this file is a **SSH public key**, which once added into the target server's `authorized_keys` file, would permit them to login to the server via SSH for as long as the key is in the file. This results in the attacker gaining persistence, meaning the attacker has access even if the server reboots, logs out, or disconnects.

Therefore, the answer to task 9 is the file the key was copied to:
`/home/ubuntu/.ssh/authorized_keys`

<img width="1000" height="141" alt="1_tqORL6kYWmuX5V5PJ6Qz7w" src="https://github.com/user-attachments/assets/4bfaf760-8229-4076-9bd5-54659320c864" />

--- 

## Task 10: Can you confirm the MITRE technique ID of this type of persistence mechanism?
Under the persistence category on [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)'s database, we can view the [Account Manipulation](https://attack.mitre.org/techniques/T1098/) subcategory. It is described as follows according to MITRE:

> Adversaries may manipulate accounts to maintain and/or elevate access to victim systems. Account manipulation may consist of any action that preserves or modifies adversary access to a compromised account, such as modifying credentials or permission groups.

Modifying SSH authorized_keys falls under this category. Viewing the left side panel, the 'SSH Authorized Keys' sub-technique is listed with the **T1098.004** ID.

<img width="1000" height="622" alt="1_gVY3cEwRHJPD9cQ49wI3Rw" src="https://github.com/user-attachments/assets/cb6c92aa-17af-4cff-bb0f-ac009ad6a7d6" />

<img width="1000" height="145" alt="1_UBN6Awf8EmL1o58FaooLRQ" src="https://github.com/user-attachments/assets/1602b142-5f8f-4090-a9b7-394eff387c97" />

--- 

# Conclusion

<img width="865" height="788" alt="1_r7-VQmPMDUOASyyWI7rIXA" src="https://github.com/user-attachments/assets/2458d985-b9d2-40a1-af07-f4975c57aa3e" />

The **Meerkat Sherlock** challenge from *Hack The Box* offers a very comprehensive exercise into blue team operations. It leverages tools such as *Wireshark*, *jq*, and the *MITRE ATT&CK framework* to teach the practical applications of network traffic analysis, log parsing with JSON, and utilizing MITRE ATT&CK's frameworks.

We identified key indicators of compromise, such as **CVE-2022–2537** in *Bonitasoft*, which has a vulnerability in its `RestAPIAuthorizationFilter`. It appends the special string `;i18ntranslation` to API URLs, bypassing the filter's exclude pattern. The attacker took advantage of that and remotely executed commands (RCE) on the server.

The attacker attempted **57 logins** (56 discounting `install:install`) and the successful login was determined. The attacker fetched a file containing a SSH public key filename from *pastes.io* to use as a payload to copy into the victim's `authorized_keys`. This served as the attacker's persistence vector. This form of attack maps to MITRE ATT&CK's database as **SSH Authorized Keys (T1098.004)** sub-technique.

If you found this walkthrough helpful, please feel free to drop a follow. Thank you for reading!

## References:
Challenge: https://app.hackthebox.com/sherlocks/552

MITRE ATT&CK: https://attack.mitre.org/

CVEdetails: https://www.cvedetails.com/cve/CVE-2022-25237/

CVE.org: https://www.cve.org/CVERecord?id=CVE-2022-25237

Zeek Documentation: https://docs.zeek.org/en/master/log-formats.html
