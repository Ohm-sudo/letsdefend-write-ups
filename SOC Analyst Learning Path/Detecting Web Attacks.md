# OWASP
- **Open Worldwide Application Security (OWASP)**: Non-profit foundation for improving software security.
## 2021 OWASP List
1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery (SSRF)

<br>

The answers to the questions below can be found by searching online about OWASP.

#### Q1: What is the name of the tool that OWASP has prepared to help scan web applications for vulnerabilities?
<pre>ZAP</pre>
<br>

#### Q2: Which area does OWASP focus on?
A) Web Applications <br>
B) Server Management <br>
C) Wireless Security <br>
<pre>A</pre>
<br>

#### Q3: What is the name of the vulnerable web application project that OWASP wrote using Node.js for security researchers to improve themselves?
Answer Format: xxx_xxx
<pre>Juice_Shop</pre>
Juice Shop is an intentionally vulnerable web app ideal for security training, CTFs, and testing security tools.

<br>

#### Q4: What does the OWASP Top 10 list, published every few years, reveal?
A) Most critical security risks to mobile applications <br>
B) Most critical security risks to web applications <br>
C) Most encountered web application vulnerabilities <br>
D) Most encountered mobile application vulnerabilities <br>
<pre>B</pre>
<br>

# How Web Applications Work
- Web applications communicate with each other using HTTP.
- HTTP is layer 7, whereas TCP, IP, and Ethernet are used before HTTP.
- HTTP request is used to retrieve specific resource from web server.
<img src="https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/HTTP-Request.png"/>
- HTTP response message is a message sent from the server to client requesting the specific resource.
<img src="https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/HTTP-Response.png"/>

#### Q1: Which HTTP Request header contains browser and operating system information?
<pre>User-Agent</pre>
<br>

#### Q2: What is the HTTP Response status code that indicates the request was successful?
<pre>200</pre>
<br>

#### Q3: Which HTTP Request Method ensures that the submitted parameters do not appear in the Request URL?
<pre>POST</pre>
HTTP GET shows the parameters in the URL, whereas POST does not.

<br>

#### Q4: Which HTTP Request header contains session tokens?
<pre>Cookie</pre>
Sessions refer to cookies.

<br>

# Detecting SQL Injection Attacks
- SQL injections (SQLi) are critical attack vectors that involve the user inputting SQL queries.
## Types of SQL Injections
1. **In-band SQLi (Classic SQLi)**: SQL query sent and responded on same channel.
2. **Inferential SQLi (Blind SQLi)**: SQL queries that cannot be seen. Also called "Blind SQLi".
3. **Out-of-band SQLi**: SQL query is communicated through a different channel (i.e., Attacker receives replies for SQL queries via DNS).
- Attack examples:
  - Authentication bypass.
  - Command execution.
  - Exfiltration of sensitive data.
  - Creating/deleting/updating database entries.
## How to Prevent SQL Queries
- **Use framework**.
- **Keep framework updated**.
- **Always sanitize data received from user**.
- **Avoid use of raw SQL queries**.
## Detecting SQL Injection Attacks
- **Check all areas of a web request**.
- **Look for SQL keywords**.
- **Check any special characters**.
- **Familiarize yourself with common SQL injection payloads**.
- It is unwise to upload critical info such as access logs to a 3rd party tool (i.e., URL decoder), so keep this in mind.
- Can check if SQL injection attack is successful if you check the response (if there is one).
- The questions below will be based off of the provided .rar file.

<br>

#### Q1: What date did the exploitation phase of SQL Injection Attack start? 
<pre>01/Mar/2022:08:35:14</pre>
The attack initiated a few entries before the SQL statements were executed (GET request for Submit). If you compare the response size (beside the status code of web request), there is one entry that is particularly lower than the rest meaning the attack was quickly executed successfully.

<br>

#### Q2: What is the IP address of the attacker who performed the SQL Injection attack?
<pre>192.168.31.167</pre>
192.168.31.200 is the web server.

<br>

#### Q3: Was the SQL Injection attack successful? (Answer Format: Y/N)
<pre>Y</pre>
<br>

#### Q4: What is the type of SQL Injection attack? (Classic, Blind, Out-of-band)
<pre>Classic</pre>
Classic because the SQL injection attack is within same communication channel and visible.

<br>

# Detecting Cross Site Scripting (XSS) Attacks
- Allows malicious code to be executed on web applications.
## Types of XSS
1. **Reflected (Non-Persistent)**: XSS payload must be present in request. Most common.
2. **Stored XSS (Persistent)**: Attacker can permanently upload XSS payload to web application. Most dangerous.
3. **DOM Based XSS**: Payload executed as a result of modifying DOM environment so that client-side code behaves unexpectedly.
- Attackers can steal user session info.
- Capture credentials.
## Preventing a XSS Vulnerability
- **Sanitize user input data** - i.e., use HTML encoding.
- **Use a framework**.
- **Use the framework correctly**.
- **Keep framework updated**.
## Detecting XSS Attacks
- **Look for keywords**.
- **Learn about common XSS payloads**.
- **Check use of special characters**.
- Again the next set of questions are based on the attache .rar file.

<br>

#### Q1: What is the start date of the XSS attack? 
<pre>01/Mar/2022:08:53:20</pre>
<br>
Search in the file for the keyword "script" and look for the first entry that contains this keyword. That entry is the start of the attack.

#### Q2: What is the IP address of the attacker who performed the XSS attack?
<pre>192.168.31.183</pre>
<br>
192.168.31.200 is the web server.

#### Q3: Was the XSS attack successful? 
<pre>Y</pre>
Yes as the request was successful.

<br>

#### Q4: What is the type of XSS attack? (Reflected, Stored, Dom based)
<pre>Reflected</pre>
The payload is present in the file so the attack type is Reflected.

<br>

# Detecting Command Injection Attacks
