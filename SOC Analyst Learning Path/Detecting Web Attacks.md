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
