# Detecting Web Attacks 2

## Detecting Open Redirection Attacks
- **Open redirection**: Redirects users to differnet URL w/o proper validation or sanitization.
- Attackers use this to trick users into visiting websites.
- Typically a legit URL is created with a malicious URL as a parameter.
- Recommended to validate, sanitize, and implement proper authentication and authorization for redirects.

<br>

### Redirection Types / Vectors
1. **URL-based open redirection**: Malicious website in URL parameter.
2. **JavaScript-based open redirection**: Malicious URL obtained using JS code or input data.
3. **Meta refresh-based open redirection**: Website uses "meta refresh" tag to redirect users to another URL.
4. **Header-based open redirection**: Website uses HTTP headers to perform a redirect.
5. **Parameter-based open redirection**: Website uses parameter for redirect (value not sanitized).

<img src="https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/open+redirection/Bash+URL.png"/>

<br>

### Impact of Open Redirection
1. Phishing attacks.
2. Malware distribution.
3. Social engineering attacks.
4. Reputation damage.
5. Legal and regulatory consequences.

<br>

### Detecting Open Redirect Attacks
1. Consecutive query string parameters (i.e., http://website.com/param.php?next=).
2. Payloads can bypass techniques like:
   1. Localhost.
   2. CDIR.
   3. Decimal bypass (i.e., http://2130706433 = http://127.0.0.1)
   4. Hexadecimal bypass (i.e., http://0x7f000001 = http://127.0.0.1)
- Can use the following regec to detect open redirection attacks:
  - /^.*"GET.*\?.*=(https%3a%2f%2f[a-z0-9-]+%2e[a-z]{2,}).+?.*HTTP\/.*".*$/gm

<img src="https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/open+redirection/decoded-open.png"/>

In the above image, attacker wants to redirect to google.com using ?pro parameter.

Answer the following questions using the provided access log.

<br>

#### Q1: What date did the exploitation phase of Open Redirection start? Format: dd/MMM/yyyy HH:mm:ss
<pre>27/Apr/2023 15:45:22</pre>
I searched for "local" then noticed a couple of suspicious entries. Some entries contained "http://victim.com/" so I kept scrolling up until I saw the first instance.

<br>


#### Q2: What is the IP address of the attacker who performed the Open Redirect attack?
<pre>86.236.188.85</pre>
This is based off of the same entry used to find the date of the start of exploitation phase.

<br>

#### Q3: What was the parameter that attacked?
<pre>postID</pre>
<br>

### Detecting Directory Traversal Attacks
- **Directory traversal**: Access files and directories outside of web server's root directory.
- Aka dot-dot-slash attack.
- Used to gain unauthorized access to sensitive data and execute arbitrary code.
- i.e., Attack can add `../` to a URL. http://example.com/profiles/picture.php?name=../../etc/passwd
- Similar to **Local File Inclusion (LFI)**
  - Difference is source of input.
  - Directory traversal manipulate input used to access files on web server.
  - LFI manipulate input used to include local files within web app.
 
<br>

### Directory Traversal Possible Vectors
1. User input (../)
2. Cookies
3. HTTP headers: Manipulating Referer or User-Agent header.
4. File upload
5. Direct requests: Guessing or brute-forcing file names or paths.
6. URL manipulation
7. Malicious links

<br>

### Impact of Directory Traversal
1. Disclosure of sensitive data.
2. Execution of arbirtrary code (malware or backdoors).
3. Denial of service.
4. System compromise

<br>

### Prevention Methods for Directory Traversal Attacks
- Input validation and sanitization.
- Access controls.
- Relative file paths.
- Whitelisting: only specific characters allowed in file name parameter.
- Secure coding practices: i.e., avoid using user input in path concatenation, eval() and system().
- Web application firewall (WAF).

<br>

### Detecting Directory Traversal Attacks
Example payloads:
<img src="https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/directory+traversal/img5.png"/>

Popular files:

**Linux**
- /etc/issue
- /etc/passwd
- /etc/shadow
- /etc/group
- /etc/hosts

**Windows**
- c:/boot.ini
- c:/inetpub/logs/logfiles
- c:/inetpub/wwwroot/global.asa
- c:/inetpub/wwwroot/index.asp
- c:/inetpub/wwwroot/web.config
- c:/sysprep.inf

<br>

Answer the following questions below using the provided file.

<br>

#### Q1: What date did the exploitation phase of Directory Traversal start? Format: dd/MMM/yyyy HH:mm:ss
<pre>23/Apr/2023 00:16:57</pre>
I searched using the common payloads i.e., %2e. The first result indicates the date when the attack started.

<br>

#### Q2: What is the IP address of the attacker who performed the Directory Traversal attack?
<pre>123.114.236.235</pre>
This is based off the entry when the attack started.

<br>

#### Q3: What was the parameter that attacked?
<pre>uid</pre>
<br>

## Detecting Brute Force Attacks
