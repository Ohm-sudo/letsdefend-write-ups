# Introduction to MITRE
- Founded in 1958 in the US as an organization.
- Purpose is to advance national security and serve public interest.
- MITRE ATT&CK - Adversarial Tactics, Techniques, and Common Knowledge.
  - Framework of a knowledge database created in 2013.
  - Cyber attacks are divided into stages and analyzed in depth.

<br>

#### Q1: In what year was the MITRE founded?
<pre>1958</pre>
<br>

#### Q2: In what year was MITRE ATT&CK Framework started to be developed?
<pre>2013</pre>
<br>

# Matrix
- A matrix is a visualization method to clasify attack methods of attackers.
- Three types for MITRE ATT&CK framework:
  - **Enterprise Matrix**: Contains more digital systems and is more common.
    - Sub-matrices: PRE, Windows, macOS, Linux, Cloud, Network, Containers 
  - **Mobile Matrix**: Contains info about cyber security of mobile devices.
    - Sub-matrices: Android, iOS.
  - ICS (Industrial Control Systems) Matrix: Contains info collected for cyber security of industrial control systems.

<br>

#### Q1: What is the name of the images on the tactic and techniques in the MITRE ATT&CK Framework?
<pre>Matrix</pre>
<br>

#### Q2: What is the matrix of information about the cybersecurity of Windows, Linux, macOS, Azure AD and Office 365 platforms?
<pre>Enterprise</pre>
<br>

#### Q3: What is the matrix that contains the information about the cyber security of Android and iOS platforms?
<pre>Mobile</pre>
<br>

# Tactics
- Tactic represents purpose of cyber attacker and their rationale.
  - i.e., Reconnaissance, Resource Development, Initial Access, Execution.
-  14 tactics for Enterprise and Mobile matrix.
-  12 tactics for ICS matrix.

<br>

#### Q1: What is the ID of the "Lateral Movement" tactic in the Enterprise matrix?
<pre>TA0008</pre>
Go to MITRE ATT&CK website. Search for Lateral Movement (Enterprise) to find the ID.

<br>

#### Q2: When was the "Persistence" tactic in the mobile matrix created? 
<pre>17 October 2018</pre>
Go to MITRE ATT&CK website. Search for Persistence (Mobile) to find when the tactic was created.

<br>

#### Q3: What is the name of the tactic in Enterprise, Mobile and ICS matrices which is under the techniques related to obtaining higher-level permission on the target system/network?
<pre>Privilege Escalation</pre>
Privilege Escalation describes this tactic.

<br>

# Techniques and Sub-Techniques
- Tactics only show attacker's goals; not detailed info about their attack method.
- Techniques and sub-techniques shows attackers methods to achieve their goals.
- Like with matrices, techniques are divided into Enterprise, Mobile, and ICS.
  - Enterprise has the most techniques (193, 401).
  - ICS has no sub-techniques.
- Procedure shows usage examples of techniques/sub-techniques.

<br>

#### Q1: What is the name of the technique with the ID T1055 among the Enterprise techniques?
<pre>Process Injection</pre>
Go to MITRE ATT&CK website. Search for T1055 and select the result related to Enterprise.

<br>

#### Q2: Among the Enterprise techniques, which platform is the technique with the ID T1112 for?
<pre>Windows</pre>
Go to MITRE ATT&CK website. Search for T1112 and read the description of the technique.

<br>

#### Q3: Under which tactic is the "Supply Chain Compromise" technique which is among the Enterprise techniques?
<pre>Initial Access</pre>
Go to MITRE ATT&CK website. Search for Supply Chain Compromise and select the first result (not sub-technique). If you read, the tactic associated with this technique is Supply Chain Compromise.
