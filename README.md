# Analyzing-DNS-Log-Files-Using-Splunk-SIEM

Introduction
DNS (Domain Name System) logs are crucial for understanding network activity and identifying potential security threats. Splunk SIEM (Security Information and Event Management) provides powerful capabilities for analyzing DNS logs and detecting anomalies or malicious activities.

🔹 1. What DNS events should look like

A “good” DNS log line should include at least these parts:

Source IP = the client making the query (e.g., 10.0.0.5)

Destination IP = the DNS server handling the query (e.g., 10.0.0.53)

Domain name (FQDN) = what was queried (e.g., example.com)

Query type = the record type requested (A, AAAA, TXT, ANY, etc.)

Response code = the server’s response (NOERROR, NXDOMAIN, SERVFAIL, etc.)


🔎 Review Settings

Input Type: Uploaded File ✅
That’s correct for one-time/manual testing.

File Name: dns.log ✅
Just the file you picked. Nothing wrong here.

Source Type: dns_sample ✅
Good choice! This is what you’ll use in searches (sourcetype=dns_sample).

Host: splunkvictor ⚠️
That’s the hostname of the machine running Splunk.


## Verify in Splunk after upload
Search for DNS Events

## Extract Relevant Fields
Identify key fields in DNS logs such as source IP, destination IP, domain name, query type, response code, etc.

1331927971.170000   → timestamp
CdaTMW2Lx6PnqsTCu6 → uid (unique flow id)
192.168.204.70     → source IP
46816              → source port
192.168.207.4      → destination IP
53                 → destination port (DNS port)
udp                → protocol
53278              → transaction ID
jigsaw.w3.org      → query (domain name)
1                  → query class
C_INTERNET         → query class name
1                  → query type number
A                  → query type (A record, AAAA, NB, etc.)
-                  → rcode name (response code)
-                  → authoritative flag
F/F/T/F…           → DNS flags


## Identify Anomalies
Look for unusual patterns or anomalies in DNS activity.
Example query to identify spikes
