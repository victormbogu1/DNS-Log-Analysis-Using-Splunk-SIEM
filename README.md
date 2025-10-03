# DNS Log Analysis Using Splunk SIEM

## 📌 Introduction
The Domain Name System (DNS) plays a critical role in network communication by resolving hostnames into IP addresses. However, attackers often abuse DNS for malicious purposes such as data exfiltration, domain generation algorithms (DGAs), and command-and-control (C2) communications.  

This project demonstrates how to ingest, parse, and analyze DNS log files in **Splunk SIEM** to detect anomalies and enhance visibility into network traffic.  Depending on the use case, analysis may focus on monitoring routine activity, detecting malicious behavior, or helping stakeholders investigate specific incidents. 

---

## 📂 Data
The project uses sample DNS logs in text format (`dns.log`) that contain the following fields:

- **Timestamp**  
- **Unique Flow ID (UID)**  
- **Source IP / Source Port**  
- **Destination IP / Destination Port**  
- **Protocol**  
- **Transaction ID**  
- **Queried Domain (FQDN)**  
- **Query Class / Type**  
- **Response Code**  
- **Flags**


## 📌 What a typical DNS event should include:

- Source IP → client sending the request (e.g., 10.0.0.5)

- Destination IP → DNS server receiving the query (e.g., 10.0.0.53)

- Domain (FQDN) → domain name requested (e.g., example.com)

- Query Type → record type (A = IPv4, AAAA = IPv6, TXT, ANY, etc.)

- Response Code → result of the query (NOERROR, NXDOMAIN, SERVFAIL, etc.)



---

## 📂 Project Files
- **data/dns.log** → Raw DNS log sample used for testing.
- **docs/field_mapping.md** → Documentation of log fields with explanations.
- **Splunk Config** → Source type and extraction rules.

---

## 🚀 Steps in the Project
1. Upload DNS log into Splunk.
2. Assign a custom sourcetype (`dns_sample`).
3. Extract fields using delimiters (timestamp, IPs, ports, query, flags).
4. Validate extracted fields in Splunk Search.
5. Build searches and dashboards for DNS monitoring.


## 📤 Uploading the DNS Log
![Fortigate.png](https://github.com/victormbogu1/Analyzing-DNS-Log-Files-Using-Splunk-SIEM/blob/43723bee124fed20c3439a7916cebd9e496beb19/spluggg/Screenshot%202025-10-01%20204349.png)

## 🔍 Verify DNS Events in Splunk

Run a search to confirm DNS events are indexed correctly.
Search for DNS Events
![Fortigate.png](https://github.com/victormbogu1/Analyzing-DNS-Log-Files-Using-Splunk-SIEM/blob/43723bee124fed20c3439a7916cebd9e496beb19/spluggg/Screenshot%202025-10-02%20183719.png)

## Extract Relevant Fields
- Identify key fields in DNS logs, including source IP, destination IP, domain name, query type, response code, and other relevant attributes to effectively analyze DNS activity.
- 
### 🧾 DNS Log Field Breakdown  

| **Value**             | **Field Name**        | **Meaning (Simple Explanation)** |
|------------------------|-----------------------|----------------------------------|
| `1331927971.170000`   | **Timestamp**         | The exact time when the DNS event happened (epoch format). |
| `CdaTMW2Lx6PnqsTCu6`  | **UID (Unique Flow ID)** | A unique identifier for this specific DNS transaction/log line. |
| `192.168.204.70`      | **Source IP**         | The IP address of the client (who made the DNS query). |
| `46816`               | **Source Port**       | The port on the client machine used for this query. |
| `192.168.207.4`       | **Destination IP**    | The IP address of the DNS server being queried. |
| `53`                  | **Destination Port**  | The port number used by DNS servers (default = 53). |
| `udp`                 | **Protocol**          | The transport protocol used (UDP or TCP). DNS usually uses UDP. |
| `53278`               | **Transaction ID**    | An ID used to match DNS requests with responses. |
| `jigsaw.w3.org`       | **Query (Domain Name)** | The domain name the client is trying to resolve. |
| `1`                   | **Query Class**       | A number representing the query class (1 = Internet). |
| `C_INTERNET`          | **Query Class Name**  | A human-readable name of the class (most are “IN” for Internet). |
| `1`                   | **Query Type Number** | Numeric code for record type (e.g., 1 = A record). |
| `A`                   | **Query Type**        | The type of DNS record requested (A = IPv4, AAAA = IPv6, TXT, etc.). |
| `-`                   | **Rcode Name**        | Response code name; `-` means no specific code here. |
| `-`                   | **Authoritative Flag** | Indicates if the DNS server is authoritative for the query. |
| `F / F / T / F …`     | **DNS Flags**         | Flags showing DNS behaviors (e.g., recursion desired, truncated, etc.). |
| `Response Code`       | **Server Response**   | The DNS server’s answer (e.g., NOERROR = success, NXDOMAIN = domain not found, SERVFAIL = error). |

---

✅ This mapping makes raw DNS logs human-readable and easy to query in Splunk.


![Fortigate.png](https://github.com/victormbogu1/Analyzing-DNS-Log-Files-Using-Splunk-SIEM/blob/43723bee124fed20c3439a7916cebd9e496beb19/spluggg/Screenshot%202025-10-02%20190646.png)
![Fortigate.png](https://github.com/victormbogu1/Analyzing-DNS-Log-Files-Using-Splunk-SIEM/blob/43723bee124fed20c3439a7916cebd9e496beb19/spluggg/Screenshot%202025-10-02%20190843.png)

## Identify Anomalies
Look for unusual patterns or anomalies in DNS activity.
Example query to identify spikes

![Fortigate.png](https://github.com/victormbogu1/Analyzing-DNS-Log-Files-Using-Splunk-SIEM/blob/43723bee124fed20c3439a7916cebd9e496beb19/spluggg/Screenshot%202025-10-02%20192729.png)

## Find the top DNS sources
Use the top command to count the occurrences of each query type:
![Fortigate.png](https://github.com/victormbogu1/Analyzing-DNS-Log-Files-Using-Splunk-SIEM/blob/43723bee124fed20c3439a7916cebd9e496beb19/spluggg/Screenshot%202025-10-02%20193000.png)

![Fortigate.png](https://github.com/victormbogu1/Analyzing-DNS-Log-Files-Using-Splunk-SIEM/blob/43723bee124fed20c3439a7916cebd9e496beb19/spluggg/Screenshot%202025-10-02%20193304.png)

## Investigate Suspicious Domains
By Ssearching for Malicious Domains:
- Investigate domains that are associated with known malicious activity or display suspicious behavior.
- Leverage threat intelligence feeds or domain reputation databases (e.g., VirusTotal, AbuseIPDB, ThreatMiner) to identify potentially harmful domains.
- For example you can also check this suspicious activities in VirusTotal to check if a domain is flagged for malicious activity.

![Fortigate.png](https://github.com/victormbogu1/Analyzing-DNS-Log-Files-Using-Splunk-SIEM/blob/43723bee124fed20c3439a7916cebd9e496beb19/spluggg/Screenshot%202025-10-02%20193946.png)
![Fortigate.png](https://github.com/victormbogu1/Analyzing-DNS-Log-Files-Using-Splunk-SIEM/blob/2483ba8bb456dcfdb888354b59cd204e1b34a945/spluggg/Screenshot%202025-10-02%20194214.png)

## Which clients are sending the most queries:
- Helpful to spot a single machine generating abnormal DNS traffic.
![Fortigate.png](https://github.com/victormbogu1/Analyzing-DNS-Log-Files-Using-Splunk-SIEM/blob/8db02df95a31bbef8c3cf360bbe7f82a2a0c6d96/spluggg/Screenshot%202025-10-02%20221004.png)

## 📌 Conclusion

Analyzing DNS logs with Splunk SIEM provides valuable visibility into network traffic and helps detect potential threats early:

- Understanding normal DNS activity

- Identifying anomalies and suspicious domains

- Leveraging threat intelligence

- organizations can strengthen their security posture and defend against malware, data exfiltration, and DNS-based attacks.


