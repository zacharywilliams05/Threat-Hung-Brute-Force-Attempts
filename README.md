# Threat Hunting - Brute Force Detection

We will work this threat hunting scenario according to NIST 800-61 Incident Response Lifecycle.

## Preparation
In the preparation phase, we would do any work possible that sets up the organization to prevent a brute force attack. In this case, we are going to assume this is a young organization and has not been monitoring for this kind of attack previously. However, we have:

- Documented roles, responsibilities, and procedures
- Ensured tools, systems, and training are in place

We assume the security team is tasked with finding evidence of brute force attacks, systems such as Azure, Microsoft Defender, etc., are set up, and the security team has training on skills such as KQL to build queries.

## Detection and Analysis
Detection starts with checking log files for evidence of brute force attempts. I built the following KQL query to filter brute force attempts in the DeviceLogonEvents table:

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed" and Timestamp >= now() - 5h
| order by Timestamp desc 
| summarize Eventcount = count() by RemoteIP, DeviceName
| where Eventcount >= 20
| order by Eventcount
```

KQL Explanation:
This query filters log events in the DeviceLogonEvents table. Initially, it looks for any event with a "LogonFailed" result within the last 5 hours and orders them in descending order by Timestamp. Then it summarizes the data by counting the events where a RemoteIP tried to log into a specific DeviceName and presents any results where the EventCount is more than or equal to 20. Finally, it will present the results in order of EventCount.

<img width="568" alt="Detection KQL Query" src="https://github.com/user-attachments/assets/07bcb9fd-4fee-481b-8b74-8d084fccb2ab" />

Analyzing the data, we see several brute force attempts by RemoteIPs making a suspicious number of login attempts and failing. From this, we can conclude that remote attackers are indeed trying to brute force their way into our systems.</br>

##Containment, Eradication, and Recovery
Containment begins with building a rule to create an incident when evidence of a brute force attempt is found in the logs.

<img width="690" alt="Containment Rule 1" src="https://github.com/user-attachments/assets/b92b7d17-9d61-4648-9dd5-139eb5be074d" />
<img width="941" alt="Containment Rule 2" src="https://github.com/user-attachments/assets/f6eac283-d0c2-44c8-b711-cb3e21680c22" />

In Microsoft Sentinel, I created a rule that utilizes the KQL query created in the Detection and Analysis phase. As this is a lab environment, I set the query to run every 4 hours, but in a live environment, we may have it run more or less often depending on the severity of the incoming attacks.

<img width="1216" alt="Incident 1" src="https://github.com/user-attachments/assets/e834af73-a9e6-4fe3-9aa3-227dff49a729" />

An incident is immediately created.

<img width="677" alt="Incident 2" src="https://github.com/user-attachments/assets/0578698b-0b44-4d82-b45d-a4ffd151c21a" />

I assign the ticket to myself, make it active, and view the endpoints of concern.

We can now see remote attackers who tried to break into our machines, but we want to know if they actually succeeded. To do this, we can query the remote attacker's IP address against the device name and filter for any successful logins. The KQL query for this looks like:

```kql
DeviceLogonEvents
| where RemoteIP == "RemoteIPAddress" and DeviceName == "Hostname" and ActionType == "LogonSuccess"
```

KQL Explanation:
This query filters log events in the DeviceLogonEvents table. Initially, it looks for any event with a "LogonFailed" result within the last 5 hours and orders them in descending order by Timestamp. Then it summarizes the data by counting the events where a RemoteIP tried to log into a specific DeviceName and presents any results where the EventCount is more than or equal to 20. Finally, it will present the results in order of EventCount.

Analyzing the data, we see several brute force attempts by RemoteIPs making a suspicious number of login attempts and failing. From this, we can conclude that remote attackers are indeed trying to brute force their way into our systems.

##Containment, Eradication, and Recovery
Containment begins with building a rule to create an incident when evidence of a brute force attempt is found in the logs.

In Microsoft Sentinel, I created a rule that utilizes the KQL query created in the Detection and Analysis phase. As this is a lab environment, I set the query to run every 4 hours, but in a live environment, we may have it run more or less often depending on the severity of the incoming attacks.

An incident is immediately created.

I assign the ticket to myself, make it active, and view the endpoints of concern.

We can now see remote attackers who tried to break into our machines, but we want to know if they actually succeeded. To do this, we can query the remote attacker's IP address against the device name and filter for any successful logins. The KQL query for this looks like:

```kql
DeviceLogonEvents
| where RemoteIP == "RemoteIPAddress" and DeviceName == "Hostname" and ActionType == "LogonSuccess"
```

In our case, for most of our devices, no successful login attempts were found. One device, however, did have a successful brute force login, so we need to quarantine that device to prevent further damage to the organization.

Using Microsoft Defender, of which all of our endpoints are onboarded to by default, we can quarantine.

From here, we would investigate with the user and possibly rebuild the VM if evidence of tampering by the attacker is found.

##Post-Incident Activities
I recorded my notes in the incident so other engineers can understand how the incident was handled.

Based on the activities I performed, I would make recommendations to update our policies and tools. The recommendations I would make are:

Implement an account lockout policy of 10 attempts.
Harden the firewall/NSG to block remote login attempts from remote IP addresses we have not approved.
Revise the KQL query to combine the brute force detection query and the brute force success query. This would help to reduce the number of tickets.

##Closure
I documented the results of our investigation and included it in the notes of the incident. The incident was then closed.
