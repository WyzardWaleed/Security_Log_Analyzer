\# Security Log Analyzer



A defensive Python tool that analyzes sample SSH authentication logs, detects suspicious repeated failed-login activity, assigns alert severity, and generates JSON incident reports.



\## Purpose



I built this project as part of my cybersecurity portfolio to demonstrate hands-on skills in Python, log analysis, threat detection, incident triage, and security reporting.



\## Features



\- Parses SSH authentication logs

\- Detects repeated failed-login attempts by source IP address

\- Assigns Medium or High alert severity

\- Generates a JSON incident report

\- Includes recommended analyst actions for each alert



\## Defensive Use Only



This project is for educational and defensive-security purposes. It analyzes only sample or authorized log data and does not scan, attack, or access external systems.



\## How It Works



1\. Reads authentication events from `data/sample\_auth.log`

2\. Extracts source IP addresses from failed login events

3\. Counts repeated failed attempts by IP address

4\. Assigns alert severity based on the number of attempts

5\. Saves findings to `reports/security\_report.json`



\## Run the Tool



From the project’s main folder, run:



```powershell

python src/analyzer.py

