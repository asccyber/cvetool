# CVETracker

## Inputs:

System Name
Relevant Software 
Contact

## Outputs:

List of IAVMs correlated to relevant system software in monthly period 

## Environment:

* Hardware - PI 3
* OS - Ubuntu Mate
* Platform - Python 2.7
* Database - PostgreSQL

## Logic:

* Query CVEs for all the relevant software on a system
* Determine the CVEs in the current month
* Sort the CVEs by software type
* Match CVEs to IAVM numbers
* Output list
* E-mail list to contact

## Data Sources:

* https://cve.mitre.org/data/downloads/index.html - Multiple data options (i.e. CSV, XML, HTML, or text). Need to determine best format
* https://nvd.nist.gov/download.cfm#CVE_FEED - XML data feeds in GZ or ZIP sorted by year

## Milestones:

* Download data into repository 
* Analyze, output, and associate CVEs to system
* Notification to program/admin of relevant notices 

## Relevant XML tag breakdown:

* <vuln:cve-id> = Provides CVE number of specific vulnerability
* <vuln:vulnerable-software-list> = provides list of what systems are effected by this CVE
* <vuln:published-datetime> provides date of publish for vulnerability
* <vuln:last-modified-datetime> provides last modification to vulnerability
* <vuln:cvss> list detailed information about impact to effected systems
* <cvss:score> = provides impact score to systems
* <cvss:access-vector> = provides information about how vulnerability is executed
* <cvss:access-complexity> = provides information about difficulty 

## Database Functionality:
* Programs using codenames
* Relate codename to a list of software packages through add program functionality 
* After choosing program set variable or something to include all packages to be utilized
