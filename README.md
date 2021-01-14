# RisingSun

RisingSun is a SUNBURST C2 decoder and Host ID encoder which can be used to attribute C2 domains to specific SolarWinds servers when network telemetry is unavailable. Our intent is to provide organizations without DNS logs (or other network-based logs) an option for validating the scope of compromise by the SolarWinds Orion backdoor. Use this tool if you:
- Have received a list of C2 domains from a major vendor claiming they originated from your network
- Lack the requisite network telemetry (DNS logs, HTTP logs, etc) to identify which hosts communicated with each C2 domain 
- Still have the compromised SolarWinds Orion servers (or backups) available 

RisingSun requires two files as input. The first must contain a comma-separated list of host information that SUNBURST uses to generate unique host IDs, plus the hostname of the server. These values are:
1. MAC address of the primary network interface
2. AD domain used by the host
3. Registry value stored in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid
4. Hostname (used by RisingSun for identification purposes)

Thus, the file containing host information should have the following format:

`
AF:AF:AF:AF:AF:AF,lab.internal.corp, xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,solarwinds-01
BF:BF:BF:BF:BF:BF,lab.internal.corp, xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,solarwinds-02
`

The second input file is simply a list of C2 domains, ideally those attribute to your organization.

RisingSun will output the results to a CSV file named "results.csv", as well as display any matches in the terminal.

Usage syntax is as follows:

- Windows
`RisingSun.exe <path to host info file> <path to domains file>`

- Uncompiled:
`go run RisingSun.go <path to host info file> <path to domains file>`
