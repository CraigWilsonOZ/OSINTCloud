# OSINT and Cloud Services discovery tools

The purpose of the code is to capture information about Azure/Microsoft 365 tenant cloud services that an attacker can use to gain access to systems of information. The developed code can be used to find possible attack areas against a tenant. Systems administrators often have miss-configure systems and Service Accounts on-premises; this is the same for a cloud service. In the course labs, we used tools like NMAP and ENUM4LINUX to scan environments and SHERLOCK to perform Open-Source Intelligence (OSINT) scans.

The tool captures information using Open-Source Intelligence to collect from DNS servers and Microsoft Azure AD PowerShell for authenticated information. It was created for security analysts to understand what is configured and the possible endpoint of an attack.

The scripts are broken into three main files.

1. Setup-PowerShellModule.ps1 -> Used to configure PowerShell Modules
2. Find-AzureADOSint.ps1 -> Used to capture public information (OSINT)
3. Find-AzureADInformation.ps1 -> Used to capture authenticated information (Enumeration)

The tool has been developed in Microsoft PowerShell version 5. It used Microsoft AzureAD PowerShell module version 2.0.2. The DNS queries are performed over HTTP using Google  and Cloudflare's DNS over HTTP services.

## Configuration and Execution

The tool uses Microsoft PowerShell and will require additional PowerShell modules.

The script file "Setup-PowerShellModule.ps1" will install the required modules. To execute, run the following commands.

- Download the code from <https://github.com/CraigWilsonOZ/OSINTCloud> using git clone or copy. Make sure the files are unblocked
- Open a Windows Terminal PowerShell as Administrator
- Confirm PowerShell version is 5.1.x; type the following

```powershell
$PSversionTable
```

- Type the following command to execute the install

```powershell
Setup-PowerShellModule.ps1
```

- Accept the NuGet provider and Untrusted Repository prompts to install the modules

"Find-AzureADOSint.ps1" uses PowerShell to call DNS over HTTP. The script uses the following options.

Option Description

```bash
-domainname # The domain name that will be scanned
-usegoogledns # Flag to use Google DNS if true and CloudFlare if false
-wordlist # Use to supply a wordlist; if not supplied, the include wordlist.txt file is used.
```

To run the script, type the following commands.

- Open a Windows Terminal PowerShell as Administrator (Microsoft, 2022)
- Navigate to the downloaded code
- Type the following command, replacing "domain.com" with your "domain"

```powershell
.\find-AzureADOSINT.ps1 -DomainName domain.com -Wordlist .\wordlist.txt -UseGoogleDNS $true
```

The code will scan DNS for available records, then brute force checks using "wordlist" for the following Azure Services:

- Azure API Manager (Publishing API endpoint to the Internet)
- Azure Front Door (Web Application Firewall and Load balancer publishing sites)
- Azure Storage Accounts (Storage blog account publishing SMB/CIFS Shares and data)
- AzureAD App Proxy (Publishing internal websites to the Internet)

"Find-AzureADInformation.ps1" uses AzureAD PowerShell and requires a Global Administrator account due to the scans performed. The script uses the following options.

Option Description

```bash
-domainname # A domain name that will be scanned
```

To run the script, type the following commands.

- Open a Windows Terminal PowerShell as Administrator (Microsoft, 2022)
- Navigate to the downloaded code
- Type the following command, replacing "domain.com" with your "domain"
Note: A login Windows will appear and may be hidden behind the Terminal.

```powershell
.\find-AzureADInformation.ps1 -DomainName domain.com
```

The script outputs information to JSON files and reports issues it finds, as shown in Figure 2.

The scripts use PowerShell 5.1; this was chosen due to a limitation on the AzureAD PowerShell. The code will need to use Microsoft Azure Graph API to enable the code to run on the current PowerShell 7.

