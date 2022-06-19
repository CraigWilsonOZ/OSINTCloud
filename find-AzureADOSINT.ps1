<#
    .SYNOPSIS
        Attempt to find Azure, AzureAD and M365 endpoints via DNS and API Endpoints. 
    
    .DESCRIPTION
        Script will attempt to find DNS records and tenant ID for a given domain. Once found, it will move onto finding other possible endpoints that are exposed via DNS.

        The script can use Google or Cloud Flair DNS over HTTP to perform lookups.
        
    .PARAMETER DomainName
        The domain you want to search for records on.
    
    .PARAMETER -UseGoogleDNS
        Use Google or Cloud Flair DNS. Set this to true if you want to use Google DNS or false if you want to use CloudFlair DNS.
    
    .PARAMETER -Wordlist
        Word list to be used for attempting to find additional endpoints via DNS lookups.
    
    .EXAMPLE
         Find-AzureADOSINT -DomainName 'domain.com' -UseGoogleDNS $true -verbose
    
    .INPUTS
        String - DomainName
        Boolean - UseGoogleDNS : Defaults to True
    
    .OUTPUTS
        Outputs inforamtion to console
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz

        Release notes:
        v1.0 - Initial release
    #>
param (
    [cmdletbinding()]    
    [Parameter(Mandatory = $true)]
    [string]$DomainName,
    [cmdletbinding()]    
    [string]$Wordlist,
    [cmdletbinding()]    
    [Bool]$UseGoogleDNS = $true
)

#region variables
###############################################################################
#
# Variables
#
###############################################################################

if (!$Wordlist) {
    $Wordlist = "wordlist.txt"
}

# Creating a variable to hold the hash record of found objects
$m365record = $null 
$m365record = @{}

$tenantrecord = $null
$tenantrecord = @{}

$tenantIDrecord = $null
$tenantIDrecord = @{}

$storagerecord = $null
$storagerecord = @{}

$azureadappproxyrecord = $null
$azureadappproxyrecord = @{}

$dynamicsrecord = $null
$dynamicsrecord = @{}

$frontdoorrecord = $null
$frontdoorrecord = @{}

$apirecord = $null
$apirecord = @{}

#endregion

#region M365 DNS Discovery Functions

###############################################################################
#
# M365 DNS Discovery Functions
#
###############################################################################

function Get-M365DomainVerificationTXTLookup {
    <#
    .SYNOPSIS
        Returns the TXT records for the M365 Domain Verification 
    
    .DESCRIPTION
        Function will call a DNS over HTTP to attempt to find M365 TXT and SPF records
    .PARAMETER DomainName
        The domain you want to search for
    
    .EXAMPLE
         get-M365DomainVerificationTXTLookup DomainName 'domain.com'
    
    .INPUTS
        String
    
    .OUTPUTS
        Stores information in the $m365record variable
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz
    #>
    param (
        [cmdletbinding()]    
        [Parameter(Mandatory = $true)]
        [string]$DomainName,
        [cmdletbinding()]    
        [Bool]$UseGoogleDNS
    )

    $TXTData = "" # Creating a variable to hold the TXT data
    if ($UseGoogleDNS) {
        $TXTData = ((Invoke-WebRequest -uri "https://dns.google/resolve?name=$DomainName&type=txt") | convertfrom-json ).Answer
        Write-Verbose "[+] Searching TXT for SPF and Verification record using Google DNS"
    } 
    elseif (!$UseGoogleDNS) {
        $header = @{
            "Accept" = "application/dns-json"
        }
        $TXTData = ((Invoke-WebRequest -uri "https://1.1.1.1/dns-query?name=$DomainName&type=txt" -headers $header)  | convertfrom-json ).Answer
        Write-Verbose "[+] Searching TXT for SPF and Verification tag using Cloud Flair DNS"
    }
    foreach ($TXTRecord in $TXTData) {
        # Look for verfiydomain and spf. This records will tell us if its a cloud service like AD.
        # verfiydomain is used by Microsoft to verify the domain ownership.
        # spf is used by Mail servers to validate who can see as the domain, looking for M365 records.
        if ($TXTRecord.data -match "verifydomain") {
            Write-Verbose "[-]   Found Microsoft 365 Verification domain record: $($TXTRecord.data)"
            $m365record.TXTVerifyDomain = $TXTRecord.data
        }
        if ($TXTRecord.data -match "include:spf.protection.outlook.com") {
            Write-Verbose "[-]   Found Microsoft 365 SPF domain record: $($TXTRecord.data)"
            $m365record.TXTSPF = $TXTRecord.data
        }
    }
}

function Get-M365MXLookup {
    <#
    .SYNOPSIS
        Returns the MX records for the M365 Domain Verification 
    
    .DESCRIPTION
        Function will call a DNS over HTTP to attempt to find mx records matching Microsoft protection record.
    .PARAMETER DomainName
        The domain you want to search for
    
    .EXAMPLE
         get-M365MXLookup -DomainName 'domain.com'
    
    .INPUTS
        String
    
    .OUTPUTS
        Stores information in the $m365record variable
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz
    #>
    param (
        [cmdletbinding()]    
        [Parameter(Mandatory = $true)]
        [string]$DomainName,
        [cmdletbinding()]    
        [Bool]$UseGoogleDNS
    )
    $MXData = "" # Initializing the MXData variable to empty

    if ($UseGoogleDNS) {
        # MX Lookup
        $MXData = ((Invoke-WebRequest -uri "https://dns.google/resolve?name=$DomainToCheck&type=mx") | convertfrom-json ).Answer
        Write-Verbose "[+] Searching MX records M365 Servers using Google DNS"
    }
    elseif (!$UseGoogleDNS) {
        $header = @{
            "Accept" = "application/dns-json"
        }
        # MX Lookup
        $MXData = ((Invoke-WebRequest -uri "https://1.1.1.1/dns-query?name=$DomainName&type=mx" -Headers $header) | convertfrom-json ).Answer
        Write-Verbose "[+] Searching MX records M365 Servers using Cloud Flair DNS"
    }
    foreach ($MXRecord in $MXData) {
        # Look for MX records with known M365 mail servers. If not found the domain maybe using an SMTP relay for protection.
        if ($MXRecord.data -match "mail.protection.outlook.com") {
            Write-Verbose "[-]   Found Microsoft 365 Mail Servers in use: $($MXRecord.data)"
            $m365record.MX = $MXRecord.data
        }
    }
}

function Get-M365AutoDiscoverLookup {
    <#
    .SYNOPSIS
        Returns the AutoDiscover records for the M365 Domain Verification 
    
    .DESCRIPTION
        Function will call a DNS over HTTP to attempt to find AutoDiscover records matching Microsoft protection record.
    .PARAMETER DomainName
        The domain you want to search for
    
    .EXAMPLE
         get-M365AutoDiscoverLookup -DomainName 'domain.com'
    
    .INPUTS
        String
    
    .OUTPUTS
        Stores information in the $m365record variable
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz
    #>
    param (
        [cmdletbinding()]    
        [Parameter(Mandatory = $true)]
        [string]$DomainName,
        [cmdletbinding()]    
        [Bool]$UseGoogleDNS
    )

    $AutoDiscoveryData = "" # Create local variable and set to empty.

    if ($UseGoogleDNS) {

        # Autodiscovery Look Up3
        $AutoDiscoveryData = ((Invoke-WebRequest -uri "https://dns.google/resolve?name=autodiscover.$DomainName&type=CNAME") | convertfrom-json ).answer.data
        Write-Verbose "[+] Searching Exchange Autodiscovery records using Google DNS"
    }
    elseif (!$UseGoogleDNS) {
        $header = @{
            "Accept" = "application/dns-json"
        }
        $AutoDiscoveryData = ((Invoke-WebRequest -uri "https://1.1.1.1/dns-query?name=autodiscover.$DomainName&type=CNAME" -Headers $header) | convertfrom-json ).Answer.data
    }
    Write-Verbose "[+] Searching Exchange Autodiscovery records using Cloud Flair DNS"
    foreach ($AutoDiscoveryRecord in $AutoDiscoveryData) {
        # Look for verfiydomain and spf. This records will tell us if its a cloud service like AD.
        # autodiscover	3600	 IN 	CNAME	autodiscover.outlook.com.
        if ($AutoDiscoveryRecord -match "autodiscover.outlook.com") {
            Write-Verbose "[-]   Found Microsoft 365 Autodiscovery server in use: $($AutoDiscoveryRecord)"
            $m365record.AutoDiscover = $AutoDiscoveryRecord
        }
    }
}

function Get-M365EnterpriseEnrollmentLookup {
    <#
    .SYNOPSIS
        Returns the AutoDiscover records for the M365 Domain Verification 
    
    .DESCRIPTION
        Function will call a DNS over HTTP to attempt to find AutoDiscover records matching Microsoft protection record.
    .PARAMETER DomainName
        The domain you want to search for
    
    .EXAMPLE
         get-M365EnterpriseEnrollmentLookup -DomainName 'domain.com'
    
    .INPUTS
        String
    
    .OUTPUTS
        Stores information in the $m365record variable
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz
    #>
    param (
        [cmdletbinding()]    
        [Parameter(Mandatory = $true)]
        [string]$DomainName,
        [cmdletbinding()]    
        [Bool]$UseGoogleDNS
    )

    $EnterpriseEnrollmentData = "" # Create local variable and set to empty.

    if ($UseGoogleDNS) {

        # EnterpriseEnrollment Look Up
        $EnterpriseEnrollmentData = ((Invoke-WebRequest -uri "https://dns.google/resolve?name=enterpriseenrollment.$DomainName&type=CNAME") | convertfrom-json ).answer.data
        Write-Verbose "[+] Searching Enterprise Enrollment MDM records using Google DNS"
    }
    elseif (!$UseGoogleDNS) {
        $header = @{
            "Accept" = "application/dns-json"
        }
        $EnterpriseEnrollmentData = ((Invoke-WebRequest -uri "https://1.1.1.1/dns-query?name=enterpriseenrollment.$DomainName&type=CNAME" -Headers $header) | convertfrom-json ).Answer.data
        Write-Verbose "[+] Searching Enterprise Enrollment MDM records using Cloud Flair DNS"
    }
    foreach ($EnterpriseEnrollment in $EnterpriseEnrollmentData) {
        # Look for Enterprise Enrollment MDM records.
        if ($EnterpriseEnrollment -match "enterpriseenrollment.manage.microsoft.com") {
            Write-Verbose "[-]   Found Enterprise Enrollment MDM server in use: $($EnterpriseEnrollment)"
            $m365record.EnterpriseEnrollment = $EnterpriseEnrollment

        }
    }
}

function Get-M365EnterpriseRegistrationLookup {
    <#
    .SYNOPSIS
        Returns the AutoDiscover records for the M365 Domain Verification 
    
    .DESCRIPTION
        Function will call a DNS over HTTP to attempt to find AutoDiscover records matching Microsoft protection record.
    .PARAMETER DomainName
        The domain you want to search for
    
    .EXAMPLE
         get-M365EnterpriseRegistrationLookup -DomainName 'domain.com'
    
    .INPUTS
        String
    
    .OUTPUTS
        Stores information in the $m365record variable
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz
    #>
    param (
        [cmdletbinding()]    
        [Parameter(Mandatory = $true)]
        [string]$DomainName,
        [cmdletbinding()]    
        [Bool]$UseGoogleDNS
    )

    $EnterpriseRegistrationData = "" # Create local variable and set to empty.

    if ($UseGoogleDNS) {
        # EnterpriseRegistration Look Up
        $EnterpriseRegistrationData = ((Invoke-WebRequest -uri "https://dns.google/resolve?name=enterpriseregistration.$DomainName&type=CNAME") | convertfrom-json ).answer.data
        Write-Verbose "[+] Searching Enterprise Registration MDM records using Google DNS"
    }
    elseif (!$UseGoogleDNS) {
        $header = @{
            "Accept" = "application/dns-json"
        }
        $EnterpriseRegistrationData = ((Invoke-WebRequest -uri "https://1.1.1.1/dns-query?name=enterpriseregistration.$DomainName&type=CNAME" -Headers $header) | convertfrom-json ).Answer.data
        Write-Verbose "[+] Searching Enterprise Registration MDM records using Cloud Flair DNS"
    }
    foreach ($EnterpriseRegistration in $EnterpriseRegistrationData) {
        # Look for Enterprise Enrollment MDM records.
        if ($EnterpriseRegistration -match "enterpriseregistration.windows.net") {
            Write-Verbose "[-]   Found Enterprise Registration MDM server in use: $($EnterpriseRegistration)"
            $m365record.EnterpriseRegistration = $EnterpriseRegistration
        }
    }
}

function Get-M365MsoidLookup {
    <#
    .SYNOPSIS
        Returns the Msoid records for the M365 Domain Verification 
    
    .DESCRIPTION
        Function will call a DNS over HTTP to attempt to find Msoid records matching Microsoft protection record.
    .PARAMETER DomainName
        The domain you want to search for
    
    .EXAMPLE
         get-M365MsoidLookup -DomainName 'domain.com'
    
    .INPUTS
        String
    
    .OUTPUTS
        Stores information in the $m365record variable
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz
    #>
    param (
        [cmdletbinding()]    
        [Parameter(Mandatory = $true)]
        [string]$DomainName,
        [cmdletbinding()]    
        [Bool]$UseGoogleDNS
    )

    $MsoidData = "" # Create local variable and set to empty.

    if ($UseGoogleDNS) {
        # Msoid Look Up
        $MsoidData = ((Invoke-WebRequest -uri "https://dns.google/resolve?name=msoid.$DomainName&type=CNAME") | convertfrom-json ).answer.data
        Write-Verbose "[+] Searching Msoid records using Google DNS"
    }
    elseif (!$UseGoogleDNS) {
        $header = @{
            "Accept" = "application/dns-json"
        }
        $MsoidData = ((Invoke-WebRequest -uri "https://1.1.1.1/dns-query?name=msoid.$DomainName&type=CNAME" -Headers $header) | convertfrom-json ).Answer.data
        Write-Verbose "[+] Searching Msoid records using Cloud Flair DNS"
    }
    foreach ($Msoid in $MsoidData) {
        # Look for Msoid. This records will tell us if its a cloud service like AD.
        if ($Msoid -match "clientconfig.microsoftonline-p.net") {
            Write-Verbose "[-]   Found Microsoft 365 Application Discovery: $($Msoid)"
            $m365record.Msoid = $Msoid
        }
    }
}

function Get-M365SIPTLSSrvLookup {
    <#
    .SYNOPSIS
        Returns the Msoid records for the M365 Domain Verification 
    
    .DESCRIPTION
        Function will call a DNS over HTTP to attempt to find SIP TLS records matching Microsoft record.
    .PARAMETER DomainName
        The domain you want to search for
    
    .EXAMPLE
         get-M365MsoidLookup -DomainName 'domain.com'
    
    .INPUTS
        String
    
    .OUTPUTS
        Stores information in the $m365record variable
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz
    #>
    param (
        [cmdletbinding()]    
        [Parameter(Mandatory = $true)]
        [string]$DomainName,
        [cmdletbinding()]    
        [Bool]$UseGoogleDNS
    )

    $SIPTLSSrvData = "" # Create local variable and set to empty.

    if ($UseGoogleDNS) {
        # Teams/Skype/Lync SIP Service Record Look Up
        $SIPTLSSrvData = ((Invoke-WebRequest -uri "https://dns.google/resolve?name=_sip._tls.$DomainName&type=SRV") | convertfrom-json ).answer.data
        Write-Verbose "[+] Searching Msoid records using Google DNS"
    }
    elseif (!$UseGoogleDNS) {
        $header = @{
            "Accept" = "application/dns-json"
        }
        $SIPTLSSrvData = ((Invoke-WebRequest -uri "https://1.1.1.1/dns-query?name=_sip._tls.$DomainName&type=SRV" -Headers $header) | convertfrom-json ).Answer.data
        Write-Verbose "[+] Searching Msoid records using Cloud Flair DNS"
    }
    foreach ($SIPTLSSrv in $SIPTLSSrvData) {
        # Look for verfiydomain and spf. This records will tell us if its a cloud service like AD.
        if ($SIPTLSSrv -match "sipdir.online.lync.com") {
            Write-Verbose "[-]   Found Microsoft 365 SIP Discovery: $($SIPTLSSrv)"
            $m365record.SIPTLSSrv = $SIPTLSSrv
        }
    }
}

function Get-M365SIPFederationTLSSrvLookup {
    <#
    .SYNOPSIS
        Returns the Msoid records for the M365 Domain Verification 
    
    .DESCRIPTION
        Function will call a DNS over HTTP to attempt to find SIp Federation records matching Microsoft record.
    .PARAMETER DomainName
        The domain you want to search for
    
    .EXAMPLE
         get-M365SIPFederationTLSSrvLookup -DomainName 'domain.com'
    
    .INPUTS
        String
    
    .OUTPUTS
        Stores information in the $m365record variable
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz
    #>
    param (
        [cmdletbinding()]    
        [Parameter(Mandatory = $true)]
        [string]$DomainName,
        [cmdletbinding()]    
        [Bool]$UseGoogleDNS
    )

    $SIPFederationTLSSrvData = "" # Create local variable and set to empty.

    if ($UseGoogleDNS) {
        # Teams/Skype/Lync SIP Federation Service Record Look Up
        $SIPFederationTLSSrvData = ((Invoke-WebRequest -uri "https://dns.google/resolve?name=_sipfederationtls._tcp.$DomainName&type=SRV") | convertfrom-json ).answer.data
        Write-Verbose "[+] Searching SIP Federation Discovery records using Google DNS"
    }
    elseif (!$UseGoogleDNS) {
        $header = @{
            "Accept" = "application/dns-json"
        }
        $SIPFederationTLSSrvData = ((Invoke-WebRequest -uri "https://1.1.1.1/dns-query?name=_sipfederationtls._tcp.$DomainName&type=SRV" -Headers $header) | convertfrom-json ).Answer.data
        Write-Verbose "[+] Searching SIP Federation Discoveryrecords using Cloud Flair DNS"
    }
    foreach ($SIPFederationTLSSrv in $SIPFederationTLSSrvData) {
        # Look for verfiydomain and spf. This records will tell us if its a cloud service like AD.
        if ($SIPFederationTLSSrv -match "sipfed.online.lync.com") {
            Write-Verbose "[-]   Found Microsoft 365 SIP Federation Discovery: $($SIPFederationTLSSrv)"
            $m365record.SIPFederationTLSSrv = $SIPFederationTLSSrv
        }
    }
}

function Get-M365SIPLookup {
    <#
    .SYNOPSIS
        Returns the SIP records for the M365 Domain Verification 
    
    .DESCRIPTION
        Function will call a DNS over HTTP to attempt to find SIP records matching Microsoft record.
    .PARAMETER DomainName
        The domain you want to search for
    
    .EXAMPLE
         get-M365SIPLookup -DomainName 'domain.com'
    
    .INPUTS
        String
    
    .OUTPUTS
        Stores information in the $m365record variable
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz
    #>
    param (
        [cmdletbinding()]    
        [Parameter(Mandatory = $true)]
        [string]$DomainName,
        [cmdletbinding()]    
        [Bool]$UseGoogleDNS
    )

    $SIPData = "" # Create local variable and set to empty.

    if ($UseGoogleDNS) {
        # SIP Autodiscover Look Up
        $SIPData = ((Invoke-WebRequest -uri "https://dns.google/resolve?name=sip.$DomainName&type=CNAME") | convertfrom-json ).answer.data
        Write-Verbose "[+] Searching SIP records using Google DNS"
    }
    elseif (!$UseGoogleDNS) {
        $header = @{
            "Accept" = "application/dns-json"
        }
        $SIPData = ((Invoke-WebRequest -uri "https://1.1.1.1/dns-query?name=sip.$DomainName&type=CNAME" -Headers $header) | convertfrom-json ).Answer.data
        Write-Verbose "[+] Searching SIP records using Cloud Flair DNS"
    }
    foreach ($SIP in $SIPData) {
        # Look for Enterprise Enrollment MDM records.
        if ($SIP -match "sipdir.online.lync.com") {
            Write-Verbose "[-]   Found SIP server in use: $($SIP)"
            $m365record.SIP = $SIP
        }
    }
}

#endregion

#region Azure Tenant Lookup
###############################################################################
#
# Azure tenant lookup
#
###############################################################################

function Get-AADTenantLookup {
    <#
    .SYNOPSIS
        Returns the AzureAD OpenID records for the Domain 
    
    .DESCRIPTION
        Function will call a Microsoft OpenID endpoint to get domain tenant id.
    .PARAMETER DomainName
        The domain you want to search for
    
    .EXAMPLE
         get-M365SIPLookup -DomainName 'domain.com'
    
    .INPUTS
        String
    
    .OUTPUTS
        Stores information in the $m365record variable
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz
    #>
    param (
        [cmdletbinding()]    
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    # Attempting to find the Azure AD Tenant ID
    try {
        Write-Verbose "[+] Finding M365 AzureAD OpenID-Configuration"
        $tenantrecord = ((Invoke-WebRequest -uri "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration") | convertfrom-json )
        $tenantIDrecord.AzureADTenantID = $tenantrecord.issuer.Split('/')[3]
        Write-Verbose "[+] Found AzureAD Tenant ID For: $($DomainName)"
        Write-Verbose "[-]   TenantID is: $($tenantIDrecord)"
        Write-Verbose $tenantrecord
        $tenantrecord
    }
    catch {
        Write-Verbose "[-]   !!! Unable to find Tenant ID, domain does not have an active subscription !!!"
    }
}

#endregion

#region Endpoint detection
###############################################################################
#
# Azure Storage DNS Discovery
#
###############################################################################

function Get-AzureStorageDiscovery {
    <#
    .SYNOPSIS
        Returns the Azure Storage CNAME records found in the domain dns 
    
    .DESCRIPTION
        Function will call a DNS of HTTP use a wordlist to brute force possible storage accounts.
    .PARAMETER DomainName
        The domain you want to search for
    
    .EXAMPLE
         Get-AzureStorageDiscovery -DomainName 'domain.com'
    
    .INPUTS
        String
    
    .OUTPUTS
        Stores information in the $storagerecord variable
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz
    #>
    param (
        [cmdletbinding()]    
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    $wordlistdata = Get-Content -Path $Wordlist
    $line_number = 1

    Write-Verbose "[+] Searching Azure Storage Account records"
    foreach ($current_line in $wordlistdata) {
        $line_number++
        if ($UseGoogleDNS)
        {
            Write-Verbose "[-]  $line_number  $current_line using GoogleDNS"
            $StorageAccountData = ((Invoke-WebRequest -uri "https://dns.google/resolve?name=$current_line.$DomainName&type=CNAME") | convertfrom-json ).Answer.data
        }
        elseif (!$UseGoogleDNS)
        {
            $header = @{
                "Accept" = "application/dns-json"
            }
            Write-Verbose "[-]  $line_number  $current_line using Cloud Flair DNS"
            $StorageAccountData  = ((Invoke-WebRequest -uri "https://1.1.1.1/dns-query?name=$current_line.$DomainName&type=CNAME" -Headers $header) | convertfrom-json ).Answer.data
        }
    
        foreach ($StorageAccount in $StorageAccountData) {
            # Look for AzureAD Proxy MDM records.
            if ($StorageAccount -match "blob.core.windows.net") {
                Write-Verbose "[-]   Found Azure Storage Account CNAME Record: $current_line.$DomainName"
                Write-Verbose "[-]   -- Azure Storage Account in use: $($StorageAccount)"
                $storagerecord.$current_line = $StorageAccount
            }
        }
       
    }
}

###############################################################################
#
# AzureAD App Proxy Discovery
#
###############################################################################
function Get-AzureADAppProxyDiscovery {
    <#
    .SYNOPSIS
        Returns the AzureAD App Proxy CNAME records found in the domain dns 
    
    .DESCRIPTION
        Function will call a DNS of HTTP use a wordlist to brute force possible AzureAD AppProxy accounts.
    .PARAMETER DomainName
        The domain you want to search for
    
    .EXAMPLE
         Get-AzureADAppProxyDiscovery -DomainName 'domain.com'
    
    .INPUTS
        String
    
    .OUTPUTS
        Stores information in the $azureadappproxyrecord variable
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz
    #>
    param (
        [cmdletbinding()]    
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    $wordlistdata = Get-Content -Path $Wordlist
    $line_number = 1

    Write-Verbose "[+] Searching Azure Storage Account records"
    foreach ($current_line  in $wordlistdata) {
        $line_number++
        if ($UseGoogleDNS)
        {
            Write-Verbose "[-]  $line_number  $current_line using GoogleDNS"
            $AzureADAppProxyData = ((Invoke-WebRequest -uri "https://dns.google/resolve?name=$current_line.$DomainName&type=CNAME") | convertfrom-json ).Answer.data
        }
        elseif (!$UseGoogleDNS)
        {
            $header = @{
                "Accept" = "application/dns-json"
            }
            Write-Verbose "[-]  $line_number  $current_line using Cloud Flair DNS"
            $AzureADAppProxyData  = ((Invoke-WebRequest -uri "https://1.1.1.1/dns-query?name=$current_line.$DomainName&type=CNAME" -Headers $header) | convertfrom-json ).Answer.data
        }
    
        foreach ($AzureADAppProxy in $AzureADAppProxyData) {
            # Look for AzureAD Proxy MDM records.
            if ($AzureADAppProxy -match ".msappproxy.net") {
                Write-Verbose "[-]   Found AzureAD App Proxy CNAME Record: $current_line.$DomainName"
                Write-Verbose "[-]   -- AzureAD App Proxy in use: $($AzureADAppProxy)"
                $azureadappproxyrecord.$current_line = $AzureADAppProxy
            }
        }
       
    }
}

###############################################################################
#
# Dynamics 365 CRM Portal Discovery
#
###############################################################################
function Get-D365PortalDiscovery {
    <#
    .SYNOPSIS
        Returns the D365 Portal CNAME records found in the domain dns 
    
    .DESCRIPTION
        Function will call a DNS of HTTP use a wordlist to brute force possible D365 Portals.
    .PARAMETER DomainName
        The domain you want to search for
    
    .EXAMPLE
         Get-D365PortalDiscovery -DomainName 'domain.com'
    
    .INPUTS
        String
    
    .OUTPUTS
        Stores information in the $dynamicsrecord variable
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz
    #>
    param (
        [cmdletbinding()]    
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    $wordlistdata = Get-Content -Path $Wordlist
    $line_number = 1
    
    Write-Verbose "[+] Searching D365 Portal Account records"
    foreach ($current_line  in $wordlistdata) {
        $line_number++
        if ($UseGoogleDNS)
        {
            Write-Verbose "[-]  $line_number  $current_line using GoogleDNS"
            $DynamicsData = ((Invoke-WebRequest -uri "https://dns.google/resolve?name=$current_line.$DomainName&type=CNAME") | convertfrom-json ).Answer.data
        }
        elseif (!$UseGoogleDNS)
        {
            $header = @{
                "Accept" = "application/dns-json"
            }
            Write-Verbose "[-]  $line_number  $current_line using Cloud Flair DNS"
            $DynamicsData  = ((Invoke-WebRequest -uri "https://1.1.1.1/dns-query?name=$current_line.$DomainName&type=CNAME" -Headers $header) | convertfrom-json ).Answer.data
        }
    
        foreach ($Dynamics in $DynamicsData) {
            # Look for Dynamics records.
            if ($Dynamics -match ".microsoftcrmportals.com") {
                Write-Verbose "[-]   Found D365 Portal CNAME Record: $current_line.$DomainName"
                Write-Verbose "[-]   -- D365 Portal in use: $($Dynamics)"
                $dynamicsrecord.$current_line = $Dynamics
            }
        }
       
    }
}

###############################################################################
#
# Azure API Manager Discovery
#
###############################################################################
function Get-AzureAPIDiscovery {
    <#
    .SYNOPSIS
        Returns the API CNAME records found in the domain dns 
    
    .DESCRIPTION
        Function will call a DNS of HTTP use a wordlist to brute force possible Azure API manager.
    
    .PARAMETER DomainName
        The domain you want to search for
    
    .EXAMPLE
         Get-AzureAPIDiscovery -DomainName 'domain.com'
    
    .INPUTS
        String
    
    .OUTPUTS
        Stores information in the $apisrecord variable
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz
    #>
    param (
        [cmdletbinding()]    
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    $wordlistdata = Get-Content -Path $Wordlist
    $line_number = 1

    Write-Verbose "[+] Searching Azure API Manager Account records"
    foreach ($current_line  in $wordlistdata) {
        $line_number++
        if ($UseGoogleDNS)
        {
            Write-Verbose "[-]  $line_number  $current_line using GoogleDNS"
            $APIData = ((Invoke-WebRequest -uri "https://dns.google/resolve?name=$current_line.$DomainName&type=CNAME") | convertfrom-json ).Answer.data
        }
        elseif (!$UseGoogleDNS)
        {
            $header = @{
                "Accept" = "application/dns-json"
            }
            Write-Verbose "[-]  $line_number  $current_line using Cloud Flair DNS"
            $APIData  = ((Invoke-WebRequest -uri "https://1.1.1.1/dns-query?name=$current_line.$DomainName&type=CNAME" -Headers $header) | convertfrom-json ).Answer.data
        }
    
        foreach ($api in $APIData) {
            # Look for Dynamics records.
            if ($api -match ".azure-api.net") {
                Write-Verbose "[-]   Found Azure API Manager CNAME Record: $current_line.$DomainName"
                Write-Verbose "[-]   -- Azure API Manager in use: $($api)"
                $apirecord.$current_line = $api
            }
        }
       
    }
}


###############################################################################
#
# Azure Front Door Discovery
#
###############################################################################
function Get-FrontDoorDiscovery {
    <#
    .SYNOPSIS
        Returns the Front Door CNAME records found in the domain dns 
    
    .DESCRIPTION
        Function will call a DNS of HTTP use a wordlist to brute force possible front door manager.
    
    .PARAMETER DomainName
        The domain you want to search for
    
    .EXAMPLE
         Get-FrontDoorDiscovery -DomainName 'domain.com'
    
    .INPUTS
        String
    
    .OUTPUTS
        Stores information in the $dynamicsrecord variable
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz
    #>
    param (
        [cmdletbinding()]    
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    $wordlistdata = Get-Content -Path $Wordlist
    $line_number = 1

    Write-Verbose "[+] Searching Azure Front Door Account records"
    
    foreach ($current_line  in $wordlistdata) {
        $line_number++
        if ($UseGoogleDNS)
        {
            Write-Verbose "[-]  $line_number  $current_line using GoogleDNS"
            $FrontDoorData = ((Invoke-WebRequest -uri "https://dns.google/resolve?name=$current_line.$DomainName&type=CNAME") | convertfrom-json ).Answer.data
        }
        elseif (!$UseGoogleDNS)
        {
            $header = @{
                "Accept" = "application/dns-json"
            }
            Write-Verbose "[-]  $line_number  $current_line using Cloud Flair DNS"
            $FrontDoorData  = ((Invoke-WebRequest -uri "https://1.1.1.1/dns-query?name=$current_line.$DomainName&type=CNAME" -Headers $header) | convertfrom-json ).Answer.data
        }
    
        foreach ($FrontDoor in $FrontDoorData) {
            # Look for Azure FrontDoor records.
            if ($FrontDoor -match ".azurefd.net") {
                Write-Verbose "[-]   Found Front Door CNAME Record: $current_line.$DomainName"
                Write-Verbose "[-]   -- Azure Front Door in use: $($FrontDoor)"
                $frontdoorrecord.$current_line = $FrontDoor
            }
        }
       
    }
}

#endregion

#region Run-LogicChecks
###############################################################################
#
# Run Logic to Check for possibe issues
#
###############################################################################
function Out-LogicChecks {
    <#
    .SYNOPSIS
        Attempt to detect issues or key points for investigation 
    
    .DESCRIPTION
        Function will check data capture to identifiy what may be a possible issue or access point.
    
    .EXAMPLE
         Run-LogicChecks
    
    .INPUTS
        String
    
    .OUTPUTS
        Outputs to Console
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz
    #>
    param (
        [cmdletbinding()]    
        #[Parameter(Mandatory = $true)]
        [string]$DomainName
    )

    Write-Output "[+] Checking for possible issues"
    If ($m365record.TXTSPF.count -gt 0 -and $m365record.MX.count -eq 0 ) {
        Write-Output "[-]  SPF record found but no MX record. <- Outbound mail only, MX redirecting to another services not M365."
    }else{
        Write-Output "[-]  SPF record found with MX record. Mail handled by M365 Exchange Online."
    }

    If ($m365record.EnterpriseRegistration.count -gt 0) {
        Write-Output "[-]  Mobile Device Management records found. Systems may have devices enrolled or registered."
        Write-Output "[-]  Mobile Device Management records found. Systems may have Microsoft Defender on devices."
    }else{
        Write-Output "[-]  No Device Management detected, Devices are not managed by this domain, Microsoft Defender may not be used."
    }

    If ($azureadappproxyrecord.count -gt 0) {
        Write-Output "[-]  Azure AD Proxy found, these can publish internal web sites to the internet."
    }
    If ($storagerecord.count -gt 0) {
        Write-Output "[-]  Azure Storage Accounts found, these can publish SMB3, CIFS shares or blob data to the internet."
    }
    If ($dynamicsrecord.count -gt 0) {
        Write-Output "[-]  Dynamics 365 Portal found, Dynamic portal exposed to the internet."
    }
    If ($apirecord.count -gt 0) {
        Write-Output "[-]  Azure API Manager found, Published APIs from the companies Azure Tenant which are exposed to the internet."
    }
    If ($frontdoorrecord.count -gt 0) {
        Write-Output "[-]  Azure Front Door found, Used to publish web sites, includes a Web Application Firewall. Should be blocking and recording to access the site."
    }
}
#endregion
#region Main Loop
###############################################################################
#
# Main Loop
#
###############################################################################

# Performing DNS checks for domain records to see what has been configured for M365.
Write-Output "---------------------------------------------------------------------------------------------------------------------"
Write-Output " Find-AzureADOSInt attempts to find AzureAD and M365 Domain information located in public DNS and endpoints"
Write-Output "---------------------------------------------------------------------------------------------------------------------"
Write-Output "Domain to check: $DomainName"
# Exchange Online DNS Records
Write-Output "[+] Searching DNS for Exchange Online records"
Get-M365DomainVerificationTXTLookup("$DomainName")
Get-M365MXLookup("$DomainName")
Get-M365AutoDiscoverLookup("$DomainName")
# Mobile Device Management DNS Records
Write-Output "[+] Searching DNS for Mobile Device Management records"
Get-M365EnterpriseEnrollmentLookup("$DomainName")
Get-M365EnterpriseRegistrationLookup("$DomainName")
get-M365MsoidLookup("$DomainName")
# Teams DNS Records
Write-Output "[+] Searching DNS for Teams records"
Get-M365SIPLookup("$DomainName")
Get-M365SIPFederationTLSSrvLookup("$DomainName")
Get-M365SIPTLSSrvLookup("$DomainName")
Write-Output ""
Write-Output "---------------------------------------------------------------------------------------------------------------------"
Write-Output " Records found for $DomainName"
Write-Output ""
If ($m365record.Count -gt 0) { $m365record | Write-Output }
Write-Output ""
Write-Output "---------------------------------------------------------------------------------------------------------------------"
Write-Output "[+] Searching AzureAD TenantID Records for $DomainName"
get-AADTenantLookup("$DomainName")
Write-Output " Records found for $DomainName"
Write-Output ""
If ($tenantrecord.issuer -ne "") { $tenantIDrecord } else { Write-Output "[-]   No AzureAD TenantID Records found for $DomainName" }
Write-Output ""
Write-Output "---------------------------------------------------------------------------------------------------------------------"
Write-Output "[+] Searching Azure Storage Records for $DomainName"
Get-AzureStorageDiscovery("$DomainName")
Write-Output " Records for Azure storage accounts found for $DomainName"
Write-Output ""
If ($storagerecord.count -gt 0) { $storagerecord | Write-Output } else { Write-Output "[-]   No Azure Storage Accounts found for $DomainName" }
Write-Output ""
Write-Output "---------------------------------------------------------------------------------------------------------------------"
Write-Output "[+] Searching AzureAD App Proxy Records for $DomainName"
Get-AzureADAppProxyDiscovery("$DomainName")
Write-Output " Records for AzureAD App Proxy found for $DomainName"
Write-Output ""
If ($azureadappproxyrecord.count -gt 0) { $azureadappproxyrecord | Write-Output } else { Write-Output "[-]   No AzureAD App Porxy records found for $DomainName" }
Write-Output ""
Write-Output "---------------------------------------------------------------------------------------------------------------------"
Write-Output "[+] Searching D365 Portal Records for $DomainName"
Get-D365PortalDiscovery("$DomainName")
Write-Output " Records for D365 Portal found for $DomainName"
Write-Output ""
If ($dynamicsrecord.count -gt 0) { $dynamicsrecord | Write-Output } else { Write-Output "[-]   No D365 Portal records found for $DomainName" }
Write-Output ""
Write-Output "---------------------------------------------------------------------------------------------------------------------"
Write-Output "[+] Searching Azure Front Door Records for $DomainName"
Get-FrontDoorDiscovery("$DomainName")
Write-Output " Records for Azure Front Door found for $DomainName"
Write-Output ""
If ($frontdoorrecord.count -gt 0) { $frontdoorrecord | Write-Output } else { Write-Output "[-]   No Azure Front Door records found for $DomainName" }
Write-Output ""
Write-Output "---------------------------------------------------------------------------------------------------------------------"
Write-Output "[+] Searching Azure API Manager Records for $DomainName"
Get-AzureAPIDiscovery("$DomainName")
Write-Output " Records for Azure API Manager found for $DomainName"
Write-Output ""
If ($apirecord.count -gt 0) { $apirecord | Write-Output } else { Write-Output "[-]   No Azure API Manager records found for $DomainName" }
Write-Output ""
Write-Output "---------------------------------------------------------------------------------------------------------------------"

Out-LogicChecks
#endregion