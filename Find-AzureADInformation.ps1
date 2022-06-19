<#
    .SYNOPSIS
        Script to report on current AzureAD configuration items. 
    
    .DESCRIPTION
        Script will use PowerShell commandlets to report AzureAD configuration items. 
        It has been tested with PowerShell version 5.1.22000.653. Will not work with PowerShell 7 or higher.
        
    .PARAMETER DomainName
        The domain you want to search for records on.
    
    .EXAMPLE
         Find-AzureADInformation -DomainName 'domain.com'
    
    .INPUTS
        String - DomainName
        
    .OUTPUTS
        Outputs inforamtion to console and saves json files with raw data.
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz

        Release notes:
        v1.0 - Initial release 20/06/2022
    #>
    param (
      [cmdletbinding()]    
      [Parameter(Mandatory = $true)]
      [string]$DomainName
  )
  
#region variables
###############################################################################
#
# Variables
#
###############################################################################

# Variable to store prefix of report file name
$ReportPreFix = ""

# Tenant Information used for testing connection
$tenantinforation = $null

#endregion

#region AzureADConnect

###############################################################################
#
# Connections to AzureAD.
#
###############################################################################

# Attempt to connect by first checking if we have a connection then compare 
# against the required domain. If not connected or wrong domain relogin.
try
{
  $tenantinforation = Get-AzureADTenantDetail -ErrorAction 'silentlycontinue'

  if ($tenantinforation.VerifiedDomains |Where-Object {$_.Name -eq $DomainName})
  {
    Write-Output "Connected to domain tenant: $($DomainName)"
    $ReportPreFix = (Get-AzureADCurrentSessionInfo).TenantDomain  
  }
  else
  {
    # Connect with Global Reader Account or higher
    Write-Output "Connecting to domain tenant: $($DomainName)"
    Write-Output "Sign-in Window will be displayed, please sign in there."
    Connect-AzureAD -Domain $Domain
    $ReportPreFix = (Get-AzureADCurrentSessionInfo).TenantDomain  
  }
}
catch
{
    # Connect with Global Reader Account or higher
    Write-Output "Connecting to domain tenant: $($DomainName)"
    Write-Output "Sign-in Window will be displayed, please sign in there."
    Connect-AzureAD -Domain $DomainName
    $ReportPreFix = (Get-AzureADCurrentSessionInfo).TenantDomain  
}

#endregion

###############################################################################
#
# Section to capture AzureAD information, output and create reports.
#
###############################################################################

#region AzureInformation

# get Azure AD Roles for Global Administrator and its members
$role = Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq 'Global Administrator'}
$GAMembers = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId

# Create a display of the results
Write-Output "Listing Global Administrator members"
$GAMembers | Select-Object ObjectId,DisplayName,UserPrincipalName,UserType | Format-Table -AutoSize
# Create a report fot the service account
$GAMembers | Select-Object ObjectId,DisplayName,UserPrincipalName,UserType | ConvertTo-Json -depth 100 | Out-File ".\$($ReportPreFix)_GAMembers.json"

# Check to see if GA has more then 1 users. If we find more then one user, there could be addtion accounts that do not requirement the permission
# or a service account. Checking to see if the addtion accounts are serivce principals, aka service accounts.
if ($GAMembers.Count -gt 1) {
  Write-Output "Found more then 1 member, checking for service principal. This is problem should be no more then 2 administrations. Checking for Service Principal accounts in GLobal Administrations."
  foreach ($member in $GAMembers) {
    # Next cehcking for service principals.
    $servicePrincipal = $null
    try 
    {
      # The Get command will create an error for each account that is not a serivce principal, wrapping in try catch me to protect the script and mask the error output.
      $servicePrincipal = Get-AzureADServicePrincipal -ObjectId $member.ObjectId
    }
    catch
    {
      Write-Verbose "No service principal found for $($member.ObjectId)"
    }
    if ($servicePrincipal) {
      # Output services principals found to console.
      Write-Output "Found service principal in Global Administrations. This means an application has full access to AzureAD and possible Azure."
      Write-Output "---------------------------------------------------------------------------"
      $servicePrincipal | Format-Table -AutoSize
      Write-Output "---------------------------------------------------------------------------"
    }
}
}

# Creating a list of devices registred in AzureAD
Write-Output "Listing Devices registered in AzureAD"
$AADDevices = Get-AzureADDevice |Select-Object DisplayName,ProfileType,DeviceOSType,DeviceOSVersion,DeviceTrustType,IsCompliant,IsManaged, AccountEnabled
$AADDevices | Format-Table -AutoSize
# Creating output and saving to json file
$AADDevices | ConvertTo-Json -depth 100 | Out-File ".\$($ReportPreFix)_AADDevices.json"

# Creating a list of users registred in AzureAD
Write-Output "Listing Users registered in AzureAD"
$AADUsers = Get-AzureADUser | Select-Object DisplayName,UserPrincipalName, UserType, AccountEnabled, PasswordPolicies, Mail 
$AADUsers | Format-Table -AutoSize
# Creating output and saving to json file
$AADUsers | ConvertTo-Json -depth 100 | Out-File ".\$($ReportPreFix)_AADUsers.json"

# Checking for Disabled Password Expiration Policy and creating output
If (($AADUsers | Where-Object {$_.PasswordPolicies -eq "DisablePasswordExpiration"}).count -gt 0)
{
  Write-Output "---------------------------------------------------------------------------"
  Write-Output "Found Disabled Password Expiration Policy"
  $AADUsers | Where-Object {$_.PasswordPolicies -eq "DisablePasswordExpiration"} | Format-Table -AutoSize
  Write-Output "---------------------------------------------------------------------------"
}

# Creating a list of Service Principals in AzureAD
Write-Output "Listing Service Principals registered in AzureAD not published by Microsoft"
$AzureADServicePrincipalList = Get-AzureADServicePrincipal | Where-Object {$_.PublisherName -ne "Microsoft Services"} | Select-Object ObjectId,ObjectType,AccountEnabled,AppDisplayName,AppId,AppRoleAssignmentRequired,DisplayName,PublisherName,ServicePrincipalType
$AzureADServicePrincipalList | Format-Table -AutoSize
# Creating output and saving to json file
$AzureADServicePrincipalList | ConvertTo-Json -depth 100 | Out-File ".\$($ReportPreFix)_AzureADServicePrincipalList.json"

# Creating a list of Conditional Access Polices in AzureAD
Write-Output "Listing Conditional Accecss Policies registered in AzureAD"
$AzureADMSConditionalAccessPolicy = Get-AzureADMSConditionalAccessPolicy | Select-Object Id,DisplayName,State,Conditions, GrantControls
$AzureADMSConditionalAccessPolicy | Format-Table -AutoSize
# Creating output and saving to json file
$AzureADMSConditionalAccessPolicy | ConvertTo-Json -depth 100 | Out-File ".\$($ReportPreFix)_AzureADMSConditionalAccessPolicy.json"

# Checking for MFA Policy, if found may limit attackers access to AzureAD
If (($AzureADMSConditionalAccessPolicy | Where-Object {$_.GrantControls.BuiltInControls -eq "Mfa"}).count -gt 0)
{
  Write-Output "---------------------------------------------------------------------------"
  Write-Output "Found MFA Policy"
  $AzureADMSConditionalAccessPolicy | Where-Object {$_.GrantControls.BuiltInControls -eq "Mfa"} | Select-Object Id,DisplayName,State  | Format-Table -AutoSize
  Write-Output "---------------------------------------------------------------------------"
}

# Removed issue with PowerShell Module, will need to redo with API.
#Write-Output "Listing Named Locations registered in AzureAD"
#$AzureADMSNamedLocationPolicy = Get-AzureADMSNamedLocationPolicy | select Id,DisplayName,IsTrusted,IpRanges
#$AzureADMSNamedLocationPolicy | ft -AutoSize
#$AzureADMSNamedLocationPolicy | ConvertTo-Json -depth 100 | Out-File ".\$($ReportPreFix)_AzureADMSNamedLocationPolicy.json"

# Creating a list of domains and federation registred in AzureAD
Write-Output "Listing Domains registered in AzureAD"
$AzureADDomain = Get-AzureADDomain | Select-Object Name,AuthenticationType,IsAdminManaged,IsVerified,IsDefault
$AzureADDomain | Format-Table -AutoSize
# Creating output and saving to json file
$AzureADDomain | ConvertTo-Json -depth 100 | Out-File ".\$($ReportPreFix)_AzureADDomain.json"

# Checking for Federation Authentication and possible link back to on-premise
If (($AzureADDomain | Where-Object {$_.AuthenticationType -eq "Federated"}).count -gt 0)
{
  Write-Output "---------------------------------------------------------------------------"
  Write-Output "Domains with Authentication Type of Federated are linked to On-Premise Active Directory"
  $AzureADDomain | Where-Object {$_.AuthenticationType -eq "Federated"} | Format-Table -AutoSize
  Write-Output "---------------------------------------------------------------------------"
}
else {
  Write-Output "Domains are all cloud only domains"
}

#endregion

