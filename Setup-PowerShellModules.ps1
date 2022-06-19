<#
    .SYNOPSIS
        Script to configure PowerShell Modules 
    
    .DESCRIPTION
        Script will download and import the required modules
        
    .EXAMPLE
         set-PowerShellModules
    
    .INPUTS
        None
        
    .OUTPUTS
        PowerShell Modules for scripts will be installed.
    
    .NOTES
        Author:  Craig Wilson
        Website: https://github.com/craigwilsonoz
        Twitter: @craigwilsonoz

        Release notes:
        v1.0 - Initial release 20/06/2022
    #>

# Output PowerShell versions
$PSVersionTable

Install-Module AzureAD -Scope AllUsers
Import-Module AzureAD
