param(
    [switch]$Populate,
    [switch]$Deploy,
    [switch]$Revert,
    [switch]$AuditSACLs,
    [switch]$GetObjectPropertiesGuids,
    [string]$Config,
    [string]$Output,
    [string]$Owner,
    [string]$CanaryOrganizationalUnit,
    [string]$ParentOU
)

# Import required modules
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module "$ScriptPath\modules\Common.psm1" -Force
Import-Module "$ScriptPath\modules\Utilities.psm1" -Force
Import-Module "$ScriptPath\modules\Configuration.psm1" -Force
Import-Module "$ScriptPath\modules\Deploy.psm1" -Force
Import-Module "$ScriptPath\modules\Remove.psm1" -Force
Import-Module "$ScriptPath\modules\Audit.psm1" -Force

# Create output directory if it doesn't exist
$OutputDir = Join-Path $ScriptPath "output"
if (-not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory | Out-Null
    Write-Host "[*] Created output directory: $OutputDir"
}

# If no explicit paths provided, set default paths in output directory
if ($Populate.IsPresent -and -not $Config) {
    $Config = Join-Path $OutputDir "adcanaries_config.json"
}

if (($Deploy.IsPresent -or $GetObjectPropertiesGuids.IsPresent) -and -not $Output) {
    $Output = Join-Path $OutputDir "adcanaries_output.csv"
}

# Display banner
DisplayCanaryBanner

# Add this function directly to ADCanaries.ps1
function CreateCanaryOUDirectly {
    param($CanaryGroupName, $ParentOU)
    
    $DistinguishedName = "OU=$CanaryGroupName,$ParentOU"
    if (Get-ADOrganizationalUnit -Filter {DistinguishedName -eq $DistinguishedName}) {
        Write-Host "[-] Canary OU already existed : $DistinguishedName"
        return $true
    }
    
    try {
        Write-Host "DIAGNOSTIC: Creating OU directly with New-ADOrganizationalUnit"
        New-ADOrganizationalUnit -Name $CanaryGroupName -Path $ParentOU -Description "[ADCanaries] Direct OU Creation"
        Write-Host "[*] Canary OU created directly: $DistinguishedName"
        return $true
    }
    catch {
        Write-Host "[!] Error creating OU: $_"
        return $false
    }
}

# Validate arguments & execute functions
if($Populate.IsPresent){
  CheckParameter $Config
  CheckParameter $ParentOU
  CheckParameter $Owner
    CheckParameter $CanaryOrganizationalUnit
    
    # First create the OU directly
    $success = CreateCanaryOUDirectly -CanaryGroupName $CanaryOrganizationalUnit -ParentOU $ParentOU
    if ($success) {
        # Then proceed with the normal configuration
        PopulateConf -Config $Config -ParentOU $ParentOU -Owner $Owner -CanaryGroupName $CanaryOrganizationalUnit
    }
} 
elseif($Deploy.IsPresent){
  CheckParameter $Config
  CheckParameter $Output
  DeployCanaries -Config $Config -Output $Output
} 
elseif($Revert.IsPresent){
  CheckParameter $Config
  DestroyCanaries -Config $Config
} 
elseif($AuditSACLs.IsPresent){
  CheckSACLs
} 
elseif($GetObjectPropertiesGuids.IsPresent){
  CheckParameter $Output
  GetObjectPropertiesGuids -Output $Output
}
else{
  DisplayHelpAndExit
}

Write-Host "`n"
