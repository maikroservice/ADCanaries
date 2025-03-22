function DefaultCanaries {
    param($ConfigJsonObject, $ParentOU)

    $NewCanary = @{}
    $NewCanary.Name = "CanaryUser"
    $NewCanary.Type = "user"
    $NewCanary.Path = "$ParentOU"
    $NewCanary.Description = "[ADCanaries] Default Canary user -- change it"
    $NewCanary.OtherAttributes = @{}
    $NewCanary.ProtectedFromAccidentalDeletion = 1
    $ConfigJsonObject.Canaries.Add($NewCanary) > $null

    $NewCanary = @{}
    $NewCanary.Name = "CanaryComputer"
    $NewCanary.Type = "computer"
    $NewCanary.Path = "$ParentOU"
    $NewCanary.Description = "[ADCanaries] Default Canary computer -- change it"
    $NewCanary.OtherAttributes = @{}
    $NewCanary.ProtectedFromAccidentalDeletion = 1
    $ConfigJsonObject.Canaries.Add($NewCanary) > $null

    $NewCanary = @{}
    $NewCanary.Name = "CanaryGroup"
    $NewCanary.Type = "group"
    $NewCanary.Path = "$ParentOU"
    $NewCanary.Description = "[ADCanaries] Default Canary group -- change it"
    $NewCanary.OtherAttributes = @{}
    $NewCanary.ProtectedFromAccidentalDeletion = 1
    $ConfigJsonObject.Canaries.Add($NewCanary) > $null

    $NewCanary = @{}
    $NewCanary.Name = "CanaryOU"
    $NewCanary.Type = "organizationalUnit"
    $NewCanary.Path = "$ParentOU"
    $NewCanary.Description = "[ADCanaries] Default Canary OU -- change it"
    $NewCanary.OtherAttributes = @{}
    $NewCanary.ProtectedFromAccidentalDeletion = 1
    $ConfigJsonObject.Canaries.Add($NewCanary) > $null

    $NewCanary = @{}
    $NewCanary.Name = "CanaryPolicy"
    $NewCanary.Type = "domainPolicy"
    $NewCanary.Path = "$ParentOU"
    $NewCanary.Description = "[ADCanaries] Default Canary policy -- change it"
    $NewCanary.OtherAttributes = @{}
    $NewCanary.ProtectedFromAccidentalDeletion = 1
    $ConfigJsonObject.Canaries.Add($NewCanary) > $null

    $NewCanary = @{}
    $NewCanary.Name = "CanaryTemplate"
    $NewCanary.Type = "pKICertificateTemplate"
    $NewCanary.Path = "$ParentOU"
    $NewCanary.Description = "[ADCanaries] Default Canary certificate template -- change it"
    $NewCanary.OtherAttributes = @{}
    $NewCanary.ProtectedFromAccidentalDeletion = 1
    $ConfigJsonObject.Canaries.Add($NewCanary) > $null
}

function PopulateConf {
    param($Config, $ParentOU, $CanaryGroupName, $Owner, $ADGroups)
    ValidateAction

    # Create the configuration object
    $ConfigJsonObject = @{}
    $ConfigJsonObject.Configuration = @{}
    
    # Set the CanaryOwner
    $ConfigJsonObject.Configuration.CanaryOwner = $Owner

    # Check if ParentOU exists
    if(-not (Get-ADObject -Filter {DistinguishedName -eq $ParentOU})) {
        Write-Host "[!] $ParentOU not found in AD Objects please provide a valid Parent OU"
        exit $false
    }
    
    # Overwrite output file
    if (Test-Path $Config) {
        Remove-Item -Path $Config -ErrorAction SilentlyContinue
    }

    # Configure the Canary OU
    $ConfigJsonObject.Configuration.CanaryOU = @{}
    $ConfigJsonObject.Configuration.CanaryOU.Name = "$CanaryGroupName"
    $ConfigJsonObject.Configuration.CanaryOU.Type = "organizationalUnit"  # Using the correct type
    $ConfigJsonObject.Configuration.CanaryOU.Path = "$ParentOU"
    $ConfigJsonObject.Configuration.CanaryOU.OtherAttributes = @{}
    $ConfigJsonObject.Configuration.CanaryOU.Description = "[ADCanaries] Default OU"
    $ConfigJsonObject.Configuration.CanaryOU.ProtectedFromAccidentalDeletion = 1

    # DIAGNOSTIC: Print out the exact OU configuration
    Write-Host "DIAGNOSTIC: CanaryOU Type = $($ConfigJsonObject.Configuration.CanaryOU.Type)"

    # Set the path for canaries within the OU
    $CanariesPath = "OU=$CanaryGroupName,$ParentOU"

    # Configure the Canary Group
    $ConfigJsonObject.Configuration.CanaryGroup = @{}
    $ConfigJsonObject.Configuration.CanaryGroup.Name = "$CanaryGroupName"
    $ConfigJsonObject.Configuration.CanaryGroup.Type = "group"
    $ConfigJsonObject.Configuration.CanaryGroup.Path = "$CanariesPath"
    $ConfigJsonObject.Configuration.CanaryGroup.OtherAttributes = @{}
    $ConfigJsonObject.Configuration.CanaryGroup.Description = "[ADCanaries] Default group"
    $ConfigJsonObject.Configuration.CanaryGroup.ProtectedFromAccidentalDeletion = 1

    # Initialize the Canaries array
    $ConfigJsonObject.Canaries = New-Object System.Collections.ArrayList

    # Add default canaries
    DefaultCanaries -ConfigJsonObject $ConfigJsonObject -ParentOU $CanariesPath
    
    # Write the configuration to file
    $ConfigJson = $ConfigJsonObject | ConvertTo-Json -Depth 20
    Set-Content -Path $Config -Value $ConfigJson
    
    # DIAGNOSTIC: Load the config file back to verify what was written
    $LoadedConfig = Get-Content -Path $Config | ConvertFrom-Json
    Write-Host "DIAGNOSTIC: Loaded CanaryOU Type = $($LoadedConfig.Configuration.CanaryOU.Type)"

    Write-Host "[*] Configuration file created: $Config"
}

# Export functions
Export-ModuleMember -Function DefaultCanaries, PopulateConf 