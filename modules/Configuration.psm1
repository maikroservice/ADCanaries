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

    $ConfigJsonObject = @{}
    $ConfigJsonObject.Configuration = @{}
    $ConfigJsonObject.Configuration.CanaryOwner = $Owner

    # Check if ParentOU exists
    if(-not (Get-ADObject -Filter *).DistinguishedName -contains $ParentOU) {
        Write-Host "[!] $ParentOU not found in AD Objects please provide a valid Parent OU"
        exit $false
    }
    
    # Overwrite output file
    Remove-Item -Path $Config -ErrorAction SilentlyContinue

    $ConfigJsonObject.Configuration.CanaryOU = @{}
    $ConfigJsonObject.Configuration.CanaryOU.Name = "$CanaryGroupName"
    $ConfigJsonObject.Configuration.CanaryOU.Type = "organizationalUnit"
    $ConfigJsonObject.Configuration.CanaryOU.Path = "$ParentOU"
    $ConfigJsonObject.Configuration.CanaryOU.OtherAttributes = @{}
    $ConfigJsonObject.Configuration.CanaryOU.Description = "[ADCanaries] Default OU"
    $ConfigJsonObject.Configuration.CanaryOU.ProtectedFromAccidentalDeletion = 1

    $CanariesPath = "OU=$CanaryGroupName,$ParentOU"

    $ConfigJsonObject.Configuration.CanaryGroup = @{}
    $ConfigJsonObject.Configuration.CanaryGroup.Name = "$CanaryGroupName"
    $ConfigJsonObject.Configuration.CanaryGroup.Type = "group"
    $ConfigJsonObject.Configuration.CanaryGroup.Path = "$CanariesPath"
    $ConfigJsonObject.Configuration.CanaryGroup.OtherAttributes = @{}
    $ConfigJsonObject.Configuration.CanaryGroup.Description = "[ADCanaries] Default group"
    $ConfigJsonObject.Configuration.CanaryGroup.ProtectedFromAccidentalDeletion = 1

    $ConfigJsonObject.Canaries = New-Object System.Collections.ArrayList

    DefaultCanaries -ConfigJsonObject $ConfigJsonObject -ParentOU $CanariesPath
    
    # Write the configuration to file
    $ConfigJsonObject | ConvertTo-Json -Depth 20 | Set-Content -Path $Config

    Write-Host "[*] Configuration saved to: $Config"
}

# Export functions
Export-ModuleMember -Function DefaultCanaries, PopulateConf 