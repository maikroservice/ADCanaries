function RemoveDenyAllOnCanary {
    param($DistinguishedName)

    $Everyone       = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
    $GenericAll     = [System.DirectoryServices.ActiveDirectoryRights]::"GenericAll"
    $Deny           = [System.Security.AccessControl.AccessControlType]::"Deny"
    $AccessRule     = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Everyone,$GenericAll,$Deny)
    $NewOwner       = New-Object System.Security.Principal.SecurityIdentifier($Everyone)
    $ACL            = Get-Acl -Path "AD:/$DistinguishedName"
    $ACL.SetOwner($NewOwner)
    $ACL | Set-Acl -Path "AD:/$DistinguishedName"
    Write-Host "[*] Changed Owner to Everyone for : $DistinguishedName"
    $ACL            = Get-Acl -Path "AD:/$DistinguishedName"
    $ACL.RemoveAccessRule($AccessRule)>$null
    $ACL | Set-Acl -Path "AD:/$DistinguishedName"
    Write-Host "[*] Removed Deny All DACL deployed on : $DistinguishedName"
}

function DestroyCanary {
    param($DistinguishedName)
    if(Get-ADObject -Filter * | Where-Object {$_.DistinguishedName -eq $DistinguishedName}){
        RemoveDenyAllOnCanary -DistinguishedName $DistinguishedName
        Set-ADObject -Identity $DistinguishedName -ProtectedFromAccidentalDeletion $False
        Remove-ADObject -Identity $DistinguishedName -Confirm:$false
        Write-Host "[*] ADCanary object removed : $DistinguishedName"
    }
    else {
        Write-Host "[-] ADCanary object not found : $DistinguishedName"
    }
}

function DestroyCanaries {
    param($Config)
    ValidateAction
    # Retreive Configuration from JSON file
    $ADCanariesJson = Get-Content -Path $Config | ConvertFrom-Json
    $Configuration  = $ADCanariesJson.Configuration
    $CanaryGroup    = $Configuration.CanaryGroup
    $CanaryOU       = $Configuration.CanaryOU
    $Canaries       = $ADCanariesJson.Canaries

    # Remove DACL on Canary OU
    $DistinguishedName = "OU="+$CanaryOU.Name+","+$CanaryOU.Path
    if (ADObjectExists -Path $DistinguishedName){
        RemoveDenyAllOnCanary -DistinguishedName $DistinguishedName
    }else{
        Write-Host "[!] Canary OU not found : $DistinguishedName"
        Write-Host "[!] Aborting, please ensure provided OU exists and ADCanaries are located under this OU.`n"
        exit $false
    }
    
    # Destroy Canary Users
    foreach ($Canary in $Canaries) {
        Write-Host ""
        $DistinguishedName = "CN="+$Canary.Name+","+$Canary.Path
        DestroyCanary -DistinguishedName $DistinguishedName
    }
    
    # Delete Primary Group for Canaries
    $DistinguishedName = "CN="+$CanaryGroup.Name+","+$CanaryGroup.Path
    Write-Host ""
    DestroyCanary -DistinguishedName $DistinguishedName
    
    # Delete OU for Canaries
    $DistinguishedName = "OU="+$CanaryOU.Name+","+$CanaryOU.Path
    Write-Host ""
    DestroyCanary -DistinguishedName $DistinguishedName
}

# Export functions
Export-ModuleMember -Function RemoveDenyAllOnCanary, DestroyCanary, DestroyCanaries 