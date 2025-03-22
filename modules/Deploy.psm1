function SetAuditSACL {
    param($DistinguishedName)
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
    $GenericAll = [System.DirectoryServices.ActiveDirectoryRights]::"ReadProperty"
    $SuccessFailure = [System.Security.AccessControl.AuditFlags]::"Success","Failure"
    $AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,$GenericAll,$SuccessFailure)
    $ACL = Get-Acl -Path "AD:/$DistinguishedName"
    $ACL.SetAuditRule($AccessRule)
    $ACL | Set-Acl -Path "AD:/$DistinguishedName"
    Write-Host "[*] SACL deployed on : $DistinguishedName"
}

function DenyAllOnCanariesAndChangeOwner {
    param($DistinguishedName, $Owner)
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
    $GenericAll = [System.DirectoryServices.ActiveDirectoryRights]::"GenericAll"
    $Deny = [System.Security.AccessControl.AccessControlType]::"Deny"
    $AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Everyone,$GenericAll,$Deny)
    $NewOwner = New-Object System.Security.Principal.SecurityIdentifier((Get-ADGroup "$Owner" -Properties *).ObjectSid)
    $ACL = Get-Acl -Path "AD:/$DistinguishedName"
    $ACL.SetAccessRuleProtection($true, $false)
    $ACL | Set-Acl -Path "AD:/$DistinguishedName"
    $ACL = Get-Acl -Path "AD:/$DistinguishedName"
    $ACL.SetAccessRule($AccessRule)
    $ACL | Set-Acl -Path "AD:/$DistinguishedName"
    $ACL = Get-Acl -Path "AD:/$DistinguishedName"
    $ACL.SetOwner($NewOwner)
    $ACL | Set-Acl -Path "AD:/$DistinguishedName"
    Write-Host "[*] Deny All DACL deployed on : $DistinguishedName"
}

function CreateCanary {
    param($Canary, $Output, $CanaryGroup, $Owner)

    $CanaryGroupDN = $CanaryGroup.distinguishedName
    $CanaryGroupToken = (Get-ADGroup $CanaryGroupDN -Properties @("primaryGroupToken")).primaryGroupToken
    $DistinguishedName = "CN="+$Canary.Name+","+$Canary.Path

    if (ADObjectExists -Path $DistinguishedName){
        Write-Host "[-] Canary User already existed : $DistinguishedName"
    }
    else {
        # Check type and use appropriate cmdlet
        switch ($Canary.Type) {
            "user" {
                New-ADUser -Name $Canary.Name -Path $Canary.Path -Description $Canary.Description -Enabled $false
            }
            "group" {
                New-ADGroup -Name $Canary.Name -GroupCategory Security -GroupScope Global -Path $Canary.Path -Description $Canary.Description
            }
            "computer" {
                New-ADComputer -Name $Canary.Name -Path $Canary.Path -Description $Canary.Description -Enabled $false
            }
            "organizationalUnit" {
                New-ADOrganizationalUnit -Name $Canary.Name -Path $Canary.Path -Description $Canary.Description
            }
            default {
                New-ADObject -Name $Canary.Name -Path $Canary.Path -Type $Canary.Type -Description $Canary.Description
            }
        }
        
        $CanaryObject = (Get-ADObject $DistinguishedName -Properties *)

        # Add Canary to CanaryGroup and set primary group (only for users and computers)
        if ($Canary.Type -eq "user" -or $Canary.Type -eq "computer") {
            Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName
            Set-ADObject $DistinguishedName -replace @{primaryGroupID=$CanaryGroupToken}
        } 
        elseif ($Canary.Type -eq "group") {
            Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName
        }
        
        foreach($G in $CanaryObject.MemberOf){
            if ($G -ne $CanaryGroupDN) {
                Remove-ADGroupMember -Identity $G -Members $DistinguishedName -Confirm:$false
            }
        }
        
        Write-Host "[*] Canary created : $DistinguishedName"
        SetAuditSACL -DistinguishedName $DistinguishedName
        Set-ADObject -Identity $DistinguishedName -ProtectedFromAccidentalDeletion $False
        DenyAllOnCanariesAndChangeOwner -DistinguishedName $DistinguishedName -Owner $Owner
        $SamAccountName = $CanaryObject.SamAccountName
        $Name = $CanaryObject.Name
        $Guid = $CanaryObject.ObjectGUID
        Add-Content -Path $Output "$SamAccountName,$Guid,$Name"
    }
}

function DeployCanaries {
    param($Config, $Output)
    ValidateAction
    
    # Retrieve Configuration from JSON file
    $ADCanariesJson = Get-Content -Path $Config | ConvertFrom-Json
    $Configuration = $ADCanariesJson.Configuration
    $CanaryGroup = $Configuration.CanaryGroup
    $CanaryOwner = $Configuration.CanaryOwner
    $CanaryOU = $Configuration.CanaryOU
    $Canaries = $ADCanariesJson.Canaries
    
    # Overwrite output file
    Remove-Item -Path $Output -ErrorAction SilentlyContinue
    Add-Content -Path $Output "CanarySamName,CanaryGUID,CanaryName"

    # Ensure Parent container exists
    $Path = $CanaryOU.Path
    if(-not (ADObjectExists -Path $Path)){
        Write-Host "[-] Parent OU for default Canary OU not found : $Path -- aborting deployment"
        exit $false
    }

    # Create OU for Canaries
    $DistinguishedName = "OU="+$CanaryOU.Name+","+$CanaryOU.Path
    if (ADObjectExists -Path $DistinguishedName){
        Write-Host "[-] Canary OU already existed : $DistinguishedName"
    }
    else {
        New-ADOrganizationalUnit -Name $CanaryOU.Name -Path $CanaryOU.Path -Description $CanaryOU.Description
        Set-ADObject -Identity $DistinguishedName -ProtectedFromAccidentalDeletion $False
        $ACL = Get-Acl -Path "AD:/$DistinguishedName"
        $ACL.SetAccessRuleProtection($true, $false)
        $ACL | Set-Acl -Path "AD:/$DistinguishedName"
        Write-Host "[*] Canary OU created and inheritance disabled : $DistinguishedName"
    }

    # Create Primary Group for Canaries
    $DistinguishedName = "CN="+$CanaryGroup.Name+","+$CanaryGroup.Path
    if (ADObjectExists -Path $DistinguishedName){
        Write-Host "[-] Canary Primary Group already existed : $DistinguishedName"
    }
    else {
        New-ADGroup -Name $CanaryGroup.Name -GroupCategory Security -GroupScope Global -DisplayName $CanaryGroup.Name -Path $CanaryGroup.Path -Description $CanaryGroup.Description
        Set-ADObject -Identity $DistinguishedName -ProtectedFromAccidentalDeletion $False
        $ACL = Get-Acl -Path "AD:/$DistinguishedName"
        $ACL.SetAccessRuleProtection($true, $false)
        $ACL | Set-Acl -Path "AD:/$DistinguishedName"
        Write-Host "[*] Canary Group created and inheritance disabled : $DistinguishedName"
    }
    $CanaryGroup = (Get-ADGroup -Identity "$DistinguishedName" -Properties *)

    # Create Canaries
    foreach ($Canary in $Canaries) {
        CreateCanary -Canary $Canary -Output $Output -CanaryGroup $CanaryGroup -Owner $CanaryOwner
    }

    # Deny all canary OU no audit
    $DN = "OU="+$CanaryOU.Name+","+$CanaryOU.Path
    DenyAllOnCanariesAndChangeOwner -DistinguishedName $DN -Owner $CanaryOwner

    # Output
    Write-Host "`n[*] Done. Lookup Name:Guid for created objects :`n"
    Get-Content -Path $Output
}

# Export functions
Export-ModuleMember -Function SetAuditSACL, DenyAllOnCanariesAndChangeOwner, CreateCanary, DeployCanaries