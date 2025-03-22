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
    
    # Different prefixes for different object types
    $prefix = "CN="
    if ($Canary.Type -eq "organizationalUnit") {
        $prefix = "OU="
    }
    
    $DistinguishedName = "$prefix"+$Canary.Name+","+$Canary.Path

    # Log creation attempt
    Write-Host "Attempting to create canary: $($Canary.Name) of type $($Canary.Type)"
    
    # Check if object already exists
    $objectExists = $false
    try {
        Get-ADObject -Identity $DistinguishedName -ErrorAction Stop
        Write-Host "[-] Canary object already existed : $DistinguishedName" -ForegroundColor Yellow
        $objectExists = $true
    } catch {
        $objectExists = $false
    }
    
    if (-not $objectExists) {
        # Create the appropriate object based on type
        try {
            switch ($Canary.Type) {
                "user" {
                    New-ADUser -Name $Canary.Name -Path $Canary.Path -Description $Canary.Description -Enabled $false
                    
                    # Add user to group and set primary group
                    Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName -ErrorAction Stop
                    Set-ADObject $DistinguishedName -replace @{primaryGroupID=$CanaryGroupToken} -ErrorAction Stop
                    
                    # Clean up other group memberships
                    $userObj = Get-ADUser -Identity $DistinguishedName -Properties MemberOf
                    foreach($G in $userObj.MemberOf){
                        if ($G -ne $CanaryGroupDN) {
                            Remove-ADGroupMember -Identity $G -Members $DistinguishedName -Confirm:$false -ErrorAction SilentlyContinue
                        }
                    }
                }
                "group" {
                    New-ADGroup -Name $Canary.Name -GroupCategory Security -GroupScope Global -Path $Canary.Path -Description $Canary.Description
                    
                    # Add group to canary group
                    Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName -ErrorAction Stop
                }
                "computer" {
                    New-ADComputer -Name $Canary.Name -Path $Canary.Path -Description $Canary.Description -Enabled $false
                    
                    # Add computer to group and set primary group
                    Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName -ErrorAction Stop
                    Set-ADObject $DistinguishedName -replace @{primaryGroupID=$CanaryGroupToken} -ErrorAction Stop
                    
                    # Clean up other group memberships
                    $computerObj = Get-ADComputer -Identity $DistinguishedName -Properties MemberOf
                    foreach($G in $computerObj.MemberOf){
                        if ($G -ne $CanaryGroupDN) {
                            Remove-ADGroupMember -Identity $G -Members $DistinguishedName -Confirm:$false -ErrorAction SilentlyContinue
                        }
                    }
                }
                "organizationalUnit" {
                    New-ADOrganizationalUnit -Name $Canary.Name -Path $Canary.Path -Description $Canary.Description
                    # Note: OUs cannot be members of groups, so we skip group operations
                }
                default {
                    # Special handling for other object types
                    Write-Host "[i] Creating special object type: $($Canary.Type)" -ForegroundColor Cyan
                    
                    # Try to create the object but don't fail if it doesn't work perfectly
                    try {
                        New-ADObject -Name $Canary.Name -Path $Canary.Path -Type $Canary.Type -Description $Canary.Description
                        Write-Host "[+] Created $($Canary.Type) object: $DistinguishedName" -ForegroundColor Green
                    } catch {
                        Write-Host "[!] Warning: Could not create $($Canary.Type) object. This might be normal: $($_.Exception.Message)" -ForegroundColor Yellow
                        # Create a simple placeholder object instead - using the "container" type which is generic
                        try {
                            New-ADObject -Name $Canary.Name -Path $Canary.Path -Type "container" -Description "$($Canary.Description) (placeholder for $($Canary.Type))"
                            Write-Host "[+] Created placeholder container instead" -ForegroundColor Green
                            # Update the distinguished name to use the container object
                            $DistinguishedName = "CN="+$Canary.Name+","+$Canary.Path
                        } catch {
                            Write-Host "[!] Could not create placeholder either: $($_.Exception.Message)" -ForegroundColor Red
                            return
                        }
                    }
                    
                    # For special types, we'll try to add to the group but handle failures gracefully
                    try {
                        Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName -ErrorAction Stop
                        Write-Host "[+] Added $($Canary.Type) to canary group" -ForegroundColor Green
                    } catch {
                        Write-Host "[!] Could not add $($Canary.Type) to group. This may be normal: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
            }
            
            # Get the created object
            try {
                $CanaryObject = Get-ADObject -Identity $DistinguishedName -Properties *
                
                Write-Host "[*] Canary created : $DistinguishedName" -ForegroundColor Green
                
                # Set audit and permissions
                SetAuditSACL -DistinguishedName $DistinguishedName
                Set-ADObject -Identity $DistinguishedName -ProtectedFromAccidentalDeletion $False
                DenyAllOnCanariesAndChangeOwner -DistinguishedName $DistinguishedName -Owner $Owner
                
                # Record the created object
                $SamAccountName = $CanaryObject.SamAccountName
                $Name = $CanaryObject.Name
                $Guid = $CanaryObject.ObjectGUID
                Add-Content -Path $Output "$SamAccountName,$Guid,$Name"
            } catch {
                Write-Host "[!] Error getting created object: $($_.Exception.Message)" -ForegroundColor Red
            }
        } catch {
            Write-Host "[!] Error creating canary $($Canary.Name): $($_.Exception.Message)" -ForegroundColor Red
        }
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
    
    # DIAGNOSTIC: Print loaded values
    Write-Host "DIAGNOSTIC: Loaded CanaryOU Type = $($CanaryOU.Type)"
    
    # Overwrite output file
    Remove-Item -Path $Output -ErrorAction SilentlyContinue
    Add-Content -Path $Output "CanarySamName,CanaryGUID,CanaryName"

    # Ensure Parent container exists using Get-ADObject directly
    $Path = $CanaryOU.Path
    try {
        $parentOU = Get-ADObject -Identity $Path -ErrorAction Stop
        Write-Host "[+] Parent OU found: $Path" -ForegroundColor Green
    } catch {
        Write-Host "[!] Parent OU for default Canary OU not found: $Path -- aborting deployment" -ForegroundColor Red
        Write-Host "[!] Error details: $($_.Exception.Message)" -ForegroundColor Red
        exit $false
    }

    # Create OU for Canaries
    $DistinguishedName = "OU=" + $CanaryOU.Name + "," + $CanaryOU.Path
    
    # First check if the OU already exists
    $ouExists = $false
    try {
        Get-ADOrganizationalUnit -Identity $DistinguishedName -ErrorAction Stop
        Write-Host "[-] Canary OU already existed : $DistinguishedName" -ForegroundColor Yellow
        $ouExists = $true
    } catch {
        # OU doesn't exist, we'll create it
        $ouExists = $false
    }
    
    if (-not $ouExists) {
        try {
            Write-Host "DIAGNOSTIC: Creating OU with New-ADOrganizationalUnit cmdlet"
            New-ADOrganizationalUnit -Name $CanaryOU.Name -Path $CanaryOU.Path -Description $CanaryOU.Description
            
            # Configure the OU
            Set-ADObject -Identity $DistinguishedName -ProtectedFromAccidentalDeletion $False
            $ACL = Get-Acl -Path "AD:/$DistinguishedName"
            $ACL.SetAccessRuleProtection($true, $false)
            $ACL | Set-Acl -Path "AD:/$DistinguishedName"
            Write-Host "[*] Canary OU created and inheritance disabled : $DistinguishedName" -ForegroundColor Green
            
            # Verify the OU was created properly
            $createdOU = Get-ADObject -Identity $DistinguishedName -Properties objectClass
            Write-Host "DIAGNOSTIC: Created OU objectClass = $($createdOU.objectClass)"
        } catch {
            Write-Host "[!] Failed to create Canary OU: $($_.Exception.Message)" -ForegroundColor Red
            exit $false
        }
    }

    # Create Primary Group for Canaries
    $DistinguishedName = "CN="+$CanaryGroup.Name+","+$CanaryGroup.Path
    
    # Check if group exists using direct AD cmdlet
    $groupExists = $false
    try {
        Get-ADGroup -Identity $DistinguishedName -ErrorAction Stop
        Write-Host "[-] Canary Primary Group already existed : $DistinguishedName" -ForegroundColor Yellow
        $groupExists = $true
    } catch {
        $groupExists = $false
    }
    
    if (-not $groupExists) {
        try {
            New-ADGroup -Name $CanaryGroup.Name -GroupCategory Security -GroupScope Global -DisplayName $CanaryGroup.Name -Path $CanaryGroup.Path -Description $CanaryGroup.Description
            Set-ADObject -Identity $DistinguishedName -ProtectedFromAccidentalDeletion $False
            $ACL = Get-Acl -Path "AD:/$DistinguishedName"
            $ACL.SetAccessRuleProtection($true, $false)
            $ACL | Set-Acl -Path "AD:/$DistinguishedName"
            Write-Host "[*] Canary Group created and inheritance disabled : $DistinguishedName" -ForegroundColor Green
        } catch {
            Write-Host "[!] Failed to create Canary Group: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    try {
        $CanaryGroup = Get-ADGroup -Identity "$DistinguishedName" -Properties *
    } catch {
        Write-Host "[!] Could not retrieve Canary Group: $($_.Exception.Message)" -ForegroundColor Red
        exit $false
    }

    # Create Canaries
    foreach ($Canary in $Canaries) {
        CreateCanary -Canary $Canary -Output $Output -CanaryGroup $CanaryGroup -Owner $CanaryOwner
    }

    # Deny all canary OU no audit
    $DN = "OU="+$CanaryOU.Name+","+$CanaryOU.Path
    try {
        DenyAllOnCanariesAndChangeOwner -DistinguishedName $DN -Owner $CanaryOwner
    } catch {
        Write-Host "[!] Failed to set permissions on Canary OU: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Output
    Write-Host "`n[*] Done. Lookup Name:Guid for created objects :`n" -ForegroundColor Green
    Get-Content -Path $Output
}

# Export functions
Export-ModuleMember -Function SetAuditSACL, DenyAllOnCanariesAndChangeOwner, CreateCanary, DeployCanaries