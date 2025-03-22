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
    
    # Keep track of the original path for all objects
    $originalPath = $Canary.Path
    
    # For problematic object types, create a dedicated container if needed
    if ($Canary.Type -eq "pKICertificateTemplate" -or $Canary.Type -eq "domainPolicy") {
        # Create a PKI container in the parent OU if it doesn't exist yet
        $containerName = "PKI-Canaries"
        $containerDN = "CN=$containerName,$originalPath"
        
        # Check if the container exists
        $containerExists = $false
        try {
            Get-ADObject -Identity $containerDN -ErrorAction Stop
            $containerExists = $true
        } catch {
            $containerExists = $false
        }
        
        # Create the container if needed
        if (-not $containerExists) {
            try {
                New-ADObject -Name $containerName -Type "container" -Path $originalPath -Description "Container for PKI and Policy canaries"
                Write-Host "[+] Created PKI container: $containerDN" -ForegroundColor Green
            } catch {
                Write-Host "[!] Failed to create PKI container: $($_.Exception.Message)" -ForegroundColor Red
                # Continue with original path if we can't create container
                $containerDN = $originalPath
            }
        }
        
        # Update the path to use the container
        $Canary.Path = $containerDN
        Write-Host "[i] Using PKI container for $($Canary.Type): $containerDN" -ForegroundColor Cyan
    }
    
    # Create the distinguished name with the updated path
    $DistinguishedName = "$prefix"+$Canary.Name+","+$Canary.Path
    
    # Track whether creation was successful
    $creationSuccessful = $false
    $createdObjectDN = $DistinguishedName  # Track actual DN of created object

    # Log creation attempt
    Write-Host "Attempting to create canary: $($Canary.Name) of type $($Canary.Type) at $DistinguishedName"
    
    # Check if object already exists
    $objectExists = $false
    try {
        Get-ADObject -Identity $DistinguishedName -ErrorAction Stop
        Write-Host "[-] Canary object already existed : $DistinguishedName" -ForegroundColor Yellow
        $objectExists = $true
        $creationSuccessful = $true
        $createdObjectDN = $DistinguishedName
    } catch {
        $objectExists = $false
    }
    
    if (-not $objectExists) {
        # Create the appropriate object based on type
        try {
            switch ($Canary.Type) {
                "user" {
                    New-ADUser -Name $Canary.Name -Path $Canary.Path -Description $Canary.Description -Enabled $false
                    $creationSuccessful = $true
                    
                    # Add user to group and set primary group
                    Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName -ErrorAction SilentlyContinue
                    Set-ADObject $DistinguishedName -replace @{primaryGroupID=$CanaryGroupToken} -ErrorAction SilentlyContinue
                    
                    # Clean up other group memberships
                    $userObj = Get-ADUser -Identity $DistinguishedName -Properties MemberOf -ErrorAction SilentlyContinue
                    if ($userObj -ne $null) {
                        foreach($G in $userObj.MemberOf){
                            if ($G -ne $CanaryGroupDN) {
                                Remove-ADGroupMember -Identity $G -Members $DistinguishedName -Confirm:$false -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }
                "group" {
                    New-ADGroup -Name $Canary.Name -GroupCategory Security -GroupScope Global -Path $Canary.Path -Description $Canary.Description
                    $creationSuccessful = $true
                    
                    # Add group to canary group
                    Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName -ErrorAction SilentlyContinue
                }
                "computer" {
                    New-ADComputer -Name $Canary.Name -Path $Canary.Path -Description $Canary.Description -Enabled $false
                    $creationSuccessful = $true
                    
                    # Add computer to group and set primary group
                    Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName -ErrorAction SilentlyContinue
                    Set-ADObject $DistinguishedName -replace @{primaryGroupID=$CanaryGroupToken} -ErrorAction SilentlyContinue
                    
                    # Clean up other group memberships
                    $computerObj = Get-ADComputer -Identity $DistinguishedName -Properties MemberOf -ErrorAction SilentlyContinue
                    if ($computerObj -ne $null) {
                        foreach($G in $computerObj.MemberOf){
                            if ($G -ne $CanaryGroupDN) {
                                Remove-ADGroupMember -Identity $G -Members $DistinguishedName -Confirm:$false -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }
                "organizationalUnit" {
                    New-ADOrganizationalUnit -Name $Canary.Name -Path $Canary.Path -Description $Canary.Description
                    $creationSuccessful = $true
                    # Note: OUs cannot be members of groups, so we skip group operations
                }
                "pKICertificateTemplate" {
                    # For PKI template, always create a container placeholder
                    Write-Host "[i] Creating container placeholder for PKI Certificate Template" -ForegroundColor Cyan
                    New-ADObject -Name $Canary.Name -Path $Canary.Path -Type "container" -Description "$($Canary.Description) (placeholder for pKICertificateTemplate)"
                    $creationSuccessful = $true
                    
                    # Try to add to the group but don't fail if it doesn't work
                    try {
                        Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName -ErrorAction Stop
                        Write-Host "[+] Added PKI template placeholder to group" -ForegroundColor Green
                    } catch {
                        Write-Host "[!] Could not add PKI template placeholder to group: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
                "domainPolicy" {
                    # Always create a container placeholder for domain policy
                    Write-Host "[i] Creating container placeholder for domain policy" -ForegroundColor Cyan
                    New-ADObject -Name $Canary.Name -Path $Canary.Path -Type "container" -Description "$($Canary.Description) (placeholder for domainPolicy)"
                    $creationSuccessful = $true
                    
                    # Try to add to the group but don't fail if it doesn't work
                    try {
                        Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName -ErrorAction Stop
                        Write-Host "[+] Added policy placeholder to group" -ForegroundColor Green
                    } catch {
                        Write-Host "[!] Could not add policy placeholder to group: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
                default {
                    # For all other types, try creating the object directly first, then fall back to a container
                    Write-Host "[i] Creating object of type: $($Canary.Type)" -ForegroundColor Cyan
                    
                    try {
                        New-ADObject -Name $Canary.Name -Path $Canary.Path -Type $Canary.Type -Description $Canary.Description
                        Write-Host "[+] Created $($Canary.Type) object: $DistinguishedName" -ForegroundColor Green
                        $creationSuccessful = $true
                        
                        # Try to add to the group but don't fail if it doesn't work
                        try {
                            Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName -ErrorAction Stop
                            Write-Host "[+] Added to group" -ForegroundColor Green
                        } catch {
                            Write-Host "[!] Could not add to group: $($_.Exception.Message)" -ForegroundColor Yellow
                        }
                    } catch {
                        Write-Host "[!] Could not create $($Canary.Type) object: $($_.Exception.Message)" -ForegroundColor Red
                        
                        # Fall back to creating a container
                        try {
                            New-ADObject -Name $Canary.Name -Path $Canary.Path -Type "container" -Description "$($Canary.Description) (placeholder for $($Canary.Type))"
                            Write-Host "[+] Created placeholder container instead" -ForegroundColor Green
                            $creationSuccessful = $true
                            
                            # Try to add the placeholder to the group but don't fail if it doesn't work
                            try {
                                Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName -ErrorAction Stop
                                Write-Host "[+] Added placeholder to group" -ForegroundColor Green
                            } catch {
                                Write-Host "[!] Could not add placeholder to group: $($_.Exception.Message)" -ForegroundColor Yellow
                            }
                        } catch {
                            Write-Host "[!] Failed to create placeholder as well: $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                }
            }
            
            # Only attempt to configure the object if creation was successful
            if ($creationSuccessful) {
                # Get the created object - verify it exists first
                $CanaryObject = $null
                try {
                    $CanaryObject = Get-ADObject -Identity $createdObjectDN -Properties * -ErrorAction Stop
                    Write-Host "[+] Successfully retrieved created object: $createdObjectDN" -ForegroundColor Green
                    
                    # Set audit and permissions
                    SetAuditSACL -DistinguishedName $createdObjectDN
                    Set-ADObject -Identity $createdObjectDN -ProtectedFromAccidentalDeletion $False
                    DenyAllOnCanariesAndChangeOwner -DistinguishedName $createdObjectDN -Owner $Owner
                    
                    # Record the created object
                    $SamAccountName = $CanaryObject.SamAccountName
                    if ($null -eq $SamAccountName) { $SamAccountName = "N/A" }
                    $Name = $CanaryObject.Name
                    $Guid = $CanaryObject.ObjectGUID
                    Add-Content -Path $Output "$SamAccountName,$Guid,$Name"
                    
                    Write-Host "[*] Canary successfully created and configured: $createdObjectDN" -ForegroundColor Green
                } catch {
                    Write-Host "[!] Error retrieving or configuring created object: $($_.Exception.Message)" -ForegroundColor Red
                    
                    # Try one more time with a direct Get-ADObject approach
                    try {
                        $filter = "name -eq '$($Canary.Name)'"
                        $searchBase = $Canary.Path
                        $possibleObject = Get-ADObject -Filter $filter -SearchBase $searchBase -SearchScope OneLevel -Properties *
                        
                        if ($possibleObject -ne $null) {
                            Write-Host "[+] Found object by searching: $($possibleObject.DistinguishedName)" -ForegroundColor Green
                            
                            # Set audit and permissions
                            SetAuditSACL -DistinguishedName $possibleObject.DistinguishedName
                            Set-ADObject -Identity $possibleObject.DistinguishedName -ProtectedFromAccidentalDeletion $False
                            DenyAllOnCanariesAndChangeOwner -DistinguishedName $possibleObject.DistinguishedName -Owner $Owner
                            
                            # Record the created object
                            $SamAccountName = $possibleObject.SamAccountName
                            if ($null -eq $SamAccountName) { $SamAccountName = "N/A" }
                            $Name = $possibleObject.Name
                            $Guid = $possibleObject.ObjectGUID
                            Add-Content -Path $Output "$SamAccountName,$Guid,$Name"
                            
                            Write-Host "[*] Canary successfully created and configured (found by search): $($possibleObject.DistinguishedName)" -ForegroundColor Green
                        } else {
                            Write-Host "[!] Could not find created object by searching either" -ForegroundColor Red
                        }
                    } catch {
                        Write-Host "[!] Final attempt to find object failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
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