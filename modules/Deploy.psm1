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

    # Log creation attempt
    Write-Host "Attempting to create canary: $($Canary.Name) of type $($Canary.Type) at $DistinguishedName"
    
    # Check if object already exists
    $objectExists = $false
    try {
        Get-ADObject -Identity $DistinguishedName -ErrorAction Stop
        Write-Host "[-] Canary object already existed : $DistinguishedName" -ForegroundColor Yellow
        $objectExists = $true
        $creationSuccessful = $true
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
                    
                    # IMPORTANT: Add user to group FIRST
                    try {
                        Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName -ErrorAction Stop
                        Write-Host "[+] Added user to canary group" -ForegroundColor Green
                    } catch {
                        Write-Host "[!] Could not add user to group: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                    
                    # Set primary group
                    try {
                        Set-ADObject $DistinguishedName -replace @{primaryGroupID=$CanaryGroupToken} -ErrorAction Stop
                        Write-Host "[+] Set primary group token" -ForegroundColor Green
                    } catch {
                        Write-Host "[!] Could not set primary group: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                    
                    # Clean up other group memberships
                    try {
                        $userObj = Get-ADUser -Identity $DistinguishedName -Properties MemberOf -ErrorAction Stop
                        foreach($G in $userObj.MemberOf){
                            if ($G -ne $CanaryGroupDN) {
                                Remove-ADGroupMember -Identity $G -Members $DistinguishedName -Confirm:$false -ErrorAction SilentlyContinue
                            }
                        }
                    } catch {
                        Write-Host "[!] Could not clean up other group memberships: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
                "group" {
                    New-ADGroup -Name $Canary.Name -GroupCategory Security -GroupScope Global -Path $Canary.Path -Description $Canary.Description
                    $creationSuccessful = $true
                    
                    # IMPORTANT: Add group to canary group FIRST
                    try {
                        Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName -ErrorAction Stop
                        Write-Host "[+] Added group to canary group" -ForegroundColor Green
                    } catch {
                        Write-Host "[!] Could not add group to canary group: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
                "computer" {
                    New-ADComputer -Name $Canary.Name -Path $Canary.Path -Description $Canary.Description -Enabled $false
                    $creationSuccessful = $true
                    
                    # IMPORTANT: Add computer to group FIRST
                    try {
                        Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName -ErrorAction Stop
                        Write-Host "[+] Added computer to canary group" -ForegroundColor Green
                    } catch {
                        Write-Host "[!] Could not add computer to group: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                    
                    # Set primary group
                    try {
                        Set-ADObject $DistinguishedName -replace @{primaryGroupID=$CanaryGroupToken} -ErrorAction Stop
                        Write-Host "[+] Set primary group token" -ForegroundColor Green
                    } catch {
                        Write-Host "[!] Could not set primary group: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                    
                    # Clean up other group memberships
                    try {
                        $computerObj = Get-ADComputer -Identity $DistinguishedName -Properties MemberOf -ErrorAction Stop
                        foreach($G in $computerObj.MemberOf){
                            if ($G -ne $CanaryGroupDN) {
                                Remove-ADGroupMember -Identity $G -Members $DistinguishedName -Confirm:$false -ErrorAction SilentlyContinue
                            }
                        }
                    } catch {
                        Write-Host "[!] Could not clean up other group memberships: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
                "organizationalUnit" {
                    New-ADOrganizationalUnit -Name $Canary.Name -Path $Canary.Path -Description $Canary.Description
                    $creationSuccessful = $true
                    # Note: OUs cannot be members of groups, so we skip group operations
                }
                "pKICertificateTemplate" {
                    # Create a placeholder object for PKI Certificate Template
                    Write-Host "[i] Creating placeholder for PKI Certificate Template" -ForegroundColor Cyan
                    New-ADObject -Name $Canary.Name -Path $Canary.Path -Type "container" -Description "$($Canary.Description) (placeholder for pKICertificateTemplate)"
                    $creationSuccessful = $true
                    
                    # IMPORTANT: Add to the group FIRST, before applying restrictive permissions
                    try {
                        Start-Sleep -Seconds 2  # Brief delay to ensure object is available
                        Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName -ErrorAction Stop
                        Write-Host "[+] Added PKI template placeholder to group" -ForegroundColor Green
                    } catch {
                        Write-Host "[!] Could not add PKI template placeholder to group: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
                "domainPolicy" {
                    # Create a placeholder for domain policy
                    Write-Host "[i] Creating placeholder for domain policy" -ForegroundColor Cyan
                    New-ADObject -Name $Canary.Name -Path $Canary.Path -Type "container" -Description "$($Canary.Description) (placeholder for domainPolicy)"
                    $creationSuccessful = $true
                    
                    # IMPORTANT: Add to the group FIRST, before applying restrictive permissions
                    try {
                        Start-Sleep -Seconds 2  # Brief delay to ensure object is available
                        Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName -ErrorAction Stop
                        Write-Host "[+] Added policy placeholder to group" -ForegroundColor Green
                    } catch {
                        Write-Host "[!] Could not add policy placeholder to group: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
                default {
                    # Generic handling for other types
                    Write-Host "[i] Creating placeholder for type: $($Canary.Type)" -ForegroundColor Cyan
                    
                    try {
                        # Always create a container placeholder for unknown types
                        New-ADObject -Name $Canary.Name -Path $Canary.Path -Type "container" -Description "$($Canary.Description) (placeholder for $($Canary.Type))"
                        Write-Host "[+] Created placeholder container" -ForegroundColor Green
                        $creationSuccessful = $true
                        
                        # IMPORTANT: Add to the group FIRST, before applying restrictive permissions
                        try {
                            Start-Sleep -Seconds 2  # Brief delay to ensure object is available
                            Add-ADGroupMember -Identity $CanaryGroupDN -Members $DistinguishedName -ErrorAction Stop
                            Write-Host "[+] Added placeholder to group" -ForegroundColor Green
                        } catch {
                            Write-Host "[!] Could not add placeholder to group: $($_.Exception.Message)" -ForegroundColor Yellow
                        }
                    } catch {
                        Write-Host "[!] Failed to create placeholder: $($_.Exception.Message)" -ForegroundColor Red
                        $creationSuccessful = $false
                    }
                }
            }
            
            # Only attempt to configure the object if creation was successful
            if ($creationSuccessful) {
                # Get the created object - verify it exists first
                $CanaryObject = $null
                try {
                    $CanaryObject = Get-ADObject -Identity $DistinguishedName -Properties * -ErrorAction Stop
                    Write-Host "[+] Successfully retrieved created object: $DistinguishedName" -ForegroundColor Green
                    
                    # IMPORTANT: Apply security settings ONLY AFTER adding to groups
                    # First apply SACL for auditing
                    SetAuditSACL -DistinguishedName $DistinguishedName
                    
                    # Then disable protection from accidental deletion
                    Set-ADObject -Identity $DistinguishedName -ProtectedFromAccidentalDeletion $False
                    
                    # Finally apply deny all DACL - this will likely block further modifications
                    DenyAllOnCanariesAndChangeOwner -DistinguishedName $DistinguishedName -Owner $Owner
                    
                    # Record the created object
                    $SamAccountName = $CanaryObject.SamAccountName
                    if ($null -eq $SamAccountName) { $SamAccountName = "N/A" }
                    $Name = $CanaryObject.Name
                    $Guid = $CanaryObject.ObjectGUID
                    Add-Content -Path $Output "$SamAccountName,$Guid,$Name"
                    
                    Write-Host "[*] Canary successfully created and configured: $DistinguishedName" -ForegroundColor Green
                } catch {
                    Write-Host "[!] Error retrieving or configuring created object: $($_.Exception.Message)" -ForegroundColor Red
                    
                    # Try to find the object by name if we can't find it by DN
                    try {
                        $filter = "name -eq '$($Canary.Name)'"
                        $searchBase = $Canary.Path
                        $possibleObject = Get-ADObject -Filter $filter -SearchBase $searchBase -SearchScope OneLevel -Properties *
                        
                        if ($possibleObject -ne $null) {
                            Write-Host "[+] Found object by searching: $($possibleObject.DistinguishedName)" -ForegroundColor Green
                            
                            # Apply security settings
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

function CreateSpecialCanaries {
    param($SpecialCanaries, $Output, $CanaryGroup, $Owner, $CanaryOU)
    
    # Create a dedicated container for special objects
    $containerName = "PKI-Canaries"
    
    # Use the Canary OU path instead
    $containerPath = "OU=" + $CanaryOU.Name + "," + $CanaryOU.Path
    Write-Host "[i] Using container path: $containerPath" -ForegroundColor Cyan
    
    $containerDN = "CN=$containerName,$containerPath"
    
    # Check if container exists
    $containerExists = $false
    try {
        Get-ADObject -Identity $containerDN -ErrorAction Stop
        $containerExists = $true
        Write-Host "[+] Special objects container already exists: $containerDN" -ForegroundColor Green
    } catch {
        # Create the container
        try {
            New-ADObject -Name $containerName -Type "container" -Path $containerPath -Description "Container for special canary objects"
            Write-Host "[+] Created special objects container: $containerDN" -ForegroundColor Green
            $containerExists = $true
            Start-Sleep -Seconds 3  # Brief delay to ensure container is available
        } catch {
            Write-Host "[!] Failed to create special objects container: $($_.Exception.Message)" -ForegroundColor Red
            $containerExists = $false
        }
    }
    
    # Only proceed if container exists
    if ($containerExists) {
        # Get all special canaries - PKI templates, domain policies, and other non-standard types
        $specialTypes = @('pKICertificateTemplate', 'domainPolicy')
        $specialObjects = $SpecialCanaries | Where-Object { $specialTypes -contains $_.Type }
        
        # Track all created objects for later permission application
        $createdObjectDNs = @()
        
        foreach ($specialObject in $specialObjects) {
            $objectName = $specialObject.Name
            $objectType = $specialObject.Type
            $objectDN = "CN=$objectName,$containerDN"
            
            Write-Host "[i] Creating special object: $objectName (type: $objectType)" -ForegroundColor Cyan
            
            # Check if object already exists
            $objectExists = $false
            try {
                Get-ADObject -Identity $objectDN -ErrorAction Stop
                $objectExists = $true
                Write-Host "[-] Special object already exists: $objectDN" -ForegroundColor Yellow
                $createdObjectDNs += $objectDN  # Add to our tracking list
            } catch {
                $objectExists = $false
            }
            
            if (-not $objectExists) {
                try {
                    # Create the placeholder container
                    New-ADObject -Name $objectName -Type "container" -Path $containerDN -Description "$($specialObject.Description) (placeholder for $objectType)"
                    Write-Host "[+] Created placeholder for $objectType : $objectDN" -ForegroundColor Green
                    $createdObjectDNs += $objectDN  # Add to our tracking list
                    Start-Sleep -Seconds 2  # Brief delay
                } catch {
                    Write-Host "[!] Failed to create $objectType placeholder: $($_.Exception.Message)" -ForegroundColor Red
                    continue  # Skip to the next object if creation fails
                }
            }
            
            # First add audit SACL only - don't apply restrictive permissions yet
            try {
                SetAuditSACL -DistinguishedName $objectDN
                Write-Host "[+] Applied audit SACL to $objectDN" -ForegroundColor Green
            } catch {
                Write-Host "[!] Could not apply audit SACL: $($_.Exception.Message)" -ForegroundColor Yellow
            }
            
            # Add to group - with non-restrictive permissions in place
            try {
                Add-ADGroupMember -Identity $CanaryGroup.distinguishedName -Members $objectDN -ErrorAction Stop
                Write-Host "[+] Added $objectType to group" -ForegroundColor Green
            } catch {
                Write-Host "[!] Could not add $objectType to group: $($_.Exception.Message)" -ForegroundColor Red
                # Try alternative method if the first fails
                try {
                    Write-Host "[i] Trying alternative method to add to group..." -ForegroundColor Cyan
                    $group = Get-ADGroup -Identity $CanaryGroup.distinguishedName -Properties member
                    Set-ADGroup -Identity $CanaryGroup.distinguishedName -Add @{member=$objectDN}
                    Write-Host "[+] Added $objectType to group using alternative method" -ForegroundColor Green
                } catch {
                    Write-Host "[!] Alternative method also failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            
            # Record in output file
            try {
                $createdObject = Get-ADObject -Identity $objectDN -Properties * -ErrorAction Stop
                $name = $createdObject.Name
                $guid = $createdObject.ObjectGUID
                Add-Content -Path $Output "N/A,$guid,$name"
            } catch {
                Write-Host "[!] Could not get $objectType properties: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        
        # Now that all objects are created and added to groups, apply the restrictive permissions
        Write-Host "`n[i] All special objects created and added to groups. Now applying restrictive permissions..." -ForegroundColor Cyan
        
        # First apply permissions to all individual objects
        foreach ($objectDN in $createdObjectDNs) {
            try {
                # First disable protection from accidental deletion
                Set-ADObject -Identity $objectDN -ProtectedFromAccidentalDeletion $False
                
                # Then apply restrictive permissions
                DenyAllOnCanariesAndChangeOwner -DistinguishedName $objectDN -Owner $Owner
                Write-Host "[+] Applied restrictive permissions to: $objectDN" -ForegroundColor Green
            } catch {
                Write-Host "[!] Failed to apply restrictive permissions to $objectDN : $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        # Finally apply permissions to the container
        try {
            DenyAllOnCanariesAndChangeOwner -DistinguishedName $containerDN -Owner $Owner
            Write-Host "[+] Applied restrictive permissions to container: $containerDN" -ForegroundColor Green
        } catch {
            Write-Host "[!] Failed to apply permissions to container: $($_.Exception.Message)" -ForegroundColor Red
        }
        
        Write-Host "[i] Completed special objects deployment with delayed permission application" -ForegroundColor Cyan
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

    # First create all standard canaries (users, computers, groups, OUs)
    $standardCanaries = $Canaries | Where-Object { @('user', 'computer', 'group', 'organizationalUnit') -contains $_.Type }
    foreach ($Canary in $standardCanaries) {
        CreateCanary -Canary $Canary -Output $Output -CanaryGroup $CanaryGroup -Owner $CanaryOwner
    }
    
    # Then create all special objects in a separate container
    CreateSpecialCanaries -SpecialCanaries $Canaries -Output $Output -CanaryGroup $CanaryGroup -Owner $CanaryOwner -CanaryOU $CanaryOU

    # Deny all canary OU no audit (do this last)
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
Export-ModuleMember -Function SetAuditSACL, DenyAllOnCanariesAndChangeOwner, CreateCanary, CreateSpecialCanaries, DeployCanaries