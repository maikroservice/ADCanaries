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
        # Track all created objects for later permission application
        $createdObjectDNs = @()
        
        # Process PKI certificate templates first
        $pkiTemplates = $SpecialCanaries | Where-Object { $_.Type -eq "pKICertificateTemplate" }
        
        foreach ($pkiTemplate in $pkiTemplates) {
            $templateName = $pkiTemplate.Name
            $templateDN = "CN=$templateName,$containerDN"
            
            Write-Host "[i] Creating PKI certificate template: $templateName" -ForegroundColor Cyan
            
            # Check if the template already exists
            $templateExists = $false
            try {
                Get-ADObject -Identity $templateDN -ErrorAction Stop
                $templateExists = $true
                Write-Host "[-] PKI certificate template already exists: $templateDN" -ForegroundColor Yellow
                $createdObjectDNs += $templateDN  # Add to our tracking list
            } catch {
                $templateExists = $false
            }
            
            if (-not $templateExists) {
                try {
                    # First, try to identify which attributes should only have single values
                    $schemaNC = (Get-ADRootDSE).schemaNamingContext
                    
                    Write-Host "[i] Analyzing schema for PKI template attribute definitions..." -ForegroundColor Cyan
                    # Create a hashtable to track which attributes are single-valued vs multi-valued
                    $attributeDefinitions = @{}
                    
                    function Get-AttributeValuesType {
                        param($AttributeName)
                        
                        try {
                            $attributeSchema = Get-ADObject -Filter "lDAPDisplayName -eq '$AttributeName'" -SearchBase $schemaNC -Properties isSingleValued
                            return @{
                                Name = $AttributeName
                                IsSingleValued = $attributeSchema.isSingleValued
                            }
                        } catch {
                            # If we can't find the attribute schema, assume it's single-valued to be safe
                            Write-Host "[!] Could not find schema definition for attribute $AttributeName" -ForegroundColor Yellow
                            return @{
                                Name = $AttributeName
                                IsSingleValued = $true
                            }
                        }
                    }
                    
                    # Create a pKICertificateTemplate object with required attributes, carefully tracking which are single/multi-valued
                    $templateAttributes = @{}
                    
                    # First set of attributes that are definitely single-valued
                    $singleValuedAttributes = @{
                        'displayName' = $templateName
                        'pKIMaxIssuingDepth' = 0
                        'pKIDefaultKeySpec' = 1
                    }
                    
                    # Add each single-valued attribute and log it
                    foreach ($key in $singleValuedAttributes.Keys) {
                        $templateAttributes[$key] = $singleValuedAttributes[$key]
                        $attributeDefinitions[$key] = @{ IsSingleValued = $true }
                        Write-Host "[+] Adding single-valued attribute: $key = $($singleValuedAttributes[$key])" -ForegroundColor Green
                    }
                    
                    # Now handle potentially multi-valued attributes with careful checking
                    $attributesToCheck = @(
                        @{ Name = 'msPKI-Certificate-Name-Flag'; Value = 1 },
                        @{ Name = 'msPKI-Enrollment-Flag'; Value = 0 },
                        @{ Name = 'msPKI-Private-Key-Flag'; Value = 16 },
                        @{ Name = 'msPKI-Template-Schema-Version'; Value = 1 },
                        @{ Name = 'revision'; Value = 100 }
                    )
                    
                    foreach ($attr in $attributesToCheck) {
                        $attrDef = Get-AttributeValuesType -AttributeName $attr.Name
                        $attributeDefinitions[$attr.Name] = $attrDef
                        
                        if ($attrDef.IsSingleValued) {
                            Write-Host "[+] Adding single-valued attribute: $($attr.Name) = $($attr.Value)" -ForegroundColor Green
                            $templateAttributes[$attr.Name] = $attr.Value
                        } else {
                            Write-Host "[+] Adding multi-valued attribute: $($attr.Name) = $($attr.Value)" -ForegroundColor Green
                            $templateAttributes[$attr.Name] = @($attr.Value)
                        }
                    }
                    
                    # Handle known multi-valued attributes carefully
                    # The error is likely in pKIKeyUsage or msPKI-Certificate-Application-Policy
                    
                    # For pKIKeyUsage, check if it's multi-valued and format accordingly
                    $pKIKeyUsageAttr = Get-AttributeValuesType -AttributeName 'pKIKeyUsage'
                    $attributeDefinitions['pKIKeyUsage'] = $pKIKeyUsageAttr
                    
                    if ($pKIKeyUsageAttr.IsSingleValued) {
                        # If it's single-valued, just use the first value (128)
                        Write-Host "[+] Adding single-valued pKIKeyUsage = 128" -ForegroundColor Green
                        $templateAttributes['pKIKeyUsage'] = 128  # Just use a single value
                    } else {
                        # If it's multi-valued, use an array with proper byte type
                        Write-Host "[+] Adding multi-valued pKIKeyUsage = (0, 128)" -ForegroundColor Green
                        $templateAttributes['pKIKeyUsage'] = [byte[]]@(0, 128)
                    }
                    
                    # For msPKI-Certificate-Application-Policy, check if it's multi-valued
                    $appPolicyAttr = Get-AttributeValuesType -AttributeName 'msPKI-Certificate-Application-Policy'
                    $attributeDefinitions['msPKI-Certificate-Application-Policy'] = $appPolicyAttr
                    
                    if ($appPolicyAttr.IsSingleValued) {
                        # If it's single-valued, just use the first value
                        Write-Host "[+] Adding single-valued msPKI-Certificate-Application-Policy = 1.3.6.1.5.5.7.3.2" -ForegroundColor Green
                        $templateAttributes['msPKI-Certificate-Application-Policy'] = "1.3.6.1.5.5.7.3.2"
                    } else {
                        # If it's multi-valued, use an array
                        Write-Host "[+] Adding multi-valued msPKI-Certificate-Application-Policy = (1.3.6.1.5.5.7.3.2, 1.3.6.1.5.5.7.3.1)" -ForegroundColor Green
                        $templateAttributes['msPKI-Certificate-Application-Policy'] = @("1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1")
                    }
                    
                    # For binary attributes, handle them carefully
                    try {
                        Write-Host "[+] Adding pKIExpirationPeriod as binary value" -ForegroundColor Green
                        $templateAttributes['pKIExpirationPeriod'] = [byte[]]@(0x00, 0x40, 0x39, 0x87, 0x2E, 0xE1, 0xFE, 0xFF)
                    } catch {
                        Write-Host "[!] Could not set pKIExpirationPeriod attribute: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                    
                    try {
                        Write-Host "[+] Adding pKIOverlapPeriod as binary value" -ForegroundColor Green
                        $templateAttributes['pKIOverlapPeriod'] = [byte[]]@(0x00, 0x80, 0xA6, 0x0A, 0xFF, 0xDE, 0xFF, 0xFF)
                    } catch {
                        Write-Host "[!] Could not set pKIOverlapPeriod attribute: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                    
                    # Log the attributes with their value types
                    Write-Host "`n[i] Final attribute list to create template:" -ForegroundColor Cyan
                    foreach ($key in $templateAttributes.Keys) {
                        $value = $templateAttributes[$key]
                        $valueType = if ($value -is [Array]) { "Array[$($value.Count)]" } else { $value.GetType().Name }
                        $isSingleValued = $attributeDefinitions[$key].IsSingleValued
                        $singleValuedText = if ($isSingleValued) { "SINGLE-VALUED" } else { "MULTI-VALUED" }
                        
                        Write-Host "   - $key = $value ($valueType) [$singleValuedText]" -ForegroundColor Gray
                    }
                    
                    # Create the template object with detailed error handling
                    try {
                        Write-Host "`n[i] Creating PKI certificate template object..." -ForegroundColor Cyan
                        
                        New-ADObject -Name $templateName -Type "pKICertificateTemplate" -Path $containerDN -OtherAttributes $templateAttributes
                        Write-Host "[+] Created PKI certificate template: $templateDN" -ForegroundColor Green
                        $createdObjectDNs += $templateDN  # Add to our tracking list
                    } catch {
                        $errorMsg = $_.Exception.Message
                        $errorDetails = if($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { "No additional details" }
                        
                        Write-Host "[!] Failed to create PKI certificate template" -ForegroundColor Red
                        Write-Host "    Error: $errorMsg" -ForegroundColor Red
                        Write-Host "    Details: $errorDetails" -ForegroundColor Red
                        
                        # Parse the error message to see if it mentions which attribute is causing the problem
                        if ($errorMsg -match "attribute that can have only one value") {
                            Write-Host "`n[i] TROUBLESHOOTING ADVICE:" -ForegroundColor Cyan
                            Write-Host "    The error suggests we're trying to provide multiple values for a single-valued attribute." -ForegroundColor Cyan
                            Write-Host "    Let's try to create the template with fewer attributes to pinpoint the problem." -ForegroundColor Cyan
                            
                            # Try a more minimal template with only essential attributes
                            $minimalAttributes = @{
                                'displayName' = $templateName
                            }
                            
                            try {
                                Write-Host "`n[i] Attempting to create minimal template with just displayName..." -ForegroundColor Yellow
                                New-ADObject -Name "${templateName}-minimal" -Type "pKICertificateTemplate" -Path $containerDN -OtherAttributes $minimalAttributes
                                Write-Host "[+] Minimal template created successfully! This suggests other attributes are causing the issue." -ForegroundColor Green
                                
                                # Try adding attributes one by one to identify the problematic one
                                $problematicAttributes = @()
                                
                                foreach ($key in $templateAttributes.Keys) {
                                    if ($key -eq 'displayName') { continue }
                                    
                                    $testAttributes = $minimalAttributes.Clone()
                                    $testAttributes[$key] = $templateAttributes[$key]
                                    
                                    try {
                                        Write-Host "[i] Testing attribute: $key" -ForegroundColor Yellow
                                        New-ADObject -Name "${templateName}-test-$key" -Type "pKICertificateTemplate" -Path $containerDN -OtherAttributes $testAttributes -ErrorAction Stop
                                        Write-Host "[+] Attribute $key is OK" -ForegroundColor Green
                                    } catch {
                                        Write-Host "[!] Attribute $key causes error: $($_.Exception.Message)" -ForegroundColor Red
                                        $problematicAttributes += $key
                                    }
                                }
                                
                                if ($problematicAttributes.Count -gt 0) {
                                    Write-Host "`n[!] Problematic attributes identified:" -ForegroundColor Red
                                    foreach ($attr in $problematicAttributes) {
                                        Write-Host "   - $attr = $($templateAttributes[$attr])" -ForegroundColor Red
                                    }
                                }
                                
                                # Use the minimal template as our created object
                                $templateDN = "CN=${templateName}-minimal,$containerDN"
                                $createdObjectDNs += $templateDN
                                
                            } catch {
                                Write-Host "[!] Even minimal template creation failed: $($_.Exception.Message)" -ForegroundColor Red
                                Write-Host "    This suggests fundamental issues with creating PKI certificate templates in this environment." -ForegroundColor Red
                            }
                        }
                        
                        # Skip to the next template
                        continue
                    }
                } catch {
                    Write-Host "[!] Error during PKI template attribute analysis: $($_.Exception.Message)" -ForegroundColor Red
                    continue  # Skip to the next object
                }
            }
            
            # First add audit SACL only - don't apply restrictive permissions yet
            try {
                SetAuditSACL -DistinguishedName $templateDN
                Write-Host "[+] Applied audit SACL to $templateDN" -ForegroundColor Green
            } catch {
                Write-Host "[!] Could not apply audit SACL: $($_.Exception.Message)" -ForegroundColor Yellow
            }
            
            # Add to group - with non-restrictive permissions in place
            try {
                Add-ADGroupMember -Identity $CanaryGroup.distinguishedName -Members $templateDN -ErrorAction Stop
                Write-Host "[+] Added PKI template to group" -ForegroundColor Green
            } catch {
                Write-Host "[!] Could not add PKI template to group: $($_.Exception.Message)" -ForegroundColor Yellow
                # Try alternative method if the first fails
                try {
                    Write-Host "[i] Trying alternative method to add to group..." -ForegroundColor Cyan
                    Set-ADGroup -Identity $CanaryGroup.distinguishedName -Add @{member=$templateDN}
                    Write-Host "[+] Added PKI template to group using alternative method" -ForegroundColor Green
                } catch {
                    Write-Host "[!] Alternative method also failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            
            # Record in output file
            try {
                $createdObject = Get-ADObject -Identity $templateDN -Properties * -ErrorAction Stop
                $name = $createdObject.Name
                $guid = $createdObject.ObjectGUID
                Add-Content -Path $Output "N/A,$guid,$name"
            } catch {
                Write-Host "[!] Could not get PKI template properties: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        
        # Process domain policies
        $domainPolicies = $SpecialCanaries | Where-Object { $_.Type -eq "domainPolicy" }
        
        foreach ($policy in $domainPolicies) {
            $policyName = $policy.Name
            $policyDN = "CN=$policyName,$containerDN"
            
            Write-Host "[i] Creating domain policy: $policyName" -ForegroundColor Cyan
            
            # Check if the policy already exists
            $policyExists = $false
            try {
                Get-ADObject -Identity $policyDN -ErrorAction Stop
                $policyExists = $true
                Write-Host "[-] Domain policy already exists: $policyDN" -ForegroundColor Yellow
                $createdObjectDNs += $policyDN  # Add to our tracking list
            } catch {
                $policyExists = $false
            }
            
            if (-not $policyExists) {
                try {
                    # Check if the groupPolicyContainer schema class exists
                    $schemaExists = $false
                    try {
                        $schemaNC = (Get-ADRootDSE).schemaNamingContext
                        $gpcSchema = Get-ADObject -Filter "name -eq 'Group-Policy-Container'" -SearchBase $schemaNC -ErrorAction SilentlyContinue
                        $schemaExists = ($gpcSchema -ne $null)
                        
                        if ($schemaExists) {
                            Write-Host "[+] Group Policy Container schema extensions are available" -ForegroundColor Green
                        } else {
                            Write-Host "[!] Group Policy Container schema extensions not found. This is required for Group Policy objects." -ForegroundColor Yellow
                        }
                    } catch {
                        Write-Host "[!] Error checking Group Policy Container schema: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                    
                    # Create a unique policy GUID
                    $policyGuid = [Guid]::NewGuid().ToString()
                    
                    # Analyze the schema to determine which attributes are single/multi-valued
                    Write-Host "[i] Analyzing schema for Group Policy Container attribute definitions..." -ForegroundColor Cyan
                    $attributeDefinitions = @{}
                    
                    function Get-AttributeValuesType {
                        param($AttributeName)
                        
                        try {
                            $attributeSchema = Get-ADObject -Filter "lDAPDisplayName -eq '$AttributeName'" -SearchBase $schemaNC -Properties isSingleValued
                            return @{
                                Name = $AttributeName
                                IsSingleValued = $attributeSchema.isSingleValued
                            }
                        } catch {
                            # If we can't find the attribute schema, assume it's single-valued to be safe
                            Write-Host "[!] Could not find schema definition for attribute $AttributeName" -ForegroundColor Yellow
                            return @{
                                Name = $AttributeName
                                IsSingleValued = $true
                            }
                        }
                    }
                    
                    # Define core GPO attributes
                    $policyAttributes = @{
                        'displayName' = $policyName
                    }
                    
                    # Add additional required attributes, checking each one for single/multi-valued status
                    $attributesToCheck = @(
                        @{ Name = 'gPCFunctionalityVersion'; Value = 2 },
                        @{ Name = 'flags'; Value = 0 },
                        @{ Name = 'versionNumber'; Value = 1 },
                        @{ Name = 'gPCFileSysPath'; Value = "\\$env:USERDNSDOMAIN\sysvol\$env:USERDNSDOMAIN\Policies\{$policyGuid}" }
                    )
                    
                    foreach ($attr in $attributesToCheck) {
                        $attrDef = Get-AttributeValuesType -AttributeName $attr.Name
                        $attributeDefinitions[$attr.Name] = $attrDef
                        
                        if ($attrDef.IsSingleValued) {
                            Write-Host "[+] Adding single-valued attribute: $($attr.Name) = $($attr.Value)" -ForegroundColor Green
                            $policyAttributes[$attr.Name] = $attr.Value
                        } else {
                            Write-Host "[+] Adding multi-valued attribute: $($attr.Name) = $($attr.Value)" -ForegroundColor Green
                            $policyAttributes[$attr.Name] = @($attr.Value)
                        }
                    }
                    
                    # Log the attributes with their value types
                    Write-Host "`n[i] Final attribute list to create Group Policy Container:" -ForegroundColor Cyan
                    foreach ($key in $policyAttributes.Keys) {
                        $value = $policyAttributes[$key]
                        $valueType = if ($value -is [Array]) { "Array[$($value.Count)]" } else { $value.GetType().Name }
                        $isSingleValued = if ($attributeDefinitions.ContainsKey($key)) { $attributeDefinitions[$key].IsSingleValued } else { "Unknown" }
                        $singleValuedText = if ($isSingleValued -eq $true) { "SINGLE-VALUED" } elseif ($isSingleValued -eq $false) { "MULTI-VALUED" } else { "UNKNOWN" }
                        
                        Write-Host "   - $key = $value ($valueType) [$singleValuedText]" -ForegroundColor Gray
                    }
                    
                    # Try to create the GPO with all attributes
                    try {
                        Write-Host "`n[i] Creating Group Policy Container..." -ForegroundColor Cyan
                        New-ADObject -Name $policyName -Type "groupPolicyContainer" -Path $containerDN -OtherAttributes $policyAttributes
                        Write-Host "[+] Created domain policy: $policyDN" -ForegroundColor Green
                        $createdObjectDNs += $policyDN  # Add to our tracking list
                    } catch {
                        $errorMsg = $_.Exception.Message
                        $errorDetails = if($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { "No additional details" }
                        
                        Write-Host "[!] Failed to create Group Policy Container" -ForegroundColor Red
                        Write-Host "    Error: $errorMsg" -ForegroundColor Red
                        Write-Host "    Details: $errorDetails" -ForegroundColor Red
                        
                        # Try diagnostic creation with minimal attributes
                        if ($errorMsg -match "attribute that can have only one value" -or $errorMsg -match "class-schema") {
                            Write-Host "`n[i] TROUBLESHOOTING GROUP POLICY CREATION:" -ForegroundColor Cyan
                            
                            # First try minimal attributes
                            try {
                                Write-Host "[i] Trying to create with minimal attributes (displayName only)..." -ForegroundColor Yellow
                                New-ADObject -Name "${policyName}-minimal" -Type "groupPolicyContainer" -Path $containerDN -OtherAttributes @{ 'displayName' = $policyName }
                                Write-Host "[+] Minimal GPO created! This confirms other attributes are problematic." -ForegroundColor Green
                                $minimalDN = "CN=${policyName}-minimal,$containerDN"
                                $createdObjectDNs += $minimalDN
                            } catch {
                                $gpoClassError = $_.Exception.Message
                                
                                if ($gpoClassError -match "no such object" -or $gpoClassError -match "class-schema") {
                                    Write-Host "[!] GPO schema isn't available. Creating container placeholder instead." -ForegroundColor Yellow
                                    
                                    # Create a more enticing GPO canary with sensitive-looking attributes
                                    $placeholderName = $policyName
                                    $sensitiveDescription = "Privileged Access Policy - DO NOT MODIFY"

                                    New-ADObject -Name $placeholderName -Type "container" -Path $containerDN -Description $sensitiveDescription -OtherAttributes @{
                                        'displayName' = "Restricted Admin Access Policy"
                                        'info' = "Contains privileged account access rules and domain admin equivalent permissions"
                                        'gPLink' = "[LDAP://CN=Domain Controllers,$((Get-ADDomain).DistinguishedName);0]"  # Make it look like it's linked to DCs
                                        'whenChanged' = (Get-Date).AddDays(-1)  # Make it look recently modified
                                    }

                                    # Add custom attributes to make it look like it contains sensitive settings
                                    Set-ADObject -Identity "CN=$placeholderName,$containerDN" -Add @{
                                        'keywords' = @("PrivilegedAccess", "AdminRights", "DomainAdmins")
                                        'wWWHomePage' = "\\$env:USERDNSDOMAIN\NETLOGON\RestrictedAccess"
                                    }

                                    Write-Host "[+] Created enticing Group Policy canary: CN=$placeholderName,$containerDN" -ForegroundColor Green
                                } else {
                                    Write-Host "[!] Minimal GPO creation also failed: $gpoClassError" -ForegroundColor Red
                                }
                            }
                        }
                        
                        # Continue to the next policy if we couldn't create this one
                        continue
                    }
                } catch {
                    Write-Host "[!] Error in domain policy creation process: $($_.Exception.Message)" -ForegroundColor Red
                    continue  # Skip to the next object
                }
            }
            
            # First add audit SACL only - don't apply restrictive permissions yet
            try {
                SetAuditSACL -DistinguishedName $policyDN
                Write-Host "[+] Applied audit SACL to $policyDN" -ForegroundColor Green
            } catch {
                Write-Host "[!] Could not apply audit SACL: $($_.Exception.Message)" -ForegroundColor Yellow
            }
            
            # Add to group - with non-restrictive permissions in place
            try {
                Add-ADGroupMember -Identity $CanaryGroup.distinguishedName -Members $policyDN -ErrorAction Stop
                Write-Host "[+] Added domain policy to group" -ForegroundColor Green
            } catch {
                Write-Host "[!] Could not add domain policy to group: $($_.Exception.Message)" -ForegroundColor Yellow
                # Try alternative method if the first fails
                try {
                    Write-Host "[i] Trying alternative method to add to group..." -ForegroundColor Cyan
                    Set-ADGroup -Identity $CanaryGroup.distinguishedName -Add @{member=$policyDN}
                    Write-Host "[+] Added domain policy to group using alternative method" -ForegroundColor Green
                } catch {
                    Write-Host "[!] Alternative method also failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            
            # Record in output file
            try {
                $createdObject = Get-ADObject -Identity $policyDN -Properties * -ErrorAction Stop
                $name = $createdObject.Name
                $guid = $createdObject.ObjectGUID
                Add-Content -Path $Output "N/A,$guid,$name"
            } catch {
                Write-Host "[!] Could not get domain policy properties: $($_.Exception.Message)" -ForegroundColor Yellow
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