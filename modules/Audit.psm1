function CheckSACLs {
    $ErrorActionPreference = "SilentlyContinue"
    Write-Host "`n[*] Listing AD objects with ReadAudit enabled (SACL) :"
    Get-ADObject -Filter * | ForEach-Object {
        $DN = $_.DistinguishedName
        (Get-Acl -Path "AD:/$DN" -Audit).Audit | ForEach-Object {
            $Rights = $_.ActiveDirectoryRights
            $Trustee = $_.IdentityReference
            if($Rights -match "ReadProperty" -or $Rights -match "GenericAll"){
                Write-Host "    - $DN : `t`t$Rights ($Trustee)"
            }
        }
    }
    $ErrorActionPreference = "Inquire"
}

function GetObjectPropertiesGuids {
    param($Output)
    
    $ErrorActionPreference = "SilentlyContinue"
    $AttributesList = New-Object System.Collections.ArrayList
    Foreach($Class in ("User", "Computer", "Group")){
        $Attributes = ListObjectAttributes -ClassName $Class
        Write-Host "[*] Attributes retrieved for objectClass : $Class"
        Foreach($Attribute in $Attributes){
            $exp = "Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter "+ '"ldapDisplayName -eq '+ "'$attribute'"+' -and objectClass -eq '+ "'attributeSchema'"+ '" -Properties * | Select ldapDisplayName, schemaIDGuid'
            $a = (Invoke-Expression $exp)
            if(-not ($null -eq $a.schemaIDGuid)){
                $a.schemaIDGuid = $a.schemaIDGuid -as [guid]
                if(-not $AttributesList.Contains($a)){$AttributesList.Add($a)>$null}
            }
        }
        Write-Host "[*] Attribute's Guids retrieved for objectClass : $Class"
    }
    Remove-Item -Path $Output -ErrorAction SilentlyContinue
    Add-Content -Path $Output ($AttributesList | ConvertTo-Csv)
    $Total = $AttributesList.Count
    Write-Host "[*] Total attributes retrieved : $Total"
    Write-Host "[*] You can grab $Output to lookup these attributes when access is denied on the canaries"
    $ErrorActionPreference = "Inquire"
}

# Export functions
Export-ModuleMember -Function CheckSACLs, GetObjectPropertiesGuids 