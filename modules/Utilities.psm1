function ADObjectExists {
    param($Path)
    try {
        # First try using Get-ADObject directly
        Get-ADObject -Identity "$Path" -ErrorAction Stop
        return $True
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        # Object not found
        Write-Host "[-] AD Object not found: $Path" -ForegroundColor Yellow
        return $False
    } catch {
        # Other error
        Write-Host "[-] Error checking AD Object: $($_.Exception.Message)" -ForegroundColor Red
        return $False
    }
}

function ListObjectAttributes {
    param($ClassName)
    # Not mine - code from easy365manager.com
    # Ref : https://www.easy365manager.com/how-to-get-all-active-directory-user-object-attributes/
    $Loop = $True
    $ClassArray = [System.Collections.ArrayList]@()
    $UserAttributes = [System.Collections.ArrayList]@()
    # Retrieve the User class and any parent classes
    While ($Loop) {
        $Class = Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter { ldapDisplayName -Like $ClassName } -Properties AuxiliaryClass, SystemAuxiliaryClass, mayContain, mustContain, systemMayContain, systemMustContain, subClassOf, ldapDisplayName
        If ($Class.ldapDisplayName -eq $Class.subClassOf) {
            $Loop = $False
        }
        $ClassArray.Add($Class)
        $ClassName = $Class.subClassOf
    }
    # Loop through all the classes and get all auxiliary class attributes and direct attributes
    $ClassArray | ForEach-Object {
        # Get Auxiliary class attributes
        $Aux = $_.AuxiliaryClass | ForEach-Object { Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter { ldapDisplayName -like $_ } -Properties mayContain, mustContain, systemMayContain, systemMustContain } |
        Select-Object @{n = "Attributes"; e = { $_.mayContain + $_.mustContain + $_.systemMaycontain + $_.systemMustContain } } |
        Select-Object -ExpandProperty Attributes
        # Get SystemAuxiliary class attributes
        $SysAux = $_.SystemAuxiliaryClass | ForEach-Object { Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter { ldapDisplayName -like $_ } -Properties MayContain, SystemMayContain, systemMustContain } |
        Select-Object @{n = "Attributes"; e = { $_.maycontain + $_.systemmaycontain + $_.systemMustContain } } |
        Select-Object -ExpandProperty Attributes
        # Get direct attributes
        $UserAttributes += $Aux + $SysAux + $_.mayContain + $_.mustContain + $_.systemMayContain + $_.systemMustContain
    }
    return $UserAttributes | Sort-Object | Get-Unique
}

# Export functions
Export-ModuleMember -Function ADObjectExists, ListObjectAttributes 