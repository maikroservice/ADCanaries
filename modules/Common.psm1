# Import required modules
Import-Module ActiveDirectory

function DisplayHelpAndExit {
    Write-Host "
Usage : ./ADCanaries.ps1  -Populate -Config <Path> -ParentOU <OU> \
                                                   -Owner <Principal|Group Name> \
                                                   -CanaryOrganizationalUnit <Name>          : Populate default ADCanaries deployment; overwrites json config file provided.
                          -Deploy -Config <Path> -Output <Path>                     : Deploy ADCanaries using json configuration file and outputs lookup CSV with CanaryName,CanaryGUID
                          -Revert -Config <Path>                                    : Destroy ADCanaries using json configuration file
                          -AuditSACLs                                               : Display the list of existing AD objects with (ReadProperty|GenericAll) audit enabled to help measure DS Access audit failure activation impact
                          -GetObjectPropertiesGuids -Output <Path>                  : Retreives the schemaIDGuid for attributes of Canaries objectClass and outputs as csv
"
    exit $true
}

function DisplayCanaryBanner {
    Write-Host @"
        .---.        .-----------
     /     \  __  /    ------
    / /     \(00)/    -----
   //////   ' \/ `   ---             ADCanaries v0.2.1
  //// / // :    : ---
 // /   /  /`    '--
//          //..\\
       ====UU====UU====
           '//||\\`
             ''``
"@
    Write-Host "[*] Deployment of ADCanaries require DS Access audit to be enabled on Failure on all your Domain Controllers :"
    Write-Host "
                  Computer Configuration
                    > Policies
                      > Windows Settings
                        > Security Settings
                          > Advanced Auditing Policy Configuration
                            > System Audit Policies
                              > DS Access
                                  Directory Service Access : Failure
    "
    Write-Host "[*] All failed read access to audit-enabled AD objects will generate Windows Security Events."
    Write-Host "[*] Please ensure you have estimated the amount of events this deployment will generate in your log managing system."
}

function CheckParameter($Param) {
    if ($null -eq $Param) {
        DisplayHelpAndExit
    }
}

function ValidateAction {
    $Confirmation = ""
    while($Confirmation -ne "y" -and $Confirmation -ne "n"){
        $Confirmation = Read-Host "[?] Are you sure you want to deploy / remove ADCanaries on your domain ? (y/n)"
    }
    Write-Host ""

    if($Confirmation -eq "n"){exit $true}
}

# Export functions
Export-ModuleMember -Function DisplayHelpAndExit, DisplayCanaryBanner, CheckParameter, ValidateAction 