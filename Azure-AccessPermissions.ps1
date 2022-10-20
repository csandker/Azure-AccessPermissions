<#
.SYNOPSIS
  Script to enumerate access permissions a user's Azure Active Directory home tenant.

.NOTES
  Version:        1.0
  Author:         0xcsandker
  Creation Date:  19.10.2022
  
.EXAMPLE
  PS:> . .\Azure-AccessPermissions.ps1
  PS:> Invoke-PermissionCheck
#>



#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script Version
$sScriptVersion = "1.0"

#Log File Info
$sLogPath = "C:\Windows\Temp"
$sLogName = "<script_name>.log"
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName

#-----------------------------------------------------------[Functions]------------------------------------------------------------


Function Invoke-PermissionCheck {
    PARAM()

    $MESSAGE_SUCCESS = '0'
    $MESSAGE_FAIL = '1'
    $MESSAGE_WARNING = '2'
    $MESSAGE_INFO = '3'
    Function Log {
        PARAM(
            [String]$Msg = '',
            [String]$MsgType = ''
        )
        Process {
            $initalFC = $host.UI.RawUI.ForegroundColor
            switch ( $MsgType )
            {
                $MESSAGE_SUCCESS {
                    $host.UI.RawUI.ForegroundColor = "Green"
                    Write-Host $Msg
                    $host.UI.RawUI.ForegroundColor = $initalFC
                    break
                }
                $MESSAGE_FAIL {
                    $host.UI.RawUI.ForegroundColor = "Red"
                    Write-Host $Msg
                    $host.UI.RawUI.ForegroundColor = $initalFC
                    break
                }
                $MESSAGE_WARNING {
                    $host.UI.RawUI.ForegroundColor = "Yellow"
                    Write-Host $Msg
                    $host.UI.RawUI.ForegroundColor = $initalFC
                    break
                }
                $MESSAGE_INFO {
                    $host.UI.RawUI.ForegroundColor = "Cyan"
                    Write-Host $Msg
                    $host.UI.RawUI.ForegroundColor = $initalFC
                    break
                }
                default {
                    $host.UI.RawUI.ForegroundColor = "DarkGray"
                    Write-Host $Msg
                    $host.UI.RawUI.ForegroundColor = $initalFC
                    break
                }
            }
        }
    }

    Function Check-RequiredModules {
        PARAM()
        Process {
            $modulesInstalled = $true
            if ( -Not (Get-Module -ListAvailable -Name Microsoft.Graph) ){
                Log -Msg "[-] Module 'Microsoft.Graph' does not exist." -MsgType $MESSAGE_FAIL
                Log -Msg "    Install it via: Install-Module Microsoft.Graph" -MsgType $MESSAGE_WARNING
                $modulesInstalled = $false
            } 
            if ( -Not (Get-Module -ListAvailable -Name AADInternals) ) {
                Log -Msg "[-] Module 'AADInternals' does not exist." -MsgType $MESSAGE_FAIL
                Log -Msg "    Install it via: Install-Module AADInternals" -MsgType $MESSAGE_WARNING
                $modulesInstalled = $false
            }
            return $modulesInstalled
        }
    }

    Function Import-RequiredModules {
        PARAM()
        Process {
            Try {
                Import-Module AADInternals 6>$null | Out-Null
                Import-Module Microsoft.Graph.Applications | Out-Null
                return $true
            }
            Catch {
                Log -Msg "[-] An error occured while trying to import required modules." -MsgType $MESSAGE_FAIL
                Log -Msg "    The error was: $_"
                return $false
            }
        }
    }

    Function Connect-MicrosoftGraph {
        PARAM()
        Process{
            $accessTokenMSGraph = Get-AADIntAccessTokenForMSGraph
            If( $accessTokenMSGraph ){
                Connect-MgGraph -AccessToken $accessTokenMSGraph
            }
            return $accessTokenMSGraph
        }
    }

    Function Get-ServicePrincipals {
        PARAM()
        Process{
            return Get-MgServicePrincipal -All
        }
    }

    Function Enumerate-ServicePrincipals {
        PARAM(
            [Object[]]$MSGraphServicePrincipals = @()
        )
        Process {
            $progressCount = 0
            $progressLimit = $MSGraphServicePrincipals.Count
            ForEach($msGraphServicePrincipal in $MSGraphServicePrincipals ){
                $progressCount += 1
                $appRoleAssignmendToResult = Get-MgServicePrincipalAppRoleAssignedTo -All -ServicePrincipalId $msGraphServicePrincipal.Id
                $appRoleAssignmentsResult = Get-MgServicePrincipalAppRoleAssignment -All -ServicePrincipalId $msGraphServicePrincipal.Id
                $oauthPermissionsResult = Get-MgServicePrincipalOauth2PermissionGrant -All -ServicePrincipalId $msGraphServicePrincipal.Id
                $owner = Get-MgServicePrincipalOwner -All -ServicePrincipalId $msGraphServicePrincipal.Id
                $delegPermissionsClassifciation = Get-MgServicePrincipalDelegatedPermissionClassification -All -ServicePrincipalId $msGraphServicePrincipal.Id
                $ownedObj = Get-MgServicePrincipalOwnedObject -All -ServicePrincipalId $msGraphServicePrincipal.Id
                $createdObjs = Get-MgServicePrincipalCreatedObject -All -ServicePrincipalId $msGraphServicePrincipal.Id
                $resourceSpecificAppPermissions = $msGraphServicePrincipal.ResourceSpecificApplicationPermissions
                #$oauthPermissionGrants = $msGraphServicePrincipal.Oauth2PermissionGrants
                #$oauthPermissionScopes = $msGraphServicePrincipal.Oauth2PermissionScopes

                Log "`n[*] Checking $($msGraphServicePrincipal.DisplayName) ($($msGraphServicePrincipal.Id))"
                ## Application-Type API Permissions of the service principal
                if( $appRoleAssignmentsResult ){
                    Log "[+] Application-Type API Permission access rights of this service principal:" -MsgType $MESSAGE_SUCCESS
                    ForEach($appRoleAssignmend in $appRoleAssignmentsResult){
                    $appRole = ((Get-MgServicePrincipal -ServicePrincipalId $appRoleAssignmend.ResourceId).AppRoles | ? {$_.Id -eq $appRoleAssignmend.AppRoleId} | Select-Object -First 1)

                    Log "  Resource: $($appRoleAssignmend.ResourceDisplayName) ($($appRoleAssignmend.ResourceId))" -MsgType $MESSAGE_INFO
                    Log "  AppRole ID: $($appRoleAssignmend.AppRoleId)" -MsgType $MESSAGE_INFO
                    Log "  AppRole:" -MsgType $MESSAGE_INFO
                    Log "    Value: $($appRole.Value)" -MsgType $MESSAGE_INFO
                    Log "    Display Name: $($appRole.DisplayName)" -MsgType $MESSAGE_INFO
                    Log "    AllowedMemberTypes: $($appRole.AllowedMemberTypes)" -MsgType $MESSAGE_INFO
                    Log "    Enabled: $($appRole.IsEnabled)" -MsgType $MESSAGE_INFO
                    #Write-Output "  $($appRoleAssignmend.PrincipalType): $($appRoleAssignmend.PrincipalDisplayName) ($($appRoleAssignmend.PrincipalId))"
                }
                }

                ## Delegated-Type API Permissions of the service principal
                if( $oauthPermissionsResult ){
                    Log "[+] Delegated-Type API Permission access rights of this service principal:" -MsgType $MESSAGE_SUCCESS
                    ForEach($oauthPermissions in $oauthPermissionsResult){
                        $principal = If($oauthPermissions.PrincipalId) {(Get-MgDirectoryObjectById -Ids $oauthPermissions.PrincipalId).AdditionalProperties.userPrincipalName} Else { "" }
                        $resource = If($oauthPermissions.ResourceId) {(Get-MgDirectoryObjectById -Ids $oauthPermissions.ResourceId).AdditionalProperties.displayName} Else {""}
                        $client = If($oauthPermissions.ClientId) {(Get-MgDirectoryObjectById -Ids $oauthPermissions.ClientId).AdditionalProperties.displayName} Else {""}

                        Log "  Resource: $($resource) ($($oauthPermissions.ResourceId))" -MsgType $MESSAGE_INFO
                        Log "  Consent To: $($oauthPermissions.ConsentType)" -MsgType $MESSAGE_INFO
                        Log "  Principal: $($principal) ($($oauthPermissions.PrincipalId))" -MsgType $MESSAGE_INFO
                        Log "  Scope: $($oauthPermissions.Scope)" -MsgType $MESSAGE_INFO
                        Log "  Client: $($client) ($($oauthPermissions.ClientId))" -MsgType $MESSAGE_INFO
                        Log "  Additional Attributes:" -MsgType $MESSAGE_INFO
                        $oauthPermissions.AdditionalProperties.Keys.ForEach{"    $($_): $($oauthPermissions.AdditionalProperties[$_])"}
                        Log ""
                    }
                }

                ## Principals with assigned AppRoles to this service account
                if( $appRoleAssignmendToResult ){
                    Log "[+] The following principals have an AppRole assigned for this this service account:" -MsgType $MESSAGE_SUCCESS
                    ForEach($appRoleAssignmendTo in $appRoleAssignmendToResult){
                        $appRoleValue = 'default'
                        ## 00000000-0000-0000-0000-000000000000 is the default appRoleID
                        If( $appRoleAssignmendTo.AppRoleId -ne '00000000-0000-0000-0000-000000000000' ){
                            $appRole = $msGraphServicePrincipal.appRoles | ? {$_.Id -eq $appRoleAssignmendTo.AppRoleId} | Select-Object -First 1
                            $appRoleValue = $appRole.Value 
                        }
                        Log "  $($appRoleAssignmendTo.PrincipalType): $($appRoleAssignmendTo.PrincipalDisplayName) ($($appRoleAssignmendTo.PrincipalId))"  -MsgType $MESSAGE_INFO
                        Log "    Value: $($appRoleValue) ($($appRoleAssignmendTo.AppRoleId))" -MsgType $MESSAGE_INFO
                    }
                }

                ## Owner of the service principal
                If($owner){
                    Log "[+] Owner" -MsgType $MESSAGE_SUCCESS
                    Log "  User: $($owner.AdditionalProperties.userPrincipalName)"
                    Log "  Additional Properties:"
                    $owner.AdditionalProperties.Keys.ForEach{"    $($_): $($owner.AdditionalProperties[$_])"} 
                }

                ## Other Attributes of interest
                if($delegPermissionsClassifciation){
                    Log "[+] Delegated permission classifications" -MsgType $MESSAGE_SUCCESS
                    $delegPermissionsClassifciation | fl
                }

                if($ownedObj){
                    Log "[+] Owned Objects" -MsgType $MESSAGE_SUCCESS
                    $ownedObj | fl
                }

                if($createdObjs){
                    Log "[+] Created Objects" -MsgType $MESSAGE_SUCCESS
                    Log $createdObjs | fl
                }

                if( $resourceSpecificAppPermissions ){
                    Log "[+] Resource specific Application Permissions" -MsgType $MESSAGE_SUCCESS
                    Log "  (Currently only supported for Teams, see: https://learn.microsoft.com/en-us/graph/api/resources/resourcespecificpermission?view=graph-rest-1.0)"
                    ForEach($resourceSpecificAppPermission in $resourceSpecificAppPermissions){
                        Log "  ID: $($resourceSpecificAppPermission.Id)" -MsgType $MESSAGE_INFO
                        Log "  Enabled: $($resourceSpecificAppPermission.IsEnabled)" -MsgType $MESSAGE_INFO
                        Log "  Value: $($resourceSpecificAppPermission.VAlue)" -MsgType $MESSAGE_INFO
                        Log "  DisplayName: $($resourceSpecificAppPermission.displayName)`n" -MsgType $MESSAGE_INFO
                    }
                }

                $progressOperation = "$progressCount/$progressLimit"
                $progressPercentage = ($progressCount/$progressLimit)*100
                Write-Progress -Activity "Enumerating Service Principals" -PercentComplete $progressPercentage -CurrentOperation $progressOperation
            }
            Write-Progress -Activity "Enumerating Service Principals" -Status "Ready" -Completed

        }
    }

    ####
    ### Getting started
    ####

    ## Check if all the required modules are installed
    If( Check-RequiredModules ){
        Log "[*] Loadign required modules."
        $windowTitle = $host.ui.RawUI.WindowTitle
        If( Import-RequiredModules ){
            $host.ui.RawUI.WindowTitle = $windowTitle
            Log "[*] Modules imported."
            Log "[*] Connecting to Microsoft Graph."
            $accessTokenMSGraph = Connect-MicrosoftGraph
            If( $accessTokenMSGraph ){
                $msGraphServicePrincipals = Get-ServicePrincipals
                Log "[+] $($msGraphServicePrincipals.Count) Service Principals found in tenant..." -MsgType $MESSAGE_SUCCESS
                Enumerate-ServicePrincipals -MSGraphServicePrincipals $msGraphServicePrincipals
            }
            Else {
                Log -Msg "[-] An error occured while trying to connect to Micrsoft Graph." -MsgType $MESSAGE_FAIL
                Log -Msg "    We can't continue. Please retry..."
            }
        }
    }
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------
