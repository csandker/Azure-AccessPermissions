<#
.SYNOPSIS
  Script to enumerate access permissions of a user's Azure Active Directory home tenant.

.NOTES
  Author:         0xcsandker
  Creation Date:  19.10.2022
  
.EXAMPLE
  PS:> . .\Azure-AccessPermissions.ps1
  PS:> Invoke-AccessCheckForCurrentUser

.EXAMPLE
  PS:> . .\Azure-AccessPermissions.ps1
  PS:> Invoke-AccessCheckForAllServicePrincipals

.EXAMPLE
  PS:> . .\Azure-AccessPermissions.ps1
  PS:> Invoke-AccessCheckForServicePrincipal -ServicePrincipalIdentifier 94fc9712-01e1-4115-ad4e-56a428e438b0
#>

#----------------------------------------------------------[Declarations]----------------------------------------------------------

# Script Version
$sScriptVersion = "0.2.2"

$banner=@"
     _                                _                         ____                     _         _                 
    / \    _____   _ _ __ ___        / \   ___ ___ ___  ___ ___|  _ \ ___ _ __ _ __ ___ (_)___ ___(_) ___  _ __  ___ 
   / _ \  |_  / | | | '__/ _ \_____ / _ \ / __/ __/ _ \/ __/ __| |_) / _ \ '__| '_ ` _ \| / __/ __| |/ _ \| '_ \/ __|
  / ___ \  / /| |_| | | |  __/_____/ ___ \ (_| (_|  __/\__ \__ \  __/  __/ |  | | | | | | \__ \__ \ | (_) | | | \__ \
 /_/   \_\/___|\__,_|_|  \___|    /_/   \_\___\___\___||___/___/_|   \___|_|  |_| |_| |_|_|___/___/_|\___/|_| |_|___/
                                                                                                                     
 v$sScriptVersion by @0xcsandker

 Here are the functions you might wanna use:
    Invoke-AccessCheckForServicePrincipal           ## Specific Service Principals
    Invoke-AccessCheckForAllServicePrincipals       ## All Service Principals
    Invoke-AccessCheckForGroup                      ## Specific Group
    Invoke-AccessCheckForAllGroups                  ## All Groups
    Invoke-AccessCheckForUser                       ## Specifc User
    Invoke-AccessCheckForAllUsers                   ## All Users
    Invoke-AccessCheckForCurrentUser                ## Your current User
    Invoke-AllAccessChecks                          ## All of the above

    Enumerate-AllHighPrivilegePrincipals            ## Find all high privileged principals
    Enumerate-MFAStatusOfHighPrivilegePrincipals    ## Check the MFA Status of all high privileged principals
"@

$wellKnownApplicationIDs = @{
    ## NOTE: THIS is not a complete list, but rather an add-on-the-go-list
    ### I don't want this script to be too bloated
    "00000002-0000-0ff1-ce00-000000000000" = "Exchange Online";
    "00000003-0000-0ff1-ce00-000000000000" = "SharePoint Online";
    "00000004-0000-0ff1-ce00-000000000000" = "Skype for Business online";
    "0000000a-0000-0000-c000-000000000000" = "DeviceManagementApp (Microsoft Intune)";
    "1b730954-1685-4b74-9bfd-dac224a7b894" = "MS Graph API";
    "a0c73c16-a7e3-4564-9a95-2bdf47383716" = "MS Exchange Remote PowerShell";
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264" = "MS Teams";
    "d3590ed6-52b3-4102-aeff-aad2292ab01c" = "Microsoft Support and Recovery Assistant (SARA)";
    "ab9b8c07-8f02-4f72-87fa-80105867a763" = "OneDrive Sync Engine";
    "de0853a1-ab20-47bd-990b-71ad5077ac7b" = "Windows Configuration Designer (WCD)";
    "d4ebce55-015a-49b5-a083-c84d1797ae8c" = "Microsoft Intune Enrollment"
}

#-----------------------------------------------------------[Functions]------------------------------------------------------------

$MESSAGE_SUCCESS = '0'
$MESSAGE_FAIL = '1'
$MESSAGE_WARNING = '2'
$MESSAGE_INFO = '3'
Function __AAP-Log {
    PARAM(
        [String]
        $Msg = '',
        
        [String]
        $MsgType = '',

        [Int]
        $IndentationLevel = 0,

        [Switch]
        $NoNewLine = $false

    )
    Process {
        $initalFC = $host.UI.RawUI.ForegroundColor
        switch ( $MsgType )
        {
            $MESSAGE_SUCCESS {
                $host.UI.RawUI.ForegroundColor = "Green"
                Write-Host "$(' '*$IndentationLevel)$($Msg)" -NoNewline:$NoNewLine
                $host.UI.RawUI.ForegroundColor = $initalFC
                break
            }
            $MESSAGE_FAIL {
                $host.UI.RawUI.ForegroundColor = "Red"
                Write-Host "$(' '*$IndentationLevel)$($Msg)" -NoNewline:$NoNewLine
                $host.UI.RawUI.ForegroundColor = $initalFC
                break
            }
            $MESSAGE_WARNING {
                $host.UI.RawUI.ForegroundColor = "Yellow"
                Write-Host "$(' '*$IndentationLevel)$($Msg)" -NoNewline:$NoNewLine
                $host.UI.RawUI.ForegroundColor = $initalFC
                break
            }
            $MESSAGE_INFO {
                $host.UI.RawUI.ForegroundColor = "Cyan"
                Write-Host "$(' '*$IndentationLevel)$($Msg)" -NoNewline:$NoNewLine
                $host.UI.RawUI.ForegroundColor = $initalFC
                break
            }
            default {
                $host.UI.RawUI.ForegroundColor = "DarkGray"
                Write-Host "$(' '*$IndentationLevel)$($Msg)" -NoNewline:$NoNewLine
                $host.UI.RawUI.ForegroundColor = $initalFC
                break
            }
        }
        if( $Outfile ){
            $script:gOutFileMessageBuffer += $Msg
            If(-Not $NoNewLine) {
                "$(' '*$IndentationLevel)$($script:gOutFileMessageBuffer)" | Out-File -Append -FilePath $Outfile
                $script:gOutFileMessageBuffer = ""
            }
        }
    }
}

Function __AAP-AppRoleIsHighPrivilegeConfidenceGuess {
    PARAM(
        [Object]
        $AppRoleObject
    )
    Process {
        ##
        ## confidence level 
        ##  0 => Assumed Not high privilege
        ##  >0 => Assumed high privilege
        ##  100 => Certainly high privilege
        $confidenceLevel = 0
        If( $AppRoleObject.Value ){
            If( $AppRoleObject.Value -eq 'Directory.ReadWrite.All' ){
                $confidenceLevel = 100
            }
            ElseIf( $AppRoleObject.Value -Like '*FullControl.All' ){
                $confidenceLevel = 10
            }
            ElseIf( $AppRoleObject.Value -Like '*ReadWrite.All' ){
                $confidenceLevel = 10
            }
            ElseIf( $AppRoleObject.Value -Like 'full_access*' ){
                $confidenceLevel = 10
            }
        }
        ## Return condifence level 
        return $confidenceLevel
    }
}

Function __AAP-DisplayAppRoleAssignments {
    PARAM(
        [Object[]]
        $AppRoleAssignments,

        [Int]
        $IndentationLevel = 0
    )
    Process {
        ForEach($appRoleAssignment in $AppRoleAssignments){
            $appRoleValue = 'default'
            $appRole = $null
            $highPrivConfidenceLevel = $null
            If( $appRoleAssignment.AppRoleId -ne '00000000-0000-0000-0000-000000000000' ){
                $appRole = ((Get-MgServicePrincipal -ServicePrincipalId $appRoleAssignment.ResourceId).AppRoles | ? {$_.Id -eq $appRoleAssignment.AppRoleId} | Select-Object -First 1)
                $appRoleValue = $appRole.Value 
                If( $appRole ){
                    $highPrivConfidenceLevel =__AAP-AppRoleIsHighPrivilegeConfidenceGuess -AppRoleObject $appRole
                }
            }
            __AAP-Log "  Resource: $($appRoleAssignment.ResourceDisplayName) ($($appRoleAssignment.ResourceId))" -MsgType $MESSAGE_INFO -IndentationLevel $RecursionCounterDoNotUse
            __AAP-Log "  AppRole ID: $($appRoleAssignment.AppRoleId)" -MsgType $MESSAGE_INFO -IndentationLevel $RecursionCounterDoNotUse
            If( $highPrivConfidenceLevel ){
                 __AAP-Log "  AppRole ([!] Might be high privileged. Confidence $($highPrivConfidenceLevel)/100): " -MsgType $MESSAGE_WARNING -IndentationLevel $RecursionCounterDoNotUse
            } Else {
                __AAP-Log "  AppRole:" -MsgType $MESSAGE_INFO -IndentationLevel $RecursionCounterDoNotUse
            }
            __AAP-Log "    Value: $($appRoleValue)" -MsgType $MESSAGE_INFO -IndentationLevel $RecursionCounterDoNotUse
            __AAP-Log "    Display Name: $($appRole.DisplayName)" -MsgType $MESSAGE_INFO -IndentationLevel $RecursionCounterDoNotUse
            __AAP-Log "    AllowedMemberTypes: $($appRole.AllowedMemberTypes)" -MsgType $MESSAGE_INFO -IndentationLevel $RecursionCounterDoNotUse
            __AAP-Log "    Enabled: $($appRole.IsEnabled)" -MsgType $MESSAGE_INFO -IndentationLevel $RecursionCounterDoNotUse
            __AAP-Log ""
            #__AAP-Log "  $($appRoleAssignmend.PrincipalType): $($appRoleAssignmend.PrincipalDisplayName) ($($appRoleAssignmend.PrincipalId))"
        }
    }
}

Function __AAP-DisplayOauth2PermissionGrants {
    PARAM(
        [Object[]]$Oauth2PermissionGrants
    )
    Process {
        ForEach($Oauth2PermissionGrant in $Oauth2PermissionGrants){
            $principal = If($Oauth2PermissionGrant.PrincipalId) {(Get-MgDirectoryObjectById -Ids $Oauth2PermissionGrant.PrincipalId).AdditionalProperties.userPrincipalName} Else { "" }
            $resource = If($Oauth2PermissionGrant.ResourceId) {(Get-MgDirectoryObjectById -Ids $Oauth2PermissionGrant.ResourceId).AdditionalProperties.displayName} Else {""}
            $client = If($Oauth2PermissionGrant.ClientId) {(Get-MgDirectoryObjectById -Ids $Oauth2PermissionGrant.ClientId).AdditionalProperties.displayName} Else {""}

            __AAP-Log "  Resource: $($resource) ($($Oauth2PermissionGrant.ResourceId))" -MsgType $MESSAGE_INFO
            __AAP-Log "  Consent To: $($Oauth2PermissionGrant.ConsentType)" -MsgType $MESSAGE_INFO
            __AAP-Log "  Principal: $($principal) ($($Oauth2PermissionGrant.PrincipalId))" -MsgType $MESSAGE_INFO
            __AAP-Log "  Scope: $($Oauth2PermissionGrant.Scope)" -MsgType $MESSAGE_INFO
            __AAP-Log "  Client: $($client) ($($Oauth2PermissionGrant.ClientId))" -MsgType $MESSAGE_INFO
            __AAP-Log "  Additional Attributes:" -MsgType $MESSAGE_INFO
            $Oauth2PermissionGrant.AdditionalProperties.Keys.ForEach{"    $($_): $($Oauth2PermissionGrant.AdditionalProperties[$_])"}
            __AAP-Log ""
        }
    }
}

Function __AAP-GetHighPrivilegedDirectoryRoleTemplateMap {
    PARAM()
    Process {
        return @{
            '62E90394-69F5-4237-9190-012177145E10' = 'Global administrator';
            '9B895D92-2CD3-44C7-9D02-A6AC2D5EA5C3' = 'Application administrator';
            'C4E39BD9-1100-46D3-8C65-FB160DA0071F' = 'Authentication Administrator';
            'B0F54661-2D74-4C50-AFA3-1EC803F12EFE' = 'Billing administrator';
            '158C047A-C907-4556-B7EF-446551A6B5F7' = 'Cloud application administrator';
            'B1BE1C3E-B65D-4F19-8427-F6FA0D97FEB9' = 'Conditional Access administrator';
            '29232CDF-9323-42FD-ADE2-1D097AF3E4DE' = 'Exchange administrator';
            '729827E3-9C14-49F7-BB1B-9608F156BBB8' = 'Helpdesk administrator';
            '966707D0-3269-4727-9BE2-8C3A10F19B9D' = 'Password administrator';
            '7BE44C8A-ADAF-4E2A-84D6-AB2649E08A13' = 'Privileged authentication administrator';
            'E8611AB8-C189-46E8-94E1-60213AB1F814' = 'Privileged Role Administrator';
            '194AE4CB-B126-40B2-BD5B-6091B380977D' = 'Security administrator';
            'F28A1F50-F6E7-4571-818B-6A12F2AF6B6C' = 'SharePoint administrator';
            'FE930BE7-5E62-47DB-91AF-98C3A49A38B1' = 'User administrator';

            ## 'F2EF992C-3AFB-46B9-B7CF-A126EE74C451' = 'Global Reader';
        }
    }
}

Function __AAP-DisplayDirectoryRoleAssignment {
    PARAM(
        [Object]$MgDirectoryRole
    )
    Begin {
        #$mgAllDirectoryRoles = Get-MgDirectoryRole -All
        $highPrivilegedDirectoryRoles = __AAP-GetHighPrivilegedDirectoryRoleTemplateMap
    }
    Process {
        ## Azure AD Builtin Roles are described here: https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference
        If( $MgDirectoryRole.RoleTemplateId.toUpper() -In $highPrivilegedDirectoryRoles.Keys ){
           __AAP-Log "  DirectoryRole: $($MgDirectoryRole.DisplayName) ([!] High privileged)" -MsgType $MESSAGE_WARNING
           __AAP-Log "    $($MgDirectoryRole.Description)"
        }
        Else {
            __AAP-Log "  DirectoryRole: $($MgDirectoryRole.DisplayName) (RoleTemplate ID: $($MgDirectoryRole.RoleTemplateId))" -MsgType $MESSAGE_INFO
            __AAP-Log "    $($MgDirectoryRole.Description)"
        }
    }
}

Function __AAP-DisplayHighPrivilegePrincipalMap {
    PARAM()
    Process {
        __AAP-Log "## High Privileged Principals "
        __AAP-Log "[*] Number of high privileged Accounts: $($script:gHighPrivilegdPrincipalMap.Keys.Count)" -MsgType $MESSAGE_WARNING
        ForEach($principalID in $script:gHighPrivilegdPrincipalMap.Keys){
            $principalEntries = $script:gHighPrivilegdPrincipalMap[$principalID]
            $firstEntry = $principalEntries[0]
            $absoluteConfidenceEntries = $principalEntries | ? { $_['ConfidenceLevel'] -eq 100 }
            
            __AAP-Log "[+] $($firstEntry['principalName']) ($($firstEntry['principalID'])) [Type: $($firstEntry['principalType'])]"  -MsgType $MESSAGE_SUCCESS
            ## If there is an entry with 100 confidence display only these entries
            If( $absoluteConfidenceEntries ){
                ForEach($absoluteConfidenceEntry in $absoluteConfidenceEntries){
                    __AAP-Log "  Reason: $($absoluteConfidenceEntry['Reason']) (Confidence: $($absoluteConfidenceEntry['ConfidenceLevel'])/100)"  -MsgType $MESSAGE_INFO
                }
            }
            ## Otherwise display all entries
            Else {
                ForEach($principalEntry in $principalEntries){
                    __AAP-Log "  Reason: $($principalEntry['Reason']) (Confidence: $($principalEntry['ConfidenceLevel'])/100)" -MsgType $MESSAGE_INFO
                }
            }
        }
    }
}

Function __AAP-ResolveDirectoryObjectByID {
    PARAM(
        [String]
        $ObjectID
    )
    Process {
        $returnValue = "$($ObjectID)"
        $directoryObject = Get-MgDirectoryObjectById -Ids $ObjectID -ErrorAction SilentlyContinue
        If($directoryObject){
            $aadDirectoryObjType = $directoryObject.AdditionalProperties['@odata.type']
            Switch($aadDirectoryObjType){
                '#microsoft.graph.user' {
                    $returnValue = "$($directoryObject.AdditionalProperties['userPrincipalName']) (User) [ID: $($ObjectID)]"
                    Break
                }
                '#microsoft.graph.group' {
                    $returnValue = "$($directoryObject.AdditionalProperties['displayName']) (Group) [ID: $($ObjectID)]"
                    Break
                }
                '#microsoft.graph.servicePrincipal' {
                    $returnValue = "$($directoryObject.AdditionalProperties['appDisplayName']) (ServicePrincipal) [ID: $($ObjectID)]"
                    Break
                }
            }
        }
        Else {
            ## Check if well known Application
            If( $wellKnownApplicationIDs.Keys -Contains $ObjectID ){
                $returnValue = "$($wellKnownApplicationIDs[$ObjectID]) (Application) [ID: $($ObjectID)]"
            }
        }
        return $returnValue
    }
}

Function __AAP-DisplayApplicableMFAConditionalAccessPolicyForUserID {
    PARAM(
        [Parameter()]
        [String]
        $UserID,

        [Int]
        $IndentationLevel = 0
    )
    Begin {
        If( -Not $script:gActiveMFAConditionalAccessPolicies ){
            $script:gActiveMFAConditionalAccessPolicies = Get-MgIdentityConditionalAccessPolicy -All | ?{ $_.State -ne "disabled" -And $_.GrantControls.BuiltInControls -Contains "mfa" }
        }
    }
    Process {
        $usersGroups = Get-MgUserMemberOf -UserId $UserID -All
        $applicablePoliciesCount = 0
        ForEach($conditionalAccessPolicy in $script:gActiveMFAConditionalAccessPolicies){
            $policyApplies = $false
            ## Check Excludes
            ### Excluded by Group
            If($conditionalAccessPolicy.Conditions.users.ExcludeGroups | ?{ $usersGroups.Id -Contains "$_" } ){
                ## Write-Verbose "[*] Group Policy exlcuded by group membership: $($conditionalAccessPolicy.DisplayName)"
                Continue
            }
            ### Excluded by User
            If($conditionalAccessPolicy.Conditions.users.ExcludeUsers -Contains $UserID ) {
                ## Write-Verbose "[*] Group Policy exlcuded by group user: $($conditionalAccessPolicy.DisplayName)"
                Continue
            }
            ### Excluded by Role
            If($conditionalAccessPolicy.Conditions.users.ExcludeRoles) {
                $excludedRoles = $conditionalAccessPolicy.Conditions.Users.ExcludeRoles
                ForEach($excludedRole in $excludedRoles){
                    If( ( Get-MgRoleManagementDirectoryRoleAssignment -Filter "(RoleDefinitionId eq '$($excludedRole)') and (PrincipalId eq '$($UserID)')") ){
                        #Write-Verbose "[*] Group Policy exlcuded by group role: $($conditionalAccessPolicy.DisplayName)"
                        Continue
                    }
                }
            }

            ## Check Includes
            ### Inclue by Group
            If($conditionalAccessPolicy.Conditions.users.IncludeGroups | ?{ $usersGroups.Id -Contains "$_" } ){
                #Write-Verbose "[+] Group Policy applies by Group: $($conditionalAccessPolicy.DisplayName)" -ForegroundColor DarkGreen
                $policyApplies = $true
            }
            ### Excluse by User
            If(
                ( $conditionalAccessPolicy.Conditions.users.IncludeUsers -Contains "All") -Or
                ( $conditionalAccessPolicy.Conditions.users.IncludeUsers -Contains $UserID )
            ){
                #Write-Verbose "[+] Group Policy applies by User: $($conditionalAccessPolicy.DisplayName)" -ForegroundColor DarkGreen
                $policyApplies = $true
            }
            ### Excluse by Role
            If($conditionalAccessPolicy.Conditions.users.IncludeRoles) {
                $includeRoles = $conditionalAccessPolicy.Conditions.Users.IncludeRoles
                ForEach($includeRole in $includeRoles){
                    If( ( Get-MgRoleManagementDirectoryRoleAssignment -Filter "(RoleDefinitionId eq '$($includeRole)') and (PrincipalId eq '$($UserID)')") ){
                        #Write-Verbose "[+] Group Policy applies by group role: $($conditionalAccessPolicy.DisplayName)" -ForegroundColor DarkGreen
                        $policyApplies = $true
                    }
                }
            }

            If($policyApplies){
                $applicablePoliciesCount += 1
                __AAP-Log "[+] $($conditionalAccessPolicy.DisplayName)" -MsgType $MESSAGE_SUCCESS -IndentationLevel $IndentationLevel
                ## Grant Controls
                If( $conditionalAccessPolicy.GrantControls.BuiltInControls -eq "block" ){
                    ## It should not be possible to set controls to "block" AND "mfa"
                    ### Therefore this is just a saftey net 
                    __AAP-Log "==> Block access" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                } ElseIf ($conditionalAccessPolicy.GrantControls.BuiltInControls.Count) {
                    __AAP-Log "==> Grant access " -NoNewline -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                    If( $conditionalAccessPolicy.GrantControls.BuiltInControls.Count ){
                        __AAP-Log "IF [ " -NoNewline -MsgType $MESSAGE_INFO
                        ForEach($bultInControl in $conditionalAccessPolicy.GrantControls.BuiltInControls){
                            If( ($conditionalAccessPolicy.GrantControls.BuiltInControls.IndexOf($bultInControl) % 2) -ne 0 ){
                                __AAP-Log "$($conditionalAccessPolicy.GrantControls.Operator) " -NoNewline -MsgType $MESSAGE_INFO
                            }
                            __AAP-Log "$($bultInControl) " -NoNewline -MsgType $MESSAGE_INFO
                        }
                        __AAP-Log "]" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                    } Else {
                        __AAP-Log "" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel ## newline
                    }
                }
                ## Session Controls
                If( $conditionalAccessPolicy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled ){
                    __AAP-Log "--> Session Control: Use app enforced restrictions" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                If( $conditionalAccessPolicy.SessionControls.CloudAppSecurity.IsEnabled ){
                    __AAP-Log "--> Session Control: CloudAppSecurity (Type: $($conditionalAccessPolicy.SessionControls.CloudAppSecurity.CloudAppSecurityType))" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                If( $conditionalAccessPolicy.SessionControls.ContinuousAccessEvaluation.Mode ){
                    __AAP-Log "--> Session Control: Customize continuous access evaluation (Mode: $($conditionalAccessPolicy.SessionControls.ContinuousAccessEvaluation.Mode))" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                If( $conditionalAccessPolicy.SessionControls.DisableResilienceDefaults ){
                    __AAP-Log "--> Session Control: Disable resilience defaults" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                If( $conditionalAccessPolicy.SessionControls.PersistentBrowser.IsEnabled ){
                    __AAP-Log "--> Session Control: Persistent browser session" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                If( $conditionalAccessPolicy.SessionControls.SignInFrequency.IsEnabled ){
                    __AAP-Log "--> Session Control: Sign-in frequency" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                    __AAP-Log "    $($conditionalAccessPolicy.SessionControls.SignInFrequency.Value) $($conditionalAccessPolicy.SessionControls.SignInFrequency.Type) ($($conditionalAccessPolicy.SessionControls.SignInFrequency.FrequencyInterval))" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }


                ## Applications
                ForEach($excludedApplication in $conditionalAccessPolicy.Conditions.Applications.ExcludeApplications){
                    ## Values could be "All", "<AppName>", "<ID>"
                    $excludedApp = __AAP-ResolveDirectoryObjectByID $excludedApplication
                    __AAP-Log "  Excluded Application: $($excludedApp)" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                ForEach($includedApplication in $conditionalAccessPolicy.Conditions.Applications.IncludeApplications){
                    ## Values could be "All", "<AppName>", "<ID>"
                    $includeApp = __AAP-ResolveDirectoryObjectByID $includedApplication
                    __AAP-Log "  Included Application: $($includeApp)" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                If( $conditionalAccessPolicy.Conditions.Applications.IncludeAuthenticationContextClassReferences ){
                    __AAP-Log "TODO IncludeAuthenticationContextClassReferences: $($conditionalAccessPolicy.Conditions.Applications.IncludeAuthenticationContextClassReferences )" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                If( $conditionalAccessPolicy.Conditions.Applications.IncludeUserActions ){
                    __AAP-Log "TODO IncludeUserActions: $($conditionalAccessPolicy.Conditions.Applications.IncludeUserActions )" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                If( $conditionalAccessPolicy.Conditions.Applications.AdditionalProperties.Count ){
                    __AAP-Log "TODO AdditionalProperties: $($conditionalAccessPolicy.Conditions.Applications.AdditionalProperties | fl )" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                ## ClientApps
                __AAP-Log "  Client Apps: " -NoNewline -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                ForEach($clientApp in $conditionalAccessPolicy.Conditions.ClientAppTypes){
                    If( ($conditionalAccessPolicy.Conditions.ClientAppTypes.IndexOf($clientApp) % 2) -ne 0 ){
                        __AAP-Log ", " -NoNewline -MsgType $MESSAGE_INFO
                    }
                    __AAP-Log "$($clientApp)" -NoNewline -MsgType $MESSAGE_INFO
                }
                __AAP-Log "" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel ## new line
                ## Devices
                If( $conditionalAccessPolicy.Conditions.Devices.ExcludeDeviceStates ){
                    __AAP-Log "  Excluded Device States: $($conditionalAccessPolicy.Conditions.Devices.ExcludeDeviceState)" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                If( $conditionalAccessPolicy.Conditions.Devices.ExcludeDevices ){
                    __AAP-Log "  Excluded Devices: $($conditionalAccessPolicy.Conditions.Devices.ExcludeDevices)" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                If( $conditionalAccessPolicy.Conditions.Devices.IncludeDeviceStates ){
                    __AAP-Log "  Included Device States: $($conditionalAccessPolicy.Conditions.Devices.IncludeDeviceStates)" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                If( $conditionalAccessPolicy.Conditions.Devices.IncludeDevices ){
                    __AAP-Log "  Included Devices: $($conditionalAccessPolicy.Conditions.Devices.IncludeDevices)" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                ## Locations
                If( $conditionalAccessPolicy.Conditions.Locations.ExcludeLocations ){
                    __AAP-Log "  Excluded Locations: $($conditionalAccessPolicy.Conditions.Locations.ExcludeLocations)" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                If( $conditionalAccessPolicy.Conditions.Locations.IncludeLocations ){
                    __AAP-Log "  Included Locations: $($conditionalAccessPolicy.Conditions.Locations.IncludeLocations)" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                ## Plattforms
                If( $conditionalAccessPolicy.Conditions.Platforms.ExcludePlatforms ){
                    __AAP-Log "  Excluded Plattforms: $($conditionalAccessPolicy.Conditions.Platforms.ExcludeLocations)" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                If( $conditionalAccessPolicy.Conditions.Platforms.IncludePlatforms ){
                    __AAP-Log "  Included Plattforms: $($conditionalAccessPolicy.Conditions.Platforms.IncludePlatforms)" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                ## ServicePrincipalRiskLevels
                If( $conditionalAccessPolicy.Conditions.ServicePrincipalRiskLevels.Count ){
                    __AAP-Log "  TODO: ServicePrincipalRiskLevels" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                ## SignInRiskLevels
                If( $conditionalAccessPolicy.Conditions.SignInRiskLevels.Count ){
                    __AAP-Log "  TODO: SignInRiskLevels" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
                ## UserRiskLevels
                If( $conditionalAccessPolicy.Conditions.UserRiskLevels.Count ){
                    __AAP-Log "  TODO: UserRiskLevels" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
                }
            }

            #Write-Host "[+] Group Policy applies ??? last call : $($conditionalAccessPolicy.DisplayName)" -ForegroundColor DarkGreen
        }
        If( $applicablePoliciesCount -eq 0 ){
            ## No policy applies
            __AAP-Log "  -- No MFA Conditional Access Policy applies for this user --" -MsgType $MESSAGE_INFO -IndentationLevel $IndentationLevel
        }
    }
}

Function __AAP-CheckRequiredModules {
    PARAM()
    Process {
        $modulesInstalled = $true
        ## Microsoft.Graph
        if ( -Not (Get-Module -ListAvailable -Name Microsoft.Graph) ){
            __AAP-Log -Msg "[-] Module 'Microsoft.Graph' does not exist." -MsgType $MESSAGE_FAIL
            __AAP-Log -Msg "    Install it via: Install-Module Microsoft.Graph" -MsgType $MESSAGE_WARNING
            $modulesInstalled = $false
        }
        ## AADInternals
        if ( -Not (Get-Module -ListAvailable -Name AADInternals) ) {
            __AAP-Log -Msg "[-] Module 'AADInternals' does not exist." -MsgType $MESSAGE_FAIL
            __AAP-Log -Msg "    Install it via: Install-Module AADInternals" -MsgType $MESSAGE_WARNING
            $modulesInstalled = $false
        }
        ## AzureADPreview
        if ( -Not (Get-Module -ListAvailable -Name AzureADPreview) ) {
            __AAP-Log -Msg "[-] Module 'AzureADPreview' does not exist." -MsgType $MESSAGE_FAIL
            __AAP-Log -Msg "    Install it via: Install-Module AzureADPreview" -MsgType $MESSAGE_WARNING
            $modulesInstalled = $false
        }
        return $modulesInstalled
    }
}

Function __AAP-ImportRequiredModules {
    PARAM()
    Process {
        Try {
            Import-Module AADInternals 6>$null | Out-Null
            Import-Module Microsoft.Graph.Applications | Out-Null
            Import-Module AzureADPreview | Out-Null
            return $true
        }
        Catch {
            __AAP-Log -Msg "[-] An error occured while trying to import required modules." -MsgType $MESSAGE_FAIL
            __AAP-Log -Msg "    The error was: $_"
            return $false
        }
    }
}

Function __AAP-GetAcessTokenForAADGraphWithRefreshToken {
    PARAM(
        [Parameter()]
        [String]
        $RefreshToken = $global:__AAPgRefreshToken,
        
        [Parameter()]
        [String]
        $Tenant = $global:__AAPgTenantID
    )
    Process {
        return (Get-AADIntAccessTokenWithRefreshToken -Resource "https://graph.windows.net" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894" -RefreshToken $RefreshToken -Tenant $global:__AAPgTenantID)
    }
}

Function __AAP-GetAcessTokenForMSGraphWithRefreshToken {
    PARAM(
        [Parameter()]
        [String]
        $RefreshToken = $global:__AAPgRefreshToken,
        
        [Parameter()]
        [String]
        $Tenant = $global:__AAPgTenantID
    )
    Process {
        return (Get-AADIntAccessTokenWithRefreshToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894" -RefreshToken $RefreshToken -Tenant $global:__AAPgTenantID)
    }
}

Function __AAP-GetAcessTokenForMSGraphWithCredentials {
    PARAM(
        [Parameter()]
        [String]
        $Tenant = $global:__AAPgTenantID
    )
    Process {
        $accessTokenMSGraph, $refreshToken = Get-AADIntAccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894" -IncludeRefreshToken:$true -Tenant $Tenant
        return @($accessTokenMSGraph, $refreshToken)
    }
}

Function __AAP-ConnectMicrosoftGraph {
    PARAM(
        [Parameter()]
        [String]
        $Tenant
    )
    Begin {
        ## Tenant dependent Script global variables
        $script:gAllMgDirectoryRoles = @()
        $script:gHighPrivilegdPrincipalMap = @{}
        $script:gLastCollectionOfHighPrivilegdPrincipalMap = $null
    }
    Process{
        $global:__AAPgAccessTokenMSGraph, $global:__AAPgRefreshToken = __AAP-GetAcessTokenForMSGraphWithCredentials -Tenant $Tenant
        
        If( $global:__AAPgAccessTokenMSGraph ){
            Connect-MgGraph -AccessToken $global:__AAPgAccessTokenMSGraph
            Select-MgProfile -Name "beta"
            $global:__AAPgTenantID = (Get-MgContext).TenantId
        }
        Else {
            __AAP-Log -Msg "[-] An error occured while trying to connect to Micrsoft Graph." -MsgType $MESSAGE_FAIL
            __AAP-Log -Msg "    We can't continue. Please retry..."
            Break
        }
        return $accessTokenMSGraph
    }
}

Function __AAP-ConnectAllResources {
    PARAM(
        [Parameter()]
        [String]
        $Tenant
    )
    Process {
        __AAP-Log "[*] Connecting to Microsoft Graph..."
        $accessTokenMSGraph = __AAP-ConnectMicrosoftGraph -Tenant $Tenant
        __AAP-Log "[*] Connecting to AzueAD Graph..."
        $graphContext = Get-MgContext
        Connect-AzureAD -AccountId $graphContext.Account
    }
}

Function __AAP-ConnectIfNecessary {
    PARAM(
        [Parameter()]
        [String]
        $Tenant
    )
    Process {
        ## Check if given Tenant matches
        If( $Tenant -And ( $global:__AAPgTenantID -ne (Get-AADIntTenantID -Domain $Tenant) )  ){
            __AAP-Log "[*] Connecting Microsoft Graph to different Tenant..."
            __AAP-ConnectAllResources -Tenant $Tenant
        }
        ## Check if connected
        If( -Not (Get-MgContext) ){
            __AAP-ConnectAllResources -Tenant $Tenant
        }
        ## Test connection
        Try {
            $mgUser = Get-MgUser -Top 1 -ErrorAction Stop
        } Catch {
            $caughtError = $_
            If( $caughtError.ToString() -Like "*Authentication needed*" ){
                __AAP-Log -Msg "[*] We need to re-authenticate..." -MsgType $MESSAGE_WARNING
                __AAP-ConnectAllResources -Tenant $Tenant
            }
            If( $caughtError.ToString() -Like "*token has expired*" ){
                __AAP-Log -Msg "[*] Access Token expired we need to re-authenticate..." -MsgType $MESSAGE_WARNING
                __AAP-ConnectAllResources -Tenant $Tenant
            }
        }
    }
}

Function __AAP-AddToHighPrivilegePrincipalMap {
    PARAM(
        [Parameter(Mandatory)]
        [String]
        $PrincipalID,

        [String]
        $PrincipalName,

        [String]
        $Reason,

        [Parameter(Mandatory)]
        [ValidateSet("User","Group","ServicePrincipal","Unknown", IgnoreCase = $true)]
        [String]
        $PrincipalType,

        [Int]
        $ConfidenceLevel = -1
    )
    Process {
        $entryArray = If( $script:gHighPrivilegdPrincipalMap.Keys -Contains $PrincipalID ){ ,$script:gHighPrivilegdPrincipalMap.Item($PrincipalID) } Else { ,@() } 
        ## Update Entries with a reason already added
        $updateEntries = $entryArray | ? { $_['Reason'] -eq $Reason  }
        If( $updateEntries ){
            ForEach($updateEntry in $updateEntries){
                ## Update only if the confidence level increased
                If( $ConfidenceLevel -gt $updateEntry['ConfidenceLevel'] ){
                    $updateEntry['ConfidenceLevel'] = $ConfidenceLevel
                }
            }
        }
        ## Add new entry if new reason
        Else {
            $entryArray += @{
                'principalID' = $PrincipalID;
                'principalName' = $PrincipalName;
                'principalType' = $PrincipalType;
                'ConfidenceLevel' = $ConfidenceLevel;
                'Reason' = $Reason
            }
            $script:gHighPrivilegdPrincipalMap[$PrincipalID] = $entryArray
        }
    }
}

Function __AAP-DisplayNonHighPrivilegedRoleAssignments {
    PARAM(
        [Parameter()]
        [hashtable]
        $NonHighPrivilegedRoleAssignments
    )
    Process {
        ForEach($roleTemplateName in $NonHighPrivilegedRoleAssignments.Keys){
            __AAP-Log "[*] The Directory Role '$($roleTemplateName)' is currently not considered high privileged, but has the following members:" -MsgType $MESSAGE_WARNING
            ForEach($principalDisplayStr in $NonHighPrivilegedRoleAssignments[$roleTemplateName]){
                __AAP-Log "  $($principalDisplayStr)"
            }
        }
    }
}

Function __AAP-CheckIfMemberOfPrivilegedDirectoryRole {
    PARAM(
        [Parameter()]
        [String]
        $PrincipalID,

        [Parameter()]
        [hashtable]
        $NonHighPrivilegedRoleAssignments,

        [Parameter()]
        [String]
        $TemplateID,

        [Parameter()]
        [String]
        $TemplateName = "",

        [Parameter()]
        [Switch]
        $AssignedViaPIM = $false
    )
    Begin {
        If( $TemplateName -eq "" ){
            $mgDirectoryRoleTemplate = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $TemplateID
            If( $mgDirectoryRoleTemplate ){
                $TemplateName = $mgDirectoryRoleTemplate.DisplayName
            }
        }
    }
    Process {
        ### Check if role is high privileged
        If( $templateID -In $highPrivilegedDirectoryRoleTemplatesMap.Keys ){
            ## 100 for Global Administrator, 99 for all others
            $confidenceLevel = If( $templateID -eq '62E90394-69F5-4237-9190-012177145E10' ){ 100 } Else { 99 }

            ## Get corresponding principal
            $principalObjectData = (Get-MgDirectoryObjectById -Ids $PrincipalID)
            $principalID = $principalObjectData.Id
            $principalName = $null
            $principalType = 'Unknown'
            $highPrivReason = "High privileged directory Role assigned: $($highPrivilegedDirectoryRoleTemplatesMap[$templateID])"
            If( $AssignedViaPIM ){
                $highPrivReason = "High privileged directory Role assigned (via PIM): $($highPrivilegedDirectoryRoleTemplatesMap[$templateID])"
            }
            If( $principalObjectData.AdditionalProperties ){
                ## Resolve principal
                $aadDirectoryObjType = $principalObjectData.AdditionalProperties['@odata.type']
                Switch($aadDirectoryObjType){
                    '#microsoft.graph.user' {
                        $principalType = 'User'
                        $principalName = $principalObjectData.AdditionalProperties['userPrincipalName']
                        ## Add entry
                        __AAP-AddToHighPrivilegePrincipalMap -PrincipalID $principalID -PrincipalName $principalName -Reason $highPrivReason -PrincipalType $principalType -ConfidenceLevel $confidenceLevel
                        Break
                    }
                    '#microsoft.graph.group' {
                        $principalType = 'Group'
                        ## Resovle members
                        $securityIdentifier = $principalObjectData.AdditionalProperties['securityIdentifier']
                        $mgGroup = Get-MgGroup -Filter "securityIdentifier eq '$($securityIdentifier)'" -Top 1
                        If( $mgGroup ){
                            $mgGroupMembers = Get-MgGroupTransitiveMember -GroupId $mgGroup.Id
                            ForEach($mgGroupMember in $mgGroupMembers){
                                $principalID = $mgGroupMember.Id
                                $principalName = $null
                                $groupMemberObjType = $mgGroupMember.AdditionalProperties['@odata.type']
                                $highPrivReason = "Member of group ($($mgGroup.DisplayName)) with high privileged directory Role: $($highPrivilegedDirectoryRoleTemplatesMap[$templateID])"
                                If( $AssignedViaPIM ){
                                    $highPrivReason = "Member of group ($($mgGroup.DisplayName)) with high privileged directory Role (via PIM): $($highPrivilegedDirectoryRoleTemplatesMap[$templateID])"
                                }
                                Switch($groupMemberObjType){
                                    '#microsoft.graph.user' {
                                        $principalType = 'User'
                                        $principalName = $mgGroupMember.AdditionalProperties['userPrincipalName']
                                        Break
                                    }
                                    '#microsoft.graph.servicePrincipal' {
                                        $principalType = 'ServicePrincipal'
                                        $principalName = $mgGroupMember.AdditionalProperties['appDisplayName']
                                        Break
                                    }
                                }
                                ## Add entry
                                __AAP-AddToHighPrivilegePrincipalMap -PrincipalID $principalID -PrincipalName $principalName -Reason $highPrivReason -PrincipalType $principalType -ConfidenceLevel $confidenceLevel
                            }
                        }
                        Break
                    }
                    '#microsoft.graph.servicePrincipal' {
                        $principalType = 'ServicePrincipal'
                        $principalName = $principalObjectData.AdditionalProperties['appDisplayName']
                        ## Add entry
                        __AAP-AddToHighPrivilegePrincipalMap -PrincipalID $principalID -PrincipalName $principalName -Reason $highPrivReason -PrincipalType $principalType -ConfidenceLevel $confidenceLevel
                        Break
                    }
                }
            }
        }Else {
            $principalEntries = If( $NonHighPrivilegedRoleAssignments.Keys -Contains $TemplateName ){ ,$NonHighPrivilegedRoleAssignments.Item($TemplateName) } Else { ,@() }
            ## Add Principal if not already contained
            If( $principalEntries.Keys -NotContains $PrincipalID ){
                $principalDisplayStr = __AAP-ResolveDirectoryObjectByID -ObjectID $PrincipalID
                If( $AssignedViaPIM ){
                    $principalDisplayStr += " [[ Assigned via PIM ]]"
                }
                $principalEntries += @($principalDisplayStr)
            }
            $NonHighPrivilegedRoleAssignments[$TemplateName] = $principalEntries
        }
    }
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

Function Invoke-AccessCheckForServicePrincipal {
    PARAM(
        [Parameter(Mandatory, ParameterSetName="ServicePrincipalIdentifier")]
        [Object]
        $ServicePrincipalIdentifier,
        
        [Parameter(Mandatory, ParameterSetName="MgServicePrincipalObject")]
        [Object]
        $MgServicePrincipalObject,

        [Parameter()]
        [String]
        $Outfile = $false,
        
        [Parameter()]
        [String]
        $Tenant
    )
    Begin {
        __AAP-ConnectIfNecessary -Tenant $Tenant
        
        If($MgServicePrincipalObject){
            $mgServicePrincipal = $MgServicePrincipalObject
        }
        ElseIf($ServicePrincipalIdentifier) {
            ## Try to find service principals via ID
            $mgServicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $ServicePrincipalIdentifier -ErrorAction SilentlyContinue
            If(-Not $mgServicePrincipal){
                ## Try to find service principal via appID
                $mgServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$($ServicePrincipalIdentifier)'" -Top 1 -ErrorAction SilentlyContinue
            }
            If(-Not $mgServicePrincipal){
                 __AAP-Log "[-] Could not find service principal: $($ServicePrincipalIdentifier)" -MsgType $MESSAGE_FAIL
            }
        }
        Else {
            $mgServicePrincipal = $null
        }
    }
    Process {
        If( $mgServicePrincipal ){
            $appRoleAssignmendToResult = Get-MgServicePrincipalAppRoleAssignedTo -All -ServicePrincipalId $mgServicePrincipal.Id
            $appRoleAssignmentsResult = Get-MgServicePrincipalAppRoleAssignment -All -ServicePrincipalId $mgServicePrincipal.Id
            $oauthPermissionsResult = Get-MgServicePrincipalOauth2PermissionGrant -All -ServicePrincipalId $mgServicePrincipal.Id
            $owner = Get-MgServicePrincipalOwner -All -ServicePrincipalId $mgServicePrincipal.Id
            $delegPermissionsClassifciation = Get-MgServicePrincipalDelegatedPermissionClassification -All -ServicePrincipalId $mgServicePrincipal.Id
            $mgOwnedObjectsByServicePrincipal = Get-MgServicePrincipalOwnedObject -All -ServicePrincipalId $mgServicePrincipal.Id
            $createdObjs = Get-MgServicePrincipalCreatedObject -All -ServicePrincipalId $mgServicePrincipal.Id
            $resourceSpecificAppPermissions = $mgServicePrincipal.ResourceSpecificApplicationPermissions
            #$oauthPermissionGrants = $mgServicePrincipal.Oauth2PermissionGrants
            #$oauthPermissionScopes = $mgServicePrincipal.Oauth2PermissionScopes


            __AAP-Log "### Service Principal: $($mgServicePrincipal.DisplayName) ($($mgServicePrincipal.Id))"
            
            ## Owned Objects
            if( $mgOwnedObjectsByServicePrincipal.Length -gt 0 ){
                ForEach($mgOwnedObjectRef in $mgOwnedObjectsByServicePrincipal){
                    __AAP-Log "[+] User owns the following object: $($mgOwnedObjectRef.Id)" -MsgType $MESSAGE_SUCCESS
                    $mgOwnedObjProperties = (Get-MgDirectoryObjectById -Ids $mgOwnedObjectRef.Id).AdditionalProperties
                    if( $mgOwnedObjProperties ){
                        $mgOwnedObjProperties.Keys | %{ __AAP-Log "  $($_): $($mgOwnedObjProperties[$_])" -MsgType $MESSAGE_INFO }
                    }
                }
            }

            ## Application-Type API Permissions of the service principal
            if( $appRoleAssignmentsResult ){
                __AAP-Log "[+] Application-Type API Permission access rights of this service principal:" -MsgType $MESSAGE_SUCCESS
                __AAP-DisplayAppRoleAssignments -AppRoleAssignments $appRoleAssignmentsResult
            }

            ## Delegated-Type API Permissions of the service principal
            if( $oauthPermissionsResult ){
                __AAP-Log "[+] Delegated-Type API Permission access rights of this service principal:" -MsgType $MESSAGE_SUCCESS
                __AAP-DisplayOauth2PermissionGrants -Oauth2PermissionGrants $oauthPermissionsResult
            }

            ## Principals with assigned AppRoles to this service account
            if( $appRoleAssignmendToResult ){
                __AAP-Log "[+] The following principals have an AppRole assigned for this this service account:" -MsgType $MESSAGE_SUCCESS
                ForEach($appRoleAssignmendTo in $appRoleAssignmendToResult){
                    $appRoleValue = 'default'
                    ## 00000000-0000-0000-0000-000000000000 is the default appRoleID
                    If( $appRoleAssignmendTo.AppRoleId -ne '00000000-0000-0000-0000-000000000000' ){
                        $appRole = $mgServicePrincipal.appRoles | ? {$_.Id -eq $appRoleAssignmendTo.AppRoleId} | Select-Object -First 1
                        $appRoleValue = $appRole.Value 
                    }
                    __AAP-Log "  $($appRoleAssignmendTo.PrincipalType): $($appRoleAssignmendTo.PrincipalDisplayName) ($($appRoleAssignmendTo.PrincipalId))"  -MsgType $MESSAGE_INFO
                    __AAP-Log "    Value: $($appRoleValue) ($($appRoleAssignmendTo.AppRoleId))" -MsgType $MESSAGE_INFO
                }
            }

            ## Owner of the service principal
            If( $owner ){
                __AAP-Log "[+] The following user is the owner of this service principal: $($owner.AdditionalProperties.userPrincipalName)" -MsgType $MESSAGE_SUCCESS
                __AAP-Log "  Additional Properties:"
                $owner.AdditionalProperties.Keys.ForEach{"    $($_): $($owner.AdditionalProperties[$_])"} 
            }

            ## Other Attributes of interest
            If( $delegPermissionsClassifciation ){
                __AAP-Log "[+] Delegated permission classifications" -MsgType $MESSAGE_SUCCESS
                $delegPermissionsClassifciation | fl
            }

            If( $createdObjs ){
                __AAP-Log "[+] Created Objects" -MsgType $MESSAGE_SUCCESS
                __AAP-Log $createdObjs | fl
            }

            If( $resourceSpecificAppPermissions ){
                __AAP-Log "[+] Resource specific Application Permissions of this service principal:" -MsgType $MESSAGE_SUCCESS
                __AAP-Log "  (Currently only supported for Teams, see: https://learn.microsoft.com/en-us/graph/api/resources/resourcespecificpermission?view=graph-rest-1.0)"
                ForEach($resourceSpecificAppPermission in $resourceSpecificAppPermissions){
                    __AAP-Log "  ID: $($resourceSpecificAppPermission.Id)" -MsgType $MESSAGE_INFO
                    __AAP-Log "  Enabled: $($resourceSpecificAppPermission.IsEnabled)" -MsgType $MESSAGE_INFO
                    __AAP-Log "  Value: $($resourceSpecificAppPermission.VAlue)" -MsgType $MESSAGE_INFO
                    __AAP-Log "  DisplayName: $($resourceSpecificAppPermission.displayName)`n" -MsgType $MESSAGE_INFO
                }
            }
        }
    }
}

Function Invoke-AccessCheckForAllServicePrincipals {
    PARAM(
        [Parameter()]
        [String]
        $Outfile = $false,

        [Parameter()]
        [String]
        $Tenant
    )
    Begin {
        __AAP-ConnectIfNecessary -Tenant $Tenant
        $mgServicePrincipals = Get-MgServicePrincipal -All
    }
    Process {
        __AAP-Log "## Access Checks for all AAD Service Principals"
        ## Init Progess
        $progressCount = 0
        $progressLimit = $mgServicePrincipals.Count
        ForEach($mgServicePrincipal in $mgServicePrincipals){
            $progressCount += 1
            Try {
                Invoke-AccessCheckForServicePrincipal -MgServicePrincipalObject $mgServicePrincipal -Outfile:$Outfile
            }
            Catch {
                $caughtError = $_
                If( $caughtError.ToString() -Like "*Authentication needed*" ){
                    __AAP-Log -Msg "[*] We need to re-authenticate..." -MsgType $MESSAGE_WARNING
                    $global:__AAPgAccessTokenMSGraph = __AAP-GetAcessTokenForMSGraphWithRefreshToken
                }
                If( $caughtError.ToString() -Like "*token has expired*" ){
                    __AAP-Log -Msg "[*] Access Token expired we need to re-authenticate..." -MsgType $MESSAGE_WARNING
                    $global:__AAPgAccessTokenMSGraph = __AAP-GetAcessTokenForMSGraphWithRefreshToken
                }
            }
            
            ## Update Progess
            $progressOperation = "$progressCount/$progressLimit"
            $progressPercentage = ($progressCount/$progressLimit)*100
            Write-Progress -Activity "Enumerating Azure AD Service Principals" -PercentComplete $progressPercentage -CurrentOperation $progressOperation
        }
        ## Complete Progess
        Write-Progress -Activity "Enumerating Azure AD Service Principals" -Status "Ready" -Completed
    }
}

Function Invoke-AccessCheckForGroup {
    PARAM(
        [Parameter(Mandatory, ParameterSetName="GroupIdentifier")]
        [Object]
        $GroupIdentifier,

        [Parameter(Mandatory, ParameterSetName="MgGroupObject")]
        [Object]
        $MgGroupObject,

        [Parameter()]
        [String]
        $Outfile = $false,

        [Parameter()]
        [String]
        $Tenant,

        [Parameter()]
        [Switch]
        $Recursive = $true,

        [Parameter()]
        [Int]
        $RecursiveDepthLevel = 5,

        [Parameter()]
        [Int]
        $RecursionCounterDoNotUse = 0
    )
    Begin {
        __AAP-ConnectIfNecessary -Tenant $Tenant

        If($MgGroupObject){
            $mgGroup = $MgGroupObject
        }
        ElseIf($GroupIdentifier) {
            ## Try to find group by SecurityIdentifier
            $mgGroup = Get-MgGroup -Filter "SecurityIdentifier eq '$($GroupIdentifier)'" -Top 1
            If(-Not $mgGroup){
                ## Try to find group by ID
                $mgGroup = Get-MgGroup -GroupId $GroupIdentifier -ErrorAction SilentlyContinue
                If(-Not $mgGroup){
                    ## Try to find group by DisplayName
                    $mgGroup = Get-MgGroup -Filter "DisplayName eq '$($GroupIdentifier)'" -ErrorAction SilentlyContinue -Top 1
                }
            }
            If(-Not $mgGroup){
                __AAP-Log "[-] Could not find group: $($GroupIdentifier)" -MsgType $MESSAGE_FAIL
            }
        }
        Else {
            $mgGroup = $null
        }
    }
    Process {
        if( $mgGroup ){
            __AAP-Log "### Group: $($mgGroup.displayName) (ID: $($mgGroup.Id))" -IndentationLevel $RecursionCounterDoNotUse
            $groupAppRoleAssignments = Get-MgGroupAppRoleAssignment -All -GroupId $mgGroup.Id
            $groupPermissionGrants =  Get-MgGroupPermissionGrant -All -GroupId $mgGroup.Id -ErrorAction SilentlyContinue
            $transitiveMemberships = Get-MgGroupTransitiveMemberOf -GroupId $mgGroup.Id
            $mgGroupIsMemberOfObjects = Get-MgGroupMemberObject  -GroupId $mgGroup.Id -SecurityEnabledOnly:$false ## Return all IDs for the groups, administrative units, and directory roles that a group is a member of.
            
            ## App Role Assignments
            If($groupAppRoleAssignments){
                __AAP-Log "[+] Application Permission Access of this group (AppRoles of this group):" -MsgType $MESSAGE_SUCCESS -IndentationLevel $RecursionCounterDoNotUse
                __AAP-DisplayAppRoleAssignments -AppRoleAssignments $groupAppRoleAssignments -IndentationLevel $RecursionCounterDoNotUse
            }
            ## Permission Grants
            If( $groupPermissionGrants ){
                 __AAP-Log Write-Output "[+] Permissions grants" -MsgType $MESSAGE_SUCCESS
                $groupPermissionGrants | fl
            }
            ## Transitive Memberships
            if( $transitiveMemberships ){
                __AAP-Log "[+] Memberships" -MsgType $MESSAGE_SUCCESS -IndentationLevel $RecursionCounterDoNotUse
                ForEach($transitiveMembership in $transitiveMemberships){
                    $transitiveMembershipProperties = $transitiveMembership.AdditionalProperties
                    If( $transitiveMembershipProperties ){
                        If( $transitiveMembershipProperties['@odata.type'] -eq "#microsoft.graph.group" ){
                            __AAP-Log "  Member of Group: $($transitiveMembershipProperties.displayName)" -MsgType $MESSAGE_INFO -IndentationLevel $RecursionCounterDoNotUse
                            $recorsionCounterStep = 3
                            $recursionLevel = $RecursionCounterDoNotUse/$recorsionCounterStep
                            If( $Recursive -And ($recursionLevel -lt $RecursiveDepthLevel)  ){
                                ## Recursively traverse group memmberships
                                $memberOfGroup = Get-MgGroup -Filter "SecurityIdentifier eq '$( $transitiveMembershipProperties.securityIdentifier )'" -Top 1 -ErrorAction SilentlyContinue
                                If( $memberOfGroup ){
                                    $recursionCounter = $RecursionCounterDoNotUse + $recorsionCounterStep
                                    Invoke-AccessCheckForGroup -MgGroupObject $memberOfGroup -RecursionCounterDoNotUse $recursionCounter -Recursive:$Recursive -RecursiveDepthLevel:$RecursiveDepthLevel
                                }Else {
                                    __AAP-Log "Could not find group with DisplayName: $($transitiveMembershipProperties.displayName)" -IndentationLevel $RecursionCounterDoNotUse
                                }
                            }
                        }
                        Else {
                            __AAP-Log "[*] This group is a member of the following object: $($transitiveMembershipProperties['@odata.type'])"
                            $transitiveMembershipProperties.Keys | %{ __AAP-Log "  $($_): $($transitiveMembershipProperties[$_])" }
                        }
                    }
                }
            }
            ## Objects where the group is a member of
            if( $mgGroupIsMemberOfObjects.Length -gt 0 ){
                ForEach($mgGroupIsMemberOfObjectId in $mgGroupIsMemberOfObjects){
                    $mgGroupIsMemberOfObjectProperties = (Get-MgDirectoryObjectById -Ids $mgGroupIsMemberOfObjectId).AdditionalProperties
                    if( $mgGroupIsMemberOfObjectProperties ){
                        ## Only add this information if this is data type is not already covered
                        if( $mgGroupIsMemberOfObjectProperties['@odata.type'] -Notin @("#microsoft.graph.group") ){
                            __AAP-Log "[*] This group is member of the following object: $($mgGroupIsMemberOfObjectProperties['@odata.type'])" -IndentationLevel $RecursionCounterDoNotUse
                            $mgGroupIsMemberOfObjectProperties.Keys | %{ Write-Output "  $($_): $($mgGroupIsMemberOfObjectProperties[$_])" }
                        }
                    }
                }
            }
        }
    }
}

Function Invoke-AccessCheckForAllGroups {
    PARAM(
        [Parameter()]
        [String]
        $Tenant,

        [Parameter()]
        [String]
        $Outfile = $false
    )
    Begin {
        __AAP-ConnectIfNecessary -Tenant $Tenant
        $mgGroups = Get-MgGroup -All
    }
    Process {
        __AAP-Log "## Access Checks for all AAD Groups"
        ## Init Progess
        $progressCount = 0
        $progressLimit = $mgGroups.Count
        ForEach($mgGroup in $mgGroups){
            $progressCount += 1
            Try {
                Invoke-AccessCheckForGroup -MgGroupObject $mgGroup -Outfile:$Outfile
            }
            Catch {
                $caughtError = $_
                If( $caughtError.ToString() -Like "*Authentication needed*" ){
                    __AAP-Log -Msg "[*] We need to re-authenticate..." -MsgType $MESSAGE_WARNING
                    $global:__AAPgAccessTokenMSGraph = __AAP-GetAcessTokenForMSGraphWithRefreshToken
                }
                If( $caughtError.ToString() -Like "*token has expired*" ){
                    __AAP-Log -Msg "[*] Access Token expired we need to re-authenticate..." -MsgType $MESSAGE_WARNING
                    $global:__AAPgAccessTokenMSGraph = __AAP-GetAcessTokenForMSGraphWithRefreshToken
                }
            }
            
            ## Update Progess
            $progressOperation = "$progressCount/$progressLimit"
            $progressPercentage = ($progressCount/$progressLimit)*100
            Write-Progress -Activity "Enumerating Azure AD Groups" -PercentComplete $progressPercentage -CurrentOperation $progressOperation
        }
        ## Complete Progess
        Write-Progress -Activity "Enumerating Azure AD Groups" -Status "Ready" -Completed
    }
}

Function Invoke-AccessCheckForUser {    
    PARAM(
        [Parameter(Mandatory, ParameterSetName="UserIdentifier")]
        [Object]
        $UserIdentifier,

        [Parameter(Mandatory, ParameterSetName="MgUserObject")]
        [Object]
        $MgUserObject,

        [Parameter()]
        [String]
        $Tenant,

        [Parameter()]
        [String]
        $Outfile = $false,

        [Parameter()]
        [Switch]
        $Recursive = $true
    )
    Begin {
        __AAP-ConnectIfNecessary -Tenant $Tenant

        If($MgUserObject){
            $mgUser = $MgUserObject
        }
        ElseIf($UserIdentifier) {
            $mgUser = Get-MgUser -UserId $UserIdentifier -ErrorAction SilentlyContinue
            If(-Not $mgUser){
                __AAP-Log "[-] Could not find user: $($UserIdentifier)" -MsgType $MESSAGE_FAIL
            }
        }
        Else {
            $mgUser = $null
        }
    }
    Process {
        if( $mgUser ){
            __AAP-Log "### User: $($mgUser.UserPrincipalName) (ID: $($mgUser.Id))" -MsgType $MESSAGE_INFO
            $userAppRoleAssignments = Get-MgUserAppRoleAssignment -All -UserId $mgUser.Id
            $userOauthGrants = Get-MgUserOauth2PermissionGrant -All -UserId $mgUser.Id
            $mgUserMemberships = Get-MgUserMemberOf -UserId $mgUser.Id -All
            $mgOwnedObjectsByUser = Get-MgUserOwnedObject -UserId $mgUser.Id -All
            $mgUserIsMemberOfObjects = Get-MgUserMemberObject -UserId $mgUser.Id -SecurityEnabledOnly:$false ## Return all IDs for the groups, administrative units, and directory roles that a user is a member of 
            
            ## Owned Objects
            if( $mgOwnedObjectsByUser.Length -gt 0 ){
                ForEach($mgOwnedObjectRef in $mgOwnedObjectsByUser){
                    __AAP-Log "[+] User owns the following object: $($mgOwnedObjectRef.Id)" -MsgType $MESSAGE_SUCCESS
                    $mgOwnedObjProperties = (Get-MgDirectoryObjectById -Ids $mgOwnedObjectRef.Id).AdditionalProperties
                    if( $mgOwnedObjProperties ){
                        $mgOwnedObjProperties.Keys | %{ __AAP-Log "  $($_): $($mgOwnedObjProperties[$_])" -MsgType $MESSAGE_INFO }
                    }
                }
            }
            ## App Role Assignments
            If( $userAppRoleAssignments){
                __AAP-Log "[+] Application Permission Access of this user (AppRoles of this user):" -MsgType $MESSAGE_SUCCESS
                __AAP-DisplayAppRoleAssignments -AppRoleAssignments $userAppRoleAssignments
            }
            ## OAuth Grants
            if( $userOauthGrants ){
                __AAP-Log "[+] Delegated Permission Access of this user (Oauth2PermissionGrants):" -MsgType $MESSAGE_SUCCESS
                __AAP-DisplayOauth2PermissionGrants -Oauth2PermissionGrants $userOauthGrants
            }
            ## Memberships
            if( $mgUserMemberships.Length -gt 0 ){
                __AAP-Log "[+] Memberships" -MsgType $MESSAGE_SUCCESS
                If( $script:gAllMgDirectoryRoles.Length -eq 0 ){ $script:gAllMgDirectoryRoles = Get-MgDirectoryRole -All }
                ForEach($mgUserMembership in $mgUserMemberships){
                    $mgUserMembershipProperties = $mgUserMembership.AdditionalProperties
                    $mgDirectoryRole = $script:gAllMgDirectoryRoles | ? {$_.Id -eq $mgUserMembership.Id }
                    
                    If( $mgDirectoryRole  ){
                        __AAP-DisplayDirectoryRoleAssignment -MgDirectoryRole $mgDirectoryRole
                    }
                    Else {
                        If( $mgUserMembershipProperties ){
                            __AAP-Log "  $($mgUserMembershipProperties.displayName) ($($mgUserMembership.Id))" -MsgType $MESSAGE_INFO
                            If( $Recursive ){
                                If( $mgUserMembershipProperties['@odata.type'] -eq '#microsoft.graph.group' ){
                                    $groupSecurityIdentifier = $mgUserMembershipProperties.securityIdentifier
                                    Invoke-AccessCheckForGroup -GroupIdentifier $groupSecurityIdentifier -RecursionCounterDoNotUse 3 -Recursive
                                }
                            }
                        }
                        Else {
                            __AAP-Log "  $($mgUserMembership.Id)" -MsgType $MESSAGE_INFO
                        }
                    }
                }
            }
            ## Objects where the user is a member of
            If( $mgUserIsMemberOfObjects.Length -gt 0 ){
                ForEach($mgUserIsMemberOfObjectId in $mgUserIsMemberOfObjects){
                    $mgUserIsMemberOfObjectProperties = (Get-MgDirectoryObjectById -Ids $mgUserIsMemberOfObjectId).AdditionalProperties
                    if( $mgUserIsMemberOfObjectProperties ){
                        ## Only add this information if this is data type is not already covered
                        if( $mgUserIsMemberOfObjectProperties['@odata.type'] -Notin @("#microsoft.graph.group",  "#microsoft.graph.directoryRole") ){
                            __AAP-Log "[*] User is member of the following object: $($mgUserIsMemberOfObjectProperties['@odata.type'])"
                            $mgUserIsMemberOfObjectProperties.Keys | %{ Write-Output "  $($_): $($mgUserIsMemberOfObjectProperties[$_])" }
                        }
                    }
                }
            }
        }
    }
}

Function Invoke-AccessCheckForCurrentUser {
    PARAM(
        [Parameter()]
        [String]
        $Tenant,

        [Parameter()]
        [String]
        $Outfile = $false
    )
    Begin {
        __AAP-ConnectIfNecessary -Tenant $Tenant
    }
    Process {
        $currentUserString = (Get-MgContext).Account
        __AAP-Log "## Permission Check for current AAD User: $currentUserString"
        Invoke-AccessCheckForUser -UserIdentifier $currentUserString -Outfile:$Outfile
    }
}

Function Invoke-AccessCheckForAllUsers {
    PARAM(
        [Parameter()]
        [String]
        $Tenant,

        [Parameter()]
        [String]
        $Outfile = $false
    )
    Begin {
        __AAP-ConnectIfNecessary -Tenant $Tenant
        $mgUsers = Get-MgUser -All
    }
    Process {
        __AAP-Log "## Access Checks for all AAD Users"
        ## Init Progess
        $progressCount = 0
        $progressLimit = $mgUsers.Count
        ForEach($mgUser in $mgUsers){
            $progressCount += 1
            ## Test connection
            Try {
                Invoke-AccessCheckForUser -MgUserObject $mgUser -Outfile:$Outfile
            } Catch {
                $caughtError = $_
                If( $caughtError.ToString() -Like "*Authentication needed*" ){
                    __AAP-Log -Msg "[*] We need to re-authenticate..." -MsgType $MESSAGE_WARNING
                    $global:__AAPgAccessTokenMSGraph = __AAP-GetAcessTokenForMSGraphWithRefreshToken
                }
                If( $caughtError.ToString() -Like "*token has expired*" ){
                    __AAP-Log -Msg "[*] Access Token expired we need to re-authenticate..." -MsgType $MESSAGE_WARNING
                    $global:__AAPgAccessTokenMSGraph = __AAP-GetAcessTokenForMSGraphWithRefreshToken
                }
            }
            
            ## Update Progess
            $progressOperation = "$progressCount/$progressLimit"
            $progressPercentage = ($progressCount/$progressLimit)*100
            Write-Progress -Activity "Enumerating Azure AD Users" -PercentComplete $progressPercentage -CurrentOperation $progressOperation
        }
        ## Complete Progess
        Write-Progress -Activity "Enumerating Azure AD Users" -Status "Ready" -Completed
    }
}

Function Invoke-AllAccessChecks {
    PARAM(
        [Parameter()]
        [String]
        $Tenant,

        [Parameter()]
        [String]
        $Outfile = $false
    )
    Begin {
        __AAP-ConnectIfNecessary -Tenant $Tenant
    }
    Process {
        __AAP-Log "# All Access Checks"
        Invoke-AccessCheckForCurrentUser -Outfile:$Outfile -Tenant $Tenant
        Invoke-AccessCheckForAllUsers -Outfile:$Outfile -Tenant $Tenant
        Invoke-AccessCheckForAllGroups -Outfile:$Outfile -Tenant $Tenant
        Invoke-AccessCheckForAllServicePrincipals -Outfile:$Outfile -Tenant $Tenant
    }
}


Function Enumerate-AllHighPrivilegePrincipals {
    PARAM(
        [Parameter()]
        [String]
        $Tenant,

        [Parameter()]
        [String]
        $Outfile = $false
    )
    Begin {
        __AAP-ConnectIfNecessary -Tenant $Tenant
        $highPrivilegedDirectoryRoleTemplatesMap = __AAP-GetHighPrivilegedDirectoryRoleTemplateMap
        If($script:gAllMgDirectoryRoles.Length -eq 0){ $script:gAllMgDirectoryRoles = Get-MgDirectoryRole -All }
    }
    Process {
        __AAP-Log "[*] Hang on, this might take a while..."
        ##
        ## Principals with high privileged default directory role
        ##  Enumerating all Directory Role Assignments
        ##
        $nonHighPrivAssignments = @{}
        $directoryRoleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty "RoleDefinition"
        $progressCount = 0
        $progressLimit = $directoryRoleAssignments.Count
        ForEach($directoryRoleAssignment in $directoryRoleAssignments ){
            $progressCount += 1
            $principalID = $directoryRoleAssignment.PrincipalId
            $templateID = $directoryRoleAssignment.RoleDefinition.TemplateId
            $templateName = $directoryRoleAssignment.RoleDefinition.DisplayName
            
            __AAP-CheckIfMemberOfPrivilegedDirectoryRole -PrincipalID $principalID -NonHighPrivilegedRoleAssignments $nonHighPrivAssignments -TemplateID $templateID -TemplateName $templateName

            # $principalObjectData = Get-MgDirectoryObjectById -Ids $principalID
            # $principalID = $principalObjectData.Id
            # $principalName = $null
            # $principalType = 'Unknown'
            # $highPrivReason = "High privileged directory Role: $($highPrivilegedDirectoryRoleTemplatesMap[$templateID])"
            # If( $principalObjectData.AdditionalProperties ){
            #     $aadDirectoryObjType = $principalObjectData.AdditionalProperties['@odata.type']
            #     Switch($aadDirectoryObjType){
            #         '#microsoft.graph.user' {
            #             $principalType = 'User'
            #             $principalName = $principalObjectData.AdditionalProperties['userPrincipalName']
            #             Break
            #         }
            #         '#microsoft.graph.group' {
            #             $principalType = 'Group'
            #             $principalName = $principalObjectData.AdditionalProperties['displayName']
            #             Break
            #         }
            #         '#microsoft.graph.servicePrincipal' {
            #             $principalType = 'ServicePrincipal'
            #             $principalName = $principalObjectData.AdditionalProperties['appDisplayName']
            #             Break
            #         }
            #     }
            # }
            # If( $templateID -In $highPrivilegedDirectoryRoleTemplatesMap.Keys ){
            #     ## 100 for Global Administrator, 99 for all others 
            #     $confidenceLevel = If( $highPrivilegedDirectoryTemplateRoleID -eq '62E90394-69F5-4237-9190-012177145E10' ){ 100 } Else { 99 }

            #     __AAP-AddToHighPrivilegePrincipalMap -PrincipalID $principalID -PrincipalName $principalName -Reason $highPrivReason -PrincipalType $principalType -ConfidenceLevel $confidenceLevel
            # }Else {
            #     $principalEntries = If( $nonHighPrivAssignments.Keys -Contains $principalID ){ ,$nonHighPrivAssignments.Item($principalID) } Else { ,@() } 
            #     $principalEntries += @{
            #         'principalID' = $principalID;
            #         'principalName' = $PrincipalName;
            #         'principalType' = $PrincipalType;
            #         'RoleDisplayName' = $directoryRoleAssignment.RoleDefinition.DisplayName
            #     }
            #     $nonHighPrivAssignments[$principalID] = $principalEntries
            # }

            $progressOperation = "$progressCount/$progressLimit"
            $progressPercentage = ($progressCount/$progressLimit)*100
            Write-Progress -Activity "Enumerating High Privileged Directory Role Assignments" -PercentComplete $progressPercentage -CurrentOperation $progressOperation
        }
        Write-Progress -Activity "Enumerating High Privileged Directory Role Assignments" -Status "Ready" -Completed
        # ForEach($principalId in $nonHighPrivAssignments.Keys){
        #     $principalEntries = $nonHighPrivAssignments[$principalId]
        #     $firstEntry = $principalEntries[0]
        #     $principalName = $firstEntry['principalName']
        #     $principalType = $firstEntry['principalType']
        #     __AAP-Log "[*] $($principalName) ($($principalType)) is assigned the following DirectoryRoles, which are currently not considered high privilege, but might be worth investigating:" -MsgType $MESSAGE_WARNING
            
        #     ForEach($principalEntry in $principalEntries){
        #         $roleDisplayName = $principalEntry['RoleDisplayName']
        #         __AAP-Log "  $($roleDisplayName)"
        #     }
        # }

        ##
        ## Principals with high privileged PIM assigned directory role
        ##  Enumerating all PIM assigned roles
        ##
        $azureADPrivRoleAssignments = Get-AzureADMSPrivilegedRoleAssignment -ProviderId "aadRoles" -ResourceId $global:__AAPgTenantID
        $azureADPrivRoleDefinitions = Get-AzureADMSPrivilegedRoleDefinition -ProviderId "aadRoles" -ResourceId $global:__AAPgTenantID

        $progressCount = 0
        $progressLimit = $azureADPrivRoleAssignments.Count
        ForEach($azureADPrivRoleAssignment in $azureADPrivRoleAssignments){
            $progressCount += 1
            If(
                ( -Not $azureADPrivRoleAssignment.EndDateTime ) -Or ## no end date ==> Permanent
                ( (Get-Date) -lt ($azureADPrivRoleAssignment.EndDateTime) ) ## End date in the future
            ){
                ## Active assginment
                $privRoleDefinition = $azureADPrivRoleDefinitions | ? { $_.Id -eq $azureADPrivRoleAssignment.RoleDefinitionId } | Select-Object -First 1

                If( $privRoleDefinition ){
                    __AAP-CheckIfMemberOfPrivilegedDirectoryRole -PrincipalID $azureADPrivRoleAssignment.SubjectId -NonHighPrivilegedRoleAssignments $nonHighPrivAssignments -TemplateID $privRoleDefinition.ExternalId -TemplateName $privRoleDefinition.DisplayName -AssignedViaPIM




                    # $templateID = $privRoleDefinition.ExternalId.toUpper()
                    # If( $templateID -In $highPrivilegedDirectoryRoleTemplatesMap.Keys ){
                    #     ## 100 for Global Administrator, 99 for all others 
                    #     $confidenceLevel = If( $highPrivilegedDirectoryTemplateRoleID -eq '62E90394-69F5-4237-9190-012177145E10' ){ 100 } Else { 99 }

                    #     ## Get corresponding principal
                    #     $principalObjectData = (Get-MgDirectoryObjectById -Ids $azureADPrivRoleAssignment.SubjectId)
                    #     $principalID = $principalObjectData.Id
                    #     $principalName = $null
                    #     $principalType = 'Unknown'
                    #     $highPrivReason = "High privileged PIM-assigned directory Role: $($highPrivilegedDirectoryRoleTemplatesMap[$templateID])"
                    #     If( $principalObjectData.AdditionalProperties ){
                    #         ## Resolve principal
                    #         $aadDirectoryObjType = $principalObjectData.AdditionalProperties['@odata.type']
                    #         Switch($aadDirectoryObjType){
                    #             '#microsoft.graph.user' {
                    #                 $principalType = 'User'
                    #                 $principalName = $principalObjectData.AdditionalProperties['userPrincipalName']
                    #                 ## Add entry
                    #                 __AAP-AddToHighPrivilegePrincipalMap -PrincipalID $principalID -PrincipalName $principalName -Reason $highPrivReason -PrincipalType $principalType -ConfidenceLevel $confidenceLevel
                    #                 Break
                    #             }
                    #             '#microsoft.graph.group' {
                    #                 $principalType = 'Group'
                    #                 ## Resovle members
                    #                 $securityIdentifier = $principalObjectData.AdditionalProperties['securityIdentifier']
                    #                 $mgGroup = Get-MgGroup -Filter "securityIdentifier eq '$($securityIdentifier)'" -Top 1
                    #                 If( $mgGroup ){
                    #                     $mgGroupMembers = Get-MgGroupTransitiveMember -GroupId $mgGroup.Id
                    #                     ForEach($mgGroupMember in $mgGroupMembers){
                    #                         $principalID = $mgGroupMember.Id
                    #                         $principalName = $null
                    #                         $groupMemberObjType = $mgGroupMember.AdditionalProperties['@odata.type']
                    #                         $highPrivReason = "Member of group ($($mgGroup.DisplayName)) with high privileged PIM-assigned directory Role: $($highPrivilegedDirectoryRoleTemplatesMap[$templateID])"
                    #                         Switch($groupMemberObjType){
                    #                             '#microsoft.graph.user' {
                    #                                 $principalType = 'User'
                    #                                 $principalName = $mgGroupMember.AdditionalProperties['userPrincipalName']
                    #                                 Break
                    #                             }
                    #                             '#microsoft.graph.servicePrincipal' {
                    #                                 $principalType = 'ServicePrincipal'
                    #                                 $principalName = $mgGroupMember.AdditionalProperties['appDisplayName']
                    #                                 Break
                    #                             }
                    #                         }
                    #                         ## Add entry
                    #                         __AAP-AddToHighPrivilegePrincipalMap -PrincipalID $principalID -PrincipalName $principalName -Reason $highPrivReason -PrincipalType $principalType -ConfidenceLevel $confidenceLevel
                    #                     }
                    #                 }
                    #                 #$principalName = $principalObjectData.AdditionalProperties['displayName']
                    #                 Break
                    #             }
                    #             '#microsoft.graph.servicePrincipal' {
                    #                 $principalType = 'ServicePrincipal'
                    #                 $principalName = $principalObjectData.AdditionalProperties['appDisplayName']
                    #                 ## Add entry
                    #                 __AAP-AddToHighPrivilegePrincipalMap -PrincipalID $principalID -PrincipalName $principalName -Reason $highPrivReason -PrincipalType $principalType -ConfidenceLevel $confidenceLevel
                    #                 Break
                    #             }
                    #         }
                    #     }
                    # }
                    #Write-Host "$($principalName) is $($privRoleDefinition.displayName) until $($azureADPrivRoleAssignment.EndDateTime)"
                }
                
            }
            $progressOperation = "$progressCount/$progressLimit"
            $progressPercentage = ($progressCount/$progressLimit)*100
            Write-Progress -Activity "Enumerating High Privileged Directory Role Assignments (via PIM)" -PercentComplete $progressPercentage -CurrentOperation $progressOperation
        }
        Write-Progress -Activity "Enumerating High Privileged Directory Role Assignments (via PIM)" -Status "Ready" -Completed
        
        ## Display Non High Privileged Role Assignments
        __AAP-DisplayNonHighPrivilegedRoleAssignments -NonHighPrivilegedRoleAssignments $nonHighPrivAssignments
        
        ## 
        ## Groups
        ##  Enumerating AppRoles assigned to a grouo
        ##
        $mgGroups = Get-MgGroup -All
        $progressCount = 0
        $progressLimit = $mgGroups.Count
        ForEach($mgGroup in $mgGroups ){
            $progressCount += 1
            $groupMarkedAsHighvalue = $false
            $groupHighValueConfidenceLevel = 0
            $groupAppRoleAssignments = Get-MgGroupAppRoleAssignment -GroupId $mgGroup.Id

            ##  Enumerating AppRoles assigned to a grouo
            If( $groupAppRoleAssignments ){
                ForEach($appRoleAssignment in $groupAppRoleAssignments ){
                    $appRole = $null
                    $appRoleValue = 'default'
                    If( $appRoleAssignment.AppRoleId -ne '00000000-0000-0000-0000-000000000000' ){
                        $appRole = ((Get-MgServicePrincipal -ServicePrincipalId $appRoleAssignment.ResourceId).AppRoles | ? {$_.Id -eq $appRoleAssignment.AppRoleId} | Select-Object -First 1)
                        $appRoleValue = $appRole.Value 
                    }

                    If( $appRole -And $appRole.IsEnabled ){
                        $highPrivConfidenceLevel = __AAP-AppRoleIsHighPrivilegeConfidenceGuess -AppRoleObject $appRole
                        If( $highPrivConfidenceLevel -gt 0 ){
                            $highPrivReason = "Assigned AppRole '$($appRole.Value)' of Resource '$($appRoleAssignment.ResourceDisplayName)'"
                            __AAP-AddToHighPrivilegePrincipalMap -PrincipalID $mgGroup.Id -PrincipalName $mgGroup.DisplayName -Reason $highPrivReason -PrincipalType 'Group' -ConfidenceLevel $highPrivConfidenceLevel
                            $groupMarkedAsHighvalue = $true
                            $groupHighValueConfidenceLevel = $highPrivConfidenceLevel
                        }
                    }
                }
            }
            If( $groupMarkedAsHighvalue ){
                ## If the group is high privilege, all its members are high privilege
                $groupMembers = Get-MgGroupTransitiveMember -GroupId $mgGroup.Id -All
                ForEach($groupMember in $groupMembers){
                    $principalID = $groupMember.Id
                    $principalType = 'Unknown'
                    $principalName = ''
                    $additionalProperties = $groupMember.AdditionalProperties
                    If( $additionalProperties ){
                        $additionalPropertiesObjType = $additionalProperties['@odata.type']
                        Switch($additionalPropertiesObjType){
                            '#microsoft.graph.user' {
                                $principalType = 'User'
                                $principalName = $additionalProperties['userPrincipalName']
                                Break
                            }
                            '#microsoft.graph.group' {
                                $principalType = 'Group'
                                $principalName = $additionalProperties['displayName']
                                Break
                            }
                            '#microsoft.graph.servicePrincipal' {
                                $principalType = 'ServicePrincipal'
                                $principalName = $additionalProperties['appDisplayName']
                                Break
                            }
                            '#microsoft.graph.device' {
                                ## Currently not including devices
                                Break
                            }
                        }
                    }
                    $highPrivReason = "Member of high privilege group '$($mgGroup.DisplayName)'"
                    __AAP-AddToHighPrivilegePrincipalMap -PrincipalID $principalID -PrincipalName $principalName -Reason $highPrivReason -PrincipalType $principalType -ConfidenceLevel $groupHighValueConfidenceLevel
                }
            }
            
            $progressOperation = "$progressCount/$progressLimit"
            $progressPercentage = ($progressCount/$progressLimit)*100
            Write-Progress -Activity "Enumerating High Privilege Groups" -PercentComplete $progressPercentage -CurrentOperation $progressOperation
        }
        Write-Progress -Activity "Enumerating High Privilege Groups" -Status "Ready" -Completed

        ##
        ## Service Principals
        ##  Enumerating AppRoles assigned to Service Princiapals
        ##  Enumerating AppRoles assigned from Service Principals to Users, Groups and Service Principals
        ##  Enumerating owners of service principals
        ##  Enumerating owners of corresponding applications
        ##  Enumerating objects owned by service principals
        ##
        $mgServicePrincipals = Get-MgServicePrincipal -All
        $progressCount = 0
        $progressLimit = $mgServicePrincipals.Count
        ForEach($mgServicePrincipal in $mgServicePrincipals ){
            $progressCount += 1
            $appRolesAssignedToServicePrincipals = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $mgServicePrincipal.Id -All
            $principalsWithAssignedAppRoleToServicePrincipal = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $mgServicePrincipal.Id -All
            $applicationObjectsOfServicePrincipal = Get-MgApplication -Filter "AppId eq '$($mgServicePrincipal.AppId)'" -All
            $objectsOwnedByServicePrincipal = Get-MgServicePrincipalOwnedObject -ServicePrincipalId $mgServicePrincipal.Id -All

            $servicePrincipalMarkedAsHighvalue = $false
            $servicePrincipalHighValueConfidenceLevel = 0

            ##  Enumerating AppRoles assigned to Service Princiapals
            If( $appRolesAssignedToServicePrincipals ){
                ForEach($appRoleAssignment in $appRolesAssignedToServicePrincipals){
                    $appRole = $null
                    $appRoleValue = 'default'
                    If( $appRoleAssignment.AppRoleId -ne '00000000-0000-0000-0000-000000000000' ){
                        $appRole = ((Get-MgServicePrincipal -ServicePrincipalId $appRoleAssignment.ResourceId).AppRoles | ? {$_.Id -eq $appRoleAssignment.AppRoleId} | Select-Object -First 1)
                        $appRoleValue = $appRole.Value 
                    }

                    If( $appRole -And $appRole.IsEnabled ){
                        $highPrivConfidenceLevel = __AAP-AppRoleIsHighPrivilegeConfidenceGuess -AppRoleObject $appRole
                        If( $highPrivConfidenceLevel -gt 0 ){
                            $highPrivReason = "Assigned AppRole '$($appRole.Value)' of Resource '$($appRoleAssignment.ResourceDisplayName)'"
                            __AAP-AddToHighPrivilegePrincipalMap -PrincipalID $mgServicePrincipal.Id -PrincipalName $mgServicePrincipal.AppDisplayName -Reason $highPrivReason -PrincipalType 'ServicePrincipal' -ConfidenceLevel $highPrivConfidenceLevel
                            $servicePrincipalMarkedAsHighvalue = $true
                            $servicePrincipalHighValueConfidenceLevel = $highPrivConfidenceLevel
                        }
                    }
                }
            }

            ##  Enumerating AppRoles assigned from Service Principals to Users, Groups and Service Principals
            If( $principalsWithAssignedAppRoleToServicePrincipal ){
                ForEach($appRoleAssignment in $principalsWithAssignedAppRoleToServicePrincipal){
                    ## 00000000-0000-0000-0000-000000000000 is the default appRoleID
                    If( $appRoleAssignment.AppRoleId -ne '00000000-0000-0000-0000-000000000000' ){
                        $appRole = $mgServicePrincipal.appRoles | ? { $_.Id -eq $appRoleAssignment.AppRoleId } | Select-Object -First 1
                        If( $appRole -And $appRole.IsEnabled ){
                            $highPrivConfidenceLevel = __AAP-AppRoleIsHighPrivilegeConfidenceGuess -AppRoleObject $appRole
                            If( $highPrivConfidenceLevel -gt 0 ){
                                $highPrivReason = "Assigned AppRole '$($appRole.Value)' of Resource '$($appRoleAssignment.ResourceDisplayName)'"
                                __AAP-AddToHighPrivilegePrincipalMap -PrincipalID $appRoleAssignment.PrincipalId -PrincipalName $appRoleAssignment.PrincipalDisplayName -Reason $highPrivReason -PrincipalType $appRoleAssignment.PrincipalType -ConfidenceLevel $highPrivConfidenceLevel
                            }
                        }
                    }
                }
            }

            ## Check if service principal has been marked as high value in previous steps
            If(-Not $servicePrincipalMarkedAsHighvalue){
                If( $script:gHighPrivilegdPrincipalMap.Keys -Contains $mgServicePrincipal.Id ){
                    $servicePrincipalMarkedAsHighvalue = $true
                    $entryArray = $script:gHighPrivilegdPrincipalMap.Item($mgServicePrincipal.Id)
                    $highestConfidenceLevel = $entryArray | Sort-Object { $_.ConfidenceLevel } -Descending | Select-Object -First 1 | %{ $_.ConfidenceLevel }
                    $servicePrincipalHighValueConfidenceLevel = $highestConfidenceLevel
                }
            }

            ##  Enumerating owners of service principals
            If( $servicePrincipalMarkedAsHighvalue ) {
                $ownersOfServicePrincipal = Get-MgServicePrincipalOwner -All -ServicePrincipalId $mgServicePrincipal.Id
                ForEach($ownerOfServicePrincipal in $ownersOfServicePrincipal){
                    $principalID = $ownerOfServicePrincipal.Id
                    $principalType = 'Unknown'
                    $principalName = ''
                    $additionalProperties = $ownerOfServicePrincipal.AdditionalProperties
                    If( $additionalProperties ){
                        $additionalPropertiesObjType = $additionalProperties['@odata.type']
                        Switch($additionalPropertiesObjType){
                            '#microsoft.graph.user' {
                                $principalType = 'User'
                                $principalName = $additionalProperties['userPrincipalName']
                                Break
                            }
                            '#microsoft.graph.group' {
                                $principalType = 'Group'
                                $principalName = $additionalProperties['displayName']
                                Break
                            }
                            '#microsoft.graph.servicePrincipal' {
                                $principalType = 'ServicePrincipal'
                                $principalName = $additionalProperties['appDisplayName']
                                Break
                            }
                        }
                    }
                    $highPrivReason = "Owns high privilege service principal '$($mgServicePrincipal.AppDisplayName)'"
                    __AAP-AddToHighPrivilegePrincipalMap -PrincipalID $principalID -PrincipalName $principalName -Reason $highPrivReason -PrincipalType $principalType -ConfidenceLevel $servicePrincipalHighValueConfidenceLevel
                }
            }

            ##  Enumerating owners of corresponding applications
            If( $servicePrincipalMarkedAsHighvalue -And $applicationObjectsOfServicePrincipal ){
                ForEach($applicationObjectOfServicePrincipal in $applicationObjectsOfServicePrincipal){
                    $applicationOwnersProperties = Get-MgApplicationOwner -ApplicationId $applicationObjectOfServicePrincipal.Id -All
                    ForEach($applicationOwnerProperties in $applicationOwnersProperties){
                        $principalID = $applicationOwnerProperties.Id
                        $principalType = 'Unknown'
                        $principalName = ''
                        $additionalProperties = $applicationOwnerProperties.AdditionalProperties
                        If( $additionalProperties ){
                            $additionalPropertiesObjType = $additionalProperties['@odata.type']
                            Switch($additionalPropertiesObjType){
                                '#microsoft.graph.user' {
                                    $principalType = 'User'
                                    $principalName = $additionalProperties['userPrincipalName']
                                    Break
                                }
                                '#microsoft.graph.group' {
                                    $principalType = 'Group'
                                    $principalName = $additionalProperties['displayName']
                                    Break
                                }
                                '#microsoft.graph.servicePrincipal' {
                                    $principalType = 'ServicePrincipal'
                                    $principalName = $additionalProperties['appDisplayName']
                                    Break
                                }
                            }
                        }
                        $highPrivReason = "Owns the application object of the high privilege service principal '$($mgServicePrincipal.AppDisplayName)'"
                        __AAP-AddToHighPrivilegePrincipalMap -PrincipalID $principalID -PrincipalName $principalName -Reason $highPrivReason -PrincipalType $principalType -ConfidenceLevel $servicePrincipalHighValueConfidenceLevel
                    }
                }
            }

            ##  Enumerating objects owned by service principals
            If( $objectsOwnedByServicePrincipal ){
                ForEach($objectOwnedByServicePrincipal in $objectsOwnedByServicePrincipal){
                    ## Check if the owned object is of high value
                    If( $script:gHighPrivilegdPrincipalMap.Keys -Contains $objectOwnedByServicePrincipal.Id ){
                        ## Get confidence Level of owned object
                        $entryArray = $script:gHighPrivilegdPrincipalMap.Item($objectOwnedByServicePrincipal.Id)
                        $highestConfidenceLevel = $entryArray | Sort-Object { $_.ConfidenceLevel } -Descending | Select-Object -First 1 | %{ $_.ConfidenceLevel }
                        ## gather additional information
                        $additionalProperties = $objectOwnedByServicePrincipal.AdditionalProperties
                        If(-Not $additionalProperties){
                            $mgDirectoryObject = Get-MgDirectoryObjectById -Ids $objectOwnedByServicePrincipal.Id
                            $additionalProperties = $mgDirectoryObject.AdditionalProperties
                        }
                        $principalID = $objectOwnedByServicePrincipal.Id
                        $principalType = 'Unknown'
                        $principalName = ''
                        If( $additionalProperties ){
                            $additionalPropertiesObjType = $additionalProperties['@odata.type']
                            Switch($additionalPropertiesObjType){
                                '#microsoft.graph.user' {
                                    $principalType = 'User'
                                    $principalName = $additionalProperties['userPrincipalName']
                                    Break
                                }
                                '#microsoft.graph.group' {
                                    $principalType = 'Group'
                                    $principalName = $additionalProperties['displayName']
                                    Break
                                }
                                '#microsoft.graph.servicePrincipal' {
                                    $principalType = 'ServicePrincipal'
                                    $principalName = $additionalProperties['appDisplayName']
                                    Break
                                }
                            }
                        }
                        $highPrivReason = "Service principal owns high value $($principalType): '$($principalName)' ($($principalID))"
                        __AAP-AddToHighPrivilegePrincipalMap -PrincipalID $mgServicePrincipal.Id -PrincipalName $mgServicePrincipal.AppDisplayName -Reason $highPrivReason -PrincipalType 'ServicePrincipal' -ConfidenceLevel $highestConfidenceLevel
                    }
                }
            }

            $progressOperation = "$progressCount/$progressLimit"
            $progressPercentage = ($progressCount/$progressLimit)*100
            Write-Progress -Activity "Enumerating High Privilege Service Principals" -PercentComplete $progressPercentage -CurrentOperation $progressOperation
        }
        Write-Progress -Activity "Enumerating High Privilege Service Principals" -Status "Ready" -Completed
        
        ##
        ## User owning objects
        ##
        $mgUsers = Get-MgUser -All -ExpandProperty 'ownedObjects'
        $usersOwningObjects = $mgUsers | ?{ $_.OwnedObjects }
        $progressCount = 0
        $progressLimit = $usersOwningObjects.Count
        ForEach( $mgUser in $usersOwningObjects ){
            $progressCount += 1
            $principalID = $mgUser.Id
            $principalName =  $mgUser.UserPrincipalName
            
            ForEach($mgOwnedObjectRef in $mgUser.OwnedObjects){
                $mgOwnedObj = Get-MgDirectoryObjectById -Ids $mgOwnedObjectRef.Id -ErrorAction SilentlyContinue
                $mgOwnedObjProperties = $mgOwnedObj.AdditionalProperties
                if( $mgOwnedObjProperties ){
                    Switch($mgOwnedObjProperties['@odata.type']){            
                        '#microsoft.graph.user' {
                            $userName = $mgOwnedObjProperties['userPrincipalName']
                            ## Check if owned user is high value
                            If( $script:gHighPrivilegdPrincipalMap.Keys -Contains $mgOwnedObjectRef.Id ){
                                __AAP-AddToHighPrivilegePrincipalMap -PrincipalID $principalID -PrincipalName $principalName -Reason "Owns high privilege user '$userName'" -PrincipalType 'User' -ConfidenceLevel 1
                            }
                            Break
                        }
                        '#microsoft.graph.group' {
                            $groupName = $mgOwnedObjProperties['displayName']
                            ## Check if owned group is high value
                            If( $script:gHighPrivilegdPrincipalMap.Keys -Contains $mgOwnedObjectRef.Id ){
                                __AAP-AddToHighPrivilegePrincipalMap -PrincipalID $principalID -PrincipalName $principalName -Reason "Owns high privilege group '$groupName'" -PrincipalType 'User' -ConfidenceLevel 1
                            }
                            Break
                        }
                        '#microsoft.graph.servicePrincipal' {
                            $principalName = $mgOwnedObjProperties['appDisplayName']
                            ## Check if owned service principal is high value
                            If( $script:gHighPrivilegdPrincipalMap.Keys -Contains $mgOwnedObjectRef.Id ){
                                __AAP-AddToHighPrivilegePrincipalMap -PrincipalID $principalID -PrincipalName $principalName -Reason "Owns high privilege service principal '$principalName'" -PrincipalType 'User' -ConfidenceLevel 1
                            }
                            Break
                        }
                        '#microsoft.graph.application' {
                            $applicationName = $mgOwnedObjProperties['displayName']
                            $applicationId = $mgOwnedObjProperties['appId']
                            $applicationServicePrincipals = Get-MgServicePrincipal -All -Filter "AppId eq '$($applicationId)'"
                            ForEach($applicationServicePrincipal in $applicationServicePrincipals){
                                ## Check if associated service principal is high value
                                If( $script:gHighPrivilegdPrincipalMap.Keys -Contains $applicationServicePrincipal.Id ){
                                    __AAP-AddToHighPrivilegePrincipalMap -PrincipalID $principalID -PrincipalName $principalName -Reason "Owns application '$($applicationName)' with high privilege service principal '$($applicationServicePrincipal.AppDisplayName)'" -PrincipalType 'User' -ConfidenceLevel 1
                                }
                            }
                            Break
                        }
                        Default {
                            ## Print for debug purposes
                            $mgOwnedObjProperties.Keys | %{ __AAP-Log "  $($_): $($mgOwnedObjProperties[$_])" -MsgType $MESSAGE_INFO }
                        }
                    }
                }                    
            }
            

            $progressOperation = "$progressCount/$progressLimit"
            $progressPercentage = ($progressCount/$progressLimit)*100
            Write-Progress -Activity "Enumerating High Privilege Ownerships" -PercentComplete $progressPercentage -CurrentOperation $progressOperation
        }
        Write-Progress -Activity "Enumerating High Privilege Ownerships" -Status "Ready" -Completed
        
    }
    End {
        $script:gLastCollectionOfHighPrivilegdPrincipalMap = (Get-Date)
        __AAP-DisplayHighPrivilegePrincipalMap
    }
}

Function Enumerate-MFAStatusOfHighPrivilegePrincipals {
    PARAM(
        [Parameter()]
        [String]
        $Tenant,

        [Parameter()]
        [String]
        $Outfile = $false
    )
    Begin {
        __AAP-ConnectIfNecessary -Tenant $Tenant
    }
    Process {

        ## Check if the high privileged principals have already been enumerated in the past
        If( $script:gLastCollectionOfHighPrivilegdPrincipalMap ){
            ## Check how long ago this was    
            $currentTimeStamp = (Get-Date)
            $diffToLastEnumRun = New-TimeSpan -End $currentTimeStamp -Start $script:gLastCollectionOfHighPrivilegdPrincipalMap
            If( $diffToLastEnumRun.Hours -gt 8  ){
                __AAP-Log "Last enumeration of high privileged principals is older than 8 hours. Let's run this again..." -MsgType $MESSAGE_WARNING
                Enumerate-AllHighPrivilegePrincipals
            }
        } Else {
            ## Enumerate all high privilege principals if this has not been done before
            Enumerate-AllHighPrivilegePrincipals
        }
        ## Go through the identified high privileged principals
        __AAP-Log "## MFA Status of high privileged principals"
        $accessTokenAADGraph = __AAP-GetAcessTokenForAADGraphWithRefreshToken
        ForEach($principalID in $script:gHighPrivilegdPrincipalMap.Keys){
            $principalEntries = $script:gHighPrivilegdPrincipalMap[$principalID]
            $firstEntry = $principalEntries[0]
            
            If( $firstEntry['principalType'] -eq 'User' ){
                ## Per User MFA
                $userMFAStatus = Get-AADIntUserMFA -AccessToken $accessTokenAADGraph -UserPrincipalName $principalID -ErrorAction SilentlyContinue
                If( $userMFAStatus ){
                    $mfaDefaultMethod = $userMFAStatus.DefaultMethod
                    If( $userMFAStatus.State -eq "Enforced" ){
                        __AAP-Log "[+] User: $($firstEntry['principalName']) ($($firstEntry['principalID'])): Per User MFA Enforced (Defaullt Method: $mfaDefaultMethod)"  -MsgType $MESSAGE_SUCCESS
                    }
                    ElseIf( $userMFAStatus.State -eq "Enabled" ){
                        __AAP-Log "[!] User: $($firstEntry['principalName']) ($($firstEntry['principalID'])): Per User MFA Enabled, but not enforced (Defaullt Method: $mfaDefaultMethod)"  -MsgType $MESSAGE_WARNING
                    }
                    ElseIf( $userMFAStatus.State -eq "Disabled" ){
                        __AAP-Log "[!] User: $($firstEntry['principalName']) ($($firstEntry['principalID'])): Per User MFA Disabled."  -MsgType $MESSAGE_WARNING
                    }
                    Else {
                        __AAP-Log "[?] User: $($firstEntry['principalName']) ($($firstEntry['principalID'])): Per User MFA status unknown/unset."  -MsgType $MESSAGE_WARNING
                    }
                }
                ## Conditional Access Policies
                __AAP-Log "[*] Applicable MFA Conditional Access Policies for this user:"  -MsgType $MESSAGE_INFO
                __AAP-DisplayApplicableMFAConditionalAccessPolicyForUserID -UserID $principalID -IndentationLevel 1
            }
            Else {
                __AAP-Log "[X] $($firstEntry['principalType']): $($firstEntry['principalName']) ($($firstEntry['principalID'])): MFA is not supported for $($firstEntry['principalType'])s."  -MsgType $MESSAGE_FAIL
            }
        }      
    }
}

If( __AAP-CheckRequiredModules ){
    __AAP-Log "[*] Loading required modules..."
    $windowTitle = $host.ui.RawUI.WindowTitle
    If( __AAP-ImportRequiredModules ){
        $host.ui.RawUI.WindowTitle = $windowTitle
        __AAP-Log "[*] Modules imported."
        __AAP-Log $banner -MsgType $MESSAGE_WARNING
    }
}