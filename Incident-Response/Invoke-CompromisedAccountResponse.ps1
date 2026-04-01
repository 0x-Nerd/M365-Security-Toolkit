<#
.SYNOPSIS
    Automated incident response for compromised Microsoft 365 accounts.

.DESCRIPTION
    Performs a structured response to a compromised M365 account including:
    - Blocking sign-in
    - Revoking active sessions
    - Resetting password
    - Exporting 30 days of sign-in logs
    - Auditing mailbox rules
    - Checking SMTP forwarding
    - Checking delegate access
    - Auditing MFA methods
    - Checking OAuth app permissions
    All actions are logged and a summary report is generated.

.PARAMETER UserPrincipalName
    The UPN of the compromised account. Example: jsmith@contoso.com

.PARAMETER OutputPath
    Optional. Base path for output folder. Defaults to current directory.

.EXAMPLE
    .\Invoke-CompromisedAccountResponse.ps1 -UserPrincipalName "jsmith@contoso.com"

.EXAMPLE
    .\Invoke-CompromisedAccountResponse.ps1 -UserPrincipalName "jsmith@contoso.com" -OutputPath "C:\IR"

.NOTES
    Author: Stephen Cothron
    Requires: Microsoft Graph PowerShell SDK, Exchange Online Management Module
    Permissions: User.ReadWrite.All, AuditLog.Read.All, Directory.ReadWrite.All,
                 UserAuthenticationMethod.ReadWrite.All, Application.Read.All
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path
)

#region Module Checks

function Test-RequiredModules {
    $requiredModules = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Identity.SignIns',
        'Microsoft.Graph.Applications',
        'ExchangeOnlineManagement'
    )

    $missingModules = @()

    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            $missingModules += $module
        }
    }

    if ($missingModules.Count -gt 0) {
        Write-Host "`n[!] The following required modules are not installed:" -ForegroundColor Yellow
        $missingModules | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }

        $install = Read-Host "`nWould you like to install them now? (Y/N)"

        if ($install -eq 'Y') {
            foreach ($module in $missingModules) {
                Write-Host "[*] Installing $module..." -ForegroundColor Cyan
                Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
            }
            Write-Host "[+] All modules installed successfully.`n" -ForegroundColor Green
        } else {
            Write-Host "[!] Cannot proceed without required modules. Exiting." -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "[+] All required modules are present.`n" -ForegroundColor Green
    }
}

Test-RequiredModules

#endregion

#region Output Setup

$timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"
$sanitizedUPN = $UserPrincipalName -replace '[^a-zA-Z0-9]', '_'
$outputFolder = Join-Path -Path $OutputPath -ChildPath "IR_$sanitizedUPN`_$timestamp"

New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null

$logFile         = Join-Path $outputFolder "ActionLog.txt"
$signInLog       = Join-Path $outputFolder "SignInLogs.csv"
$mailboxRulesLog = Join-Path $outputFolder "MailboxRules.csv"
$forwardingLog   = Join-Path $outputFolder "ForwardingConfig.txt"
$delegateLog     = Join-Path $outputFolder "DelegateAccess.txt"
$mfaLog          = Join-Path $outputFolder "MFAMethods.txt"
$oauthLog        = Join-Path $outputFolder "OAuthApps.txt"
$summaryReport   = Join-Path $outputFolder "IncidentSummary.txt"

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ACTION','SUCCESS','ERROR')]
        [string]$Level = 'INFO'
    )

    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"

    switch ($Level) {
        'INFO'    { Write-Host $entry -ForegroundColor White }
        'WARN'    { Write-Host $entry -ForegroundColor Yellow }
        'ACTION'  { Write-Host $entry -ForegroundColor Cyan }
        'SUCCESS' { Write-Host $entry -ForegroundColor Green }
        'ERROR'   { Write-Host $entry -ForegroundColor Red }
    }

    Add-Content -Path $logFile -Value $entry
}

Write-Log "Incident response initiated for $UserPrincipalName" -Level ACTION
Write-Log "Output folder created: $outputFolder" -Level INFO

#endregion

#region Connections

function Connect-RequiredServices {
    Write-Log "Connecting to Microsoft Graph..." -Level ACTION
    try {
        Connect-MgGraph -Scopes `
            "User.ReadWrite.All",
            "AuditLog.Read.All",
            "Directory.ReadWrite.All",
            "UserAuthenticationMethod.ReadWrite.All",
            "Application.Read.All" `
            -ErrorAction Stop
        Write-Log "Microsoft Graph connected successfully." -Level SUCCESS
    } catch {
        Write-Log "Failed to connect to Microsoft Graph: $_" -Level ERROR
        exit 1
    }

    Write-Log "Connecting to Exchange Online..." -Level ACTION
    try {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Log "Exchange Online connected successfully." -Level SUCCESS
    } catch {
        Write-Log "Failed to connect to Exchange Online: $_" -Level ERROR
        exit 1
    }
}

Connect-RequiredServices

#endregion

#region Account Lockout

function Invoke-AccountLockout {
    Write-Log "Retrieving user account: $UserPrincipalName" -Level ACTION

    try {
        $user = Get-MgUser -UserId $UserPrincipalName -ErrorAction Stop
        Write-Log "User found: $($user.DisplayName) | ID: $($user.Id)" -Level INFO
    } catch {
        Write-Log "User not found: $UserPrincipalName — $_" -Level ERROR
        exit 1
    }

    # Block sign-in
    Write-Log "Blocking sign-in for $UserPrincipalName..." -Level ACTION
    try {
        Update-MgUser -UserId $user.Id `
            -AccountEnabled:$false `
            -ErrorAction Stop
        Write-Log "Sign-in blocked successfully." -Level SUCCESS
    } catch {
        Write-Log "Failed to block sign-in: $_" -Level ERROR
    }

    # Revoke all active sessions
    Write-Log "Revoking all active sessions..." -Level ACTION
    try {
        Revoke-MgUserSignInSession -UserId $user.Id -ErrorAction Stop
        Write-Log "All active sessions revoked successfully." -Level SUCCESS
    } catch {
        Write-Log "Failed to revoke sessions: $_" -Level ERROR
    }

    # Generate and set a new temporary password
    Write-Log "Resetting account password..." -Level ACTION
    try {
        Add-Type -AssemblyName System.Web
        $newPassword = [System.Web.Security.Membership]::GeneratePassword(20, 4)

        $passwordProfile = @{
            Password                      = $newPassword
            ForceChangePasswordNextSignIn = $true
        }

        Update-MgUser -UserId $user.Id `
            -PasswordProfile $passwordProfile `
            -ErrorAction Stop

        Write-Log "Password reset successfully." -Level SUCCESS
        Write-Log "TEMPORARY PASSWORD: $newPassword — Store securely and do not share via email." -Level WARN
    } catch {
        Write-Log "Failed to reset password: $_" -Level ERROR
    }

    return $user
}

$compromisedUser = Invoke-AccountLockout

#endregion

#region Sign-In Logs

function Get-SignInLogs {
    param([string]$UserId)

    Write-Log "Collecting 30 days of sign-in logs..." -Level ACTION

    try {
        $startDate = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")

        $signInLogs = Get-MgAuditLogSignIn `
            -Filter "userId eq '$UserId' and createdDateTime ge $startDate" `
            -All `
            -ErrorAction Stop

        if ($signInLogs.Count -eq 0) {
            Write-Log "No sign-in logs found for the past 30 days." -Level WARN
            return
        }

        Write-Log "Retrieved $($signInLogs.Count) sign-in events." -Level INFO

        $suspicious = @()

        $signInLogs | ForEach-Object {
            $entry = [PSCustomObject]@{
                DateTime          = $_.CreatedDateTime
                AppDisplayName    = $_.AppDisplayName
                IPAddress         = $_.IpAddress
                Location          = "$($_.Location.City), $($_.Location.State), $($_.Location.CountryOrRegion)"
                Status            = $_.Status.ErrorCode
                StatusDetail      = $_.Status.FailureReason
                DeviceOS          = $_.DeviceDetail.OperatingSystem
                Browser           = $_.DeviceDetail.Browser
                ConditionalAccess = $_.ConditionalAccessStatus
                Suspicious        = $false
            }

            if ($_.Location.CountryOrRegion -ne 'US' -and
                $_.Location.CountryOrRegion -ne '') {
                $entry.Suspicious = $true
                $suspicious += $entry
            }

            $entry
        } | Export-Csv -Path $signInLog -NoTypeInformation

        Write-Log "Sign-in logs exported to $signInLog" -Level SUCCESS

        if ($suspicious.Count -gt 0) {
            Write-Log "FLAGGED: $($suspicious.Count) sign-in event(s) from outside the United States." -Level WARN
            $suspicious | ForEach-Object {
                Write-Log "  >> $($_.DateTime) | $($_.Location) | $($_.IPAddress) | $($_.AppDisplayName)" -Level WARN
            }
        } else {
            Write-Log "No foreign sign-in activity detected." -Level INFO
        }

    } catch {
        Write-Log "Failed to retrieve sign-in logs: $_" -Level ERROR
    }
}

Get-SignInLogs -UserId $compromisedUser.Id

#endregion

#region Mailbox Rules

function Get-MailboxRulesAudit {
    param([string]$UPN)

    Write-Log "Auditing mailbox rules for $UPN..." -Level ACTION

    try {
        $rules = Get-InboxRule -Mailbox $UPN -ErrorAction Stop

        if ($rules.Count -eq 0) {
            Write-Log "No mailbox rules found." -Level INFO
            "No mailbox rules found." | Out-File $mailboxRulesLog
            return
        }

        Write-Log "Found $($rules.Count) mailbox rule(s)." -Level INFO

        $flaggedRules = @()

        $rules | ForEach-Object {
            $rule = [PSCustomObject]@{
                Name                = $_.Name
                Enabled             = $_.Enabled
                Priority            = $_.Priority
                DeleteMessage       = $_.DeleteMessage
                MoveToFolder        = $_.MoveToFolder
                ForwardTo           = $_.ForwardTo
                ForwardAsAttachment = $_.ForwardAsAttachmentTo
                RedirectTo          = $_.RedirectTo
                StopProcessingRules = $_.StopProcessingRules
                Suspicious          = $false
                SuspiciousReason    = ''
            }

            if ($_.DeleteMessage -eq $true) {
                $rule.Suspicious = $true
                $rule.SuspiciousReason += 'Deletes incoming messages. '
            }

            if ($_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo) {
                $rule.Suspicious = $true
                $rule.SuspiciousReason += 'Forwards or redirects mail. '
            }

            if ($_.MoveToFolder -and
                $_.MoveToFolder -notmatch 'Inbox|Archive|Deleted') {
                $rule.Suspicious = $true
                $rule.SuspiciousReason += "Moves mail to folder: $($_.MoveToFolder). "
            }

            if ($rule.Suspicious) { $flaggedRules += $rule }

            $rule
        } | Export-Csv -Path $mailboxRulesLog -NoTypeInformation

        Write-Log "Mailbox rules exported to $mailboxRulesLog" -Level SUCCESS

        if ($flaggedRules.Count -gt 0) {
            Write-Log "FLAGGED: $($flaggedRules.Count) suspicious mailbox rule(s) detected." -Level WARN
            $flaggedRules | ForEach-Object {
                Write-Log "  >> Rule: '$($_.Name)' | Reason: $($_.SuspiciousReason)" -Level WARN
            }
        } else {
            Write-Log "No suspicious mailbox rules detected." -Level INFO
        }

    } catch {
        Write-Log "Failed to retrieve mailbox rules: $_" -Level ERROR
    }
}

Get-MailboxRulesAudit -UPN $UserPrincipalName

#endregion

#region Forwarding Check

function Get-ForwardingConfig {
    param([string]$UPN)

    Write-Log "Checking mailbox-level forwarding configuration..." -Level ACTION

    try {
        $mailbox = Get-Mailbox -Identity $UPN -ErrorAction Stop

        $output = [PSCustomObject]@{
            ForwardingAddress     = $mailbox.ForwardingAddress
            ForwardingSMTPAddress = $mailbox.ForwardingSmtpAddress
            DeliverToMailbox      = $mailbox.DeliverToMailboxAndForward
        }

        $output | Out-File $forwardingLog

        if ($mailbox.ForwardingSmtpAddress -or $mailbox.ForwardingAddress) {
            Write-Log "FLAGGED: Mailbox-level forwarding is configured." -Level WARN
            Write-Log "  >> ForwardingAddress: $($mailbox.ForwardingAddress)" -Level WARN
            Write-Log "  >> ForwardingSMTPAddress: $($mailbox.ForwardingSmtpAddress)" -Level WARN
            Write-Log "  >> DeliverToMailboxAlso: $($mailbox.DeliverToMailboxAndForward)" -Level WARN
        } else {
            Write-Log "No mailbox-level forwarding detected." -Level INFO
        }

    } catch {
        Write-Log "Failed to retrieve forwarding configuration: $_" -Level ERROR
    }
}

Get-ForwardingConfig -UPN $UserPrincipalName

#endregion

#region Delegate Access

function Get-DelegateAccess {
    param([string]$UPN)

    Write-Log "Checking mailbox delegate access..." -Level ACTION

    try {
        $delegates = Get-MailboxPermission -Identity $UPN -ErrorAction Stop |
            Where-Object {
                $_.User -notmatch 'NT AUTHORITY' -and
                $_.User -notmatch 'S-1-5' -and
                $_.IsInherited -eq $false
            }

        if ($delegates.Count -eq 0) {
            Write-Log "No non-inherited delegate access found." -Level INFO
            "No delegate access found." | Out-File $delegateLog
            return
        }

        $delegates | Select-Object User, AccessRights, IsInherited |
            Export-Csv -Path $delegateLog -NoTypeInformation

        Write-Log "FLAGGED: $($delegates.Count) delegate permission(s) found." -Level WARN
        $delegates | ForEach-Object {
            Write-Log "  >> User: $($_.User) | Rights: $($_.AccessRights)" -Level WARN
        }

    } catch {
        Write-Log "Failed to retrieve delegate access: $_" -Level ERROR
    }
}

Get-DelegateAccess -UPN $UserPrincipalName

#endregion

#region MFA Audit

function Get-MFAMethods {
    param([string]$UserId)

    Write-Log "Auditing registered MFA methods..." -Level ACTION

    try {
        $authMethods = Get-MgUserAuthenticationMethod `
            -UserId $UserId `
            -ErrorAction Stop

        $output = @()
        $flagged = @()

        $authMethods | ForEach-Object {
            $methodType = $_.AdditionalProperties['@odata.type']

            $entry = [PSCustomObject]@{
                MethodType = $methodType
                Id         = $_.Id
                Suspicious = $false
            }

            if ($methodType -notmatch 'microsoftAuthenticator' -and
                $methodType -notmatch 'password') {
                $entry.Suspicious = $true
                $flagged += $entry
            }

            $output += $entry
        }

        $output | Export-Csv -Path $mfaLog -NoTypeInformation

        Write-Log "Found $($output.Count) registered authentication method(s)." -Level INFO

        if ($flagged.Count -gt 0) {
            Write-Log "FLAGGED: $($flagged.Count) non-standard MFA method(s) detected." -Level WARN
            $flagged | ForEach-Object {
                Write-Log "  >> Method: $($_.MethodType) | ID: $($_.Id)" -Level WARN
            }
        } else {
            Write-Log "All MFA methods match expected standard." -Level INFO
        }

    } catch {
        Write-Log "Failed to retrieve MFA methods: $_" -Level ERROR
    }
}

Get-MFAMethods -UserId $compromisedUser.Id

#endregion

#region OAuth Apps

function Get-OAuthPermissions {
    param([string]$UserId)

    Write-Log "Checking OAuth application permissions..." -Level ACTION

    try {
        $oauthGrants = Get-MgUserOauth2PermissionGrant `
            -UserId $UserId `
            -ErrorAction Stop

        if ($oauthGrants.Count -eq 0) {
            Write-Log "No OAuth application permissions found." -Level INFO
            "No OAuth permissions found." | Out-File $oauthLog
            return
        }

        $output = $oauthGrants | ForEach-Object {
            try {
                $app = Get-MgServicePrincipal `
                    -ServicePrincipalId $_.ClientId `
                    -ErrorAction Stop
                $appName = $app.DisplayName
            } catch {
                $appName = "Unknown App ($($_.ClientId))"
            }

            [PSCustomObject]@{
                AppName     = $appName
                ClientId    = $_.ClientId
                Scope       = $_.Scope
                ConsentType = $_.ConsentType
            }
        }

        $output | Export-Csv -Path $oauthLog -NoTypeInformation

        Write-Log "FLAGGED: $($output.Count) OAuth permission grant(s) found. Review required." -Level WARN
        $output | ForEach-Object {
            Write-Log "  >> App: $($_.AppName) | Scope: $($_.Scope)" -Level WARN
        }

    } catch {
        Write-Log "Failed to retrieve OAuth permissions: $_" -Level ERROR
    }
}

Get-OAuthPermissions -UserId $compromisedUser.Id

#endregion

#region Summary Report

function New-IncidentSummaryReport {
    param([string]$UPN, [string]$DisplayName)

    Write-Log "Generating incident summary report..." -Level ACTION

    $reportContent = @"
================================================
    M365 COMPROMISED ACCOUNT INCIDENT REPORT
================================================
Generated:       $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Analyst:         $env:USERNAME
Workstation:     $env:COMPUTERNAME

------------------------------------------------
ACCOUNT DETAILS
------------------------------------------------
User Principal Name:  $UPN
Display Name:         $DisplayName

------------------------------------------------
ACTIONS TAKEN
------------------------------------------------
[+] Sign-in blocked
[+] All active sessions revoked
[+] Temporary password set (ForceChangePasswordNextSignIn = True)

------------------------------------------------
INVESTIGATION OUTPUT FILES
------------------------------------------------
Sign-In Logs:       $signInLog
Mailbox Rules:      $mailboxRulesLog
Forwarding Config:  $forwardingLog
Delegate Access:    $delegateLog
MFA Methods:        $mfaLog
OAuth Apps:         $oauthLog
Action Log:         $logFile

------------------------------------------------
NEXT STEPS
------------------------------------------------
[ ] Review sign-in logs for suspicious geographic activity
[ ] Review and remove any flagged mailbox rules
[ ] Confirm no unauthorized forwarding is configured
[ ] Review and remove any unauthorized delegate access
[ ] Review and remove any non-standard MFA methods
[ ] Review OAuth application permissions
[ ] Notify user and conduct awareness conversation
[ ] Determine initial compromise vector
[ ] Assess whether other accounts accessed from same IP
[ ] Consider whether phishing simulation follow-up is warranted
[ ] Document incident in ticketing system
[ ] Close incident when all items confirmed resolved

------------------------------------------------
NOTES
------------------------------------------------
[Add analyst notes here]

================================================
"@

    $reportContent | Out-File $summaryReport
    Write-Log "Summary report saved to $summaryReport" -Level SUCCESS
}

#endregion

#region Disconnect

function Disconnect-AllServices {
    Write-Log "Disconnecting from Microsoft Graph..." -Level ACTION
    Disconnect-MgGraph | Out-Null

    Write-Log "Disconnecting from Exchange Online..." -Level ACTION
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null

    Write-Log "All services disconnected." -Level SUCCESS
}

#endregion

New-IncidentSummaryReport -UPN $UserPrincipalName -DisplayName $compromisedUser.DisplayName
Disconnect-AllServices

Write-Log "Incident response script completed. Output folder: $outputFolder" -Level SUCCESS
Write-Host "`n[+] All output saved to: $outputFolder`n" -ForegroundColor Green