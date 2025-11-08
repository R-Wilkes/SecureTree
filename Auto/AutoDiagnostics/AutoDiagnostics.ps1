# This script only tells and alerts the user of any misconfigurations and stuff
# it does NOT fix any issues, cause I don't want to blow up the machine immediately
# Kind of like winPEAS, but for IRSec stuff


# Just some info
ScreenClear
Write-Host "Starting AutoDiagnostics.ps1"
Write-Host "SCRIPT WILL NOT MAKE ANY CHANGES, ONLY REPORTS THEM" -ForegroundColor Green
Start-Sleep $shortSleep
Write-Host "`n`n`n`n"

$hour = (Get-Date).Hour
$sec = (Get-Date).Second
$min = (Get-Date).Minute

$logPath = ".\Logs\AutoDiagnosticsLog-$hour-$min-$sec.txt"
CreatePath -DirectoryPath $logPath -Type "File"

# Out log file
$date = Get-Date 
"SecureTree AutoDiagnostics Log" >> $logPath
"`nWritten On: $date" >> $logPath
"`nProgram Version: $version" >> $logPath 
"`nPowershell Version: $($PSVersionTable.PSVersion)" >> $logPath
"`nUser Logged in: $curuser" >> $logPath
"`nComputer Name: $computerName" >> $logPath

$current_path = Get-Location

# Looks for Local users, only works if not on AD
if (-not (IsDC)){

    # Define paths to user and admin text files
    $userListPath = "$current_path/UserLists/Local_Users.txt"
    $adminListPath = "$current_path/UserLists/Local_Admins.txt"
    $doNotTouchUsersPath = "$current_path/UserLists/No_Touch_Users.txt"

    # Ignore these users
    $usersToNotRemove = "Administrator", "DefaultAccount", "Guest", "WDAGUtilityAccount", "$curuser", "krbtgt", "dd-agent", "whiteteam"

    $doNotTouchUsers =  Get-Content $doNotTouchUsersPath

    foreach ($user in $doNotTouchUsers){
        $usersToNotRemove += $user.trim();
    }

    # Will just see if the user is in users to not remove
    function UserCheck {
        param (
            [string]$inputString
        )

        $inputString = $inputString.replace("$computerName\","").Replace("$($computerName.ToUpper())\", "")

        if ($usersToNotRemove -contains $inputString) {
            return $true
        }

        else {
            return $false
        }
    }

    # Read the list of users and admins from text files
    $users = Get-Content -Path $userListPath
    $admins = Get-Content -Path $adminListPath
    $usersToRemove = @()
    "`nUsers Needing Changes `n<--------------------------------------------->" >> $logPath

    # Create users who are not already created
    foreach ($user in $users) {
        $existingUser = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
        if (-not $existingUser) {
            $good = UserCheck $user.Name
            if ($good -eq $false) {
        
                Write-Host "Should Create Local User: '$user'" -ForegroundColor Yellow
                "`nShould create Local User: $user" >> $logPath
                
            }
        }
    }

    # Creates admins
    foreach ($admin in $admins) {
        $existingAdmin = Get-LocalUser -Name $admin -ErrorAction SilentlyContinue
        if (-not $existingAdmin) {
            $good = UserCheck $user.Name
            if ($good -eq $false) {
        
                Write-Host "Should Create Local admin: '$admin'" -ForegroundColor Yellow
                "`nShould Create Local Admin: $admin" >> $logPath

            }
        }
    }

    # Remove users who are not in the user list
    $allLocalUsers = Get-LocalUser | Where-Object { $_.Name -notin $users }
    foreach ($user in $allLocalUsers) {
        if ($user.Name -notin $admins) {
            $good = UserCheck $user.Name
            if ($good -eq $false) {

                if ($user.Name -notlike "*$*"){
                    Write-Host "Need to Remove Local User: $user" -ForegroundColor Red
                    "`nRemove Local User: $user" >> $logPath
                    $usersToRemove += $user.Name
                }
                
                else{
                    $userToRemove += $user.Name
                }

            }
        }
    }

    # Little error handling
    try {
        
        # Revoke administrative privileges from users not in the admins list
        $allAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop| Where-Object { $_.Name.replace("$computerName\","").Replace("$($computerName.ToUpper())\", "") -notin $admins }
        foreach ($admin in $allAdmins) {
            $good = UserCheck $admin.Name
            if ($good -eq $false) {
                if ($admin.Name.replace("$computerName\","").Replace("$($computerName.ToUpper())\", "") -notin $usersToRemove){
        
                    $adminName = $admin.Name.replace("$computerName\","").Replace("$($computerName.ToUpper())\", "")
                    Write-Host "Need to Remove admin perms: $adminName" -ForegroundColor Red
                    "`nNeed to Changes Perms to standard for user: $adminName" >> $logPath
                
                }
            }
        }
    }

    catch {
        Write-Host "Unable to get group: Administrators" -ForegroundColor Red
        "`nUnable to get group: Administrators" >> $logPath
    }

    # Grant administrative privileges to users in the admins list | AI
    foreach ($admin in $admins) {
        $existingUser = Get-LocalUser -Name $admin -ErrorAction SilentlyContinue
        if ($existingUser) {

            $good = UserCheck $admin
            if ($good -eq $false) {
                if ($admin.replace("$computerName\","").Replace("$($computerName.ToUpper())\", "") -notin $usersToRemove){
                    
                    # NEW: Check if user is already in Administrators group
                    $cleanAdminName = $admin.replace("$computerName\","").Replace("$($computerName.ToUpper())\", "")
                    $isAlreadyAdmin = $false
                    
                    try {
                        $currentAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
                        foreach ($currentAdmin in $currentAdmins) {
                            $currentCleanName = $currentAdmin.Name.replace("$computerName\","").Replace("$($computerName.ToUpper())\", "")
                            if ($currentCleanName -eq $cleanAdminName) {
                                $isAlreadyAdmin = $true
                                break
                            }
                        }
                    } catch {
                        # If we can't check, assume they need to be added
                        $isAlreadyAdmin = $false
                    }
                    
                    # Only report if they're NOT already an admin
                    if (-not $isAlreadyAdmin) {
                        Write-Host "Need to Add admin perms: $admin" -ForegroundColor Yellow
                        "`nChange Perms to Admin for user: $admin" >> $logPath
                    }
                }
            }
        }
        else {
            Write-Host "$admin does not exist or is not a local user. (Ignore)"
        }
    }
    # For each loop to change passwords for users in user_list.txt
    foreach ($user in $users) {
        $existingUser = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
        if ($existingUser -and $user -notin $usersToNotRemove) {

            Write-Host "Change password for local user: '$user'" -ForegroundColor Magenta
            "`nChange Password for Local user: $user" >> $logPath

        }
    }

    # For each loop to change passwords for admins in user_admin_list.txt
    foreach ($admin in $admins) {
        $existingUser = Get-LocalUser -Name $admin -ErrorAction SilentlyContinue
        if ($existingUser -and $admin -notin $usersToNotRemove) {

            Write-Host "Change password for Local admin '$admin'" -ForegroundColor Magenta
            "`nChange password for Local admin: $admin" >> $logPath

        }
    }

    "`n<--------------------------------------------->`nEnd User Changes" >> $logPath

}

# All AI, just revamped my local users, only works for AD users | AI
if (IsDC) {

    "`nActive Directory: $((Get-ADDomain).Name)" >> $logPath
    Write-Host "On Active Directory Domain: $((Get-ADDomain).Name)" -ForegroundColor Cyan

    # Define paths to user and admin text files
    $userListPath = "$current_path/UserLists/Domain_Users.txt"
    $adminListPath = "$current_path/UserLists/Domain_Admins.txt"
    $doNotTouchUsersPath = "$current_path/UserLists/No_Touch_Users.txt"

    # Ignore these users
    $usersToNotRemove = "Administrator", "DefaultAccount", "Guest", "WDAGUtilityAccount", "$curuser", "krbtgt"

    $doNotTouchUsers =  Get-Content $doNotTouchUsersPath

    foreach ($user in $doNotTouchUsers){
        $usersToNotRemove += $user.trim();
    }

    # Function to check if user should be protected
    function DomainUserCheck {
        param (
            [string]$inputString
        )
        
        # Remove domain prefix if present
        $cleanName = ($inputString -split "\\")[-1]
        
        if ($usersToNotRemove -contains $cleanName) {
            return $true
        }
        else {
            return $false
        }
    }

    # Read the list of users and admins from text files
    $users = Get-Content -Path $userListPath -ErrorAction SilentlyContinue
    $admins = Get-Content -Path $adminListPath -ErrorAction SilentlyContinue
    $usersToRemove = @()

    "`nDomain Users Needing Changes `n<--------------------------------------------->" >> $logPath

    # Check for missing domain users
    foreach ($user in $users) {
        try {
            $existingUser = Get-ADUser -Identity $user -ErrorAction Stop
        }
        catch {
            $good = DomainUserCheck $user
            if ($good -eq $false) {
                Write-Host "Should Create Domain User: '$user'" -ForegroundColor Yellow
                "`nShould create Domain User: $user" >> $logPath
            }
        }
    }

    # Check for missing domain admins
    foreach ($admin in $admins) {
        try {
            $existingAdmin = Get-ADUser -Identity $admin -ErrorAction Stop
        }
        catch {
            $good = DomainUserCheck $admin
            if ($good -eq $false) {
                Write-Host "Should Create Domain Admin: '$admin'" -ForegroundColor Yellow
                "`nShould Create Domain Admin: $admin" >> $logPath
            }
        }
    }

    # Find users that should be removed (exist in domain but not in lists)
    try {
        $allDomainUsers = Get-ADUser -Filter * | Where-Object { 
            $_.Name -notin $users -and $_.Name -notin $admins 
        }
        
        foreach ($user in $allDomainUsers) {
            $good = DomainUserCheck $user.Name
            if ($good -eq $false) {
                Write-Host "Need to Remove Domain User: $($user.Name)" -ForegroundColor Red
                "`nRemove Domain User: $($user.Name)" >> $logPath
                $usersToRemove += $user.Name
            }
        }
    }
    catch {
        Write-Host "Error getting domain users: $($_.Exception.Message)" -ForegroundColor Red
        "`nError getting domain users: $($_.Exception.Message)" >> $logPath
    }

    # Check Domain Admins group membership
    try {
        $domainAdminsGroup = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction Stop
        
        foreach ($domainAdmin in $domainAdminsGroup) {
            if ($domainAdmin.Name -notin $admins) {
                $good = DomainUserCheck $domainAdmin.Name
                if ($good -eq $false) {
                    if ($domainAdmin.Name -notin $usersToRemove) {
                        Write-Host "Need to Remove from Domain Admins: $($domainAdmin.Name)" -ForegroundColor Red
                        "`nRemove from Domain Admins: $($domainAdmin.Name)" >> $logPath
                    }
                }
            }
        }
    }
    catch {
        Write-Host "Error checking Domain Admins group: $($_.Exception.Message)" -ForegroundColor Red
        "`nError checking Domain Admins group: $($_.Exception.Message)" >> $logPath
    }

    # Check who should be added to Domain Admins
    foreach ($admin in $admins) {
        try {
            $user = Get-ADUser -Identity $admin -ErrorAction Stop
            $isDomainAdmin = Get-ADGroupMember -Identity "Domain Admins" | Where-Object { $_.Name -eq $admin }
            
            if (-not $isDomainAdmin) {
                $good = DomainUserCheck $admin
                if ($good -eq $false) {
                    if ($admin -notin $usersToRemove) {
                        Write-Host "Need to Add to Domain Admins: $admin" -ForegroundColor Yellow
                        "`nAdd to Domain Admins: $admin" >> $logPath
                    }
                }
            }
        }
        catch {
            # User doesn't exist, already handled above
        }
    }

    # Check for users that need password changes
    foreach ($user in $users) {
        try {
            $adUser = Get-ADUser -Identity $user -Properties PasswordLastSet -ErrorAction Stop
            $adUser | Out-Null
            $good = DomainUserCheck $user
            if ($good -eq $false) {
                Write-Host "Should change password for domain user: '$user'" -ForegroundColor Magenta
                "`nChange password for domain user: $user" >> $logPath
            }
        }
        catch {
            # User doesn't exist, already handled above
        }
    }

    # Check admin passwords
    foreach ($admin in $admins) {
        try {
            $adAdmin = Get-ADUser -Identity $admin -Properties PasswordLastSet -ErrorAction Stop
            $adAdmin | Out-Null
            $good = DomainUserCheck $admin
            if ($good -eq $false) {
                Write-Host "Should change password for domain admin: '$admin'" -ForegroundColor Magenta
                "`nChange password for domain admin: $admin" >> $logPath
            }
        }
        catch {
            # Admin doesn't exist, already handled above
        }
    }

    "`n<--------------------------------------------->`nEnd Domain User Changes" >> $logPath
}

# Check if Guest account is enabled
$guest = Get-LocalUser -Name "Guest"
if ($guest.Enabled) {

    Write-Host "Guest account is ENABLED" -ForegroundColor Red
    "`nGuest account is ENABLED (BAD)" >> $logPath

} 

else {

    Write-Host "Guest account is disabled" -ForegroundColor Green
    "`nGuest account is DISABLED (GOOD)" >> $logPath

}

# SMBV1 is enabled
$smbV1 = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State
if ($smbV1 -ne "Disabled"){

    Write-Host "SMBV1 is enabled" -ForegroundColor Red
    "`nSMBV1 is enabled (BAD)" >> $logPath

}

else{

    Write-Host "SMBV1 is disabled" -ForegroundColor Green
    "`nSMBV1 is disabled (GOOD)" >> $logPath

}

# Checks reg keys | AI
if ($true){

    Write-Host "`nCheck Reg Keys..." -ForegroundColor Cyan
    "`nChecking Reg Keys `n<--------------------------------------------->" >> $logPath


    # Check common startup registry locations
    $startupKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    )

    foreach ($key in $startupKeys) {
        try {
            $entries = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            if ($entries) {
                Write-Host "`n[$key]" -ForegroundColor Yellow
                "`nKey: $key" >> $logPath

                
                $entries.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                    $name = $_.Name
                    $value = $_.Value
                    
                    # Flag suspicious patterns
                    $suspicious = $false
                    $reasons = @()
                    
                    if ($value -match "temp|tmp|appdata\\local\\temp") { $suspicious = $true; $reasons += "TEMP_PATH" }
                    if ($value -match "\.bat|\.cmd|\.vbs|\.js|\.ps1") { $suspicious = $true; $reasons += "SCRIPT_FILE" }
                    if ($value -match "powershell|cmd\.exe|wscript|cscript") { $suspicious = $true; $reasons += "SCRIPT_EXEC" }
                    if ($value -match "hidden|windowstyle|bypass|executionpolicy") { $suspicious = $true; $reasons += "HIDDEN_EXEC" }
                    if ($value -match "download|curl|wget|invoke-webrequest") { $suspicious = $true; $reasons += "DOWNLOAD" }
                    if ($value -match "base64|encoded") { $suspicious = $true; $reasons += "ENCODED" }
                    if ($value -match "\\\\|ftp://|http://") { $suspicious = $true; $reasons += "REMOTE_PATH" }
                    
                    $color = if ($suspicious) { "Red" } else { "White" }
                    $flag = if ($suspicious) { " [SUSPICIOUS: $($reasons -join ',')]" } else { "" }
                    
                    Write-Host "  $name = $value$flag" -ForegroundColor $color
                    " $name = $value$flag" >> $logPath

                }
            }
        } catch {
            Write-Host "Cannot access: $key" -ForegroundColor Gray
        }
    }

    # Check Windows startup folder
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            $files = Get-ChildItem -Path $folder -ErrorAction SilentlyContinue
            if ($files) {
                Write-Host "`n[STARTUP FOLDER: $folder]" -ForegroundColor Yellow
                "`nStartup Folder: $folder" >> $logPath
                foreach ($file in $files) {
                    $suspicious = $file.Extension -match "\.(bat|cmd|vbs|js|ps1)$"
                    $color = if ($suspicious) { "Red" } else { "White" }
                    $flag = if ($suspicious) { " [SUSPICIOUS: SCRIPT_FILE]" } else { "" }
                    Write-Host "  $($file.Name)$flag" -ForegroundColor $color
                    " $($file.Name)$flag" >> $logPath
                }
            }
        }
    }

    "`n<---------------------------------------------> `nEnd Reg Keys" >> $logPath

}

# Check for Non-Default Firewall Rules | AI
if ($true){

    Write-Host "Checking for non-default firewall rules..." -ForegroundColor Yellow

    try {
        # Get all firewall rules
        $allRules = Get-NetFirewallRule | Sort-Object DisplayName
        
        # Define default Windows firewall rule patterns (common built-in rules)
        $defaultRulePatterns = @(
            "^Core Networking",
            "^Windows",
            "^File and Printer Sharing",
            "^Network Discovery",
            "^Remote Desktop",
            "^Windows Management Instrumentation",
            "^Windows Remote Management",
            "^SNMP",
            "^Performance Logs and Alerts",
            "^Remote Event Log Management",
            "^Remote Service Management",
            "^Remote Volume Management",
            "^Windows Firewall Remote Management",
            "^Hyper-V",
            "^iSCSI",
            "^BranchCache",
            "^DirectAccess",
            "^Distributed File System",
            "^Key Management Service",
            "^Remote Assistance",
            "^Windows Media Player",
            "^BITS",
            "^Telnet",
            "^FTP",
            "^Microsoft",
            "^@",
            "^Cast to Device",
            
            # Active Directory Domain Services
            "^Active Directory Domain Controller",
            "^Active Directory Web Services",
            "^Kerberos Key Distribution Center",
            "^File Replication",
            "^DFS",
            "^Netlogon Service",
            
            # DNS Server
            "^DNS",
            "^All Outgoing",
            "^RPC.*Incoming",
            "^RPC Endpoint Mapper",
            
            # Network Services
            "^AllJoyn Router",
            "^mDNS",
            "^Delivery Optimization",
            "^Connected User Experiences and Telemetry",
            
            # Remote Management
            "^File Server Remote Management",
            "^Remote Event Monitor",
            "^Remote Scheduled Tasks Management",
            "^Inbound Rule for Remote Shutdown",
            
            # VPN/Routing
            "^Routing and Remote Access",
            "^Secure Socket Tunneling Protocol",
            
            # System Services
            "^COM\+ Network Access",
            "^COM\+ Remote Administration",
            "^Distributed Transaction Coordinator",
            "^Software Load Balancer Multiplexer",
            "^TPM Virtual Smart Card Management",
            "^Virtual Machine Monitoring",
            
            # Windows Apps/Features
            "^DIAL protocol server",
            "^Desktop App Web Viewer",
            "^Captive Portal Flow",
            "^Email and accounts",
            "^Work or school account",
            "^Your account",
            "^Start",
            "^Narrator",
            
            # GUID-based rules (Windows Store/UWP apps)
            "^\{[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\}$"
        )

        # Filter out default rules
        $customRules = $allRules | Where-Object {
            $ruleName = $_.DisplayName
            $isDefault = $false
            
            foreach ($pattern in $defaultRulePatterns) {
                if ($ruleName -match $pattern) {
                    $isDefault = $true
                    break
                }
            }
            
            return -not $isDefault
        }

        Write-Host "`n=== FIREWALL RULE SUMMARY ===" -ForegroundColor Magenta
        Write-Host "Total Rules: $($allRules.Count)" -ForegroundColor White
        Write-Host "Custom/Non-Default Rules: $($customRules.Count)" -ForegroundColor Yellow
        
        "`n=== FIREWALL RULE SUMMARY ===" >> $logPath
        "`nTotal Rules: $($allRules.Count)" >> $logPath
        "`nCustom/Non-Default Rules: $($customRules.Count)" >> $logPath

        if ($customRules.Count -gt 0) {
            
            Write-Host "`n=== NON-DEFAULT FIREWALL RULES ===" -ForegroundColor Red
            "`n=== NON-DEFAULT FIREWALL RULES ===" >> $logPath
            
            foreach ($rule in $customRules) {
                
                # Get additional rule details
                try {
                    $ruleDetails = Get-NetFirewallRule -Name $rule.Name | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                    $addressFilter = Get-NetFirewallRule -Name $rule.Name | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
                    $appFilter = Get-NetFirewallRule -Name $rule.Name | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
                } catch {
                    $ruleDetails = $null
                    $addressFilter = $null
                    $appFilter = $null
                }

                # Determine suspicion level
                $suspiciousFlags = @()
                
                if ($rule.Action -eq "Allow" -and $rule.Direction -eq "Inbound") {
                    $suspiciousFlags += "INBOUND_ALLOW"
                }
                if ($ruleDetails -and ($ruleDetails.LocalPort -eq "Any" -or $ruleDetails.RemotePort -eq "Any")) {
                    $suspiciousFlags += "ANY_PORT"
                }
                if ($addressFilter -and ($addressFilter.RemoteAddress -eq "Any" -or $addressFilter.RemoteAddress -eq "0.0.0.0/0")) {
                    $suspiciousFlags += "ANY_ADDRESS"
                }
                if ($appFilter -and $appFilter.Program -like "*temp*") {
                    $suspiciousFlags += "TEMP_PROGRAM"
                }
                if ($rule.DisplayName -match "bypass|hack|backdoor|shell|rat|trojan") {
                    $suspiciousFlags += "SUSPICIOUS_NAME"
                }

                # Color coding based on suspicion
                $ruleColor = "White"
                if ($suspiciousFlags.Count -gt 0) {
                    $ruleColor = "Red"
                } elseif ($rule.Action -eq "Allow" -and $rule.Direction -eq "Inbound") {
                    $ruleColor = "Yellow"
                }

                Write-Host "`nRule: $($rule.DisplayName)" -ForegroundColor $ruleColor
                Write-Host "  Name: $($rule.Name)" -ForegroundColor Gray
                Write-Host "  Action: $($rule.Action)" -ForegroundColor $(if($rule.Action -eq "Allow"){"Green"}else{"Red"})
                Write-Host "  Direction: $($rule.Direction)" -ForegroundColor Gray
                Write-Host "  Enabled: $($rule.Enabled)" -ForegroundColor $(if($rule.Enabled -eq "True"){"Green"}else{"Gray"})
                Write-Host "  Profile: $($rule.Profile)" -ForegroundColor Gray
                
                if ($ruleDetails) {
                    Write-Host "  Local Port: $($ruleDetails.LocalPort)" -ForegroundColor Gray
                    Write-Host "  Remote Port: $($ruleDetails.RemotePort)" -ForegroundColor Gray
                    Write-Host "  Protocol: $($ruleDetails.Protocol)" -ForegroundColor Gray
                }
                
                if ($addressFilter) {
                    Write-Host "  Remote Address: $($addressFilter.RemoteAddress)" -ForegroundColor Gray
                    Write-Host "  Local Address: $($addressFilter.LocalAddress)" -ForegroundColor Gray
                }
                
                if ($appFilter -and $appFilter.Program -ne "Any") {
                    Write-Host "  Program: $($appFilter.Program)" -ForegroundColor Gray
                }
                
                if ($suspiciousFlags.Count -gt 0) {
                    Write-Host "  SUSPICIOUS: $($suspiciousFlags -join ', ')" -ForegroundColor Red
                }

                # Log to file
                "`nCustom Rule: $($rule.DisplayName)" >> $logPath
                "`n  Action: $($rule.Action), Direction: $($rule.Direction), Enabled: $($rule.Enabled)" >> $logPath
                if ($ruleDetails) {
                    "`n  Ports: Local=$($ruleDetails.LocalPort), Remote=$($ruleDetails.RemotePort), Protocol=$($ruleDetails.Protocol)" >> $logPath
                }
                if ($addressFilter) {
                    "`n  Addresses: Local=$($addressFilter.LocalAddress), Remote=$($addressFilter.RemoteAddress)" >> $logPath
                }
                if ($appFilter -and $appFilter.Program -ne "Any") {
                    "`n  Program: $($appFilter.Program)" >> $logPath
                }
                if ($suspiciousFlags.Count -gt 0) {
                    "`n  SUSPICIOUS: $($suspiciousFlags -join ', ')" >> $logPath
                }
            }

            # Security summary
            $allowInboundRules = $customRules | Where-Object { $_.Action -eq "Allow" -and $_.Direction -eq "Inbound" -and $_.Enabled -eq "True" }
            $suspiciousRules = $customRules | Where-Object { 
                $_.DisplayName -match "bypass|hack|backdoor|shell|rat|trojan" -or
                $_.Action -eq "Allow" -and $_.Direction -eq "Inbound" -and $_.Profile -eq "Public"
            }

            Write-Host "`n=== SECURITY ANALYSIS ===" -ForegroundColor Magenta
            Write-Host "Custom Inbound Allow Rules: $($allowInboundRules.Count)" -ForegroundColor $(if($allowInboundRules.Count -gt 0){"Yellow"}else{"Green"})
            Write-Host "Potentially Suspicious Rules: $($suspiciousRules.Count)" -ForegroundColor $(if($suspiciousRules.Count -gt 0){"Red"}else{"Green"})

            "`n=== SECURITY ANALYSIS ===" >> $logPath
            "`nCustom Inbound Allow Rules: $($allowInboundRules.Count)" >> $logPath
            "`nPotentially Suspicious Rules: $($suspiciousRules.Count)" >> $logPath

            if ($allowInboundRules.Count -gt 0) {
                Write-Host "`nWARNING: Found custom inbound allow rules - review for security" -ForegroundColor Yellow
            }

        } else {
            Write-Host "`nNo custom firewall rules detected - all rules appear to be default Windows rules" -ForegroundColor Green
            "`nNo custom firewall rules detected" >> $logPath
        }

        # Quick stats by profile
        $domainRules = $allRules | Where-Object { $_.Profile -match "Domain" }
        $privateRules = $allRules | Where-Object { $_.Profile -match "Private" }  
        $publicRules = $allRules | Where-Object { $_.Profile -match "Public" }

        Write-Host "`n=== RULES BY PROFILE ===" -ForegroundColor Magenta
        Write-Host "Domain: $($domainRules.Count)" -ForegroundColor Green
        Write-Host "Private: $($privateRules.Count)" -ForegroundColor Yellow
        Write-Host "Public: $($publicRules.Count)" -ForegroundColor Red

        "`n=== RULES BY PROFILE ===" >> $logPath
        "`nDomain: $($domainRules.Count), Private: $($privateRules.Count), Public: $($publicRules.Count)" >> $logPath

    } catch {
        Write-Host "Failed to check firewall rules: $($_.Exception.Message)" -ForegroundColor Red
        "`nFailed to check firewall rules: $($_.Exception.Message)" >> $logPath
    }

}

# Check Domain Policy Edit Permissions and Display GPOs | AI
if ((IsDC)) {

    Write-Host "`n`nChecking Domain Policy Permissions and GPOs..." -ForegroundColor Yellow
    "`nDomain Policy Permissions and GPO Check `n<--------------------------------------------->" >> $logPath

    try {
        # Get domain information
        $domain = Get-ADDomain
        # $domainDN = $domain.DistinguishedName
        $domainName = $domain.Name
        
        Write-Host "Domain: $domainName" -ForegroundColor Cyan
        "`nDomain: $domainName" >> $logPath

        # Get current user's identity and groups
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $currentUserSID = $currentUser.User.Value
        $currentUserName = $currentUser.Name
        
        Write-Host "Current User: $currentUserName ($currentUserSID)" -ForegroundColor White
        "`nCurrent User: $currentUserName ($currentUserSID)" >> $logPath

        # Check if user is in key admin groups
        $userGroups = @()
        $currentUser.Groups | ForEach-Object {
            try {
                $group = $_.Translate([System.Security.Principal.NTAccount]).Value
                $userGroups += $group
            } catch {}
        }

        $adminGroups = @("Domain Admins", "Enterprise Admins", "Group Policy Creator Owners", "Administrators")
        $userAdminGroups = $userGroups | Where-Object { 
            $adminGroups | ForEach-Object { if ($_ -and $userGroups -match $_) { return $true } }
        }

        if ($userAdminGroups) {
            Write-Host "Admin Groups: $($userAdminGroups -join ', ')" -ForegroundColor Green
        } else {
            Write-Host "Admin Groups: None detected" -ForegroundColor Red
        }

        # Get all domain GPOs
        Write-Host "`n=== ALL DOMAIN GPOS ===" -ForegroundColor Magenta
        "`n=== ALL DOMAIN GPOS ===" >> $logPath

        $allGPOs = Get-GPO -All | Sort-Object DisplayName
        
        Write-Host "Total GPOs in domain: $($allGPOs.Count)" -ForegroundColor White
        "`nTotal GPOs in domain: $($allGPOs.Count)" >> $logPath

        foreach ($gpo in $allGPOs) {
            $gpoColor = "White"
            $gpoNote = ""
            
            # Highlight important default policies
            if ($gpo.DisplayName -eq "Default Domain Policy") {
                $gpoColor = "Yellow"
                $gpoNote = " [DEFAULT DOMAIN POLICY]"
            } elseif ($gpo.DisplayName -eq "Default Domain Controllers Policy") {
                $gpoColor = "Cyan"
                $gpoNote = " [DEFAULT DC POLICY]"
            } elseif ($gpo.GpoStatus -eq "UserSettingsDisabled" -or $gpo.GpoStatus -eq "ComputerSettingsDisabled") {
                $gpoColor = "Gray"
                $gpoNote = " [PARTIALLY DISABLED]"
            } elseif ($gpo.GpoStatus -eq "AllSettingsDisabled") {
                $gpoColor = "Red"
                $gpoNote = " [DISABLED]"
            }

            Write-Host "  $($gpo.DisplayName)$gpoNote" -ForegroundColor $gpoColor
            Write-Host "    ID: $($gpo.Id)" -ForegroundColor Gray
            Write-Host "    Status: $($gpo.GpoStatus)" -ForegroundColor Gray
            Write-Host "    Created: $($gpo.CreationTime)" -ForegroundColor Gray
            Write-Host "    Modified: $($gpo.ModificationTime)" -ForegroundColor Gray
            
            "`n  GPO: $($gpo.DisplayName)$gpoNote" >> $logPath
            "`n    ID: $($gpo.Id), Status: $($gpo.GpoStatus)" >> $logPath
        }

        # Check permissions on default domain policies
        Write-Host "`n=== DEFAULT POLICY PERMISSIONS ===" -ForegroundColor Magenta
        "`n=== DEFAULT POLICY PERMISSIONS ===" >> $logPath

        $defaultPolicies = @(
            @{ Name = "Default Domain Policy"; DisplayName = "Default Domain Policy" },
            @{ Name = "Default Domain Controllers Policy"; DisplayName = "Default Domain Controllers Policy" }
        )

        foreach ($policy in $defaultPolicies) {
            try {
                $gpo = Get-GPO -Name $policy.DisplayName -ErrorAction Stop
                
                Write-Host "`nChecking: $($policy.DisplayName)" -ForegroundColor Yellow
                "`nChecking: $($policy.DisplayName)" >> $logPath

                # Get GPO permissions
                $gpoPermissions = Get-GPPermission -Guid $gpo.Id -All -ErrorAction Stop
                
                # Check if current user has edit permissions
                $hasEditPermission = $false
                $userPermissions = @()

                foreach ($permission in $gpoPermissions) {
                    # Check direct user permissions
                    if ($permission.Trustee.Sid -eq $currentUserSID) {
                        $userPermissions += "$($permission.Permission) (Direct)"
                        if ($permission.Permission -match "Edit|FullControl") {
                            $hasEditPermission = $true
                        }
                    }
                    
                    # Check group permissions
                    foreach ($userGroup in $userGroups) {
                        if ($permission.Trustee.Name -eq $userGroup -or $permission.Trustee.Name -like "*$($userGroup.Split('\')[-1])") {
                            $userPermissions += "$($permission.Permission) (via $($permission.Trustee.Name))"
                            if ($permission.Permission -match "Edit|FullControl") {
                                $hasEditPermission = $true
                            }
                        }
                    }
                }

                # Display results
                if ($hasEditPermission) {
                    Write-Host "  EDIT PERMISSION: YES" -ForegroundColor Green
                    "`n  EDIT PERMISSION: YES" >> $logPath
                } else {
                    Write-Host "  EDIT PERMISSION: NO" -ForegroundColor Red
                    "`n  EDIT PERMISSION: NO" >> $logPath
                }

                if ($userPermissions.Count -gt 0) {
                    Write-Host "  User Permissions: $($userPermissions -join ', ')" -ForegroundColor Cyan
                    "`n  User Permissions: $($userPermissions -join ', ')" >> $logPath
                } else {
                    Write-Host "  User Permissions: None detected" -ForegroundColor Red
                    "`n  User Permissions: None detected" >> $logPath
                }

                # Show all permissions for reference
                Write-Host "  All Permissions on this GPO:" -ForegroundColor Gray
                foreach ($perm in $gpoPermissions) {
                    Write-Host "    $($perm.Trustee.Name): $($perm.Permission)" -ForegroundColor Gray
                    "`n    $($perm.Trustee.Name): $($perm.Permission)" >> $logPath
                }

            } catch {
                Write-Host "  ERROR checking $($policy.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
                "`n  ERROR checking $($policy.DisplayName): $($_.Exception.Message)" >> $logPath
            }
        }

        # Quick security check
        Write-Host "`n=== SECURITY SUMMARY ===" -ForegroundColor Magenta
        "`n=== SECURITY SUMMARY ===" >> $logPath

        $securityIssues = @()

        # Check for disabled GPOs
        $disabledGPOs = $allGPOs | Where-Object { $_.GpoStatus -eq "AllSettingsDisabled" }
        if ($disabledGPOs) {
            $securityIssues += "Found $($disabledGPOs.Count) completely disabled GPOs"
            Write-Host "WARNING: $($disabledGPOs.Count) GPOs are completely disabled" -ForegroundColor Yellow
        }

        # Check for old GPOs
        $oldGPOs = $allGPOs | Where-Object { $_.ModificationTime -lt (Get-Date).AddMonths(-6) }
        if ($oldGPOs) {
            $securityIssues += "Found $($oldGPOs.Count) GPOs not modified in 6+ months"
            Write-Host "INFO: $($oldGPOs.Count) GPOs haven't been modified in 6+ months" -ForegroundColor Cyan
        }

        if ($securityIssues.Count -eq 0) {
            Write-Host "No obvious GPO security issues detected" -ForegroundColor Green
            "`nNo obvious GPO security issues detected" >> $logPath
        } else {
            "`nSecurity Issues: $($securityIssues -join '; ')" >> $logPath
        }

        "`n<--------------------------------------------->`nEnd Domain Policy Check" >> $logPath

    } catch {
        Write-Host "Failed to check domain policies: $($_.Exception.Message)" -ForegroundColor Red
        "`nFailed to check domain policies: $($_.Exception.Message)" >> $logPath
    }

}

# Shows all programs on PC
Get-Package -Provider Programs
Get-WmiObject -Class Win32_Product | Select-Object -Property Name

# Will report on Local users on other machines | AI
if (IsDC){

    if ((Config("remote_users"))){
        
        "`nRemote Machine Local Users Check `n<--------------------------------------------->" >> $logPath
        Write-Host "Checking local users on remote domain machines..." -ForegroundColor Cyan

        # Get all domain computers (excluding DCs and current machine)
        try {
            $domainComputers = Get-ADComputer -Filter * | Where-Object { 
                $_.Name -ne $env:COMPUTERNAME -and 
                $_.DistinguishedName -notlike "*Domain Controllers*" 
            } | Select-Object -ExpandProperty Name
        } catch {
            Write-Host "Failed to get domain computers" -ForegroundColor Red
            "`nFailed to get domain computers: $($_.Exception.Message)" >> $logPath
            return
        }

        # Define paths for remote machine user lists
        $remoteUserListPath = "$current_path/UserLists/Local_Users.txt"
        $remoteAdminListPath = "$current_path/UserLists/Local_Admins.txt"

        # Read remote user and admin lists (if they exist)
        $remoteUsers = @()
        $remoteAdmins = @()
        
        if (Test-Path $remoteUserListPath) {
            $remoteUsers = Get-Content -Path $remoteUserListPath -ErrorAction SilentlyContinue
        }
        
        if (Test-Path $remoteAdminListPath) {
            $remoteAdmins = Get-Content -Path $remoteAdminListPath -ErrorAction SilentlyContinue
        }

        # Process each remote computer
        foreach ($computer in $domainComputers) {
            
            Write-Host "Checking computer: $computer" -ForegroundColor Yellow
            "`nChecking Remote Computer: $computer" >> $logPath

            # Test connectivity first
            if (-not (Test-Connection -ComputerName $computer -Count 1 -Quiet)) {
                Write-Host "  $computer is not reachable" -ForegroundColor Red
                "`n  $computer is not reachable" >> $logPath
                continue
            }

            try {
                # Get remote local users via Invoke-Command
                $remoteData = Invoke-Command -ComputerName $computer -ScriptBlock {
                    
                    # Get all local users
                    $allUsers = Get-LocalUser -ErrorAction SilentlyContinue
                    
                    # Get administrators
                    $adminMembers = @()
                    try {
                        $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
                        $adminMembers = $adminGroup | ForEach-Object { 
                            $_.Name.Split('\')[-1] 
                        } | Where-Object { $_ -notmatch "^(NT AUTHORITY|BUILTIN)" }
                    } catch {}
                    
                    # Get regular users
                    $userMembers = @()
                    try {
                        $userGroup = Get-LocalGroupMember -Group "Users" -ErrorAction SilentlyContinue
                        $userMembers = $userGroup | ForEach-Object { 
                            $_.Name.Split('\')[-1] 
                        } | Where-Object { $_ -notmatch "^(NT AUTHORITY|BUILTIN)" }
                    } catch {}

                    return @{
                        AllUsers = $allUsers.Name
                        Administrators = $adminMembers
                        Users = $userMembers
                        ComputerName = $env:COMPUTERNAME
                    }
                } -ErrorAction Stop

                # Check for users that should exist but don't
                foreach ($expectedUser in $remoteUsers) {
                    if ($expectedUser -notin $remoteData.AllUsers) {
                        $good = DomainUserCheck $expectedUser
                        if ($good -eq $false) {
                            Write-Host "  Should Create Local User on $($computer): '$expectedUser'" -ForegroundColor Yellow
                            "`n  Should create Local User on $($computer): $expectedUser" >> $logPath
                        }
                    }
                }

                # Check for admins that should exist but don't
                foreach ($expectedAdmin in $remoteAdmins) {
                    if ($expectedAdmin -notin $remoteData.AllUsers) {
                        $good = DomainUserCheck $expectedAdmin
                        if ($good -eq $false) {
                            Write-Host "  Should Create Local Admin on $($computer): '$expectedAdmin'" -ForegroundColor Yellow
                            "`n  Should create Local Admin on $($computer): $expectedAdmin" >> $logPath
                        }
                    }
                }

                # Check for users that shouldn't exist (not in either list and not protected)
                foreach ($actualUser in $remoteData.AllUsers) {
                    if ($actualUser -notin $remoteUsers -and $actualUser -notin $remoteAdmins) {
                        $good = DomainUserCheck $actualUser
                        if ($good -eq $false) {
                            if ($actualUser -notlike "*$*") {  # Skip computer accounts
                                Write-Host "  Need to Remove Local User on $($computer): '$actualUser'" -ForegroundColor Red
                                "`n  Remove Local User on $($computer): $actualUser" >> $logPath
                            }
                        }
                    }
                }

                # Check for incorrect admin permissions
                foreach ($actualAdmin in $remoteData.Administrators) {
                    if ($actualAdmin -notin $remoteAdmins) {
                        $good = DomainUserCheck $actualAdmin
                        if ($good -eq $false) {
                            Write-Host "  Need to Remove Admin Perms on $($computer): '$actualAdmin'" -ForegroundColor Red
                            "`n  Remove Admin Perms on $($computer): $actualAdmin" >> $logPath
                        }
                    }
                }

                # Check for users who should have admin perms but don't
                foreach ($expectedAdmin in $remoteAdmins) {
                    if ($expectedAdmin -in $remoteData.AllUsers -and $expectedAdmin -notin $remoteData.Administrators) {
                        $good = DomainUserCheck $expectedAdmin
                        if ($good -eq $false) {
                            Write-Host "  Need to Add Admin Perms on $($computer): '$expectedAdmin'" -ForegroundColor Yellow
                            "`n  Add Admin Perms on $($computer): $expectedAdmin" >> $logPath
                        }
                    }
                }

                # Check for password changes needed
                foreach ($user in ($remoteUsers + $remoteAdmins)) {
                    if ($user -in $remoteData.AllUsers) {
                        $good = DomainUserCheck $user
                        if ($good -eq $false) {
                            Write-Host "  Should change password on $computer for: '$user'" -ForegroundColor Magenta
                            "`n  Change password on $computer for: $user" >> $logPath
                        }
                    }
                }

                Write-Host "  $computer check completed" -ForegroundColor Green
                "`n  $computer check completed successfully" >> $logPath

            } catch {
                Write-Host "  Failed to check $($computer): $($_.Exception.Message)" -ForegroundColor Red
                "`n  Failed to check $($computer): $($_.Exception.Message)" >> $logPath
            }
        }

        "`n<--------------------------------------------->`nEnd Remote Machine Local Users Check" >> $logPath
    }
}

Write-Host  "All Findings are logged`nLog Location: '$logPath'" -ForegroundColor Gray

# Keep at end of code
Write-Host "Press enter to Continue, Screen will CLEAR"
GetKeyInput -AllowedKeys "`r" | Out-Null 
ScreenClear

# Will run find files as the last things
if ((Config("find_files"))){

    ImportantScan
    ShowBannedFiles
    Read-Host -Prompt "Press ENTER to continue..."

}

if ((Config("run_winPEAS"))){

    "`n Running WinPEAS" >> $logPath

    # Unzip and overwrite existing files
    Expand-Archive -Path "./Auto/AutoDiagnostics/WinPEAS.zip" -DestinationPath "./Auto/AutoDiagnostics/" -Force
    Unblock-File -Path "./Auto/AutoDiagnostics/WinPEAS.ps1"
    & ./Auto/AutoDiagnostics/WinPEAS.ps1

}
