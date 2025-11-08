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

# Opens new terminal for logging monitoring, only on the Domain Controller
if ((IsDC)){

    "`nStarted Accounts Log Monitoring" >> $logPath

    # Starts a new process, not gonna import the 500 lins script for easy handing of Jobs
    Start-Process powershell -ArgumentList "-NoExit", "-File", ".\Auto\AutoDiagnostics\Monitoring\LoginMonitor.ps1"

    "`nStarted SystemChange Log Monitoring" >> $logPath

    # Starts a new process, not gonna import the 500 lins script for easy handing of Jobs
    Start-Process powershell -ArgumentList "-NoExit", "-File", ".\Auto\AutoDiagnostics\Monitoring\SystemChangeMonitor.ps1"

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
