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
"IRSec AutoDiagnostics Log" >> $logPath
"`nWritten On: $date" >> $logPath
"`nProgram Version: $version" >> $logPath 
"`nPowershell Version: $($PSVersionTable.PSVersion)" >> $logPath
"`nUser Logged in: $curuser" >> $logPath
"`nComputer Name: $computerName" >> $logPath

$current_path = Get-Location
$hostname = hostname

$allUsersPassword = "CybersecurityRules3301" # Maybe want to obscure this, cause if red-team gets ahold of this script im cooked

# All AI, just revamped my local users | AI
if (IsAD) {

    "`nActive Directory: $((Get-ADDomain).Name)" >> $logPath
    Write-Host "On Active Directory Domain: $((Get-ADDomain).Name)" -ForegroundColor Cyan

    # Define paths to user and admin text files
    $userListPath = "$current_path/UserLists/Domain_Admins.txt"
    $adminListPath = "$current_path/UserLists/Domain_Users.txt"

    # Ignore these users (domain format)
    $usersToNotRemove = "Administrator", "DefaultAccount", "Guest", "WDAGUtilityAccount", "$curuser", "krbtgt"

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

# NOTE: Very janky, its barely holding itself together
# If Statement is here for minimizing the code in VScode
if ($True){

    # Define paths to user and admin text files
    $userListPath = "$current_path/UserLists/Local_Admins.txt"
    $adminListPath = "$current_path/UserLists/Local_Users.txt"

    # Ignore these users
    $usersToNotRemove = "Administrator", "DefaultAccount", "Guest", "WDAGUtilityAccount", "$curuser", "krbtgt"

    # Will just see if the user is in users to not remove
    function UserCheck {
        param (
            [string]$inputString
        )

        $inputString = $inputString.replace("$hostname\","")

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
                "`nShould create Local User: $user With password '$allUsersPassword'" >> $logPath
                
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
                "`nShould Create Local Admin: $admin With password '$allUsersPassword'" >> $logPath

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
        $allAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop| Where-Object { $_.Name -notin $admins }
        foreach ($admin in $allAdmins) {
            $good = UserCheck $admin.Name
            if ($good -eq $false) {
                if ($admin.Name.replace("$hostname\","") -notin $usersToRemove){
        
                    Write-Host "Need to Remove admin perms: $($admin.name)" -ForegroundColor Red
                    "`nNeed to Changes Perms to standard for user: $($admin.name)" >> $logPath
                
                }
            }
        }
    }

    catch {
        Write-Host "Unable to get group: Administrators" -ForegroundColor Red
        "`nUnable to get group: Administrators" >> $logPath
    }

    # Grant administrative privileges to users in the admins list
    foreach ($admin in $admins) {
        $existingUser = Get-LocalUser -Name $admin -ErrorAction SilentlyContinue
        if ($existingUser) {

            $good = UserCheck $admin
            if ($good -eq $false) {
                if ($admin.Name.replace("$hostname\","") -notin $usersToRemove){
                    Write-Host "Need to Add admin perms: $admin" -ForegroundColor Yellow
                    "`nChange Perms to Admin for user: $admin" >> $logPath
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

# Check if Guest account is enabled
$guest = Get-LocalUser -Name "Guest"
if ($guest.Enabled) {

    Write-Host "Guest account is ENABLED" -ForegroundColor Red
    "`nGuest account is ENABLED" >> $logPath

} 

else {

    Write-Host "Guest account is disabled" -ForegroundColor Green
    "`nGuest account is DISABLED" >> $logPath

}

# SMBV1 is enabled
$smbV1 = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State
if ($smbV1 -ne "Disabled"){

    Write-Host "SMBV1 is enabled" -ForegroundColor Red
    "`nSMBV1 is enabled" >> $logPath

}

else{

    Write-Host "SMBV1 is disabled" -ForegroundColor Green
    "`nSMBV1 is disabled" >> $logPath

}

# Shows all programs on PC
Get-Package -Provider Programs
Get-WmiObject -Class Win32_Product | Select-Object -Property Name

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
