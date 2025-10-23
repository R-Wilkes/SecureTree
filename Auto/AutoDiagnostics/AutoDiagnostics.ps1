# This script only tells and alerts the user of any misconfigurations and stuff
# it does NOT fix any issues, cause I don't want to blow up the machine immediately
# Kind of like winPEAS, but for IRSec stuff


# Just some info
ScreenClear
Write-Host "Starting AutoDiagnostics.ps1" -ForegroundColor Red
Write-Host "SCRIPT WILL NOT MAKE ANY CHANGES, ONLY REPORTS THEM" -ForegroundColor Red
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

# Little helpful status
Write-Progress -Activity  "All Findings are logged" -Status "Log Location: '$logPath'" 

$current_path = Get-Location
$hostname = hostname

# NOTE: Same exact logic as parent, just does not do anything about it bro, will have to make one for AD
# NOTE: Very janky, its barely holding itself together
# Checks if the computer is on a domain
if (-not (IsAD)){

    # Define paths to user and admin text files
    $userListPath = "$current_path/User_list.txt"
    $adminListPath = "$current_path/User_Admin_list.txt"

    # Ignore these users
    $usersToNotRemove = "Administrator", "DefaultAccount", "Guest", "WDAGUtilityAccount", "$curuser"

    # Define the password for the users that get changed, will essentially be all of the users
    $password = "CybersecurityRules3301" # Maybe want to obscure this, cause if red-team gets ahold of this script im cooked

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
                "`nShould create Local Users: $user With password '$password'" >> $logPath
                
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
                "`nShould Create Admin: $admin With password '$password'" >> $logPath

            }
        }
    }

    # Remove users who are not in the user list
    $allLocalUsers = Get-LocalUser | Where-Object { $_.Name -notin $users }
    foreach ($user in $allLocalUsers) {
        if ($user.Name -notin $admins) {
            $good = UserCheck $user.Name
            if ($good -eq $false) {

                Write-Host "Need to Remove: $user" -ForegroundColor Red
                "`nRemove User: $user" >> $logPath
                $usersToRemove += $user.Name

            }
        }
    }

    # Revoke administrative privileges from users not in the admins list
    $allAdmins = Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.Name -notin $admins }
    foreach ($admin in $allAdmins) {
        $good = UserCheck $admin.Name
        if ($good -eq $false) {
            if ($admin.Name.replace("$hostname\","") -notin $usersToRemove){
    
                Write-Host "Need to Remove admin perms: $($admin.name)" -ForegroundColor Red
                "`nNeed to Changes Perms to standard for user: $($admin.name)" >> $logPath
            
            }
        }
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

            Write-Host "Change password for user: '$user'" -ForegroundColor Magenta
            "`nChange Password for user: $user" >> $logPath

        }
    }

    # For each loop to change passwords for admins in user_admin_list.txt
    foreach ($admin in $admins) {
        $existingUser = Get-LocalUser -Name $admin -ErrorAction SilentlyContinue
        if ($existingUser -and $admin -notin $usersToNotRemove) {

            Write-Host "Change password for admin '$admin'" -ForegroundColor Magenta
            "`nChange password for admin: $admin" >> $logPath

        }
    }

    "`n<--------------------------------------------->`nEnd User Changes" >> $logPath

}

else {
    
    Write-Warning "You are on a domain, Auto Users will not work, everything else is unaffected"
    Start-Sleep $longSleep
    "`n Unable to Run Users: Reason - On Active Directory `n `n" >> $logPath

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

# Keep at end of code
Write-Host "Press enter to Continue, Screen will CLEAR"
GetKeyInput -AllowedKeys "`r" | Out-Null 
ScreenClear

# Removes the banner
Write-Progress -Activity  "All Findings are logged" -Status "Log Location: '$logPath'" -Completed

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
