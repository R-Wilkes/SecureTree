# Meant to shuffle the passwords of the domain users, uses the same file as AutoPassShuffle

# Needed to run properly
# -------------------------------------
$global:rootPath = $env:SecureTree_RootPath
Set-Location -Path "$rootPath"

# Imports the functions needed
Import-Module -Name "./Data/CommonFunctions/CommonFunctions"

# Set as global variables in the new process
$global:version = $env:SecureTree_Version
$global:curuser = $env:SecureTree_CurUser
$global:computerName = $env:SecureTree_ComputerName
# -------------------------------------

# Starts the password shuffle for AD domain users | AI
function Start-ADPassShuffle {

    $hour = (Get-Date).Hour
    $sec = (Get-Date).Second
    $min = (Get-Date).Minute

    $logPath = "./Logs/AutoPassShuffleDomain-$hour-$min-$sec.txt"
    CreatePath -DirectoryPath $logPath -Type "File"

    $date = Get-Date 
    "SecureTree AutoPassShuffleDomain Log" >> $logPath
    "`nWritten On: $date" >> $logPath
    "`nProgram Version: $version" >> $logPath 
    "`nPowershell Version: $($PSVersionTable.PSVersion)" >> $logPath
    "`nUser Logged in: $curuser" >> $logPath
    "`nComputer Name: $computerName`n`n`n" >> $logPath
    
    # Continuous Password Change on All AD Domain Users | AI
    Write-Host "Starting continuous password changes on Active Directory domain users..." -ForegroundColor Red
    Write-Host "This will run continuously until manually stopped!" -ForegroundColor Red
    Write-Host "Press Ctrl+C to stop the loop" -ForegroundColor Yellow
    Start-Sleep 3
    Write-Host "You have 5 seconds to abort!" -ForegroundColor Red
    Start-Sleep 5

    "`nContinuous AD User Password Changes Started `n<--------------------------------------------->" >> $logPath

    # Define protected users for domain accounts
    $doNotTouchUsersPath = "./UserLists/No_Touch_Users.txt"
    $usersToNotChange = "Administrator", "Guest", "krbtgt", "DefaultAccount", "$curuser", 
                       "KRBTGT", "SUPPORT_388945a0", "DefaultAccount", "WDAGUtilityAccount"

    # Add domain-specific protected accounts
    $domainName = (Get-ADDomain).NetBIOSName
    $usersToNotChange += "$domainName\Administrator", "$domainName\Guest", "$domainName\krbtgt"
    
    # # Add service accounts and system accounts
    # $usersToNotChange += "ANONYMOUS LOGON", "Authenticated Users", "BATCH", "BUILTIN\*", 
    #                     "CREATOR OWNER", "DIALUP", "DIGEST AUTH", "INTERACTIVE", "INTERNET", 
    #                     "LOCAL", "LOCAL SERVICE", "NETWORK", "NETWORK SERVICE", "NT AUTHORITY\*",
    #                     "NT SERVICE\*", "SERVICE", "SYSTEM", "TERMINAL SERVER USER", "THIS ORGANIZATION",
    #                     "USERS", "WORLD"

    $doNotTouchUsers = Get-Content $doNotTouchUsersPath
    foreach ($user in $doNotTouchUsers){
        $usersToNotChange += $user.trim()
    }

    $basePassword = Get-Content "./UserLists/Pass_Shuffle.txt" -ErrorAction SilentlyContinue
    if (-not $basePassword -or $basePassword.Length -eq 0){
        $basePassword = "ChangeMe42069"
    }

    # Initialize counter
    $passwordCounter = 1
    $cycleCount = 1

    # Get all AD users (excluding system accounts)
    try {
        $allDomainUsers = Get-ADUser -Filter * -Properties Enabled, PasswordNeverExpires, CannotChangePassword | 
                         Where-Object { 
                             $_.Enabled -eq $true -and 
                             $_.SamAccountName -notin $usersToNotChange -and
                             $_.DistinguishedName -notlike "*OU=Domain Controllers*" -and
                             $_.SamAccountName -notlike "*$" -and
                             $_.CannotChangePassword -eq $false
                         }
        
        Write-Host "Found $($allDomainUsers.Count) domain users to manage" -ForegroundColor Green
        Write-Host "Protected users: $($usersToNotChange -join ', ')" -ForegroundColor Cyan
        "`nManaging $($allDomainUsers.Count) domain users" >> $logPath
        "`nProtected users: $($usersToNotChange -join ', ')" >> $logPath
        
    } catch {
        Write-Host "Failed to get domain users: $($_.Exception.Message)" -ForegroundColor Red
        "`nFailed to get domain users: $($_.Exception.Message)" >> $logPath
        return
    }

    # Continuous loop
    while ($true) {
        
        Write-Host "`n`n=== CYCLE $cycleCount - PASSWORD ITERATION $passwordCounter ===" -ForegroundColor Magenta
        "`n=== CYCLE $cycleCount - PASSWORD ITERATION $passwordCounter ===" >> $logPath
        
        # Create current password with incremented number
        $currentPassword = "$basePassword$passwordCounter"
        $securePassword = ConvertTo-SecureString $currentPassword -AsPlainText -Force
        
        "`nUsing password: $currentPassword" >> $logPath

        $changedUsers = @()
        $skippedUsers = @()
        $errorUsers = @()

        # Process each domain user
        foreach ($user in $allDomainUsers) {
            
            Write-Host "Processing user: $($user.SamAccountName)" -ForegroundColor Cyan

            try {
                # Double-check protection (additional safety)
                if ($user.SamAccountName -in $usersToNotChange -or 
                    $user.SamAccountName -like "*svc*" -or 
                    $user.SamAccountName -like "*service*" -or
                    $user.PasswordNeverExpires -eq $true) {
                    
                    $skippedUsers += $user.SamAccountName
                    Write-Host "  Skipped (protected): $($user.SamAccountName)" -ForegroundColor Yellow
                    continue
                }

                # Set new password
                Set-ADAccountPassword -Identity $user.SamAccountName -NewPassword $securePassword -Reset -ErrorAction Stop
                
                # Force password change at next logon (optional)
                # Set-ADUser -Identity $user.SamAccountName -ChangePasswordAtLogon $true -ErrorAction SilentlyContinue
                
                $changedUsers += $user.SamAccountName
                Write-Host "  Changed password: $($user.SamAccountName)" -ForegroundColor Green
                
            } catch {
                $errorUsers += "$($user.SamAccountName):$($_.Exception.Message)"
                Write-Host "  Error changing $($user.SamAccountName): $($_.Exception.Message)" -ForegroundColor Red
            }
            
            # Brief pause between users to avoid overwhelming DC
            Start-Sleep 0.5
        }

        # Summary for this cycle
        Write-Host "`nCycle Summary:" -ForegroundColor White
        Write-Host "  Total users processed: $($allDomainUsers.Count)" -ForegroundColor White
        Write-Host "  Passwords changed: $($changedUsers.Count)" -ForegroundColor Green
        Write-Host "  Users skipped: $($skippedUsers.Count)" -ForegroundColor Yellow
        Write-Host "  Errors encountered: $($errorUsers.Count)" -ForegroundColor Red

        if ($changedUsers.Count -gt 0) {
            Write-Host "  Changed users: $($changedUsers -join ', ')" -ForegroundColor Green
        }
        if ($errorUsers.Count -gt 0) {
            Write-Host "  Error users: $($errorUsers -join ', ')" -ForegroundColor Red
        }

        # Log details
        "`nCycle $cycleCount Summary:" >> $logPath
        "`n  Total: $($allDomainUsers.Count), Changed: $($changedUsers.Count), Skipped: $($skippedUsers.Count), Errors: $($errorUsers.Count)" >> $logPath
        if ($changedUsers.Count -gt 0) {
            "`n  Changed users: $($changedUsers -join ', ')" >> $logPath
        }
        if ($skippedUsers.Count -gt 0) {
            "`n  Skipped users: $($skippedUsers -join ', ')" >> $logPath
        }
        if ($errorUsers.Count -gt 0) {
            "`n  Error users: $($errorUsers -join ', ')" >> $logPath
        }

        # Increment password counter
        $passwordCounter++
        $cycleCount++
        
        Write-Host "`nCycle $($cycleCount-1) completed. Waiting before next cycle..." -ForegroundColor Green
        "`nCycle $($cycleCount-1) completed at $(Get-Date)" >> $logPath
        
       
        $cycleDelay = 30
        
        Write-Host "Waiting $cycleDelay seconds before next cycle..." -ForegroundColor Cyan
        Start-Sleep $cycleDelay
    }

    "`n<--------------------------------------------->`nContinuous AD Password Changes Stopped" >> $logPath
}

Start-ADPassShuffle