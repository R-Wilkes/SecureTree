# This is used to constantly set passwords on every machines local users and admins, given you know the scored user

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

# Starts the password shuffle
function Start-PassShuffle {

    $hour = (Get-Date).Hour
    $sec = (Get-Date).Second
    $min = (Get-Date).Minute

    $logPath = "./Logs/AutoPassShuffle-$hour-$min-$sec.txt"
    CreatePath -DirectoryPath $logPath -Type "File"

    $date = Get-Date 
    "SecureTree AutoPassShuffle Log" >> $logPath
    "`nWritten On: $date" >> $logPath
    "`nProgram Version: $version" >> $logPath 
    "`nPowershell Version: $($PSVersionTable.PSVersion)" >> $logPath
    "`nUser Logged in: $curuser" >> $logPath
    "`nComputer Name: $computerName`n`n`n" >> $logPath
    
    # Continuous Password Change on All Remote Domain Machines | AI
    Write-Host "Starting continuous password changes on remote domain machines..." -ForegroundColor Red
    Write-Host "This will run continuously until manually stopped!" -ForegroundColor Red
    Write-Host "Press Ctrl+C to stop the loop" -ForegroundColor Yellow
    Start-Sleep 3
    Write-Host "You have 5 seconds to abort!" -ForegroundColor Red
    Start-Sleep 5

    "`nContinuous Remote Password Changes Started `n<--------------------------------------------->" >> $logPath

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

    # Define protected users (same as existing)
    $doNotTouchUsersPath = "$current_path/UserLists/No_Touch_Users.txt"
    $usersToNotChange = "Administrator", "DefaultAccount", "Guest", "WDAGUtilityAccount", "$curuser", "krbtgt", "$env:USERDOMAIN\Domain Admins"

    $doNotTouchUsers = Get-Content $doNotTouchUsersPath -ErrorAction SilentlyContinue
    foreach ($user in $doNotTouchUsers){
        $usersToNotChange += $user.trim()
    }

    $basePassword = Get-Content "./UserLists/Pass_Shuffle.txt"

    if ($basePassword.Length() -eq 0){
        $basePassword = "TempPass1234!"
    }

    # Initialize counter
    $passwordCounter = 1
    $cycleCount = 1

    Write-Host "Found $($domainComputers.Count) domain computers to manage" -ForegroundColor Green
    Write-Host "Protected users: $($usersToNotChange -join ', ')" -ForegroundColor Cyan
    "`nManaging $($domainComputers.Count) computers" >> $logPath
    "`nProtected users: $($usersToNotChange -join ', ')" >> $logPath

    # Continuous loop
    while ($true) {
        
        Write-Host "`n`n=== CYCLE $cycleCount - PASSWORD ITERATION $passwordCounter ===" -ForegroundColor Magenta
        "`n=== CYCLE $cycleCount - PASSWORD ITERATION $passwordCounter ===" >> $logPath
        
        # Create current password with incremented number
        $currentPassword = "$basePassword$passwordCounter"
        $securePassword = ConvertTo-SecureString $currentPassword -AsPlainText -Force
        
        "`nUsing password: $currentPassword" >> $logPath

        # Process each remote computer
        foreach ($computer in $domainComputers) {
            
            Write-Host "Processing computer: $computer" -ForegroundColor Cyan
            "`nProcessing computer: $computer" >> $logPath

            # Test connectivity first
            if (-not (Test-Connection -ComputerName $computer -Count 1 -Quiet)) {
                Write-Host "  $computer is not reachable" -ForegroundColor Red
                "`n  $computer is not reachable" >> $logPath
                continue
            }

            try {
                # Get all local users and change passwords for non-protected users
                $result = Invoke-Command -ComputerName $computer -ScriptBlock {
                    param($securePass, $usersToNotChange, $passNumber)
                    
                    $computerName = $env:COMPUTERNAME
                    $changedUsers = @()
                    $skippedUsers = @()
                    $errorUsers = @()

                    # Function to check if user should be protected
                    function IsProtectedUser {
                        param ([string]$username)
                        $cleanName = $username.replace("$computerName\","").replace("$($computerName.ToUpper())\", "")
                        return ($usersToNotChange -contains $cleanName)
                    }

                    # Get all local users
                    try {
                        $allUsers = Get-LocalUser -ErrorAction Stop
                        
                        foreach ($user in $allUsers) {
                            $isProtected = IsProtectedUser $user.Name
                            
                            if ($isProtected) {
                                $skippedUsers += $user.Name
                            } else {
                                try {
                                    # Skip computer accounts
                                    if ($user.Name -notlike "*$*") {
                                        Set-LocalUser -Name $user.Name -Password $securePass -ErrorAction Stop
                                        $changedUsers += $user.Name
                                    } else {
                                        $skippedUsers += $user.Name
                                    }
                                } catch {
                                    $errorUsers += "$($user.Name):$($_.Exception.Message)"
                                }
                            }
                        }
                    } catch {
                        return "ERROR: Unable to get local users - $($_.Exception.Message)"
                    }

                    return @{
                        Changed = $changedUsers
                        Skipped = $skippedUsers
                        Errors = $errorUsers
                        TotalUsers = $allUsers.Count
                    }
                    
                } -ArgumentList $securePassword, $usersToNotChange, $passwordCounter -ErrorAction Stop

                # Process results
                if ($result -is [string] -and $result.StartsWith("ERROR:")) {
                    Write-Host "  $result" -ForegroundColor Red
                    "`n  $computer - $result" >> $logPath
                } else {
                    Write-Host "  Total users: $($result.TotalUsers)" -ForegroundColor White
                    Write-Host "  Changed passwords: $($result.Changed.Count) users" -ForegroundColor Green
                    Write-Host "  Skipped (protected): $($result.Skipped.Count) users" -ForegroundColor Yellow
                    Write-Host "  Errors: $($result.Errors.Count) users" -ForegroundColor Red
                    
                    if ($result.Changed.Count -gt 0) {
                        Write-Host "    Changed: $($result.Changed -join ', ')" -ForegroundColor Green
                    }
                    if ($result.Errors.Count -gt 0) {
                        Write-Host "    Errors: $($result.Errors -join ', ')" -ForegroundColor Red
                    }

                    # Log details
                    "`n  $computer - Total: $($result.TotalUsers), Changed: $($result.Changed.Count), Skipped: $($result.Skipped.Count), Errors: $($result.Errors.Count)" >> $logPath
                    if ($result.Changed.Count -gt 0) {
                        "`n    Changed users: $($result.Changed -join ', ')" >> $logPath
                    }
                    if ($result.Errors.Count -gt 0) {
                        "`n    Errors: $($result.Errors -join ', ')" >> $logPath
                    }
                }

            } catch {
                Write-Host "  Failed to process $computer : $($_.Exception.Message)" -ForegroundColor Red
                "`n  Failed to process $computer : $($_.Exception.Message)" >> $logPath
            }
            
            # Brief pause between computers
            Start-Sleep 1
        }

        # Increment password counter
        $passwordCounter++
        $cycleCount++
        
        Write-Host "`nCycle $($cycleCount-1) completed. Waiting before next cycle..." -ForegroundColor Green
        "`nCycle $($cycleCount-1) completed at $(Get-Date)" >> $logPath
        
        # Wait between cycles (configurable)
        $cycleDelay = Config("password_cycle_delay")
        if (-not $cycleDelay) { $cycleDelay = 10 }  # Default 5 minutes
        
        Write-Host "Waiting $cycleDelay seconds before next cycle..." -ForegroundColor Cyan
        Start-Sleep $cycleDelay
    }

    "`n<--------------------------------------------->`nContinuous Password Changes Stopped" >> $logPath

}

Start-PassShuffle