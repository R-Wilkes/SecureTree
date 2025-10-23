# ---------------------------
# For the IRSec competitions
# Created by Ricker Wilkes
# Daughter Script of the CyberPatriot Script
# Master Repository: https://github.com/R-Wilkes/IRSec
# ---------------------------

# NOTE: Its gonna be a lot of copy past from parent repo

# This sets your path to the script root, so you can run it from anywhere
Set-Location -Path "$PSScriptRoot"

# Most of the main Function for the StartScript
Import-Module -Name "./Data/StartFunctions/StartFunctions" -Force

# Common Functions that are used in all of the scripts
Import-Module -Name "./Data/CommonFunctions/CommonFunctions" -Force

# This is only here because I want some cool frames around the text
Import-Module -Name "./Data/FrameBuilder/FrameBuilder" -Force

# Allows search of prohibited file
Import-Module -Name "./Data/FileFinder/FileFinder" -Force

# Set the terminal screen size to 138 columns and 36 rows
[System.Console]::WindowWidth = 138
[System.Console]::WindowHeight = 36

# Hides the Cursor
[Console]::CursorVisible = $false

# I had 2 places in which the auto runs
function RunAuto(){

    # Get the file properties
    $UAL = Get-Item -Path ".\User_Admin_list.txt"
    $UL = Get-Item -Path ".\User_list.txt"

    # Will remind you to fill out the auto
    if (($UAL.Length -eq 0 -or $UL.Length -eq 0)) {

        Write-Host "Users or admin list not filled out"
        Write-Host "Press anything to continue once you do that"
        Start-Sleep $longSleep 
        GetKeyInput | Out-Null 
        ScreenClear

    }

    # Runs the diagnostic script
    if ((Config("run_auto_diagnostic"))){
        & ./Auto/AutoDiagnostics/AutoDiagnostics.ps1
    }
    
    # Runs the fix script
    if ((Config("run_auto_fix"))){
        & ./Auto/AutoFix/AutoFix.ps1
    }
}

# Shrimple Variables
# -----------------------------------------
# The original creator of this script
$global:creator = "Ricker Wilkes"
$global:creator | Out-Null

# Version = MainVersion.SubVersion.PatchVersion
$global:version = "0.1"
$global:version | Out-Null

# Gets current User
$global:curuser = [System.Environment]::UserName
$global:computerName = hostname

# Sleep Variables
$global:shortSleep = 3
$global:longSleep = 5

# Temp Data Directory
$global:tempData = "./Data/TempData"
$global:tempData | Out-Null
# -----------------------------------------


# Most of just the simple variables and code that are needed for the script to even start up
# -------------------------------------------------------------------

# NOTE: I confined all the variables and run checks into the LoadingScreen, so its kind of needed to run
# Does the loading screen, and all checks to make sure everything is good to go

# LoadingScreen

# ScreenClear

# ConfirmInfo

# ScreenClear

# ShowDisabled

# ScreenClear

# End of the variables and code that are needed for the script to even start up
# -------------------------------------------------------------------

#Auto or Manual
$autoMode = PromptAutoMode

# Start of the Auto and Manual Sections of the script
# -------------------------------------------------------------------

ScreenClear

# Auto Mode
if ($autoMode -eq "A") {

    # Makes you agree something before Continuing
    ScreenClear
    Write-Warning "AUTO may obliterate your machine!!!!"

    # This is just to prevent the script from absolutely destroying your computer
    if ((2FA -Message "Are you sure you want to continue?")) {

        ScreenClear
        RunAuto

    }

    else{

        ScreenClear
        Write-Host "Come back when your ready :)"
        Start-Sleep $longSleep
        Exit

    }
}

# Manual Mode
else{

    # Good for seeing errors
    if ((Config("debug_mode"))){

        # All nonterminating error will be asked by the user
        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Inquire   

    }

    else{

        # If debug mode is off, it will not log any errors to the manual log
        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

    }

    # Log setup
    $hour = (Get-Date).Hour
    $sec = (Get-Date).Second
    $min = (Get-Date).Minute
    $global:manLog = "./Logs/ManualLog-$hour-$min-$sec.txt"
    CreatePath -DirectoryPath $manLog -Type "File"
    
    $global:numberError = 0

    LogHeader -Name "IRSec Manual Log" -Path $manLog

    # Adds to the manual log
    "[" + (Get-CurrentTime) + "] Start of Manual Mode Log" >> $manLog

    ScreenClear
    
    # For the view of the main menu, just so its simplified
    $global:advanceView = $false

    # For new CLI
    $global:SelectionPosition = 1

    # NOTE: Its like reading ancient hieroglyphs looking back at this code
    # The Start of the almighty main script
    while ($true) { 

        ScreenClear

        # Uses the new CLI
        if ((Config("new_CLI"))){

            # Prevent constant enter key presses, hard to describe in comments
            :KeyLoop While ($true){

                # Builds it for the first time
                ScreenClear
                BuildMenuFrame

                $key = [Console]::ReadKey($true)

                # Switch statement to handle the key presses
                switch ($key.Key) {
                    'UpArrow' {
                        ChangeSelectionPosition -Direction "Up" -Menu (GetMenu($global:advanceView))
                        
                    }
                    'DownArrow' {
                        ChangeSelectionPosition -Direction "Down" -Menu (GetMenu($global:advanceView))
                    
                    }
                    'Enter' {

                        $choice = [string]$global:SelectionPosition
                        $global:SelectionPosition = 1
                        break KeyLoop

                    }
                    'Escape' {
                        $exitNumber = (GetMaxOptions -Menu  (BuildFrame -Text (GetMenu($global:advanceView)) -NoOutput $true))
                        
                        # Exits if you hit escape twice
                        if (($global:SelectionPosition -eq $exitNumber)){
                            $choice = $exitNumber
                            break KeyLoop
                        }

                        $global:SelectionPosition = $exitNumber

                    }

                    default{
                        
                        # If the key you press is a digit
                        if ($key.KeyChar -match '^\d$' -or $key.Modifiers -band [ConsoleModifiers]::Shift) {
                            
                            # If the shift key is pressed
                            if ($key.Modifiers -band [ConsoleModifiers]::Shift -and $key.Key -ge 'D0' -and $key.Key -le 'D9') {

                                # Handle the case where Shift and a number are pressed
                                $shiftedNumber = ([int]([string]($key.Key)).replace("D", "")) + 10

                                if ($shiftedNumber -ge 1 -and $shiftedNumber -le (GetMaxOptions -Menu (BuildFrame -Text (GetMenu($global:advanceView)) -NoOutput $true))){

                                    if ($shiftedNumber -eq $global:SelectionPosition){

                                        $choice = [string]$global:SelectionPosition
                                        $global:SelectionPosition = 1
                                        break KeyLoop

                                    }

                                    else{
                                        $global:SelectionPosition = $shiftedNumber
                                    }
                                    continue
                                }
                            }

                            # The 48 is to set it back to the original position
                            $numberPressed =([int]$key.KeyChar) - 48

                            # Sets to 10 if you press 0
                            if ($numberPressed -eq 0){
                                $numberPressed = 10
                            }
                    
                            # Checks to see if its valid within range
                            if ($numberPressed -ge 1 -and $numberPressed -le (GetMaxOptions -Menu (BuildFrame -Text (GetMenu($global:advanceView)) -NoOutput $true))) {

                                # Will enter for you if you press the number while its already selected
                                if ($numberPressed -eq $global:SelectionPosition){

                                    $choice = [string]$global:SelectionPosition
                                    $global:SelectionPosition = 1
                                    break KeyLoop

                                }

                                else{
                                    $global:SelectionPosition = $numberPressed
                                }
                            }
                        }

                        else{
                            continue
                        }
                    }
                }
            }
        }

        else{

            # Function to get menu
            $mainMenuTitle = GetMenu($global:advanceView)
        
            # The New Menu
            $choice = Read-Host -Prompt $mainMenuTitle

        }

        # NOTE: I know its bad practice to have a lots of if statements, but I can't really think of a better way to do this 

        # NOTE: When it comes to not logging error, like things you do
        # NOTE: I just used the good old fashion "[" + (Get-CurrentTime) + "]" Message" >> $manLog

        # TODO: Will have to update for AD
        # Edits Users
        if ($choice -eq "1" -and -not (IsAD)) {

            "[" + (Get-CurrentTime) + "] $curuser Entered User Configuration" >> $manLog

            # Another menu that will allow you to edit users, edit groups, add users, add groups
            While ($True) {

                ScreenClear
                
                $editInput = BuildSubOptionFrame(" 1) Edit Users `n 2) Edit Groups `n 3) Add Users `n 4) Add Groups `n 5) Exit")
               
                # Edit Users
                if ($editInput -eq "1") {

                    # Adds to the manual log
                    "[" + (Get-CurrentTime) + "] $curuser Entered User Edit Mode" >> $manLog

                    :editUsers While ($True) {

                        ScreenClear
        
                        $b = (((Get-LocalGroupMember -Group "Administrators").name).Replace("$computerName", "")).Replace("\" , "").Replace("NT AUTHORITY", "")
                        $a = (((Get-LocalGroupMember -Group "Users").name).Replace("$computerName", "")).Replace("\" , "").Replace("NT AUTHORITY", "")
                        
                        $users = $b + $a
    
                        # Turns the array into the string that the BuildSubOptionFrame can work with
                        $userString = FormatArrayToString -Array $users

                        # Chooses the user you want to edit
                        $userInput = BuildSubOptionFrame($userString)


                        # Encase you want to exit, only custom to the users part
                        if ($userInput -eq ($users.Length + 1)){

                            # Adds to the manual log
                            "[" + (Get-CurrentTime) + "] $curuser Exited User Edit Mode" >> $manLog
                            break 

                        }

                        $who = ($users[$userInput - 1])

                        # The options of the users
                        While ($True) {

                            ScreenClear

                            # This just makes the menu more concise, no need to go to another member to set perms
                            $isAdmin = Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.Name.contains($who) }
                           
                            if (-not $isAdmin){
                                $option3 = "Swap " + $who + " Perms to Admin"
                            }
                            
                            else{
                                $option3 = "Swap "+ $who + " Perms to Standard User"
                            }

                            Write-Progress -Activity  "Editing User" -Status "Editing User $who | Permissions: $(if ($isAdmin){"Admin"}else{"Standard"})"

                            # Gives Options of what do to with the user
                            $what = BuildSubOptionFrame(" 1) Rename $who `n 2) Change $who Password `n 3) $option3 `n 4) Delete $who `n 5) Change Current Edit User `n 6) Exit User Configuration")
                       
                            try {
                                
                                # Rename User
                                if ($what -eq "1") {

                                    ScreenClear

                                    # Changes the name of a certain User
                                    $newName = CenterText -Text "Renaming $who" -PromptString "New Name"
                                    Rename-LocalUser -Name $who -NewName $newName
                                    Write-Host "Changed name of $who to $newName" -ForegroundColor Green
                
                                    # Adds to the manual log
                                    "[" + (Get-CurrentTime) + "] $curuser Renamed User $who to $newName" >> $manLog
                                    $who = $newName
            
                                }
                            
                                # Change Password
                                elseif ($what -eq "2") {

                                    ScreenClear

                                    $password = CenterText -Text "Changing Password for $who" -PromptString "New Password" -SecureString $true
                                    Set-LocalUser "$who" -Password $password 

                                    # Does NOT show the password, that would be insecure and not safe
                                    "[" + (Get-CurrentTime) + "] $curuser Changed Password for User $who" >> $manLog
                    
                                }
                    
                                # Change Permissions
                                elseif ($what -eq "3") {


                                    if (-not $isAdmin){
                                        
                                        Add-LocalGroupMember -Group "Administrators" -Member "$who"
                                        Remove-LocalGroupMember -Group "Users" -Member "$who"

                                        # Adds to the manual log
                                        "[" + (Get-CurrentTime) + "] $curuser Changed Permissions of User $who to Administrators" >> $manLog
    
                                    }

                                    else{
                                     
                                        Remove-LocalGroupMember -Group "Administrators" -Member "$who"
                                        Add-LocalGroupMember -Group "Users" -Member "$who"

                                        # Adds to the manual log
                                        "[" + (Get-CurrentTime) + "] $curuser Changed Permissions of User $who to Standard" >> $manLog

                                    }
                                }
                    
                                # Delete User
                                elseif ($what -eq "4") {

                                    Write-Host "Delete $who"
                                    ScreenClear
                                    
                                    $AREYOUSURE = 2FA -Message "Are you sure you want to delete $($who)?"

                                    if ($AREYOUSURE -eq "Y") {

                                        Remove-LocalUser -Name "$who"

                                        # Adds to the manual log
                                        "[" + (Get-CurrentTime) + "] $curuser Obliterated User $who (ROR2 Reference)" >> $manLog
                                        Write-Progress -Activity  "Editing User" -Completed
                                        break 
                            
                                    }

                                    else{

                                        # Adds to the manual log
                                        "[" + (Get-CurrentTime) + "] $curuser Decided Not to Obliterate User $who" >> $manLog

                                    }
                                }
                    
                                # Change Current Edit User
                                elseif ($what -eq "5") {
                        
                                    # Let you change the user you are working on
                                    Write-Host "Change Edit User"

                                    # Adds to the manual log
                                    "[" + (Get-CurrentTime) + "] $curuser Changed the user they were editing" >> $manLog
                                    Write-Progress -Activity  "Editing User" -Completed
                                    break
                    
                                }
                    
                                # Exits User Config
                                elseif ($what -eq "6") {

                                    # Adds to the manual log
                                    "[" + (Get-CurrentTime) + "] $curuser Exited User Configuration" >> $manLog
                                    Write-Progress -Activity  "Editing User" -Completed
                                    break editUsers
                        
                                } 
                            }

                            catch {
                                WriteErrorLog -ErrorRecord $_
                            }
                        }
                    }
                }

                # Edits Groups
                elseif ($editInput -eq "2") {

                    "[" + (Get-CurrentTime) + "] $curuser Entered Edit Group Configuration" >> $manLog

                    $groupArray = (Get-LocalGroup).name
                    $groupString = FormatArrayToString -Array $groupArray

                    $groupInput = BuildSubOptionFrame($groupString)

                    if ($groupInput -eq ($groupArray.Length + 1)){

                        "[" + (Get-CurrentTime) + "] $curuser Exited Edit Group Configuration" >> $manLog
                        continue 
    
                    }

                    $groupSelected = ($groupArray[$groupInput - 1])

                    While ($True) {

                        ScreenClear

                        # Little hard to read
                        Write-Progress -Activity  "Editing Group" -Status "Editing Group $groupSelected | Users: $(if ((Get-LocalGroupMember -Group "$groupSelected" | Where-Object { $_.Name.contains($computerName) } | Measure-Object).Count -eq 0) {"None"}else{(Get-LocalGroupMember -Group "$groupSelected" | Select-Object -ExpandProperty Name).Replace($computerName + '\', '')})"
                        $editGroup = BuildSubOptionFrame(" 1) Add Group User `n 2) Remove Groups User `n 3) Delete Group `n 4) Exit")

                        try{

                            # Adds a user to a group
                            if ($editGroup -eq "1") {

                                "[" + (Get-CurrentTime) + "] $curuser Entered Edit Group '$groupSelected' User Configuration" >> $manLog

                                # Makes it so you can add multiple users at once
                                While ($true){

                                    # If there is nobody in the group
                                    if ((Get-LocalGroupMember -Group "$groupSelected" | Where-Object { $_.Name.contains($computerName) } | Measure-Object).Count -eq 0){
                                        
                                        # Get all local users
                                        $filteredUsers = Get-LocalUser

                                    }

                                    else{

                                        # Get all local users
                                        $allUsers = Get-LocalUser

                                        # Get members of the specified group (e.g., "Administrators")
                                        $groupMembers = (Get-LocalGroupMember -Group "$groupSelected" | Select-Object -ExpandProperty Name).Replace("$computerName\", "")

                                        # Filter out users who are in the specified group
                                        $filteredUsers = $allUsers | Where-Object { $groupMembers -notcontains $_.Name }

                                    }

                                    $filteredUsersArray = FormatArrayToString -Array $filteredUsers

                                    $userToAddNumber = BuildSubOptionFrame($filteredUsersArray)

                                    # Exits the group menu
                                    if ($userToAddNumber -eq ($filteredUsers.Length + 1)){

                                        # Adds to the manual log
                                        "[" + (Get-CurrentTime) + "] $curuser Exited Edit Group '$groupSelected' User Configuration" >> $manLog
                                        break 

                                    }

                                    else{

                                        $userToAdd = ($filteredUsers[$userToAddNumber - 1])

                                        Add-LocalGroupMember -Group $groupSelected -Member $userToAdd
                                        "[" + (Get-CurrentTime) + "] $curuser Added User '$userToAdd' to group '$groupSelected'" >> $manLog
                                    
                                    }
                                }
                            }

                            # Removes a user from the group
                            if ($editGroup -eq "2") {

                                "[" + (Get-CurrentTime) + "] $curuser Entered remove user for group '$groupSelected' " >> $manLog
                                
                                # If there is nobody in the group
                                if ((Get-LocalGroupMember -Group "$groupSelected" | Where-Object { $_.Name.contains($computerName) } | Measure-Object).Count -eq 0){

                                    BuildSubTerminalText -Text "There is no users in the group $groupSelected"
                                    "[" + (Get-CurrentTime) + "] $curuser Exited remove user for group '$groupSelected' (No Users in group) " >> $manLog
                                    continue

                                }

                                # Makes it so you can add multiple users at once
                                While ($true){

                                    # If there is nobody in the group
                                    if ((Get-LocalGroupMember -Group "$groupSelected" | Where-Object { $_.Name.contains($computerName) } | Measure-Object).Count -eq 0){

                                        "[" + (Get-CurrentTime) + "] $curuser Exited remove user for group '$groupSelected' (No Users in group) " >> $manLog
                                        break

                                    }

                                    # Get members of the specified group (e.g., "Administrators")
                                    $groupMembers = @(Get-LocalGroupMember -Group "$groupSelected" | Select-Object -ExpandProperty Name | ForEach-Object { $_.Replace("$computerName\", "") })

                                    $filteredUsersArray = FormatArrayToString -Array $groupMembers

                                    $userToRemoveNumber = BuildSubOptionFrame($filteredUsersArray)

                                    # Exits the group menu
                                    if ($userToRemoveNumber -eq ($groupMembers.Length + 1)){

                                        # Adds to the manual log
                                        "[" + (Get-CurrentTime) + "] $curuser Exited remove user for Group '$groupSelected'" >> $manLog
                                        break 

                                    }

                                    # Removes users chosen
                                    else{

                                        $userToRemove = ($groupMembers[$userToRemoveNumber - 1])
                                        Remove-LocalGroupMember -Group $groupSelected -Member $userToRemove
                                        "[" + (Get-CurrentTime) + "] $curuser Removed User '$userToRemove' from group '$groupSelected'" >> $manLog

                                    }
                                }
                            }

                            # Deletes the group
                            if ($editGroup -eq "3"){

                                $AREYOUSURE = 2FA -Message "Are you sure you want to delete $($groupSelected)?"

                                if ($AREYOUSURE -eq "Y") {

                                    Remove-LocalGroup -Name "$groupSelected"

                                    # Adds to the manual log
                                    "[" + (Get-CurrentTime) + "] $curuser Deleted Group '$groupSelected'" >> $manLog
                                    Write-Progress -Activity  "Editing Group" -Completed
                                    break 

                                }

                                else{

                                    # Adds to the manual log
                                    "[" + (Get-CurrentTime) + "] $curuser Decided Not to Delete Group '$groupSelected'" >> $manLog

                                }
                            }

                            # Exits Groups Editing
                            if ($editGroup -eq "4") {

                                "[" + (Get-CurrentTime) + "] $curuser Exited Edit Group Configuration" >> $manLog
                                Write-Progress -Activity  "Editing Group" -Completed
                                break
                
                            }
                        }

                        catch {
                            WriteErrorLog -ErrorRecord $_
                        }
                    }
                } 
                
                # Adds a new user as standard users
                elseif ($editInput -eq "3") {

                    "[" + (Get-CurrentTime) + "] $curuser Entered Add User Configuration" >> $manLog

                    # Adds a new User
                    $NewUserName = CenterText -Text "Adding New User" -PromptString "New User Name"

                    if ($NewUserName -eq "") {
                        "[" + (Get-CurrentTime) + "] $curuser Did not provide name for New User, Exiting Add User Configuration" >> $manLog
                    }

                    else {

                        try{

                            $NewUserPassword = CenterText -Text "Password for $NewUserName" -PromptString "Password" -SecureString $true
                            New-LocalUser "$NewUserName" -Password $NewUserPassword -FullName $NewUserName | Out-Null
                            Add-LocalGroupMember -Group "Users" -Member "$NewUserName" | Out-Null
            
                            # Adds to the manual log
                            "[" + (Get-CurrentTime) + "] $curuser Added new User $NewUserName to Local Group Users" >> $manLog
                        
                        }

                        catch {
                            WriteErrorLog -ErrorRecord $_
                        }
                    }
                }

                # Adds a new group
                elseif ($editInput -eq "4") {

                    try{

                        "[" + (Get-CurrentTime) + "] $curuser Entered Adding Group Configuration" >> $manLog
                        $groupName = CenterText -Text "Adding New Group" -PromptString "New Group Name"
                        $groupDescription = CenterText -Text "$groupName Description" -PromptString "Group Description"
                        New-LocalGroup -Name $groupName -Description $groupDescription | Out-Null
                        
                        # Adds to the manual log
                        "[" + (Get-CurrentTime) + "] $curuser Added New group '$groupName' with description '$groupDescription'" >> $manLog
                    
                    }

                    catch{
                        WriteErrorLog -ErrorRecord $_
                    }
                } 

                # Exits users Configuration
                elseif ($editInput -eq "5") {

                    "[" + (Get-CurrentTime) + "] $curuser Exited User Configuration" >> $manLog
                    break
        
                }
            }
        }

        # Stupid Note thing
        elseif ($choice -eq "2" -and $global:advanceView) {

            ScreenClear
            Write-Host "Don't blow up your machine"
            Write-Host "Some registry Keys can not be set via Script, I don't know why, so you have to do it manually"
            Write-Host "Set SMB protocol to version 2, cause version 1 has Eternal blue vulnerability"
            Read-Host -Prompt "Press enter to exit"

            # Adds to the manual log
            "[" + (Get-CurrentTime) + "] $curuser Read Note.txt" >> $manLog    

        }

        # Password policy config
        elseif ($choice -eq "3" -and $global:advanceView) {

            ScreenClear

            # Adds to the manual log
            "[" + (Get-CurrentTime) + "] $curuser Entered Password Policy Configuration" >> $manLog
            
            While ($true) { 

                ScreenClear
                $bob3 = BuildSubOptionFrame(" 1) Set minimum password length `n 2) Set minimum password age `n 3) Set maximum password age `n 4) Number of previous password remembered `n 5) Secure lockout threshold `n 6) Lockout Duration `n 7) Exit password config")

                try{

                    # Min Password Length
                    if ($bob3 -eq "1") {

                        $minPass = Read-Host -Prompt "Minimum Password Length?"
                        net accounts /minpwlen:$minPass

                        # Adds to the manual log
                        "[" + (Get-CurrentTime) + "] $curuser Set Minimum password Length to $minPass" >> $manLog

                    }

                    # Min Password Age
                    elseif ($bob3 -eq "2") {

                        $minPassage = Read-Host -Prompt "Minimum Password Age?"
                        net accounts /minpwage:$minPassage

                        # Adds to the manual log
                        "[" + (Get-CurrentTime) + "] $curuser Set Minimum password Age to $minPassage" >> $manLog

                    }

                    # Max Password Age
                    elseif ($bob3 -eq "3") {

                        $maxPassage = Read-Host -Prompt "Maximum Password Age?"
                        net accounts /maxpwage:$maxPassage

                        # Adds to the manual log
                        "[" + (Get-CurrentTime) + "] $curuser Set Maximum password Age to $maxPassage" >> $manLog

                    }

                    # Number of Previously Remembered Password
                    elseif ($bob3 -eq "4") {

                        $NoPRP = Read-Host -Prompt "Number of previously remembered passwords?"
                        net accounts /uniquepw:$NoPRP

                        # Adds to the manual log
                        "[" + (Get-CurrentTime) + "] $curuser Set Number of previously remembered passwords $NoPRP" >> $manLog

                    }

                    # Lockout threshold attempts
                    elseif ($bob3 -eq "5") {

                        $lockAttempts = Read-Host -Prompt "Lockout threshold attempts?"
                        net accounts /lockoutthreshold:$lockAttempts

                        # Adds to the manual log
                        "[" + (Get-CurrentTime) + "] $curuser Set Lockout threshold Attempts to $lockAttempts" >> $manLog

                    }

                    # Lockout Duration
                    elseif ($bob3 -eq "6") {
                        
                        $lockDuration = Read-Host -Prompt "Lockout Duration"
                        net accounts /lockoutduration:$lockDuration

                        # Adds to the manual log
                        "[" + (Get-CurrentTime) + "] $curuser Set Lockout Duration to $lockDuration" >> $manLog

                    }

                    # Exit
                    elseif ($bob3 -eq "7") {

                        # Adds to the manual log
                        "[" + (Get-CurrentTime) + "] $curuser Exited Password Policy Config" >> $manLog
                        break
                    }
                }
                
                catch {
                    WriteErrorLog -ErrorRecord $_
                }
            }
        }

        # Installs The stuff from the installers
        elseif (($choice -eq "4" -and $global:advanceView) -or ($choice -eq "2" -and -not ($global:advanceView))) {

            "[" + (Get-CurrentTime) + "] $curuser Entered Program Install" >> $manLog
            $server = IsServer

            While ($True) {

                ScreenClear
                
                try{

                    # Shows Avast depending on if you are running windows server or not
                    if (-not $server){

                        $which = BuildSubOptionFrame(" 1) Install MalwareBytes `n 2) Install Avast `n 3) Install Revo Uninstaller `n 4) Install Chrome `n 5) Install Firefox `n 6) Exit Installers")

                        # MalwareBytes Installer
                        if ($which -eq "1") {

                            # Malwarebytes Installer
                            & .\Software\AntiVirus\MBSetup-Windows.exe
    
                            # Manual Log
                            "[" + (Get-CurrentTime) + "] $curuser Installed Malwarebytes" >> $manLog
    
                        }

                        # Avast Installer
                        if ($which -eq "2") {

                            # Avast  install
                            & .\Software\AntiVirus\avast_free_antivirus_setup_online.exe
    
                            # Manual Log
                            "[" + (Get-CurrentTime) + "] $curuser Installed Avast" >> $manLog
                
                        }

                        # Revo Installer
                        if ($which -eq "3") {

                            # Revo Installer
                            & .\Software\Uninstallers\revosetup.exe
    
                            # Manual Log
                            "[" + (Get-CurrentTime) + "] $curuser Installed Revo Uninstaller" >> $manLog
    
                        }

                        # Chrome Installer
                        if ($which -eq "4") {

                            # CHromeInstaller
                            & .\Software\Browser\ChromeSetup.exe
    
                            # Manual Log
                            "[" + (Get-CurrentTime) + "] $curuser Installed Chrome" >> $manLog
    
                        }

                        # Firefox Installer
                        if ($which -eq "5") {

                            # Revo Installer
                            & ".\Software\Browser\Firefox Installer.exe"
    
                            # Manual Log
                            "[" + (Get-CurrentTime) + "] $curuser Installed Firefox" >> $manLog
    
                        }
                        
                        

                        # Exit
                        if ($which -eq "6") {

                            # Manual Log
                            "[" + (Get-CurrentTime) + "] $curuser Exited Anti-Virus Install" >> $manLog
                            break
    
                        }
                    }

                    else{
                        
                        $which = BuildSubOptionFrame(" 1) Install MalwareBytes `n 2) Install Revo Uninstaller `n 3) Install Chrome `n 4) Install Firefox `n 5) Exit Installers")
                
                        # MalwareBytes Installer
                        if ($which -eq "1") {

                            # Malwarebytes Installer
                            & .\Software\AntiVirus\MBSetup-Windows.exe
    
                            # Manual Log
                            "[" + (Get-CurrentTime) + "] $curuser Installed Malwarebytes" >> $manLog
    
                        }

                        # Revo Installer
                        if ($which -eq "2") {

                            # Revo Installer
                            & .\Software\Uninstallers\revosetup.exe
    
                            # Manual Log
                            "[" + (Get-CurrentTime) + "] $curuser Installed Revo Uninstaller" >> $manLog
    
                        }

                        # Chrome Installer
                        if ($which -eq "3") {

                            # CHromeInstaller
                            & .\Software\Browser\ChromeSetup.exe
    
                            # Manual Log
                            "[" + (Get-CurrentTime) + "] $curuser Installed Chrome" >> $manLog
    
                        }

                        # Firefox Installer
                        if ($which -eq "4") {

                            # Revo Installer
                            & ".\Software\Browser\Firefox Installer.exe"
    
                            # Manual Log
                            "[" + (Get-CurrentTime) + "] $curuser Installed Firefox" >> $manLog
    
                        }
                                                    
                        # Exit
                        if ($which -eq "5") {

                            # Manual Log
                            "[" + (Get-CurrentTime) + "] $curuser Exited Anti-Virus Install" >> $manLog
                            break
    
                        }
                    }
                }
                catch {
                    WriteErrorLog -ErrorRecord $_
                }
            }
        }

        # For Running the programs
        elseif (($choice -eq "5" -and $global:advanceView) -or ($choice -eq "3" -and -not ($global:advanceView))) {

            # Manual Log
            "[" + (Get-CurrentTime) + "] $curuser Entered Sysinternals Programs" >> $manLog

            While ($true) {

                ScreenClear

                $which = BuildSubOptionFrame(" 1) Run AutoRuns64 `n 2) Run Bginfo64 `n 3) Run Cacheset64 `n 4) Run Portmon `n 5) Run Procmon64 `n 6) Run Tcpview64 `n 7) Exit")

                try{

                    # Autoruns
                    if ($which -eq "1") {

                        & .\Software\Sysinternals\MainPrograms\Autoruns64.exe

                        # Manual Log
                        "[" + (Get-CurrentTime) + "] $curuser Ran AutoRuns64" >> $manLog
            
                    }

                    # Bginfo
                    if ($which -eq "2") {

                        & .\Software\Sysinternals\MainPrograms\Bginfo64.exe

                        # Manual Log
                        "[" + (Get-CurrentTime) + "] $curuser Ran Bginfo64" >> $manLog

                    }

                    # Cacheset
                    if ($which -eq "3") {

                        & .\Software\Sysinternals\MainPrograms\Cacheset64.exe

                        # Manual Log
                        "[" + (Get-CurrentTime) + "] $curuser Ran Cacheset64" >> $manLog

                    }

                    # Portmon
                    if ($which -eq "4") {

                        & .\Software\Sysinternals\MainPrograms\portmon.exe
                        
                        # Manual Log
                        "[" + (Get-CurrentTime) + "] $curuser Ran Portmon" >> $manLog
                    
                    }

                    # Procmon
                    if ($which -eq "5") {

                        & .\Software\Sysinternals\MainPrograms\Procmon64.exe

                        # Manual Log
                        "[" + (Get-CurrentTime) + "] $curuser Ran Procmon64" >> $manLog
                    
                    }
                    
                    # TcpView
                    if ($which -eq "6") {

                        & .\Software\Sysinternals\MainPrograms\tcpview64.exe

                        # Manual Log
                        "[" + (Get-CurrentTime) + "] $curuser Ran Tcpview64" >> $manLog

                    }

                    # Exit
                    if ($which -eq "7") {

                        # Manual Log
                        "[" + (Get-CurrentTime) + "] $curuser Exited Sysinternals Program" >> $manLog
                        break

                    }

                }
                catch {
                    WriteErrorLog -ErrorRecord $_
                }
            }
        }

        # Manually running each script individually
        elseif ($choice -eq "6" -and $global:advanceView) {

            # Manual Log
            "[" + (Get-CurrentTime) + "] $curuser Entered Run Scripts" >> $manLog
            
            while ($true) {

                # This is because the amount of errors that come from auto modes
                $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Continue

                ScreenClear
                
                $op = BuildSubOptionFrame(" 1) Run Auto2.bat `n 2) Run Auto1.ps1 `n 3) Run  `n 4) Run `n 5) Run  `n 6) Run `n 7) Exit")
    
                # Auto2
                if ($op -eq "1") {

                    & .\Auto\Auto2.bat

                    # Manual Log
                    "[" + (Get-CurrentTime) + "] $curuser Ran Auto2.bat" >> $manLog
        
                }

                # Auto1
                if ($op -eq "2") {

                    & .\Auto\Auto1.ps1

                    # Manual Log
                    "[" + (Get-CurrentTime) + "] $curuser Ran Auto1.ps1" >> $manLog
        
                }

      

    

                # Exit
                if ($op -eq "7") {
                    
                    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Inquire

                    # Manual Log
                    "[" + (Get-CurrentTime) + "] $curuser Exited Run Scripts" >> $manLog
                    break
        
                }
            }
        }

        # Enable/Disable
        elseif ($choice -eq "7" -and $global:advanceView) {

            "[" + (Get-CurrentTime) + "] $curuser Entered Enable/Disable" >> $manLog

            while ($True) {

                ScreenClear

                $choice = BuildSubOptionFrame(" 1) Guest Account [1E/1D] `n 2) Fire Wall [2E/2D] `n 3) Linked Connections [3E/3D] `n 4) UAC [4E/4D] `n 5) FTP Service [5E/5D] `n 6) Exit")

                try{

                    # Enable Guest account
                    if ($choice -eq "1E") {

                        ScreenClear
                        Write-Host "Enabling Guest account..." -ForegroundColor Magenta
                        Start-Sleep $shortSleep
                        Enable-LocalUser -Name "Guest"

                        # Adds to the manual log
                        "[" + (Get-CurrentTime) + "] $curuser Enabled Guest account" >> $manLog

                    }

                    # Disable Guest account
                    if ($choice -eq "1D") {

                        ScreenClear
                        Write-Host "Disabling Guest account..." -ForegroundColor Magenta
                        Start-Sleep $shortSleep
                        Disable-LocalUser -Name "Guest"

                        # Adds to the manual log
                        "[" + (Get-CurrentTime) + "] $curuser Disabled Guest account" >> $manLog

                    }

                    # Enable Firewall
                    if ($choice -eq "2E") {

                        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

                        # Adds to the manual log
                        "[" + (Get-CurrentTime) + "] $curuser Enabled Firewall" >> $manLog

                    }

                    # Disable Fire Wall
                    if ($choice -eq "2D") {

                        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False

                        # Adds to the manual log
                        "[" + (Get-CurrentTime) + "] $curuser Disabled Firewall" >> $manLog

                    }

                    # Enable Linked Connections
                    if ($choice -eq "3E") {

                        New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLinkedConnections -Value 1
                        
                        # Adds to the manual log
                        "[" + (Get-CurrentTime) + "] $curuser Enabled Linked connections" >> $manLog
                        
                    }

                    # Disable Linked Connections
                    if ($choice -eq "3D") {

                        New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLinkedConnections -Value 0
                        
                        # Adds to the manual log
                        "[" + (Get-CurrentTime) + "] $curuser Disabled Linked Connections" >> $manLog

                    }

                    # Enabled UAC
                    if ($choice -eq "4E") {

                        Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 5
                        
                        # Adds to the manual log
                        "[" + (Get-CurrentTime) + "] $curuser Set UAC to Enable" >> $manLog

                    }

                    # Disable UAC
                    if ($choice -eq "4D") {

                        Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0

                        # Adds to the manual log
                        "[" + (Get-CurrentTime) + "] $curuser Set UAC to Disable" >> $manLog

                    }

                    # Enable FTP
                    if ($choice -eq "5E") {

                        Start-Service -Name "FTPSVC"
                        Set-Service -Name "FTPSVC" -StartupType Enabled
                        
                        # Adds to the manual log
                        "[" + (Get-CurrentTime) + "] $curuser Enabled FTP and StartupType is set to Enabled" >> $manLog
        
                    }

                    # Disable  FTP
                    if ($choice -eq "5D") {

                        # Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-FTP-Server
                        Stop-Service -Name "FTPSVC"
                        Set-Service -Name "FTPSVC" -StartupType Disabled

                        "[" + (Get-CurrentTime) + "] $curuser Disabled FTP and StartupType is set to Disabled" >> $manLog
                
                    }

                    # Exit
                    if ($choice -eq "6") {

                        "[" + (Get-CurrentTime) + "] $curuser Exited Enable/Disable" >> $manLog
                        Break

                    }
                }
                catch{
                    WriteErrorLog -ErrorRecord $_
                }
            }
        }

        # Lets you run some terminal commands that ya won't need to remember
        elseif (($choice -eq "8" -and $global:advanceView) -or ($choice -eq "4" -and -not ($global:advanceView))) {

            "[" + (Get-CurrentTime) + "] $curuser Entered Run terminal commands" >> $manLog

            While ($true) {

                ScreenClear

                $choice = BuildSubOptionFrame(" 1) Registry Editor `n 2) Device Manager `n 3) Task Manager `n 4) System Configuration `n 5) DirectX Diagnostic `n 6) Firewall Settings `n 7) Computer Management `n 8) Services `n 9) Event Viewer `n 10) System Information `n 11) Group Edit `n 12) Local Security Policy `n 13) Local Group Policy `n 14) Microsoft Paint `n 15) Exit")

                try{

                    # Registry Editor
                    if ($choice -eq "1") {

                        "[" + (Get-CurrentTime) + "] $curuser Opened Registry Editor" >> $manLog
                        Start-Process regedit

                    }

                    # Device Manager
                    elseif ($choice -eq "2") {

                        "[" + (Get-CurrentTime) + "] $curuser Opened Device Manager" >> $manLog
                        Start-Process devmgmt.msc

                    }

                    # Task Manager
                    elseif ($choice -eq "3") {

                        "[" + (Get-CurrentTime) + "] $curuser Opened Task Manager" >> $manLog
                        Start-Process taskmgr

                    }

                    # System Configuration
                    elseif ($choice -eq "4") {

                        "[" + (Get-CurrentTime) + "] $curuser Opened System Configuration" >> $manLog
                        Start-Process msconfig

                    }

                    # DirectX Diagnostic
                    elseif ($choice -eq "5") {

                        "[" + (Get-CurrentTime) + "] $curuser Opened DirectX Diagnostic" >> $manLog
                        Start-Process dxdiag

                    }

                    # Firewall Settings
                    elseif ($choice -eq "6") {

                        "[" + (Get-CurrentTime) + "] $curuser Opened Firewall Settings" >> $manLog
                        Start-Process wf.msc

                    }

                    # Computer Management
                    elseif ($choice -eq "7") {

                        "[" + (Get-CurrentTime) + "] $curuser Opened Computer Management" >> $manLog
                        Start-Process compmgmt.msc

                    }

                    # Services
                    elseif ($choice -eq "8") {

                        "[" + (Get-CurrentTime) + "] $curuser Opened Services" >> $manLog
                        Start-Process services.msc

                    }

                    # Event Viewer
                    elseif ($choice -eq "9") {

                        "[" + (Get-CurrentTime) + "] $curuser Opened Event Viewer" >> $manLog
                        Start-Process eventvwr

                    }

                    # System Information
                    elseif ($choice -eq "10") {

                        "[" + (Get-CurrentTime) + "] $curuser Opened System Information" >> $manLog
                        Start-Process msinfo32

                    }

                    # Group Edit
                    elseif ($choice -eq "11") {

                        if (IsHome){
                            BuildSubTerminalText -Text  "On Windows Home, Local Users and Groups not Available in sub terminal" 
                        }

                        else{

                            "[" + (Get-CurrentTime) + "] $curuser Opened Group Edit" >> $manLog
                            Start-Process lusrmgr.msc

                        }
                    }

                    # Local Security Policy
                    elseif ($choice -eq "12") {

                        if (IsHome){
                            BuildSubTerminalText -Text  "On Windows Home, Local Security Policy not Available" 
                        }
                        
                        else{

                            "[" + (Get-CurrentTime) + "] $curuser Opened Local Security Policy" >> $manLog
                            Start-Process secpol.msc

                        }
                    }

                    # Local Group Policy 
                    elseif ($choice -eq "13") {
                        
                        # This is a check to see if the system is a home version
                        if (IsHome){
                            BuildSubTerminalText -Text  "On Windows Home, Local Group Policy not Available"
                        }

                        else{

                            "[" + (Get-CurrentTime) + "] $curuser Opened Local Group Policy" >> $manLog
                            Start-Process gpedit.msc

                        }
                    }

                    # Microsoft Paint
                    elseif ($choice -eq "14") {

                        "[" + (Get-CurrentTime) + "] $curuser Opened Microsoft Paint" >> $manLog
                        Start-Process mspaint

                    }

                    # Exit
                    elseif ($choice -eq "15") {

                        "[" + (Get-CurrentTime) + "] $curuser Exited" >> $manLog
                        break

                    }
                }
                catch{
                    WriteErrorLog -ErrorRecord $_
                }
            }
        }

        # Opens File Finder
        elseif (($choice -eq "9" -and $global:advanceView) -or ($choice -eq "5" -and -not ($global:advanceView))){

            "[" + (Get-CurrentTime) + "] $curuser Entered File Finder" >> $manLog

            ScreenClear

            # Options for File Finder
            while($true){

                ScreenClear

                # Sets the menu choices, only shows certain menus
                if (Test-Path -Path $global:fileScanOutput){
                    
                    $subChoice = BuildSubOptionFrame(" 1) Run Important File Scan `n 2) Run Whole File Scan `n 3) Scan Custom Directory `n 4) Show Banned Files `n 5) Show Difference Files `n 6) Show All Files `n 7) Exit")
                    $scanned = $true
                    
                }
                
                else{
                
                    $subChoice = BuildSubOptionFrame(" 1) Run Important File Scan `n 2) Run Whole File Scan `n 3) Scan Custom Directory `n 4) Exit")
                    $scanned = $false
                
                }

                try{

                    # Scan of just the important stuff
                    if ($subChoice -eq "1"){

                        "[" + (Get-CurrentTime) + "] Initiated Important File Search" >> $manLog
                        ImportantScan
                        "[" + (Get-CurrentTime) + "] Important File Search END" >> $manLog

                    }

                    # Full Search of Computer
                    if ($subChoice -eq "2"){
                        if (2FA -Message "Are you Sure you want to run a full SYSTEM WIDE SEARCH? This will take a while"){

                            "[" + (Get-CurrentTime) + "] Initiated Full Search" >> $manLog
                            FindAndHighlightFiles -directory "/" -highlightedFiles (Get-Content -Path "./Data/FileFinder/BannedFiles.txt") -ClearFile $true
                            "[" + (Get-CurrentTime) + "] Fill Search END" >> $manLog

                        }
                    }

                    # Scans A CustomDirectory and updates the found files
                    if ($subChoice -eq "3"){

                        $choice = Read-Host -Prompt "Directory Path"
                        "[" + (Get-CurrentTime) + "] Scanned Custom Directory '$choice'" >> $manLog
                        FindAndHighlightFiles -directory $choice -outputFile "./Logs/FileOutput.txt" -highlightedFiles (Get-Content -Path "./Data/FileFinder/BannedFiles.txt") -ClearFile $true
                        "[" + (Get-CurrentTime) + "] Scanned Custom Directory '$choice' END" >> $manLog

                    }

                    # Shows the Banned Files
                    if ($subChoice -eq "4" -and $scanned){

                        "[" + (Get-CurrentTime) + "] Shown Banned Files" >> $manLog
                        ShowBannedFiles
                        Read-Host "Press Enter to Continue"

                    }

                    # Shows the Difference Files
                    if ($subChoice -eq "5" -and $scanned){

                        "[" + (Get-CurrentTime) + "] Shown Difference Files" >> $manLog
                        ShowDifferenceFiles
                        Read-Host "Press Enter to Continue"

                    }

                    # Shows all Files
                    if ($subChoice -eq "6" -and $scanned){

                        "[" + (Get-CurrentTime) + "] Shown All Files" >> $manLog
                        ShowFoundFiles
                        Read-Host "Press Enter to Continue"

                    }

                    # Exits
                    if ($subChoice -eq "7" -or ($subChoice -eq "4" -and -not $scanned)){

                        "[" + (Get-CurrentTime) + "] $curuser Exited File Finder" >> $manLog
                        Break

                    }
                }

                catch{
                    WriteErrorLog -ErrorRecord $_
                }
            }
        }

        # Lets you run Auto
        elseif (($choice -eq "10" -and $global:advanceView) -or ($choice -eq "6" -and -not ($global:advanceView))){

            if ((2FA -Message "Are you sure you want to run Auto?")){

                "[" + (Get-CurrentTime) + "] $curuser is manually running Auto" >> $manLog
                RunAuto
                "[" + (Get-CurrentTime) + "] Auto has finished, returned back to manual mode" >> $manLog
    
            }
            else{
                "[" + (Get-CurrentTime) + "] Declined 2FA" >> $manLog
            }
        }

        # Swaps the view of the terminal
        elseif (($choice -eq "11" -and $global:advanceView) -or ($choice -eq "7" -and -not ($global:advanceView))) {

            $global:advanceView = !$global:advanceView
            ScreenClear

        }

        # The code to exit program
        elseif (($choice -eq "12" -and $global:advanceView) -or ($choice -eq "8" -and -not ($global:advanceView))) {


            "[" + (Get-CurrentTime) + "] Number of Errors Occurred: $numberError" >> $manLog

            if ($numberError -eq 0) {

                "[" + (Get-CurrentTime) + "] Congrats $curuser, you made no errors happen" >> $manLog
            
            }
            elseif ($numberError -gt 10) {

                "[" + (Get-CurrentTime) + "] WOW, $curuser, you made $numberError errors happen throughout this script" >> $manLog

            }

            "[" + (Get-CurrentTime) + "] $curuser Thinks their done with the IRSec... (END of manual mode log)" >> $manLog
            break

        }
    }
}
