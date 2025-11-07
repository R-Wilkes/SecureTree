# ---------------------------
# SecureTree
# For the IRSec competitions
# Created by Ricker Wilkes
# Daughter Script of the CyberPatriot Script
# Master Repository: https://github.com/R-Wilkes/SecureTree
# ---------------------------

# NOTE: Its gonna be a lot of copy paste from parent repo

# NOTE: the | AI at top of code and such means that AI was used to create it
# NOTE: Not like Fully copy paste, I still edit it to my liking and such

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

# Wallpaper stuff :)
Import-Module -Name "./Data/FileShare/FileShare" -Force

# Set the terminal screen size to 138 columns and 36 rows
[System.Console]::WindowWidth = 138
[System.Console]::WindowHeight = 36

# Hides the Cursor
[Console]::CursorVisible = $false

# I had 2 places in which the auto runs
function RunAuto(){

    # Get the file properties
    $UAL = Get-Item -Path ".\UserLists\Local_Admins.txt"
    $UL = Get-Item -Path ".\UserLists\Local_Users.txt"

    # Will remind you to fill out the auto
    if (($UAL.Length -eq 0 -or $UL.Length -eq 0)) {

        Write-Host "Local Users or Local admins list not filled out"
        Write-Host "Press anything to continue once you do that"
        Start-Sleep $shortSleep 
        GetKeyInput | Out-Null 
        ScreenClear

    }

    # Checks for the domain users
    # Get the file properties
    $UAL = Get-Item -Path ".\UserLists\Domain_Admins.txt"
    $UL = Get-Item -Path ".\UserLists\Domain_Users.txt"

    # Will remind you to fill out the auto
    if (($UAL.Length -eq 0 -or $UL.Length -eq 0)) {

        Write-Host "Domain users or Domain admins list not filled out"
        Write-Host "Press anything to continue once you do that"
        Start-Sleep $shortSleep 
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
$global:version = "1.0"
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

$global:rootPath = "$PSScriptRoot"

# Messing with environment variables, sessions specific, not user
$env:SecureTree_Version = $version
$env:SecureTree_CurUser = $curuser
$env:SecureTree_ComputerName = $computerName
$env:SecureTree_RootPath = $rootPath

# Pretend you don't see this red team :)
$global:scriptDefaultPassword = ConvertTo-SecureString "ChangeMe42069" -AsPlainText -Force # Maybe want to obscure this, cause if red-team gets ahold of this script im cooked

# -----------------------------------------


# Most of just the simple variables and code that are needed for the script to even start up
# -------------------------------------------------------------------

# NOTE: I confined all the variables and run checks into the LoadingScreen, so its kind of needed to run
# Does the loading screen, and all checks to make sure everything is good to go

LoadingScreen

ScreenClear

ConfirmInfo

ScreenClear

ShowDisabled

ScreenClear

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
    $domainControllerTries = 0

    LogHeader -Name "SecureTree Manual Log" -Path $manLog

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

        # Edits Local/Domain users
        if ($choice -eq "1") {

            "[" + (Get-CurrentTime) + "] $curuser is deciding between local and domain users" >> $manLog

            While ($true){

                $optionOneText = if (IsDC) {"Edit Remote Local Users"} else {"Edit Local Users"} 

                $choice = BuildSubOptionFrame(" 1) $optionOneText `n 2) Edit Domain Users `n 3) Exit")

                # Edits local or remote users
                if ($choice -eq "1"){
                    
                    # Edit local users
                    if (-not (IsDC)){

                        "[" + (Get-CurrentTime) + "] $curuser Entered Local User Configuration" >> $manLog

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
                    
                                    $b = (((Get-LocalGroupMember -Group "Administrators").name).Replace("$computerName", "")).Replace("\" , "").Replace("NT AUTHORITY", "").Replace("$($computerName.ToUpper())", "")
                                    $a = (((Get-LocalGroupMember -Group "Users").name).Replace("$computerName", "")).Replace("\" , "").Replace("NT AUTHORITY", "").Replace("$($computerName.ToUpper())", "")
                                    
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

                                                $checkedPass = CheckPasswordDefault -TestPass $password

                                                if ($checkedPass -is [System.Object[]] -and $checkedPass.Count -gt 0) {
                                                    # AHHH, IDK WHY IT NEEDS THIS, JUST TRUST
                                                    $checkedPass = $checkedPass | Where-Object { $_ -is [System.Security.SecureString] } | Select-Object -First 1                                                            
                                                }

                                                if ($null -ne $checkedPass){

                                                    Set-LocalUser "$who" -Password $checkedPass 

                                                    # Does NOT show the password, that would be insecure and not safe
                                                    "[" + (Get-CurrentTime) + "] $curuser Changed Password for User $who" >> $manLog

                                                }
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

                                        $checkedPass = CheckPasswordDefault -TestPass $NewUserPassword

                                        if ($checkedPass -is [System.Object[]] -and $checkedPass.Count -gt 0) {
                                            #  AHHH, IDK WHY IT NEEDS THIS, JUST TRUST
                                            $checkedPass = $checkedPass | Where-Object { $_ -is [System.Security.SecureString] } | Select-Object -First 1
                                        }

                                        if ($null -ne $checkedPass){
                                        

                                            New-LocalUser "$NewUserName" -Password $checkedPass -FullName $NewUserName | Out-Null
                                            Add-LocalGroupMember -Group "Users" -Member "$NewUserName" | Out-Null
                            
                                            # Adds to the manual log
                                            "[" + (Get-CurrentTime) + "] $curuser Added new User $NewUserName to Local Group Users" >> $manLog
                                        
                                        }
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

                    # Remote Editing local users | AI
                    elseif (IsDC){

                        # BTW this code here is terrible, but it works

                        "[" + (Get-CurrentTime) + "] $curuser Entered Remote Local User Configuration" >> $manLog

                        :remoteUserEdit while ($true){

                            # Select target computer first
                            try {
                                $domainComputers = Get-ADComputer -Filter * | Where-Object { $_.Name -ne $env:COMPUTERNAME } | Select-Object -ExpandProperty Name
                            } catch {
                                BuildSubTerminalText -Text "Failed to query domain computers"
                                WriteErrorLog -ErrorRecord $_
                                continue
                            }

                            if (-not $domainComputers -or $domainComputers.Count -eq 0) {
                                BuildSubTerminalText -Text "No domain computers found"
                                continue
                            }

                            $computerString = FormatArrayToString -Array $domainComputers
                            $computerChoice = BuildSubOptionFrame($computerString)

                            # Exit if user chose to cancel
                            if ($computerChoice -eq ($domainComputers.Length + 1)) {
                                "[" + (Get-CurrentTime) + "] $curuser is done editing users" >> $manLog
                                break remoteUserEdit
                            }

                            $selectedComputer = $domainComputers[$computerChoice - 1]
                            
                            # Test connectivity first
                            if (-not (Test-Connection -ComputerName $selectedComputer -Count 1 -Quiet)) {
                                BuildSubTerminalText -Text "Cannot reach computer: $selectedComputer"
                                continue
                            }

                            "[" + (Get-CurrentTime) + "] $curuser Selected target computer: $selectedComputer" >> $manLog

                            # Remote local user management menu
                            While ($True) {

                                ScreenClear
                                Write-Progress -Activity "Remote Local User Management" -Status "Target: $selectedComputer"
                                
                                $editInput = BuildSubOptionFrame(" 1) Edit Users `n 2) Add Users `n 3) Change Target Computer `n 4) Exit")
                            
                                # Edit Remote Users
                                if ($editInput -eq "1") {

                                    "[" + (Get-CurrentTime) + "] $curuser Entered Remote User Edit Mode on $selectedComputer" >> $manLog

                                    :editUsers While ($True) {

                                        ScreenClear

                                        try {
                                            # Get remote local users via Invoke-Command
                                            $remoteUsers = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                $adminUsers = (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Name | ForEach-Object { $_.Split('\')[-1] } | Where-Object { $_ -notmatch "^(NT AUTHORITY|BUILTIN)" }
                                                $standardUsers = (Get-LocalGroupMember -Group "Users" -ErrorAction SilentlyContinue).Name | ForEach-Object { $_.Split('\')[-1] } | Where-Object { $_ -notmatch "^(NT AUTHORITY|BUILTIN)" }
                                                return ($adminUsers + $standardUsers) | Sort-Object | Get-Unique
                                            } -ErrorAction Stop

                                            if (-not $remoteUsers) {
                                                BuildSubTerminalText -Text "No local users found on $selectedComputer"
                                                break editUsers
                                            }

                                        } catch {
                                            BuildSubTerminalText -Text "Failed to connect to $selectedComputer or retrieve users"
                                            WriteErrorLog -ErrorRecord $_
                                            break editUsers
                                        }

                                        # Turn the array into string for menu
                                        $userString = FormatArrayToString -Array $remoteUsers

                                        # Choose the user to edit
                                        $userInput = BuildSubOptionFrame($userString)

                                        # Exit option
                                        if ($userInput -eq ($remoteUsers.Length + 1)){
                                            "[" + (Get-CurrentTime) + "] $curuser Exited Remote User Edit Mode" >> $manLog
                                            break 
                                        }

                                        $who = $remoteUsers[$userInput - 1]

                                        # The options for the remote user
                                        While ($True) {

                                            ScreenClear

                                            try {
                                                # Check if user is admin on remote machine
                                                $isAdmin = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                    param($username)
                                                    $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
                                                    return ($adminMembers.Name | ForEach-Object { $_.Split('\')[-1] }) -contains $username
                                                } -ArgumentList $who -ErrorAction Stop

                                            } catch {
                                                $isAdmin = $false
                                            }
                                        
                                            if (-not $isAdmin){
                                                $option3 = "Swap $who Perms to Admin"
                                            } else {
                                                $option3 = "Swap $who Perms to Standard User"
                                            }

                                            Write-Progress -Activity "Editing Remote User" -Status "Target: $selectedComputer | User: $who | Permissions: $(if ($isAdmin){"Admin"}else{"Standard"})"

                                            # Give options for remote user management
                                            $what = BuildSubOptionFrame(" 1) Rename $who `n 2) Change $who Password `n 3) $option3 `n 4) Delete $who `n 5) Change Current Edit User `n 6) Exit User Configuration")
                                    
                                            try {
                                                
                                                # Rename User
                                                if ($what -eq "1") {

                                                    ScreenClear
                                                    $newName = CenterText -Text "Renaming $who on $selectedComputer" -PromptString "New Name"
                                                    
                                                    Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                        param($oldName, $newName)
                                                        Rename-LocalUser -Name $oldName -NewName $newName
                                                    } -ArgumentList $who, $newName -ErrorAction Stop

                                                    Write-Host "Changed name of $who to $newName on $selectedComputer" -ForegroundColor Green
                                
                                                    "[" + (Get-CurrentTime) + "] $curuser Renamed Remote User $who to $newName on $selectedComputer" >> $manLog
                                                    $who = $newName
                            
                                                }
                                            
                                                # Change Password
                                                elseif ($what -eq "2") {

                                                    ScreenClear
                                                    $password = CenterText -Text "Changing Password for $who on $selectedComputer" -PromptString "New Password" -SecureString $true
                                                    
                                                    $checkedPass = CheckPasswordDefault -TestPass $password

                                                    if ($checkedPass -is [System.Object[]] -and $checkedPass.Count -gt 0) {
                                                        # AHHH, IDK WHY IT NEEDS THIS, JUST TRUST
                                                        $checkedPass = $checkedPass | Where-Object { $_ -is [System.Security.SecureString] } | Select-Object -First 1                                                              # Has to be third element idk why 
                                                    }
                                                    
                                                    if ($null -ne $checkedPass){

                                                        Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                            param($username, $checkedPass)
                                                            Set-LocalUser $username -Password $checkedPass
                                                        } -ArgumentList $who, $checkedPass -ErrorAction Stop

                                                        "[" + (Get-CurrentTime) + "] $curuser Changed Password for Remote User $who on $selectedComputer" >> $manLog
                                                        
                                                    }
                                                }
                                    
                                                # Change Permissions
                                                elseif ($what -eq "3") {

                                                    Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                        param($username, $isCurrentlyAdmin)
                                                        if (-not $isCurrentlyAdmin){
                                                            Add-LocalGroupMember -Group "Administrators" -Member $username
                                                            Remove-LocalGroupMember -Group "Users" -Member $username -ErrorAction SilentlyContinue
                                                        } else {
                                                            Remove-LocalGroupMember -Group "Administrators" -Member $username
                                                            Add-LocalGroupMember -Group "Users" -Member $username -ErrorAction SilentlyContinue
                                                        }
                                                    } -ArgumentList $who, $isAdmin -ErrorAction Stop

                                                    if (-not $isAdmin){
                                                        "[" + (Get-CurrentTime) + "] $curuser Changed Permissions of Remote User $who to Administrators on $selectedComputer" >> $manLog
                                                    } else {
                                                        "[" + (Get-CurrentTime) + "] $curuser Changed Permissions of Remote User $who to Standard on $selectedComputer" >> $manLog
                                                    }
                                                }
                                        
                                                # Delete User
                                                elseif ($what -eq "4") {

                                                    ScreenClear
                                                    $AREYOUSURE = 2FA -Message "Are you sure you want to delete $($who) on $selectedComputer?"

                                                    if ($AREYOUSURE -eq "Y") {

                                                        Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                            param($username)
                                                            Remove-LocalUser -Name $username
                                                        } -ArgumentList $who -ErrorAction Stop

                                                        "[" + (Get-CurrentTime) + "] $curuser Obliterated Remote User $who on $selectedComputer" >> $manLog
                                                        Write-Progress -Activity "Editing Remote User" -Completed
                                                        break 
                                            
                                                    } else {
                                                        "[" + (Get-CurrentTime) + "] $curuser Decided Not to Obliterate Remote User $who on $selectedComputer" >> $manLog
                                                    }
                                                }
                                        
                                                # Change Current Edit User
                                                elseif ($what -eq "5") {
                                        
                                                    "[" + (Get-CurrentTime) + "] $curuser Changed the remote user they were editing on $selectedComputer" >> $manLog
                                                    Write-Progress -Activity "Editing Remote User" -Completed
                                                    break
                                                }
                                        
                                                # Exit User Config
                                                elseif ($what -eq "6") {

                                                    "[" + (Get-CurrentTime) + "] $curuser Exited Remote User Configuration" >> $manLog
                                                    Write-Progress -Activity "Editing Remote User" -Completed
                                                    break editUsers
                                        
                                                } 
                                            }

                                            catch {
                                                WriteErrorLog -ErrorRecord $_
                                                BuildSubTerminalText -Text "Failed to perform action on remote computer"
                                            }
                                        }
                                    }
                                }
                                
                                # Add new remote user
                                elseif ($editInput -eq "2") {

                                    "[" + (Get-CurrentTime) + "] $curuser Entered Add Remote User Configuration on $selectedComputer" >> $manLog

                                    $NewUserName = CenterText -Text "Adding New User to $selectedComputer" -PromptString "New User Name"

                                    if ($NewUserName -eq "") {
                                        "[" + (Get-CurrentTime) + "] $curuser Did not provide name for New Remote User" >> $manLog
                                    } else {

                                        try{
                                            $NewUserPassword = CenterText -Text "Password for $NewUserName on $selectedComputer" -PromptString "Password" -SecureString $true
                                            
                                            $checkedPass = CheckPasswordDefault -TestPass $NewUserPassword

                                            if ($checkedPass -is [System.Object[]] -and $checkedPass.Count -gt 0) {
                                                # AHHH, IDK WHY IT NEEDS THIS, JUST TRUST
                                                $checkedPass = $checkedPass | Where-Object { $_ -is [System.Security.SecureString] } | Select-Object -First 1                                                            
                                            }

                                            if ($null -ne $checkedPass){

                                                Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                    param($username, $checkedPass, $fullname)
                                                    New-LocalUser $username -Password $checkedPass -FullName $fullname | Out-Null
                                                    Add-LocalGroupMember -Group "Users" -Member $username | Out-Null
                                                } -ArgumentList $NewUserName, $checkedPass, $NewUserName -ErrorAction Stop

                                                "[" + (Get-CurrentTime) + "] $curuser Added new Remote User $NewUserName to Local Group Users on $selectedComputer" >> $manLog
                                                Write-Host "Created user $NewUserName on $selectedComputer" -ForegroundColor Green
                                            }
                                        } catch {
                                            WriteErrorLog -ErrorRecord $_
                                            BuildSubTerminalText -Text "Failed to create user on remote computer"
                                        }
                                    }
                                }

                                # Change target computer
                                elseif ($editInput -eq "3") {
                                    "[" + (Get-CurrentTime) + "] $curuser Changing target computer from $selectedComputer" >> $manLog
                                    break
                                }

                                # Exit remote user configuration
                                elseif ($editInput -eq "4") {
                                    "[" + (Get-CurrentTime) + "] $curuser Exited Remote Local User Configuration" >> $manLog
                                    Write-Progress -Activity "Remote Local User Management" -Status "Target: $selectedComputer" -Completed
                                    break remoteUserEdit
                                }
                            }
                        }
                    }
                    
                    else{
                         
                        BuildSubTerminalText -Text "Not part of a domain or Not a domain controller"
                        "[" + (Get-CurrentTime) + "] $computerName is not part of a domain or on a domain controller" >> $manLog

                    }
                }
                
                # Active Directory User Configuration | AI
                if ($choice -eq "2") {

                    if ((IsAD) -and (IsDC)){

                        "[" + (Get-CurrentTime) + "] $curuser Entered AD User Configuration" >> $manLog

        
                        # Another menu that will allow you to edit users, edit groups, add users, add groups
                        While ($True) {

                            ScreenClear
                            
                            $editInput = BuildSubOptionFrame(" 1) Edit Domain Users `n 2) Edit Domain Groups `n 3) Add Domain Users `n 4) Add Domain Groups `n 5) Edit Organizational Units `n 6) Exit")
                        
                            # Edit Domain Users
                            if ($editInput -eq "1") {

                                # Adds to the manual log
                                "[" + (Get-CurrentTime) + "] $curuser Entered AD User Edit Mode" >> $manLog

                                :editUsers While ($True) {

                                    ScreenClear

                                    # Get domain users (limit to first 50 for performance)
                                    try {
                                        $domainUsers = Get-ADUser -Filter * -Properties MemberOf | Select-Object -First 50
                                        $userNames = $domainUsers | ForEach-Object { $_.SamAccountName }
                                    } catch {
                                        BuildSubTerminalText -Text "Failed to retrieve domain users"
                                        break editUsers
                                    }

                                    # Turns the array into the string that the BuildSubOptionFrame can work with
                                    $userString = FormatArrayToString -Array $userNames

                                    # Chooses the user you want to edit
                                    $userInput = BuildSubOptionFrame($userString)

                                    # Exit option
                                    if ($userInput -eq ($userNames.Length + 1)){
                                        "[" + (Get-CurrentTime) + "] $curuser Exited AD User Edit Mode" >> $manLog
                                        break 
                                    }

                                    $selectedUser = $domainUsers[$userInput - 1]
                                    $who = $selectedUser.SamAccountName

                                    # The options for the domain user
                                    While ($True) {

                                        ScreenClear

                                        # Check if user is Domain Admin
                                        $isDomainAdmin = $selectedUser.MemberOf | Where-Object { $_ -match "Domain Admins" }
                                    
                                        if (-not $isDomainAdmin){
                                            $option3 = "Add $who to Domain Admins"
                                        } else {
                                            $option3 = "Remove $who from Domain Admins"
                                        }

                                        # Refresh user to get Enabled property
                                        $isEnabled = (Get-ADUser -Identity $who -Properties Enabled).Enabled
                                        Write-Progress -Activity "Editing AD User" -Status "Editing User: $who | Domain Admin: $(if ($isDomainAdmin){"Yes"}else{"No"}) | Account: $(if ($isEnabled){"Enabled"}else{"Disabled"})"

                                        # Gives Options for domain user management
                                        $what = BuildSubOptionFrame(" 1) Reset $who Password `n 2) Set Password to Script Default `n 3) $option3 `n 4) Enable/Disable $who `n 5) Move $who to Different OU `n 6) Show $who Group Memberships `n 7) Add $who to Group `n 8) Remove $who from Group `n 9) Delete $who `n 10) Change Current Edit User `n 11) Exit User Configuration")
                                
                                        try {
                                            
                                            # Reset Password
                                            if ($what -eq "1") {

                                                while ($true){

                                                    ScreenClear
                                                    $newPassword = CenterText -Text "Resetting Password for $who" -PromptString "New Password" -SecureString $true

                                                    $checkedPass = CheckPasswordDefault -TestPass $newPassword

                                                    if ($checkedPass -is [System.Object[]] -and $checkedPass.Count -gt 0) {
                                                        # AHHH, IDK WHY IT NEEDS THIS, JUST TRUST
                                                        $checkedPass = $checkedPass | Where-Object { $_ -is [System.Security.SecureString] } | Select-Object -First 1                                                            
                                                    }

                                                    if ($null -ne $checkedPass){

                                                        Set-ADAccountPassword -Identity $who -NewPassword $checkedPass -Reset
                                                        Set-ADUser -Identity $who -ChangePasswordAtLogon $true
                                                        Write-Host "Password reset for $who" -ForegroundColor Green
                                                    
                                                        # Adds to the manual log
                                                        "[" + (Get-CurrentTime) + "] $curuser Reset Password for AD User $who" >> $manLog
                                                        $plainPassword = $null
                                                        break

                                                    }
                                                }
                                            }

                                            # Sets to script default
                                            elseif ($what -eq "2"){
                                                
                                                ScreenClear
                                                Set-ADAccountPassword -Identity $who -NewPassword  $global:scriptDefaultPassword
                                                Set-ADUser -Identity $who -ChangePasswordAtLogon $false
                                                Write-Host "Password set to script default for $who" -ForegroundColor Green

                                                # Adds to the manual log
                                                "[" + (Get-CurrentTime) + "] $curuser Set Password to Script Default for AD User $who" >> $manLog

                                            }
                                        
                                            # Change Domain Admin Status
                                            elseif ($what -eq "3") {

                                                if (-not $isDomainAdmin){
                                                    Add-ADGroupMember -Identity "Domain Admins" -Members $who
                                                    "[" + (Get-CurrentTime) + "] $curuser Added User $who to Domain Admins" >> $manLog
                                                } else {
                                                    Remove-ADGroupMember -Identity "Domain Admins" -Members $who -Confirm:$false
                                                    "[" + (Get-CurrentTime) + "] $curuser Removed User $who from Domain Admins" >> $manLog
                                                }
                                                
                                                # Refresh user object
                                                $selectedUser = Get-ADUser -Identity $who -Properties MemberOf
                                            }
                                    
                                            # Enable/Disable User
                                            elseif ($what -eq "4") {

                                                $currentStatus = (Get-ADUser -Identity $who).Enabled
                                                if ($currentStatus) {
                                                    Disable-ADAccount -Identity $who
                                                    "[" + (Get-CurrentTime) + "] $curuser Disabled AD User $who" >> $manLog
                                                    Write-Host "Disabled user $who" -ForegroundColor Yellow
                                                } else {
                                                    Enable-ADAccount -Identity $who
                                                    "[" + (Get-CurrentTime) + "] $curuser Enabled AD User $who" >> $manLog
                                                    Write-Host "Enabled user $who" -ForegroundColor Green
                                                }
                                            }

                                            # Move to Different OU
                                            elseif ($what -eq "5") {

                                                ScreenClear
                                                # Get available OUs
                                                $ous = Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName
                                                $ouNames = $ous | ForEach-Object { $_.Name }
                                                $ouString = FormatArrayToString -Array $ouNames

                                                $ouChoice = BuildSubOptionFrame($ouString)
                                                if ($ouChoice -le $ous.Length) {
                                                    $targetOU = $ous[$ouChoice - 1].DistinguishedName
                                                    Move-ADObject -Identity $selectedUser.DistinguishedName -TargetPath $targetOU
                                                    "[" + (Get-CurrentTime) + "] $curuser Moved User $who to OU $($ous[$ouChoice - 1].Name)" >> $manLog
                                                    Write-Host "Moved $who to $($ous[$ouChoice - 1].Name)" -ForegroundColor Green
                                                }
                                            }

                                            # Show Group Memberships
                                            elseif ($what -eq "6") {

                                                ScreenClear
                                                $groups = Get-ADUser -Identity $who -Properties MemberOf | Select-Object -ExpandProperty MemberOf
                                                if ($groups) {
                                                    $groupNames = $groups | ForEach-Object { (Get-ADGroup $_).Name }
                                                    Write-Host "Group memberships for $who :" -ForegroundColor Cyan
                                                    $groupNames | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
                                                } else {
                                                    Write-Host "$who is not a member of any groups" -ForegroundColor Yellow
                                                }
                                                "[" + (Get-CurrentTime) + "] $curuser Viewed Group Memberships for $who" >> $manLog
                                                Read-Host "Press Enter to continue"
                                            }

                                            # Add to Group
                                            elseif ($what -eq "7") {

                                                ScreenClear
                                                $availableGroups = Get-ADGroup -Filter * | Select-Object Name
                                                $groupNames = $availableGroups | ForEach-Object { $_.Name }
                                                $groupString = FormatArrayToString -Array $groupNames

                                                $groupChoice = BuildSubOptionFrame($groupString)
                                                if ($groupChoice -le $groupNames.Length) {
                                                    $targetGroup = $groupNames[$groupChoice - 1]
                                                    Add-ADGroupMember -Identity $targetGroup -Members $who
                                                    "[" + (Get-CurrentTime) + "] $curuser Added User $who to Group $targetGroup" >> $manLog
                                                    Write-Host "Added $who to $targetGroup" -ForegroundColor Green
                                                }
                                            }

                                            # Remove from Group
                                            elseif ($what -eq "8") {

                                                ScreenClear
                                                $userGroups = Get-ADUser -Identity $who -Properties MemberOf | Select-Object -ExpandProperty MemberOf
                                                if ($userGroups) {
                                                    $groupNames = $userGroups | ForEach-Object { (Get-ADGroup $_).Name }
                                                    $groupString = FormatArrayToString -Array $groupNames

                                                    $groupChoice = BuildSubOptionFrame($groupString)
                                                    if ($groupChoice -le $groupNames.Length) {
                                                        $targetGroup = $groupNames[$groupChoice - 1]
                                                        Remove-ADGroupMember -Identity $targetGroup -Members $who -Confirm:$false
                                                        "[" + (Get-CurrentTime) + "] $curuser Removed User $who from Group $targetGroup" >> $manLog
                                                        Write-Host "Removed $who from $targetGroup" -ForegroundColor Yellow
                                                    }
                                                } else {
                                                    BuildSubTerminalText -Text "$who is not a member of any groups"
                                                }
                                            }
                                    
                                            # Delete User
                                            elseif ($what -eq "9") {

                                                ScreenClear
                                                $AREYOUSURE = 2FA -Message "Are you sure you want to delete AD user $($who)?"

                                                if ($AREYOUSURE -eq "Y") {
                                                    Remove-ADUser -Identity $who -Confirm:$false
                                                    "[" + (Get-CurrentTime) + "] $curuser Deleted AD User $who" >> $manLog
                                                    Write-Progress -Activity "Editing AD User" -Completed
                                                    break 
                                                } else {
                                                    "[" + (Get-CurrentTime) + "] $curuser Decided Not to Delete AD User $who" >> $manLog
                                                }
                                            }
                                    
                                            # Change Current Edit User
                                            elseif ($what -eq "10") {
                                    
                                                "[" + (Get-CurrentTime) + "] $curuser Changed the AD user they were editing" >> $manLog
                                                Write-Progress -Activity "Editing AD User" -Completed
                                                break
                                            }
                                    
                                            # Exit User Config
                                            elseif ($what -eq "11") {

                                                "[" + (Get-CurrentTime) + "] $curuser Exited AD User Configuration" >> $manLog
                                                Write-Progress -Activity "Editing AD User" -Completed
                                                break editUsers
                                            } 
                                        }

                                        catch {
                                            WriteErrorLog -ErrorRecord $_
                                        }
                                    }
                                }
                            }

                            # TODO: Fix the sheer amount of groups
                            # Edit Domain Groups
                            elseif ($editInput -eq "2") {

                                "[" + (Get-CurrentTime) + "] $curuser Entered Edit Domain Group Configuration" >> $manLog

                                # try {
                                    $domainGroups = Get-ADGroup -Filter * | Select-Object Name
                                    $groupNames = $domainGroups | ForEach-Object { $_.Name }
                                    $groupString = FormatArrayToString -Array $groupNames

                                    $groupInput = BuildSubOptionFrame($groupString)

                                    if ($groupInput -eq ($groupNames.Length + 1)){
                                        "[" + (Get-CurrentTime) + "] $curuser Exited Edit Domain Group Configuration" >> $manLog
                                        continue 
                                    }

                                    $groupSelected = $groupNames[$groupInput - 1]

                                    While ($True) {

                                        ScreenClear

                                        # Get group members
                                        $groupMembers = Get-ADGroupMember -Identity $groupSelected | Select-Object Name
                                        $memberNames = if ($groupMembers) { $groupMembers | ForEach-Object { $_.Name } } else { @() }

                                        Write-Progress -Activity "Editing Domain Group" -Status "Editing Group: $groupSelected | Members: $(if ($memberNames.Count -eq 0) {"None"} else {$memberNames -join ', '})"
                                        $editGroup = BuildSubOptionFrame(" 1) Add User to Group `n 2) Remove User from Group `n 3) Delete Group `n 4) Exit")

                                        try{

                                            # Add user to group
                                            if ($editGroup -eq "1") {

                                                "[" + (Get-CurrentTime) + "] $curuser Entered Add User to Domain Group '$groupSelected'" >> $manLog

                                                # Get users not in this group
                                                $allUsers = Get-ADUser -Filter * | Select-Object SamAccountName
                                                $groupMemberSAMs = Get-ADGroupMember -Identity $groupSelected | Where-Object { $_.objectClass -eq "user" } | ForEach-Object { $_.SamAccountName }
                                                $availableUsers = $allUsers | Where-Object { $groupMemberSAMs -notcontains $_.SamAccountName }

                                                if ($availableUsers) {
                                                    $userNames = $availableUsers | ForEach-Object { $_.SamAccountName }
                                                    $userString = FormatArrayToString -Array $userNames

                                                    $userChoice = BuildSubOptionFrame($userString)
                                                    if ($userChoice -le $userNames.Length) {
                                                        $userToAdd = $userNames[$userChoice - 1]
                                                        Add-ADGroupMember -Identity $groupSelected -Members $userToAdd
                                                        "[" + (Get-CurrentTime) + "] $curuser Added User '$userToAdd' to Domain Group '$groupSelected'" >> $manLog
                                                        Write-Host "Added $userToAdd to $groupSelected" -ForegroundColor Green
                                                    }
                                                } else {
                                                    BuildSubTerminalText -Text "All users are already in this group"
                                                }
                                            }

                                            # Remove user from group
                                            if ($editGroup -eq "2") {

                                                "[" + (Get-CurrentTime) + "] $curuser Entered Remove User from Domain Group '$groupSelected'" >> $manLog
                                                
                                                $groupMembers = Get-ADGroupMember -Identity $groupSelected | Where-Object { $_.objectClass -eq "user" }
                                                
                                                if ($groupMembers) {
                                                    $memberNames = $groupMembers | ForEach-Object { $_.SamAccountName }
                                                    $memberString = FormatArrayToString -Array $memberNames

                                                    $memberChoice = BuildSubOptionFrame($memberString)
                                                    if ($memberChoice -le $memberNames.Length) {
                                                        $userToRemove = $memberNames[$memberChoice - 1]
                                                        Remove-ADGroupMember -Identity $groupSelected -Members $userToRemove -Confirm:$false
                                                        "[" + (Get-CurrentTime) + "] $curuser Removed User '$userToRemove' from Domain Group '$groupSelected'" >> $manLog
                                                        Write-Host "Removed $userToRemove from $groupSelected" -ForegroundColor Yellow
                                                    }
                                                } else {
                                                    BuildSubTerminalText -Text "No users in this group"
                                                }
                                            }

                                            # Delete group
                                            if ($editGroup -eq "3"){

                                                $AREYOUSURE = 2FA -Message "Are you sure you want to delete domain group $($groupSelected)?"

                                                if ($AREYOUSURE -eq "Y") {
                                                    Remove-ADGroup -Identity $groupSelected -Confirm:$false
                                                    "[" + (Get-CurrentTime) + "] $curuser Deleted Domain Group '$groupSelected'" >> $manLog
                                                    Write-Progress -Activity "Editing Domain Group" -Completed
                                                    break 
                                                } else {
                                                    "[" + (Get-CurrentTime) + "] $curuser Decided Not to Delete Domain Group '$groupSelected'" >> $manLog
                                                }
                                            }

                                            # Exit group editing
                                            if ($editGroup -eq "4") {
                                                "[" + (Get-CurrentTime) + "] $curuser Exited Edit Domain Group Configuration" >> $manLog
                                                Write-Progress -Activity "Editing Domain Group" -Completed
                                                break
                                            }
                                        }

                                        catch {
                                            WriteErrorLog -ErrorRecord $_
                                        }
                                    }

                                # } catch {
                                #     Read-Host $_
                                #     WriteErrorLog -ErrorRecord $_
                                # }
                            } 
                            
                            # Add new domain user
                            elseif ($editInput -eq "3") {

                                "[" + (Get-CurrentTime) + "] $curuser Entered Add Domain User Configuration" >> $manLog

                                try {
                                    $newUserName = CenterText -Text "Adding New Domain User `n Enter nothing to exit" -PromptString "New User Name"

                                    if ($newUserName -eq "") {
                                        "[" + (Get-CurrentTime) + "] $curuser Did not provide name for New Domain User" >> $manLog
                                    } 
                                    
                                    else {

                                        # Makes you enter a password required
                                        While ($true){

                                            $newUserPassword = CenterText -Text "Password for $newUserName" -PromptString "Password" -SecureString $true

                                            # Don't know if this is safe, but oh well
                                            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($newUserPassword)
                                            $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                                            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

                                            # In case you don't enter anything
                                            if ($plainPassword -eq "" -or $NewUserPassword -eq ""){

                                                $NewUserPassword =  $global:scriptDefaultPassword
                                                BuildSubTerminalText -Text "Setting password to script default"
                                                "[" + (Get-CurrentTime) + "] Setting password for $newUserName to script default" >> $manLog
                                                $plainPassword = $null
                                                break

                                            }

                                            # If it does not pass the password tests
                                            elseif (-not (PassesPasswordPolicy -TestPass $plainPassword)){

                                                BuildSubTerminalText -Text "Password does not meet password policy requirements"
                                                $plainPassword = $null 

                                            }

                                            else{

                                                $plainPassword = $null 
                                                break

                                            }
                                        }
                                        
                                        # Get default Users container or let user choose OU
                                        $defaultPath = "CN=Users," + (Get-ADDomain).DistinguishedName
                                        
                                        New-ADUser -SamAccountName $newUserName -Name $newUserName -DisplayName $newUserName -AccountPassword $newUserPassword -Path $defaultPath -Enabled $true
                                        
                                        "[" + (Get-CurrentTime) + "] $curuser Added new Domain User $newUserName" >> $manLog
                                        Write-Host "Created domain user $newUserName" -ForegroundColor Green
                                    }

                                } catch {
                                    WriteErrorLog -ErrorRecord $_
                                }
                            }

                            # Add new domain group
                            elseif ($editInput -eq "4") {

                                try {
                                    
                                    "[" + (Get-CurrentTime) + "] $curuser Entered Adding Domain Group Configuration" >> $manLog
                                    
                                    $groupName = CenterText -Text "Adding New Domain Group `n Enter nothing to exit " -PromptString "New Group Name"

                                    # If its empty
                                    if ($groupName -eq ""){
                                        "[" + (Get-CurrentTime) + "] $curuser Exited Domain Group Configuration" >> $manLog
                                    }

                                    else{

                                        $groupDescription = CenterText -Text "$groupName Description" -PromptString "Group Description"
                                        $groupScope = BuildSubOptionFrame(" 1) Global `n 2) Universal `n 3) DomainLocal")
                                        
                                        $scope = switch ($groupScope) {
                                            1 { "Global" }
                                            2 { "Universal" }
                                            3 { "DomainLocal" }
                                            default { "Global" }
                                        }
                                        
                                        $defaultPath = "CN=Users," + (Get-ADDomain).DistinguishedName
                                        New-ADGroup -Name $groupName -Description $groupDescription -GroupScope $scope -Path $defaultPath
                                        
                                        "[" + (Get-CurrentTime) + "] $curuser Added New Domain Group '$groupName' with scope '$scope'" >> $manLog
                                        Write-Host "Created domain group $groupName" -ForegroundColor Green

                                    }

                                } catch {
                                    WriteErrorLog -ErrorRecord $_
                                }
                            }

                            # Edit Organizational Units
                            elseif ($editInput -eq "5") {

                                "[" + (Get-CurrentTime) + "] $curuser Entered OU Management" >> $manLog

                                While ($True) {
                                    ScreenClear
                                    $ouChoice = BuildSubOptionFrame(" 1) Create New OU `n 2) Delete OU `n 3) Move Objects Between OUs `n 4) Exit")

                                    try {
                                        # Create new OU
                                        if ($ouChoice -eq "1") {
                                            $ouName = CenterText -Text "Creating New OU" -PromptString "OU Name"
                                            $ouDescription = CenterText -Text "OU Description" -PromptString "Description"
                                            
                                            # Get parent OU (default to domain root)
                                            $domainDN = (Get-ADDomain).DistinguishedName
                                            New-ADOrganizationalUnit -Name $ouName -Description $ouDescription -Path $domainDN
                                            
                                            "[" + (Get-CurrentTime) + "] $curuser Created OU '$ouName'" >> $manLog
                                            Write-Host "Created OU $ouName" -ForegroundColor Green
                                        }

                                        # Delete OU
                                        elseif ($ouChoice -eq "2") {
                                            $ous = Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName
                                            $ouNames = $ous | ForEach-Object { $_.Name }
                                            $ouString = FormatArrayToString -Array $ouNames

                                            $ouSelection = BuildSubOptionFrame($ouString)
                                            if ($ouSelection -le $ous.Length) {
                                                $targetOU = $ous[$ouSelection - 1]
                                                $AREYOUSURE = 2FA -Message "Are you sure you want to delete OU $($targetOU.Name)?"
                                                
                                                if ($AREYOUSURE -eq "Y") {
                                                    Remove-ADOrganizationalUnit -Identity $targetOU.DistinguishedName -Confirm:$false
                                                    "[" + (Get-CurrentTime) + "] $curuser Deleted OU '$($targetOU.Name)'" >> $manLog
                                                }
                                            }
                                        }

                                        # Exit OU management
                                        elseif ($ouChoice -eq "4") {
                                            "[" + (Get-CurrentTime) + "] $curuser Exited OU Management" >> $manLog
                                            break
                                        }
                                    } catch {
                                        WriteErrorLog -ErrorRecord $_
                                    }
                                }
                            }

                            # Exit AD configuration
                            elseif ($editInput -eq "6") {
                                "[" + (Get-CurrentTime) + "] $curuser Exited AD User Configuration" >> $manLog
                                break
                            }
                        }
                    }

                    else{

                        BuildSubTerminalText -Text "Not part of a domain or Not a domain controller"
                        "[" + (Get-CurrentTime) + "] $computerName is not part of a domain or on a domain controller" >> $manLog

                    }
                }

                # Exits
                if ($choice -eq "3"){

                    "[" + (Get-CurrentTime) + "] $curuser is done editing users" >> $manLog
                    break
                }
            }
        }

        # Stupid Note thing
        elseif ($choice -eq "2" -and $global:advanceView) {

            ScreenClear
            Write-Host "Don't blow up your machine"
            Write-Host "GPO are set from the Domain Controller, those will be manual set until I find a way to import them without giving my security audits away"
            Write-Host "Will have to manually update GPO on client machines using 'gpupdate'"
            Write-Host "Some registry Keys can not be set via Script, I don't know why, so you have to do it manually"
            Write-Host "Set SMB protocol to version 2, cause version 1 has Eternal blue vulnerability"
            Write-Host "`n `n `n `n"
            Write-Host "For GPO Advanced audit logging must override the setting:"
            Write-Host "Audit: Force audit policy subcategory setting (Windows Vista or later) to override audit policy category settings"
            Write-Host "Found in Policys/Windows Settings/Security Settings/Local Policys/Security Options"
            Write-Host "`n `n `n `n"
            Write-Host "Set up remote management for easy GPO updating: `n -------------------------------------"
            Write-Host "Enable-NetFirewallRule -DisplayGroup 'Remote Scheduled Tasks Management'"
            Write-Host "Start-Service -Name RemoteRegistry"
            Write-Host "Set-Service -Name RemoteRegistry -StartupType Automatic"
            Write-Host "`n"
            Write-Host "Also have to make sure your in the correct group on the local machine"
            Write-Host "net localgroup administrators 'JJM\Domain Admins' /add"
            Write-Host "Run that command on the machine you need to edit if you get an access is denied error"

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

            While ($True) {

                ScreenClear
                
                try{
                        
                    $which = BuildSubOptionFrame(" 1) Install Revo Uninstaller `n 2) Install Chrome `n 3) Install Firefox `n 4) Exit Installers")
            
                    # Revo Installer
                    if ($which -eq "1") {

                        # Revo Installer
                        & .\Software\Uninstallers\revosetup.exe

                        # Manual Log
                        "[" + (Get-CurrentTime) + "] $curuser Installed Revo Uninstaller" >> $manLog

                    }

                    # Chrome Installer
                    if ($which -eq "2") {

                        # CHromeInstaller
                        & .\Software\Browser\ChromeSetup.exe

                        # Manual Log
                        "[" + (Get-CurrentTime) + "] $curuser Installed Chrome" >> $manLog

                    }

                    # Firefox Installer
                    if ($which -eq "3") {

                        # Revo Installer
                        & ".\Software\Browser\Firefox Installer.exe"

                        # Manual Log
                        "[" + (Get-CurrentTime) + "] $curuser Installed Firefox" >> $manLog

                    }
                                                
                    # Exit
                    if ($which -eq "4") {

                        # Manual Log
                        "[" + (Get-CurrentTime) + "] $curuser Exited Install Programs Install" >> $manLog
                        break

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
                
                $op = BuildSubOptionFrame(" 1) Run AutoDiagnostics.ps1 `n 2) Run AutoFix.ps1 `n 3) Run Policys.ps1 `n 4) Run LoginMonitor.ps1 `n 5) Run SystemChangeMonitor.ps1 `n 6) Run AutoPassShuffle.ps1 `n 7) Exit")
    
                # AutoDiagnostics
                if ($op -eq "1") {

                    & .\Auto\AutoDiagnostics\AutoDiagnostics.ps1

                    # Manual Log
                    "[" + (Get-CurrentTime) + "] $curuser Ran AutoDiagnostics.ps1" >> $manLog
        
                }

                # AutoFix
                if ($op -eq "2") {

                    & .\Auto\AutoFix\AutoFix.ps1

                    # Manual Log
                    "[" + (Get-CurrentTime) + "] $curuser Ran AutoFix.ps1" >> $manLog
        
                }

                # Policys
                if ($op -eq "3") {

                    & .\Auto\AutoFix\Policys.ps1

                    # Manual Log
                    "[" + (Get-CurrentTime) + "] $curuser Ran Policys.ps1" >> $manLog
        
                }

                # LoginMonitoring
                if ($op -eq "4") {

                    if ((IsDC)){

                        Start-Process powershell -ArgumentList "-NoExit", "-File", ".\Auto\AutoDiagnostics\Monitoring\LoginMonitor.ps1"

                        # Manual Log
                        "[" + (Get-CurrentTime) + "] $curuser Ran LoginMonitor.ps1" >> $manLog
                    
                    }

                    else{
                        BuildSubTerminalText -Text "Not on a Domain Controller"
                    }
                }

                # SystemChangeMonitor
                if ($op -eq "5") {

                    if ((IsDC)){

                        Start-Process powershell -ArgumentList "-NoExit", "-File", ".\Auto\AutoDiagnostics\Monitoring\SystemChangeMonitor.ps1"

                        # Manual Log
                        "[" + (Get-CurrentTime) + "] $curuser Ran SystemChangeMonitor.ps1" >> $manLog

                    }

                    else{
                        BuildSubTerminalText -Text "Not on a Domain Controller"
                    }
                }

                # AutoPassShuffle
                if ($op -eq "6") {

                    if ((IsDC)){

                        Start-Process powershell -ArgumentList "-NoExit", "-File", ".\Auto\AutoFix\AutoPassShuffle.ps1"

                        # Manual Log
                        "[" + (Get-CurrentTime) + "] $curuser Ran AutoPassShuffle.ps1" >> $manLog

                    }

                    else{
                        BuildSubTerminalText -Text "Not on a Domain Controller"
                    }
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

                # Here temporary till I feel like fixing
                $Text = " 1) Guest Account [1E/1D] `n 2) Fire Wall [2E/2D] `n 3) Linked Connections [3E/3D] `n 4) UAC [4E/4D] `n 5) FTP Service [5E/5D] `n 6) Exit"
                BuildFrame -text $Text
                $choice = Read-Host "Input: "

                # $choice = BuildSubOptionFrame(" 1) Guest Account [1E/1D] `n 2) Fire Wall [2E/2D] `n 3) Linked Connections [3E/3D] `n 4) UAC [4E/4D] `n 5) FTP Service [5E/5D] `n 6) Exit")

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

                        elseif (IsDC){
                            BuildSubTerminalText -Text  "On a Domain Controller, Local Users and Groups not Available in sub terminal" 
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

        # Domain controller menu
        elseif (($choice -eq "11" -and $global:advanceView) -or ($choice -eq "7" -and -not ($global:advanceView))){

            if ((IsDC)){

                "[" + (Get-CurrentTime) + "] $curuser Entered DC Menu" >> $manLog
                
                While ($true){
                
                    $choice = BuildSubOptionFrame(" 1) Invoke GPO update `n 2) Wallpaper Settings `n 3) Terminals `n 4) Remote Commands `n 5) Exit")
                    
                    # invoke GPO update on selected computers | AI
                    if ($choice -eq "1"){

                        "[" + (Get-CurrentTime) + "] $curuser Entered DC GPO Invoke Menu" >> $manLog
                        ScreenClear

                        try {
                            $computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
                        }
                        catch {
                            BuildSubTerminalText -Text "Failed to query domain computers"
                            WriteErrorLog -ErrorRecord $_
                            continue
                        }

                        if (-not $computers -or $computers.Count -eq 0) {
                            BuildSubTerminalText -Text "No domain computers found"
                            continue
                        }

                        # Add convenience options
                        $menuArray = $computers + @("All Domain Computers")
                        $menuString = FormatArrayToString -Array $menuArray
                        $sel = BuildSubOptionFrame($menuString)

                        # Exit
                        if ($sel -eq ($menuArray.Length + 1)) {
                            # If user picked Cancel (last item), go back to DC menu
                            continue
                        }

                        # Determine targets
                        if ($sel -eq ($computers.Length + 1)) {
                            $targets = $computers
                        }
                        else {
                            $targets = @($computers[$sel - 1])
                        }

                        # Confirm before running
                        if (-not (2FA -Message "Run GPO update on $($targets.Count) computer(s)?")) {
                            "[" + (Get-CurrentTime) + "] Declined GPO Update" >> $manLog
                            continue
                        }

                        # Ensure GroupPolicy module is available
                        if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
                            try { Import-Module GroupPolicy -ErrorAction Stop } catch { WriteErrorLog -ErrorRecord $_; BuildSubTerminalText -Text "GroupPolicy module not available"; continue }
                        }

                        foreach ($t in $targets) {
                            try {
                                Invoke-GPUpdate -Computer $t -RandomDelayInMinutes 0 -Force -ErrorAction Stop
                                "[" + (Get-CurrentTime) + "] $curuser Invoked GPO Update on $t" >> $manLog
                            }
                            catch {
                                WriteErrorLog -ErrorRecord $_
                            }
                        }

                        BuildSubTerminalText -Text "GPO update initiated on selected computer(s)."
                    }

                    # Wallpaper Settings | AI
                    elseif ($choice -eq "2"){

                        "[" + (Get-CurrentTime) + "] $curuser Entered Wallpaper settings" >> $manLog


                        While ($true){

                            $choice = BuildSubOptionFrame(" 1) Initiate Wallpaper `n 2) Remove Wallpaper `n 3) Reset Wallpaper GPO `n 4) Test Wallpaper Share `n 5) Exit")

                            # Initiates the wallpaper
                            if ($choice -eq "1"){

                                if ((2FA -Message "Want to run Set Wallpaper (UNTESTED)")){

                                    "[" + (Get-CurrentTime) + "] $curuser Set wallpaper" >> $manLog

                                    Set-DomainWallpaperGPO
                                }
                            }

                            # Removes the wallpaper
                            if ($choice -eq "2"){
                                "[" + (Get-CurrentTime) + "] $curuser Removed Wallpaper settings" >> $manLog

                                Remove-DomainWallpaperGPO -ResetToDefault

                            }

                            # REmoves the wallpaper GPO
                            if ($choice -eq "3"){

                                "[" + (Get-CurrentTime) + "] $curuser Remove Wallpaper GPO" >> $manLog

                                Remove-WallpaperResetGPO

                            }

                            # Tests the wallpaper share
                            if ($choice -eq "4"){

                                "[" + (Get-CurrentTime) + "] $curuser Tested Wallpaper deployment" >> $manLog

                                Test-WallpaperDeployment

                            }

                            # Exits
                            if ($choice -eq "5"){

                                "[" + (Get-CurrentTime) + "] $curuser Exited Wallpaper settings" >> $manLog
                                break

                            }
                        }
                    }

                    # Useful domain controller terminals | AI
                    elseif ($choice -eq "3"){

                        "[" + (Get-CurrentTime) + "] $curuser Entered Domain Useful Terminals" >> $manLog

                        While ($true){
                        
                            $choice = BuildSubOptionFrame(" 1) AD Users and Groups `n 2) Remote Desktop Connections `n 3) Group Policy Editor `n 4) Exit")

                            # AD Users and groups
                            if ($choice -eq "1") {

                                "[" + (Get-CurrentTime) + "] $curuser Opened AD users and groups" >> $manLog
                                Start-Process dsa.msc

                            }

                            
                            # RDC
                            elseif ($choice -eq "2") {

                                "[" + (Get-CurrentTime) + "] $curuser Opened RDP" >> $manLog
                                Start-Process mstsc

                            }

                            
                            # Group Policy Editor
                            elseif ($choice -eq "3") {

                                "[" + (Get-CurrentTime) + "] $curuser Opened Group Policy Editor" >> $manLog
                                Start-Process gpedit.msc

                            }

                            # Exit
                            elseif ($choice -eq "4") {

                                "[" + (Get-CurrentTime) + "] $curuser Exited Domain Useful Terminals" >> $manLog
                                break

                            }
                        }
                    }

                    # Remote Command Execution on Domain Machines | AI
                    elseif ($choice -eq "4") {

                        "[" + (Get-CurrentTime) + "] $curuser Entered Remote Command Execution" >> $manLog

                        :remoteCommandEdit while ($true){

                            # Select target computer first
                            try {
                                $domainComputers = Get-ADComputer -Filter * | Where-Object { $_.Name -ne $env:COMPUTERNAME } | Select-Object -ExpandProperty Name
                            } catch {
                                BuildSubTerminalText -Text "Failed to query domain computers"
                                WriteErrorLog -ErrorRecord $_
                                continue
                            }

                            if (-not $domainComputers -or $domainComputers.Count -eq 0) {
                                BuildSubTerminalText -Text "No domain computers found"
                                continue
                            }

                            $computerString = FormatArrayToString -Array $domainComputers
                            $computerChoice = BuildSubOptionFrame($computerString)

                            # Exit if user chose to cancel
                            if ($computerChoice -eq ($domainComputers.Length + 1)) {
                                "[" + (Get-CurrentTime) + "] $curuser is done with remote commands" >> $manLog
                                break remoteCommandEdit
                            }

                            $selectedComputer = $domainComputers[$computerChoice - 1]
                            
                            # Test connectivity first
                            if (-not (Test-Connection -ComputerName $selectedComputer -Count 1 -Quiet)) {
                                BuildSubTerminalText -Text "Cannot reach computer: $selectedComputer"
                                continue
                            }

                            "[" + (Get-CurrentTime) + "] $curuser Selected target computer: $selectedComputer" >> $manLog

                            # Remote command execution menu
                            While ($True) {

                                ScreenClear
                                Write-Progress -Activity "Remote Command Execution" -Status "Target: $selectedComputer"
                                
                                $commandInput = BuildSubOptionFrame(" 1) Useful Commands `n 2) Security Commands `n 3) System Commands `n 4) Network Commands `n 5) Diagnostic Commands `n 6) Custom Command `n 7) Change Target Computer `n 8) Exit")
                            
                                # Useful commands
                                if ($commandInput -eq "1"){

                                    "[" + (Get-CurrentTime) + "] $curuser Entered Useful Commands on $selectedComputer" >> $manLog

                                    While ($True) {

                                        ScreenClear
                                        Write-Progress -Activity "Useful Commands" -Status "Target: $selectedComputer"
                                        
                                        $usefulChoice = BuildSubOptionFrame(" 1) Audit Services `n 2) Check Open Ports `n 3) System File Scan`n 4) Back to Main Menu")
                                        
                                        Write-Progress -Activity "Useful Commands" -Status "Target: $selectedComputer" -Completed
                                        try {
                                            
                                            # Audit Services
                                            if ($usefulChoice -eq "1") {

                                                ScreenClear
                                                Write-Host "Auditing Services on $selectedComputer..." -ForegroundColor Yellow
                                                
                                                $result = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                    try {
                                                        $suspiciousServices = Get-Service | Where-Object { 
                                                            $_.Status -eq "Running" -and 
                                                            ($_.Name -match "suspicious|backdoor|malware|trojan|red|team|redteam|steam" -or 
                                                            $_.DisplayName -match "suspicious|backdoor|malware|trojan|red|team|redteam|steam")
                                                        }
                                                        if ($suspiciousServices) {
                                                            return "WARNING: Found suspicious services: $($suspiciousServices.Name -join ', ')"
                                                        } else {
                                                            return "SUCCESS: No suspicious services found"
                                                        }
                                                    } catch {
                                                        return "ERROR: $($_.Exception.Message)"
                                                    }
                                                } -ErrorAction Stop

                                                if ($result -like "SUCCESS:*") {
                                                    Write-Host $result -ForegroundColor Green
                                                } elseif ($result -like "WARNING:*") {
                                                    Write-Host $result -ForegroundColor Yellow
                                                } else {
                                                    Write-Host $result -ForegroundColor Red
                                                }
                                                
                                                "[" + (Get-CurrentTime) + "] $curuser Audited Services on $selectedComputer - $result" >> $manLog
                                                Write-Host "Press Enter to continue"
                                                GetKeyInput -AllowedKeys "`r" -Return $false

                                            }
                                    
                                            # Check Open Ports
                                            elseif ($usefulChoice -eq "2") {

                                                ScreenClear
                                                Write-Host "Checking Open Ports on $selectedComputer..." -ForegroundColor Yellow
                                                
                                                $result = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                    try {
                                                        $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | Select-Object -First 20
                                                        $portProcessInfo = @()
                                                        
                                                        foreach ($conn in $connections) {
                                                            try {
                                                                $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                                                                $processName = if ($process) { $process.ProcessName } else { "Unknown" }
                                                                $portProcessInfo += "$($conn.LocalPort):$processName"
                                                            } catch {
                                                                $portProcessInfo += "$($conn.LocalPort):Unknown"
                                                            }
                                                        }
                                                        
                                                        $uniquePorts = $portProcessInfo | Sort-Object -Unique
                                                        return "SUCCESS: Open ports with processes (first 20): $($uniquePorts -join ', ')"
                                                    } catch {
                                                        return "ERROR: $($_.Exception.Message)"
                                                    }
                                                } -ErrorAction Stop

                                                if ($result -like "SUCCESS:*") {
                                                    Write-Host $result -ForegroundColor Green
                                                } else {
                                                    Write-Host $result -ForegroundColor Red
                                                }
                                                
                                                "[" + (Get-CurrentTime) + "] $curuser Checked Ports on $selectedComputer" >> $manLog
                                                Write-Host "Press Enter to continue"
                                                GetKeyInput -AllowedKeys "`r" -Return $false

                                            }

                                            # Run SFC Scan
                                            elseif ($usefulChoice -eq "3") {

                                                ScreenClear
                                                $AREYOUSURE = 2FA -Message "Are you sure you want to run SFC /scannow on $selectedComputer? This may take several minutes."

                                                if ($AREYOUSURE -eq "Y") {

                                                    Write-Host "Running SFC /scannow on $selectedComputer..." -ForegroundColor Yellow
                                                    Write-Host "This may take several minutes, please wait..." -ForegroundColor Cyan
                                                    
                                                    $result = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                        try {
                                                            # Run SFC scan and capture output
                                                            $sfcOutput = & sfc /scannow 2>&1
                                                            
                                                            # Check the output for common results
                                                            $outputString = $sfcOutput -join "`n"
                                                            
                                                            if ($outputString -match "Windows Resource Protection did not find any integrity violations") {
                                                                return "SUCCESS: SFC scan completed - No integrity violations found"
                                                            }
                                                            elseif ($outputString -match "Windows Resource Protection found corrupt files and successfully repaired them") {
                                                                return "SUCCESS: SFC scan completed - Found and repaired corrupt files"
                                                            }
                                                            elseif ($outputString -match "Windows Resource Protection found corrupt files but was unable to fix some of them") {
                                                                return "WARNING: SFC scan completed - Found corrupt files but unable to fix some"
                                                            }
                                                            elseif ($outputString -match "Windows Resource Protection could not perform the requested operation") {
                                                                return "ERROR: SFC scan failed - Could not perform operation (may need to run DISM first)"
                                                            }
                                                            else {
                                                                return "SUCCESS: SFC scan completed - $($outputString.substring(100))"
                                                            }
                                                        } catch {
                                                            return "ERROR: $($_.Exception.Message)"
                                                        }
                                                    } -ErrorAction Stop

                                                    if ($result -like "SUCCESS:*") {
                                                        Write-Host $result -ForegroundColor Green
                                                    } elseif ($result -like "WARNING:*") {
                                                        Write-Host $result -ForegroundColor Yellow
                                                    } else {
                                                        Write-Host $result -ForegroundColor Red
                                                    }
                                                    
                                                    "[" + (Get-CurrentTime) + "] $curuser Ran SFC scan on $selectedComputer - $result" >> $manLog
                                                    
                                                    Write-Host "`nSFC scan log location: C:\Windows\Logs\CBS\CBS.log" -ForegroundColor Cyan
                                                    Write-Host "Press Enter to continue"
                                                    GetKeyInput -AllowedKeys "`r" -Return $false

                                                } else {
                                                    "[" + (Get-CurrentTime) + "] $curuser Decided not to run SFC scan on $selectedComputer" >> $manLog
                                                }
                                            }

                                            # Back to Main Menu
                                            elseif ($usefulChoice -eq "4") {
                                                "[" + (Get-CurrentTime) + "] $curuser Exited Useful Commands" >> $manLog
                                                Write-Progress -Activity "Useful Commands" -Completed
                                                break
                                            } 
                                        }

                                        catch {
                                            WriteErrorLog -ErrorRecord $_
                                            BuildSubTerminalText -Text "Failed to execute security command on remote computer"
                                        }
                                    }
                                }

                                # Security Commands
                                elseif ($commandInput -eq "2") {

                                    "[" + (Get-CurrentTime) + "] $curuser Entered Security Commands on $selectedComputer" >> $manLog

                                    While ($True) {

                                        ScreenClear
                                        Write-Progress -Activity "Security Commands" -Status "Target: $selectedComputer"
                                        
                                        $securityChoice = BuildSubOptionFrame(" 1) Disable Guest Account `n 2) Enable Windows Firewall `n 3) Disable AutoRun `n 4) Set Password Policy `n 5) Check User Accounts `n 6) Back to Main Menu")
                                    
                                        Write-Progress -Activity "Security Commands" -Status "Target: $selectedComputer" -Completed

                                        try {
                                            
                                            # Disable Guest Account
                                            if ($securityChoice -eq "1") {

                                                ScreenClear
                                                Write-Host "Disabling Guest Account on $selectedComputer..." -ForegroundColor Yellow
                                                
                                                $result = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                    try {
                                                        Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
                                                        return "SUCCESS: Guest account disabled"
                                                    } catch {
                                                        return "ERROR: $($_.Exception.Message)"
                                                    }
                                                } -ErrorAction Stop

                                                if ($result -like "SUCCESS:*") {
                                                    Write-Host $result -ForegroundColor Green
                                                } else {
                                                    Write-Host $result -ForegroundColor Red
                                                }
                                                
                                                "[" + (Get-CurrentTime) + "] $curuser Disabled Guest Account on $selectedComputer - $result" >> $manLog
                                                Write-Host "Press Enter to continue"
                                                GetKeyInput -AllowedKeys "`r" -Return $false

                                            }
                                        
                                            # Enable Windows Firewall
                                            elseif ($securityChoice -eq "2") {

                                                ScreenClear
                                                Write-Host "Enabling Windows Firewall on $selectedComputer..." -ForegroundColor Yellow
                                                
                                                $result = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                    try {
                                                        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
                                                        return "SUCCESS: Windows Firewall enabled for all profiles"
                                                    } catch {
                                                        return "ERROR: $($_.Exception.Message)"
                                                    }
                                                } -ErrorAction Stop

                                                if ($result -like "SUCCESS:*") {
                                                    Write-Host $result -ForegroundColor Green
                                                } else {
                                                    Write-Host $result -ForegroundColor Red
                                                }
                                                
                                                "[" + (Get-CurrentTime) + "] $curuser Enabled Firewall on $selectedComputer - $result" >> $manLog
                                                Write-Host "Press Enter to continue"
                                                GetKeyInput -AllowedKeys "`r" -Return $false

                                            }
                                
                                            # Disable AutoRun
                                            elseif ($securityChoice -eq "3") {

                                                ScreenClear
                                                Write-Host "Disabling AutoRun on $selectedComputer..." -ForegroundColor Yellow
                                                
                                                $result = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                    try {
                                                        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
                                                        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
                                                        return "SUCCESS: AutoRun disabled for all drives"
                                                    } catch {
                                                        return "ERROR: $($_.Exception.Message)"
                                                    }
                                                } -ErrorAction Stop

                                                if ($result -like "SUCCESS:*") {
                                                    Write-Host $result -ForegroundColor Green
                                                } else {
                                                    Write-Host $result -ForegroundColor Red
                                                }
                                                
                                                "[" + (Get-CurrentTime) + "] $curuser Disabled AutoRun on $selectedComputer - $result" >> $manLog
                                                Write-Host "Press Enter to continue"
                                                GetKeyInput -AllowedKeys "`r" -Return $false

                                            }

                                            # Set Password Policy
                                            elseif ($securityChoice -eq "4") {

                                                ScreenClear
                                                Write-Host "Configuring Password Policy on $selectedComputer..." -ForegroundColor Yellow
                                                
                                                $result = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                    try {
                                                        # Placeholder password policy commands
                                                        net accounts /minpwlen:(Config("min_password_length")) | Out-Null
                                                        net accounts /maxpwage:(Config("max_password_age")) | Out-Null
                                                        net accounts /minpwage:(Config("min_password_age")) | Out-Null
                                                        net accounts /uniquepw:(Config("unique_password")) | Out-Null
                                                        net accounts /lockoutthreshold:(Config("lock_out_threshold")) | Out-Null
                                                        return "SUCCESS: Password policy configured"
                                                    } catch {
                                                        return "ERROR: $($_.Exception.Message)"
                                                    }
                                                } -ErrorAction Stop

                                                if ($result -like "SUCCESS:*") {
                                                    Write-Host $result -ForegroundColor Green
                                                } else {
                                                    Write-Host $result -ForegroundColor Red
                                                }
                                                
                                                "[" + (Get-CurrentTime) + "] $curuser Set Password Policy on $selectedComputer - $result" >> $manLog
                                                Write-Host "Press Enter to continue"
                                                GetKeyInput -AllowedKeys "`r" -Return $false

                                            }

                                            # Check User Accounts
                                            elseif ($securityChoice -eq "5") {

                                                ScreenClear
                                                Write-Host "Checking User Accounts on $selectedComputer..." -ForegroundColor Yellow
                                                
                                                $result = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                    try {
                                                        $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
                                                        $adminUsers = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name
                                                        return "SUCCESS: Found $($users.Count) enabled users, $($adminUsers.Count) administrators"
                                                    } catch {
                                                        return "ERROR: $($_.Exception.Message)"
                                                    }
                                                } -ErrorAction Stop

                                                if ($result -like "SUCCESS:*") {
                                                    Write-Host $result -ForegroundColor Green
                                                } else {
                                                    Write-Host $result -ForegroundColor Red
                                                }
                                                
                                                "[" + (Get-CurrentTime) + "] $curuser Checked User Accounts on $selectedComputer - $result" >> $manLog
                                                Write-Host "Press Enter to continue"
                                                GetKeyInput -AllowedKeys "`r" -Return $false

                                            }

                                            # Back to Main Menu
                                            elseif ($securityChoice -eq "6") {
                                                "[" + (Get-CurrentTime) + "] $curuser Exited Security Commands" >> $manLog
                                                Write-Progress -Activity "Security Commands" -Completed
                                                break
                                            } 
                                        }

                                        catch {
                                            WriteErrorLog -ErrorRecord $_
                                            BuildSubTerminalText -Text "Failed to execute security command on remote computer"
                                        }
                                    }
                                }
                                
                                # System Commands
                                elseif ($commandInput -eq "3") {

                                    "[" + (Get-CurrentTime) + "] $curuser Entered System Commands on $selectedComputer" >> $manLog

                                    While ($True) {

                                        ScreenClear
                                        Write-Progress -Activity "System Commands" -Status "Target: $selectedComputer"
                                        
                                        $systemChoice = BuildSubOptionFrame(" 1) Get System Info `n 2) Restart Computer `n 3) Check Uptime `n 4) Back to Main Menu")
                                    
                                        Write-Progress -Activity "System Commands" -Status "Target: $selectedComputer" -Completed
                                        
                                        try {
                                            
                                            # Get System Info
                                            if ($systemChoice -eq "1") {

                                                ScreenClear
                                                Write-Host "Getting System Information from $selectedComputer..." -ForegroundColor Yellow
                                                
                                                $result = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                    try {
                                                        $os = Get-CimInstance -ClassName Win32_OperatingSystem
                                                        $computer = Get-CimInstance -ClassName Win32_ComputerSystem
                                                        return "SUCCESS: OS: $($os.Caption), RAM: $([math]::Round($computer.TotalPhysicalMemory/1GB,2))GB, Uptime: $((Get-Date) - $os.LastBootUpTime)"
                                                    } catch {
                                                        return "ERROR: $($_.Exception.Message)"
                                                    }
                                                } -ErrorAction Stop

                                                if ($result -like "SUCCESS:*") {
                                                    Write-Host $result -ForegroundColor Green
                                                } else {
                                                    Write-Host $result -ForegroundColor Red
                                                }
                                                
                                                "[" + (Get-CurrentTime) + "] $curuser Got System Info from $selectedComputer" >> $manLog
                                                Write-Host "Press Enter to continue"
                                                GetKeyInput -AllowedKeys "`r" -Return $false

                                            }

                                            # Restart Computer
                                            elseif ($systemChoice -eq "2") {

                                                ScreenClear
                                                $AREYOUSURE = 2FA -Message "Are you sure you want to restart $selectedComputer?"

                                                if ($AREYOUSURE -eq "Y") {

                                                    Write-Host "Restarting $selectedComputer..." -ForegroundColor Red
                                                    
                                                    try {
                                                        Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                            Restart-Computer -Force
                                                        } -ErrorAction Stop

                                                        Write-Host "Restart command sent to $selectedComputer" -ForegroundColor Green
                                                        "[" + (Get-CurrentTime) + "] $curuser Restarted $selectedComputer" >> $manLog
                                                        
                                                        Write-Host "Press Enter to continue"
                                                        GetKeyInput -AllowedKeys "`r" -Return $false

                                                    } catch {
                                                        WriteErrorLog -ErrorRecord $_
                                                        BuildSubTerminalText -Text "Failed to restart remote computer"
                                                    }
                                                } else {
                                                    "[" + (Get-CurrentTime) + "] $curuser Decided not to restart $selectedComputer" >> $manLog
                                                }
                                            }

                                            # Check Uptime
                                            elseif ($systemChoice -eq "3") {

                                                ScreenClear
                                                Write-Host "Checking Uptime on $selectedComputer..." -ForegroundColor Yellow
                                                
                                                $result = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                    try {
                                                        $os = Get-CimInstance -ClassName Win32_OperatingSystem
                                                        $uptime = (Get-Date) - $os.LastBootUpTime
                                                        return "SUCCESS: Uptime: $($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes"
                                                    } catch {
                                                        return "ERROR: $($_.Exception.Message)"
                                                    }
                                                } -ErrorAction Stop

                                                if ($result -like "SUCCESS:*") {
                                                    Write-Host $result -ForegroundColor Green
                                                } else {
                                                    Write-Host $result -ForegroundColor Red
                                                }
                                                
                                                "[" + (Get-CurrentTime) + "] $curuser Checked Uptime on $selectedComputer" >> $manLog
                                                Write-Host "Press Enter to continue"
                                                GetKeyInput -AllowedKeys "`r" -Return $false

                                            }
                                    
                                            # Back to Main Menu
                                            elseif ($systemChoice -eq "4") {
                                                "[" + (Get-CurrentTime) + "] $curuser Exited System Commands" >> $manLog
                                                Write-Progress -Activity "System Commands" -Completed
                                                break
                                            } 
                                        }

                                        catch {
                                            WriteErrorLog -ErrorRecord $_
                                            BuildSubTerminalText -Text "Failed to execute system command on remote computer"
                                        }
                                    }
                                }

                                # Network Commands
                                elseif ($commandInput -eq "4") {

                                    "[" + (Get-CurrentTime) + "] $curuser Entered Network Commands on $selectedComputer" >> $manLog

                                    While ($True) {

                                        ScreenClear
                                        Write-Progress -Activity "Network Commands" -Status "Target: $selectedComputer"
                                        
                                        $networkChoice = BuildSubOptionFrame(" 1) Get IP Configuration `n 2) Flush DNS `n 3) Back to Main Menu")
                                    
                                        try {
                                            
                                            # Get IP Configuration
                                            if ($networkChoice -eq "1") {

                                                ScreenClear
                                                Write-Host "Getting IP Configuration from $selectedComputer..." -ForegroundColor Yellow
                                                
                                                $result = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                    try {
                                                        $adapters = Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" -and $_.IPAddress -ne "127.0.0.1" }
                                                        $ipInfo = $adapters | ForEach-Object { "$($_.InterfaceAlias): $($_.IPAddress)" }
                                                        return "SUCCESS: IP Configuration - $($ipInfo -join ', ')"
                                                    } catch {
                                                        return "ERROR: $($_.Exception.Message)"
                                                    }
                                                } -ErrorAction Stop

                                                if ($result -like "SUCCESS:*") {
                                                    Write-Host $result -ForegroundColor Green
                                                } else {
                                                    Write-Host $result -ForegroundColor Red
                                                }
                                                
                                                "[" + (Get-CurrentTime) + "] $curuser Got IP Config from $selectedComputer" >> $manLog
                                                Write-Host "Press Enter to continue"
                                                GetKeyInput -AllowedKeys "`r" -Return $false

                                            }

                                            # Flush DNS
                                            elseif ($networkChoice -eq "2") {

                                                ScreenClear
                                                Write-Host "Flushing DNS on $selectedComputer..." -ForegroundColor Yellow
                                                
                                                $result = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                    try {
                                                        Clear-DnsClientCache
                                                        return "SUCCESS: DNS cache flushed"
                                                    } catch {
                                                        return "ERROR: $($_.Exception.Message)"
                                                    }
                                                } -ErrorAction Stop

                                                if ($result -like "SUCCESS:*") {
                                                    Write-Host $result -ForegroundColor Green
                                                } else {
                                                    Write-Host $result -ForegroundColor Red
                                                }
                                                
                                                "[" + (Get-CurrentTime) + "] $curuser Flushed DNS on $selectedComputer" >> $manLog
                                                Write-Host "Press Enter to continue"
                                                GetKeyInput -AllowedKeys "`r" -Return $false

                                            }

                                            # Back to Main Menu
                                            elseif ($networkChoice -eq "3") {
                                                "[" + (Get-CurrentTime) + "] $curuser Exited Network Commands" >> $manLog
                                                Write-Progress -Activity "Network Commands" -Completed
                                                break
                                            } 
                                        }

                                        catch {
                                            WriteErrorLog -ErrorRecord $_
                                            BuildSubTerminalText -Text "Failed to execute network command on remote computer"
                                        }
                                    }
                                }

                                # Diagnostic Commands
                                elseif ($commandInput -eq "5") {

                                    "[" + (Get-CurrentTime) + "] $curuser Entered Diagnostic Commands on $selectedComputer" >> $manLog

                                    While ($True) {

                                        ScreenClear
                                        Write-Progress -Activity "Diagnostic Commands" -Status "Target: $selectedComputer"
                                        
                                        $diagChoice = BuildSubOptionFrame(" 1) Check Event Logs `n 2) Get Running Processes `n 3) Check Services Status `n 4) Back to Main Menu")
                                    
                                        try {
                                            
                                            # Check Event Logs
                                            if ($diagChoice -eq "1") {

                                                ScreenClear
                                                Write-Host "Checking Event Logs on $selectedComputer..." -ForegroundColor Yellow
                                                
                                                $result = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                    try {
                                                        $errors = Get-WinEvent -LogName System -MaxEvents 10 | Where-Object { $_.LevelDisplayName -eq "Error" }
                                                        $warnings = Get-WinEvent -LogName System -MaxEvents 10 | Where-Object { $_.LevelDisplayName -eq "Warning" }
                                                        return "SUCCESS: Recent errors: $($errors.Count), warnings: $($warnings.Count)"
                                                    } catch {
                                                        return "ERROR: $($_.Exception.Message)"
                                                    }
                                                } -ErrorAction Stop

                                                if ($result -like "SUCCESS:*") {
                                                    Write-Host $result -ForegroundColor Green
                                                } else {
                                                    Write-Host $result -ForegroundColor Red
                                                }
                                                
                                                "[" + (Get-CurrentTime) + "] $curuser Checked Event Logs on $selectedComputer" >> $manLog
                                                Write-Host "Press Enter to continue"
                                                GetKeyInput -AllowedKeys "`r" -Return $false

                                            }

                                            # Get Running Processes
                                            elseif ($diagChoice -eq "2") {

                                                ScreenClear
                                                Write-Host "Getting Running Processes from $selectedComputer..." -ForegroundColor Yellow
                                                
                                                $result = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                    try {
                                                        $processes = Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
                                                        $topProc = $processes | ForEach-Object { "$($_.Name) ($($_.CPU))" }
                                                        return "SUCCESS: Top processes by CPU: $($topProc -join ', ')"
                                                    } catch {
                                                        return "ERROR: $($_.Exception.Message)"
                                                    }
                                                } -ErrorAction Stop

                                                if ($result -like "SUCCESS:*") {
                                                    Write-Host $result -ForegroundColor Green
                                                } else {
                                                    Write-Host $result -ForegroundColor Red
                                                }
                                                
                                                "[" + (Get-CurrentTime) + "] $curuser Got Processes from $selectedComputer" >> $manLog
                                                Write-Host "Press Enter to continue"
                                                GetKeyInput -AllowedKeys "`r" -Return $false

                                            }

                                            # Check Services Status
                                            elseif ($diagChoice -eq "3") {

                                                ScreenClear
                                                Write-Host "Checking Services Status on $selectedComputer..." -ForegroundColor Yellow
                                                
                                                $result = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                    try {
                                                        $running = (Get-Service | Where-Object { $_.Status -eq "Running" }).Count
                                                        $stopped = (Get-Service | Where-Object { $_.Status -eq "Stopped" }).Count
                                                        return "SUCCESS: Services - Running: $running, Stopped: $stopped"
                                                    } catch {
                                                        return "ERROR: $($_.Exception.Message)"
                                                    }
                                                } -ErrorAction Stop

                                                if ($result -like "SUCCESS:*") {
                                                    Write-Host $result -ForegroundColor Green
                                                } else {
                                                    Write-Host $result -ForegroundColor Red
                                                }
                                                
                                                "[" + (Get-CurrentTime) + "] $curuser Checked Services on $selectedComputer" >> $manLog
                                                Write-Host "Press Enter to continue"
                                                GetKeyInput -AllowedKeys "`r" -Return $false

                                            }

                                            # Back to Main Menu
                                            elseif ($diagChoice -eq "4") {
                                                "[" + (Get-CurrentTime) + "] $curuser Exited Diagnostic Commands" >> $manLog
                                                Write-Progress -Activity "Diagnostic Commands" -Completed
                                                break
                                            } 
                                        }

                                        catch {
                                            WriteErrorLog -ErrorRecord $_
                                            BuildSubTerminalText -Text "Failed to execute diagnostic command on remote computer"
                                        }
                                    }
                                }

                                # Custom Command
                                elseif ($commandInput -eq "6") {

                                    "[" + (Get-CurrentTime) + "] $curuser Entered Custom Command on $selectedComputer" >> $manLog

                                    ScreenClear
                                    $customCommand = CenterText -Text "Enter Custom Command for $selectedComputer" -PromptString "PowerShell Command"

                                    if ($customCommand -ne "") {
                                        try {
                                            Write-Host "Executing custom command on $selectedComputer..." -ForegroundColor Yellow
                                            
                                            $result = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                                                param($cmd)
                                                try {
                                                    $output = Invoke-Expression $cmd 2>&1
                                                    if ($output) {
                                                        return "SUCCESS: $($output | Out-String)"
                                                    } else {
                                                        return "SUCCESS: Command executed (no output)"
                                                    }
                                                } catch {
                                                    return "ERROR: $($_.Exception.Message)"
                                                }
                                            } -ArgumentList $customCommand -ErrorAction Stop

                                            if ($result -like "SUCCESS:*") {
                                                Write-Host $result -ForegroundColor Green
                                            } else {
                                                Write-Host $result -ForegroundColor Red
                                            }
                                            
                                            "[" + (Get-CurrentTime) + "] $curuser Executed custom command '$customCommand' on $selectedComputer" >> $manLog
                                            Write-Host "Press Enter to continue"
                                            GetKeyInput -AllowedKeys "`r" -Return $false

                                        } catch {
                                            WriteErrorLog -ErrorRecord $_
                                            BuildSubTerminalText -Text "Failed to execute custom command on remote computer"
                                        }
                                    } else {
                                        "[" + (Get-CurrentTime) + "] $curuser Did not provide custom command" >> $manLog
                                    }
                                }

                                # Change target computer
                                elseif ($commandInput -eq "7") {
                                    "[" + (Get-CurrentTime) + "] $curuser Changing target computer from $selectedComputer" >> $manLog
                                    Write-Progress -Activity "Remote Command Execution" -Completed
                                    break
                                }

                                # Exit remote command configuration
                                elseif ($commandInput -eq "8") {
                                    "[" + (Get-CurrentTime) + "] $curuser Exited Remote Command Execution" >> $manLog
                                    Write-Progress -Activity "Remote Command Execution" -Completed
                                    break remoteCommandEdit
                                }
                            }
                        }
                    }

                    # Exits
                    elseif ($choice -eq "5"){
                        "[" + (Get-CurrentTime) + "] $curuser Exited DC GPO Menu" >> $manLog
                        break
                    }
                }
            }

            # Error messages
            else{

                # Im funny
                if ($domainControllerTries -gt 100){
                    
                    BuildSubTerminalText("Feel good about your self, could have done ANYTHING else `n but noooo just kept on clicking and clicking and clicking `n Go ahead, click anything to continue, see what happends.... `n Your not WORTHY of SecureTree")
                    "[" + (Get-CurrentTime) + "] $curuser is not worthy of SecureTree" >> $manLog

                    Read-Host "Sure you want to press enter again?"
                    Write-Host "Your an idiot"
                    Start-Sleep $shortSleep
                    Write-Host "Terminating computer session..."
                    Start-Sleep $shortSleep

                    for ($i = 0; $i -lt 100; $i++) {
                        Write-Progress -Activity "Deleting System32..." -Status "Thats what you get" -PercentComplete $i
                    }

                    Write-Progress -Activity "Deleting System32..." -Status "Thats what you get" -Completed
                    Write-Host "Removed System32"
                    Write-Host "GoodBye..."
                    Start-Sleep 2

                    # Open image in Windows Photo Viewer and simulate F11 for full screen
                    $imagePath = "./Data/FileShare/Wallpaper/BlueScreen.jpeg"
                    Start-Process "rundll32.exe" -ArgumentList "C:\PROGRA~1\Windows Photo Viewer\PhotoViewer.dll, ImageView_Fullscreen $imagePath"
                    Start-Sleep 3
                    Start-Process $imagePath

                    "[" + (Get-CurrentTime) + "] Terminating SecureTree (End Log) (Secret ending)" >> $manLog

                    Exit
                }

                elseif ($domainControllerTries -gt 20){
                    
                    BuildSubTerminalText("Wonder what happens if you do this for 100 times? `n $domainControllerTries/100")
                    "[" + (Get-CurrentTime) + "] $curuser might try to get to 100: $domainControllerTries/100" >> $manLog

                }

                elseif ($domainControllerTries -gt 15){
                    
                    BuildSubTerminalText("Ok, im done with this")
                    "[" + (Get-CurrentTime) + "] $curuser im done bro" >> $manLog

                }

                elseif ($domainControllerTries -gt 10){
                    
                    BuildSubTerminalText("Bro, let me be real with you `n 'You NEED to BE a DOMAIN CONTROLLER!!!'")
                    "[" + (Get-CurrentTime) + "] $curuser is starting to be annoying" >> $manLog

                }

                elseif ($domainControllerTries -gt 5){

                    BuildSubTerminalText("Your NOT a DOMAIN CONTROLLER")
                    "[" + (Get-CurrentTime) + "] $curuser is NOT on a DOMAIN CONTROLLER" >> $manLog

                }

                else{

                    BuildSubTerminalText("Your not a Domain Controller")
                    "[" + (Get-CurrentTime) + "] $curuser is not on a domain controller" >> $manLog
                }

                $domainControllerTries ++

            }
        }

        # Swaps the view of the terminal
        elseif (($choice -eq "12" -and $global:advanceView) -or ($choice -eq "8" -and -not ($global:advanceView))) {

            $global:advanceView = !$global:advanceView
            ScreenClear

        }

        # The code to exit program
        elseif (($choice -eq "13" -and $global:advanceView) -or ($choice -eq "9" -and -not ($global:advanceView))) {


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
