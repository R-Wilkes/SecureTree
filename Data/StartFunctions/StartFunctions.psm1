# Just to split up some of the functions from the start script, makes it cleaner to read

# Get the inspirational message
function GetInspirationalMessage{

    # Gonna add like a minecraft inspirational quote or something
    # This is just for fun, for anyone who is looking into the code
    $linesOfCode = 0

    # NOTE: This is not the most efficient way to count lines of code, but it works, its not worth the time to make a function :)
    $linesOfCode += (Get-Content "./Start.ps1").Length
    $linesOfCode += (Get-Content "./Data/CommonFunctions/CommonFunctions.psm1").Length
    $linesOfCode += (Get-Content "./Data/FileFinder/FileFinder.psm1").Length
    $linesOfCode += (Get-Content "./Data/FileFinder/Filter.psm1").Length
    $linesOfCode += (Get-Content "./Data/FrameBuilder/FrameBuilder.psm1").Length
    $linesOfCode += (Get-Content "./Data/FrameBuilder/CLIBuilder.psm1").Length
    $linesOfCode += (Get-Content "./Data/FrameBuilder/LoadingScreen.psm1").Length
    $linesOfCode += (Get-Content "./Data/StartFunctions/StartFunctions.psm1").Length
    
    # Statement that decide the message and color
    $messages = "$linesOfCode Lines of Code!!!", "YES... The new CLI was worth it, i don't care what everyone thinks", "Totally not coping Minecraft", "Remember to delete System32!", "Try out manual mode for better customization!", "Alt-F4 for better FPS", "I can't fix the screen flickering :("
    $colors = "Yellow", "Green", "White", "Cyan", "Magenta", "DarkRed", "DarkYellow", "DarkGreen", "DarkCyan", "DarkMagenta"
    $numChoice = Get-Random -Minimum 0 -Maximum $messages.Length
    $colorChoice = Get-Random -Minimum 0 -Maximum $colors.Length
    $color = $colors[$colorChoice]
    $inspirationalMessage = $messages[$numChoice]

    # Sets logo, Don't even think about changing the logo in the files...
    if ((Get-Random -Minimum 0 -Maximum 100) -lt 20) {

        # Open the file and set the logo variable to its contents
        $logoFilePath2 = "./Data/Logo/Cicada Logo.txt"
        $logo = Get-Content $logoFilePath2 -Raw
        $inspirationalMessage = "For An Extra Challenge, try Cicada 3301!"

    }

    else{

        $baseLogo = "./Data/Logo/Base Logo.txt"
        $logo = Get-Content $baseLogo -Raw

    }


    return $color, $inspirationalMessage, $logo

}

# Used to change settings based on OS
function IsServer{

    $os = Get-WmiObject -Class Win32_OperatingSystem

    if ($os.ProductType -eq 2 -or $os.ProductType -eq 3) {
        return $true
    } 
    
    else {
        return $false
    }
}

# Used to change settings based on OS 
function IsHome{

    $os = Get-WmiObject -Class Win32_OperatingSystem

    if ($os.ProductType -eq 1) {
        return $true
    } 
    
    else {
        return $false
    }
}

# Checks to see if its a domain
function IsAD{

    # Check if the computer is part of an Active Directory domain
    $isDomainJoined = (Get-WmiObject Win32_ComputerSystem).PartOfDomain

    if ($isDomainJoined) {
       return $True
    } 

    else {
        return $False
    }
}

# Displays some ADInfo
function ADInfo{

    # Check if the computer is part of an Active Directory domain
    $domain = (Get-WmiObject Win32_ComputerSystem).Domain
    $isDomainJoined = (Get-WmiObject Win32_ComputerSystem).PartOfDomain

    if ($isDomainJoined) {

        Write-Host "This computer is part of the domain: $domain" 
        return $True
    
    } 

    else {

        return $False
    
    }
}

# Checks if its a Domain Controller | AI
function IsDC{
    try {
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        return ($computerSystem.DomainRole -eq 4 -or $computerSystem.DomainRole -eq 5)
        # 4 = Backup Domain Controller, 5 = Primary Domain Controller
    }
    catch {
        return $false
    }
}

# Used for the screen to make sure all the info is correct
function WindowsVersionInfo{

    $os = Get-WmiObject -Class Win32_OperatingSystem
    return ($os.Caption)

}

# Checks if IRSec image, don't have anything for this yet
function IsIRSec{
   return $false
}

# Moved the 2 menu types into this function
# Its where all the menus are stored
function GetMenu($advanceView){
        
        # For advance view
        if ($advanceView) {

            $mainMenuTitleTH = @'
            [-------------------------------------------------------------------------------------------------------------------]
            |                               /$$$$$$ /$$$$$$$   /$$$$$$                                                          |
            |                              |_  $$_/| $$__  $$ /$$__  $$                                                         |
            |                                | $$  | $$  \ $$| $$  \__/  /$$$$$$   /$$$$$$$                                     |
            |                                | $$  | $$$$$$$/|  $$$$$$  /$$__  $$ /$$_____/                                     |
            |                                | $$  | $$__  $$ \____  $$| $$$$$$$$| $$                                           |
            |                                | $$  | $$  \ $$ /$$  \ $$| $$_____/| $$                                           |
            |                               /$$$$$$| $$  | $$|  $$$$$$/|  $$$$$$$|  $$$$$$$                                     |
            |                              |______/|__/  |__/ \______/  \_______/ \_______/                                     |
            |-------------------------------------------------------------------------------------------------------------------|
'@
            $mainMenuTitleBH = @"

            |   1) Edit Users                                                                             $(ProgressText) |
            |   2) Note.txt                                                                                                     |
            |   3) Manually set password policy                                                                                 |
            |   4) Install Programs                                                                                             |
            |   5) Run Sysinternals Programs                                                                                    |
            |   6) Manually Run Scripts                                                                                         |
            |   7) Enable/Disable                                                                                               |
            |   8) Useful Terminals                                                                                             |
            |   9) File Finder                                                                                                  |
            |  10) Run Auto                                                                                                     |
            |  11) Swap View                                                                                                    |
            |  12) Exit                                                                                                         |
            [-------------------------------------------------------------------------------------------------------------------]  
            Choice
"@
            $mainMenuTitle = $mainMenuTitleTH + $mainMenuTitleBH
        }
    
        # For simple view
        elseif( -not ($advanceView)){
    
            $mainMenuTitleTH = @'
            [-------------------------------------------------------------------------------------------------------------------]
            |                               /$$$$$$ /$$$$$$$   /$$$$$$                                                          |
            |                              |_  $$_/| $$__  $$ /$$__  $$                                                         |
            |                                | $$  | $$  \ $$| $$  \__/  /$$$$$$   /$$$$$$$                                     |
            |                                | $$  | $$$$$$$/|  $$$$$$  /$$__  $$ /$$_____/                                     |
            |                                | $$  | $$__  $$ \____  $$| $$$$$$$$| $$                                           |
            |                                | $$  | $$  \ $$ /$$  \ $$| $$_____/| $$                                           |
            |                               /$$$$$$| $$  | $$|  $$$$$$/|  $$$$$$$|  $$$$$$$                                     |
            |                              |______/|__/  |__/ \______/  \_______/ \_______/                                     |
            |-------------------------------------------------------------------------------------------------------------------|
'@
            $mainMenuTitleBH = @"

            |   1) Edit Users                                                                             $(ProgressText) |
            |   2) Install Programs                                                                                             |
            |   3) Run Sysinternals Programs                                                                                    |
            |   4) Useful Terminals                                                                                             |
            |   5) File Finder                                                                                                  |
            |   6) Run Auto                                                                                                     |
            |   7) Swap View                                                                                                    |
            |   8) Exit                                                                                                         |
            [-------------------------------------------------------------------------------------------------------------------]
            Choice
"@
            $mainMenuTitle = $mainMenuTitleTH + $mainMenuTitleBH

        }

    return $mainMenuTitle

}

# Will write errors to the error logs
function WriteErrorLog {

    param (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
              
    $hour = (Get-Date).Hour
    $sec = (Get-Date).Second
    $min = (Get-Date).Minute
    $manLogError = "./Logs/ErrorLogs/ManualLogError-$hour-$min-$sec.txt"
    CreatePath -DirectoryPath $manLogError -Type "File"
    Write-Host "ERROR occurred, added to error log" -ForegroundColor Red
    Start-Sleep 3
    "[" + (Get-CurrentTime) + "] $curuser made an error occur, adding to error log 'ManualLogError-$hour-$min-$sec.txt', error log number $global:numberError" >> $manLog

    "IRSec Error Log" >> $manLogError
    "`nWritten On: $date" >> $manLogError
    "Program Version: $version" >> $manLogError
    "Powershell Version: $($PSVersionTable.PSVersion)" >> $manLogError
    "`nUser Logged in: $curuser" >> $manLogError
    "`nComputer Name: $computerName" >> $manLogError
    "`n `nError log number: $global:numberError `n  `n `n" >> $manLogError

    # Writes out to screen if debugging
    if ($debug){

        Write-Host "$ErrorRecord"
        Read-Host "Press ENTER to continue..."

    }

    Write-Output "$ErrorRecord" >> "$manLogError"
    $global:numberError += 1
    "`nEND of error log " >> $manLogError
    $error.clear()
    
}

# Will write background errors to the error logs
function BackgroundErrorLog {
    
    param (
        $ProName
    )

    $hour = (Get-Date).Hour
    $sec = (Get-Date).Second
    $min = (Get-Date).Minute
    $date = Get-Date

    $mainLogPath = "./Logs/BackgroundJobs/$ProName/$($ProName)log.txt"
    $backLogError = "./Logs/BackgroundJobs/$ProName/ErrorLogs/$ProName-ErrorLog-$hour-$min-$sec.txt"
    CreatePath -DirectoryPath $backLogError -Type "File"

    "[" + (Get-CurrentTime) + "] Background Error, adding to error log 'ManualLogError-$hour-$min-$sec.txt'" >> $mainLogPath

    "IRSec Background Error Log" >> $backLogError
    "`nWritten On: $date" >> $backLogError
    "Program Version: $version" >> $backLogError
    "Powershell Version: $($PSVersionTable.PSVersion)" >> $backLogError
    "`nUser Logged in: $curuser" >> $backLogError
    "`nComputer Name: $computerName `n" >> $backLogError

    Write-Host "$_"

    Write-Output "$_" >> "$backLogError"
    "`nEND of error log " >> $backLogError
    $error.Clear()
    Start-Sleep 5

}

# Little header at the top of the logs, just to make it look nice
function LogHeader{

    param(
        [Parameter(Mandatory=$true)]
        [string]$Name, # Name of the log
        [string]$Path # Path of the log
    )

    $date = Get-Date

    "$Name" >> $Path
    "`nWritten On: $date" >> $Path
    "Program Version: $version" >> $Path
    "Powershell Version: $($PSVersionTable.PSVersion)" >> $Path
    "Is IRSec Image: $(IsIRSec)" >> $Path
    "`nUser Logged in: $curuser" >> $Path
    "`nComputer Name: $computerName" >> $Path
}

# Will ask about running auto upon fist boot
function PromptAutoMode{

    if (-not (Test-Path -Path "$Global:tempData/BootedUp.txt")){

        CreatePath -Type "File" -DirectoryPath "$Global:tempData/BootedUp.txt"

        # Do some trolling
        "Ya know what they say my boy, Curiosity Killed The Cat" >> "$Global:tempData/BootedUp.txt"
        CenterText -Text "First Time Running this script, would you like to run Auto or enter Manual mode? [A/M]" -Border $true
       
        return (GetKeyInput -AllowedKeys "am")

    }

    else{
        return "M"
    }
}

