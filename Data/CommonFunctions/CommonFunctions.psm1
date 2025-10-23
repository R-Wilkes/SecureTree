# All the functions in here are meant to be used across all scripts if needed
# Trying to split up my code so that the main and auto scripts are not that big with functions

# Will now allow the config to be easily accessible
function Config($textToFind){

    $listOfConfigOptions = "True", "False", "Ask"
    $config = Get-Content "./Config/config.txt"

    foreach ($line in $config) {

        if ($line -match "$textToFind = (.*)") {

            $value = $matches[1]

            # Makes sure its in the List of Options or a number
            if ($listOfConfigOptions -contains $value -or $value -match '\d+') {
                
                # Sets the values to respective True and False
                if ($value -eq "True"){
                    return $true
                }

                elseif ($value -eq "False"){
                    return $false
                }

                # Will ask the question here, saves lots of code
                elseif ($value -eq "Ask"){
                    
                    if ((Read-Host -Prompt "Do you want to run '$textToFind'? [Y/N]") -eq "Y"){
                        return $true
                    }

                    else{
                        return $false
                    }
                }

                else{
                    return $value
                }
            }
            
            else{
                throw "Disallowed Value in Config in option '$textToFind' with value '$value'"    
            }
        }
    }
}

# Just the functions that is used for the logs and stuff
function Get-CurrentTime{

    $currentTime = Get-Date -Format "HH:mm:ss"
    return $currentTime 

}

# Clears screen if debug is not on
function ScreenClear{
    if (-not (Config("debug_mode"))) {
        Clear-Host
    }
}

# Just moved the startup checks here, checks for admin and x86 shell, and some other stuff
function StartupCheck{

    # Makes it so you have to run as admin
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {

        Write-Error "Insufficient permissions to run this script. Open the PowerShell console as an administrator and run this script again." -ErrorAction Stop
        Exit

    }

    # Makes you run the script in a x64 shell, Mainly for the Policy script
    if ([Environment]::Is64BitProcess -ne [Environment]::Is64BitOperatingSystem){
        
        Write-Error "You must execute this script on a x64 shell" -ErrorAction Stop
        Exit
    
    }

    # Check if running in a PowerShell terminal
    if ($host.Name -ne 'ConsoleHost') {
            
        Write-Error "You must execute this script in a PowerShell terminal" -ErrorAction Stop
        Exit
        
    } 

    # Troll, if you somehow manage to delete the config file
    if (-not (Test-Path "./Config/config.txt")) {

        Write-Error "Somehow you managed to delete/move the config file, so now the script won't work until you put it back!" -ErrorAction Stop
        Exit

    }

    # Make sure your powershell is within the right version
    if ($PSVersionTable.PSVersion.Major -gt 5 -or $PSVersionTable.PSVersion.Major -lt 5) {

        Write-Warning "This script is meant to be run on PowerShell 5.1, some features might not work on newer/Older versions"
        Read-Host "Press Enter to continue"

    }
}

# Just a little helper function to create a path or a file if it does not exist
function CreatePath{

    param(
        [Parameter(Mandatory = $true)]
        [string]$DirectoryPath, # The path to the file or directory
        [string]$Type # File or Directory, if file it expects a file at end of directory path EX ./Data/Logs/Log.txt
    )

    if (-not (Test-Path -Path $DirectoryPath)){
        
        # Will create the path before the file
        if ($Type -ieq "file"){

            $originalPath = Split-Path -Path $DirectoryPath -Parent
            New-Item -ItemType Directory -Path $originalPath  -ErrorAction SilentlyContinue | Out-Null
            New-Item -ItemType $Type -Path $DirectoryPath | Out-Null

        }
        
        elseif ($Type -ieq "directory"){

            New-Item -ItemType $Type -Path $DirectoryPath | Out-Null

        }

        else{
            throw "Not a valid type, must be either 'File' or 'Directory'"
        }
    }
}

# Little guy to get key inputs, added with new CLI
function GetKeyInput{

    param(
        [string]$AllowedKeys = $null, # Will only return if the key is in the list, if null will return all keys
        [bool]$Return = $true # Will return the key press
    )

    while ($true){

        $key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character

        if ([console]::CapsLock) {
            Write-Progress -Activity  "Caps Lock is ON" -Status "Turn OFF Caps Lock"
        }
        
        else{
            Write-Progress -Activity  "Caps Lock is ON" -Completed 
        }
    

        if ($AllowedKeys.Contains($key) -or "" -eq $AllowedKeys){
            if ($Return){
                return $key
            }
            
            else{
                return $null
            }
        }
    }
}

# Asks again and forces you to hit enter with your key press
function 2FA{
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $oldColor = $host.UI.RawUI.BackgroundColor

    # Sets the text background to red
    $host.UI.RawUI.BackgroundColor = "Red"
    $host.UI.RawUI.FlushInputBuffer()
    
    $response = (Read-Host -Prompt "2FA - $Message [Y/N]")

    # Sets the text background to the original color
    $host.UI.RawUI.BackgroundColor = $oldColor
    $host.UI.RawUI.FlushInputBuffer()
    Clear-Host
    
    if ($response -eq "Y"){
        return $true
    }

    else{
        return $false
    }
}