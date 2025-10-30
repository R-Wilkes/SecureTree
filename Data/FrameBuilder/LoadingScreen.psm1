# Just all the stuff related to loading screen and what not
# Not gonna be extremely documented, as its just a loading screen

$global:permissionCheckRun = $false
$global:killAllJobsRun = $false
$global:psVersionRun = $false
$global:miscSettingsRun = $false
$global:debugChechRun = $false

# Adds the loading bar to the loading screen
function LoadingBar {
    
    param (
        [int]$LoadingBarValue,
        [bool]$ReturnOutput
    )

    $loadingBar = "[" + ("#" * $LoadingBarValue) + (" " * (100 - $LoadingBarValue)) + "]"

    if ($ReturnOutput){
        return $loadingBar + " " + $LoadingBarValue + "%"
    }

    else{

        Write-Host $loadingBar -NoNewline
        Write-Host (" " + $LoadingBarValue + "%") -NoNewline
    
    }
}

# This will add the function to the loading screen, so it actually does something, runs all the system checks and what not
function BootupBackground{

    param(
        $LoadingProgress
    )

    # Checks the PowerShell version, does this in startup check, but not for this loading screen
    if ($LoadingProgress -gt 15 -and -not $global:psVersionRun){

        $global:psVersionRun = $true

        # Make sure your powershell is within the right version
        if ($PSVersionTable.PSVersion.Major -gt 5 -or $PSVersionTable.PSVersion.Major -lt 5) {
            LoadingScreenQuery -Query "PowerShell 5.1 Recommended, some features might not work on Newer/Older versions [ANY KEY]"
        }
    }

    # Lets you know if debug mode is enabled
    elseif ($LoadingProgress -gt 30 -and -not $global:debugChechRun){

        $global:debugChechRun = $true

        # Make sure your powershell is within the right version
        if (Config("debug_mode")) {
            LoadingScreenQuery -Query "Debug Mode Enabled from Config, Screen does not clear and all errors are inquired [ANY KEY]"
        }
    }

    # Checks file permissions
    elseif ($LoadingProgress -gt 50 -and -not $global:permissionCheckRun){

        $global:permissionCheckRun = $true

        try{
            StartupCheck
        }

        catch{
            LoadingScreenQuery -Query $_ -Fatal $true

            # Somehow this has to be here, or it does not work
            Exit
        }
    }

    # Kills all jobs and sets fast mode
    elseif ($LoadingProgress -gt 75 -and -not $global:killAllJobsRun){
        
        $global:killAllJobsRun = $true

        try{

            if ((Config("fast_mode"))) {

                $global:shortSleep = Config("fast_mode_time")
                $global:longSleep = Config("fast_mode_time")

                $global:shortSleep | Out-Null
                $global:longSleep | Out-Null

            }
        }

        catch{
            LoadingScreenQuery -Query $_ -Fatal $true

            # Somehow this has to be here, or it does not work
            Exit
        }
    }

    # Some Misc settings
    elseif ($LoadingProgress -gt 85 -and -not $global:miscSettingsRun){

        $global:miscSettingsRun = $true

        # Warns you that this is not a IRSec image
        if (-Not (IsIRSec)){

            # Little Subnautica Reference :)
            $response = LoadingScreenQuery -Query "This is NOT a IRSec Image, this script can and will cause SERIOUS DAMAGE to your computer `n `t `t `t `t `t Are you certain whatever your doing, is worth it? [Y/N]" -AllowedKeys "yn"

            if ($response -ne "y"){

                LoadingScreenQuery -Query "Come back when your ready :)" -Fatal $true
                
                Exit
            }
        }
    }
}

# Displays the text, had to put this here due to amount of calls of repeated code
function LoadingScreenText {

    param (
        [int]$LoadingProgress = 0,
        [string]$Text = "Not Set",
        [string]$InspirationalMessage = "Not Set",
        [string]$Color = "White",
        [string]$LoadingColor = "White"
    )

    # Saves it so it prints everything out at once, so it loads faster
    $loadingBar = LoadingBar -LoadingBarValue $LoadingProgress -ReturnOutput $true
    $MM = CenterText -Text ($Text) -Border $true -BottomPadding $false -ReturnOutput $true

    if ($MM.Contains("0")){
        $spacing = 1
    }
    
    else{
        $spacing = 3
    }

    Clear-Host


    Write-Host $MM 
    Write-Host (("`n" * $spacing) + (" " * ((GetCenterX -Text $inspirationalMessage) + 2)) + $inspirationalMessage) -ForegroundColor $color
    Write-Host (("`n" * 5) + (" " * ((GetCenterX -Text $loadingBar) + 2)) + $loadingBar) -ForegroundColor $LoadingColor 
    Write-Host (("`n" * 1) + (" " * ((GetCenterX -Text "Creator: $global:creator   Version: $global:version") + 47)) + "Creator: $global:creator   Version: $global:version") 

}

# For asking the user about errors/displaying the errors
function LoadingScreenQuery {

    param (
        [string]$Query = "Not Set", #Question to be asked
        [string]$AllowedKeys = "", #Keys that are allowed to be pressed
        [bool]$Fatal = $false #if Its fatal or not
    )

    $color = if ($Fatal){ "Red" } else { "Yellow" }

    LoadingScreenText -LoadingProgress $i -Text $logo -InspirationalMessage $Query -Color $color -LoadingColor $color

    # Will return keys if its not fatal
    if (-not $Fatal){
        return GetKeyInput -AllowedKeys $AllowedKeys
    }
}

# Just a cool little loading screen, doesn't actually load anything tho, it loads really fast
function LoadingScreen{

    # Resets all the Global Variables
    $global:permissionCheckRun = $false
    $global:killAllJobsRun = $false
    $global:psVersionRun = $false
    $global:miscSettingsRun = $false
    $global:debugChechRun = $false

    $color, $inspirationalMessage, $logo = GetInspirationalMessage

    # Boots up this glorious script, 80% looks 20% functionality
    for ( $i = 0; $i -le 100; $i += (Get-Random -Minimum 2 -Maximum 8) ){

        BootupBackground -LoadingProgress $i 
        LoadingScreenText -LoadingProgress $i -Text $logo -InspirationalMessage $inspirationalMessage -Color $color

        # Will make it boot up faster if fast mode is enabled HAHA
        if (Config("fast_mode")){

            Start-Sleep -Milliseconds (Get-Random -Minimum 10 -Maximum 20)
            $i += 5

        }

        else{
            Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 200)
        }

        # Allows you to skip the booting up, never gonna find this until you look here
        if ([Console]::KeyAvailable) {

            $key = [Console]::ReadKey($true)

            if ($key.Key -eq "Enter") {
                break
            }
        }
    }

    # When Done
    LoadingScreenText -LoadingProgress 100 -Text $logo -InspirationalMessage $inspirationalMessage -Color $color -LoadingColor "Green" 

    # Keeps things quick
    if (Config("fast_mode")){
        Start-Sleep -Milliseconds 500
    }

    else{
       Start-Sleep -Milliseconds 2000
    }
    
    ScreenClear

}

# Just prints out a little bit of info that is useful
function ConfirmInfo{

    # The amount of spacing in between the string
    $spacing = "`n `n `n `t `t `t `t `t `t `t" 

    # Im sorry, its a very long string
    CenterText -Text ("Please make sure all information below is correct before moving forward!`n`n`n $spacing Current User: $curuser $spacing Computer Name: $computerName $spacing OS: $(WindowsVersionInfo) $spacing Is IRSec Image: $(IsIRSec) $spacing Is Active Directory: $(ADInfo) $spacing Is Domain Controller: $(IsDC)`n `n `n") -Border $true
    # Keeps things quick
    if (Config("fast_mode")){
        Start-Sleep -Milliseconds 500
    }

    else{
        Start-Sleep 2
    }

    GetKeyInput | Out-Null 

}

# This is same and different as confirmInfo, just with the stuff the script won't due to to software and OS restrictions
function ShowDisabled{

    $disabledText = ""

    # NOTE: not much here, I fixed a lot ofo it

    # If the OS is not a pro version, then disable the group policy editor
    if (IsHome){
        $disabledText += "Home Edition - Local Group Editor, Security Editor and Policy Editor are disabled`n`n"
    }

    # If not on a IRSec image, then disable the IRSec options
    if (-not (IsIRSec)){
        $disabledText += "Not IRSec Image - Be Carful"
    }

    # Will print this out if there are options that have been disabled
    if ($disabledText -ne ""){

        Write-Progress -Activity  "Important features are disabled due to OS restrictions" -Status "Read Below for more information"
    
        CenterText -Text ($disabledText) -Border $true

        # Keeps things quick
        if (Config("fast_mode")){
            Start-Sleep -Milliseconds 500
        }

        else{
            Start-Sleep 5
        }

        $Host.UI.RawUI.FlushInputBuffer()
        GetKeyInput | Out-Null  

        Write-Progress -Activity  "Important features are disabled due to OS restrictions" -Status "Read Below for more information" -Completed

    }
}