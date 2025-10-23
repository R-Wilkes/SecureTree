# Used to have a lot more in here, but got rid of it, so now its a peasant living like a king, getting its own file

# Common Functions that are used in all of the scripts
Import-Module -Name "./Data/CommonFunctions/CommonFunctions"

# Just here to filter out any duplicated lines and what not
function RemoveDuplicateLines($filePath) {

    Write-Host "Auto Filtering Files"
    $lines = Get-Content $filePath | Select-Object -Unique
    $lines | Set-Content $filePath
    Start-Sleep $Global:shortSleep

}

# Just here to filter out any duplicated lines and what not
function RemoveSpaces($inputString) {
    return ($inputString -replace ' ', '') 
}
