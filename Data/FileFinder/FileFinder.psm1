
# Searches through the specified directory to look for files that are not allowed 
# Beginning of file codes
# '%': Files that are not in the base files list
# '*': Files that are in the banned files list
# '#': Files that are in the exception files list

# Needs to filter down the output of the file scanner
Import-Module -Name "./Data/FileFinder/Filter"

# All of the File paths to the files that are needed
$baseFiles = Get-Content -Path "./Data/FileFinder/BaseFiles.txt"
$exceptionFiles = Get-Content -Path "./Data/FileFinder/ExceptionFiles.txt"
$exceptionFolders = Get-Content -Path "./Data/FileFinder/ExceptionFolder.txt"
$newBaseFile = "./Logs/NewBaseFiles.txt"
$global:fileScanOutput = "./Data/TempData/FileOutput.txt"

function FindAndHighlightFiles {

    param (
        [Parameter(Mandatory = $true)]
        [string]$directory, #Directory where to search
        [string[]]$highlightedFiles, # files that is should look for

        [bool]$Filter = $true, # Filter out duplicate files, only set to false when searching multiple directories in quick succession
        [bool]$ClearFile = $false #Clears the output file before writing to it
    )

    if ($ClearFile){
        Remove-Item -Path $global:fileScanOutput -Force -ErrorAction Ignore
    }

    # Will Prevent repeat folders
    $alreadyFoundFolders = ""

    # Had to add my own error handling here, to prevent it from searching a directory that does not exist
    try{

        # Hopefully makes it quit faster
        if (-not (Test-Path -Path $directory)) {
            throw 
        }

        # Get all files in the directory and its subdirectories, skips the function if path does not exist
        $files = Get-ChildItem -Path $directory -Recurse -File -ErrorAction Stop
        
    }
    
    catch {

        Write-Host "Path '$directory' does not exist/Cant be accessed"

        # Makes it filter even though the directory does not exist
        if ($Filter){
            RemoveDuplicateLines($global:fileScanOutput)
        }

        # Forces the function to stop
        return $null

    }

    # Create a new text document to store the file list
    $fileList = New-Object -TypeName System.Collections.ArrayList
    $maxFileNumber = @($files).Count
    $currentFileNumber = 0

    Write-Host "There are $maxFileNumber files in the directory $directory"

    # Breaks if the file is too large
    if (@($files).Count -gt 10000){
        if((Read-Host -Prompt "Too many files: Are you sure you want to continue? [Y/N]") -ne "Y"){

            # Adds to the banned list, just to get your attention
            $fileList.Add("*" + $directory + "  --Too Many Files--")
            Write-Host "Banned Folder Found: $($directory)" 
            return

        }
    }

    Start-Sleep $global:shortSleep

    # Creates the file if it doesn't exist
    CreatePath -DirectoryPath $global:fileScanOutput -Type "file"

    # Iterate through each file
    :fileQuit foreach ($file in $files) {

        # Just give you a little progress bar so you know something is happening
        Write-Progress -Activity "File Scanning" -Status "Scanning File: $($file.FullName)" -PercentComplete (($currentFileNumber / $maxFileNumber) * 100)
        
        $skip = $false

        # NOTE: Code readability is not the best

        # This will skip over the folders that are in the exception list
        # NOTE: The Split Delimiter(What its splitting by) has to be two \\ for windows, due to how its file directorys are set up, and one / for mac and linux
        $splitPath = $file.Directory.FullName -split "\\"

        # This is a loop that goes through the parts of the filepath to look for the key word
        :fileQuit foreach ($part in $splitPath){
            
            if ($exceptionFolders -contains $part -or ($alreadyFoundFolders -contains $part -and $part -ne "")) {

                # Write-Host "Skipping Folders: $($file.Directory.FullName)"
                $alreadyFoundFolders += $file.Directory.Name + " "
                $skip = $true
                break 

            }

            # Will flag if the filename is a banned file
            elseif($highlightedFiles -contains $part -or $highlightedFiles -contains $part.Split(".")[0] -or $highlightedFiles -contains $part.Split(".")[1] -or $part.Contains($highlightedFiles)){

                # Will not report them if they are in the exception files list
                if  (-not ($exceptionFiles -contains $part -or $exceptionFiles -contains $part.Split(".")[0])){

                    # Highlight the file by adding an asterisk before its name
                    $fileList.Add("*" + $file.Directory.FullName)
                    # Write-Host "Banned Folder Found: $($file.Directory.Name)"
                    $alreadyFoundFolders += $file.Directory.Name + " "
                    $skip = $true
                    break
                    
                }
            }
        }

        # This will just Skip over everything if its in the folder
        if ($skip) {

            $skip = $false
            continue

        }

        # If its not a skip file, then it will check it with everything else
        else{

            # Start-Sleep 1
            # Checks to see if its a banned folder
            if ($highlightedFiles -contains $file.Directory.Name -or $highlightedFiles -contains $file.Directory.Name.Split(".")[0] -or $highlightedFiles -contains $file.Directory.Name.Split(".")[1] -or $file.Directory.Name.Contains($highlightedFiles)){

                # Will not report them if they are in the exception files list
                if  (-not ($exceptionFiles -contains $file.Directory.Name -or $exceptionFiles -contains $file.Directory.Name.Split(".")[0])){
                
                    # Will Prevent repeat folders
                    if (-not ($alreadyFoundFolders.Contains($file.Directory.Name))){

                        # Highlight the file by adding an asterisk before its name
                        $fileList.Add("*" + $file.Directory.FullName) | Out-Null
                        # Write-Host "Banned Folder Found: $($file.Directory.Name)"
                        $alreadyFoundFolders += $file.Directory.Name + " " 

                    }
                }
            }
           
            # Check if the file is in the list of highlighted files AKA Banned files
            elseif ($highlightedFiles -contains $file.Name -or $highlightedFiles -contains $file.Name.Split(".")[0] -or $highlightedFiles -contains $file.Name.Split(".")[1] -or $file.Name.Contains($highlightedFiles)) {

                # Will not report them if they are in the exception files list
                if  (-not ($exceptionFiles -contains $file.Name -or $exceptionFiles -contains $file.Name.Split(".")[0])){
                
                    # Highlight the file by adding an asterisk before its name
                    $fileList.Add("*" + $file.FullName) | Out-Null
                    # Write-Host "Banned File Found: $($file.Name)"
            
                }
            }
            
            # Same thing as above, but for difference files
            elseif (-not ($baseFiles -contains $file.Name -or $baseFiles -contains $file.Name.Split(".")[0] -or $file.Name.Contains($baseFiles))){

                # Will not report them if they are in the exception files list
                if (-not ($exceptionFiles -contains $file.Name -or $exceptionFiles -contains $file.Name.Split(".")[0])){

                    # Highlight the file by adding an Percent before its name
                    $fileList.Add("%" + $file.FullName) | Out-Null
                    # Write-Host "Different File Found: $($file.Name)"
                    
                }
            }

            if ($exceptionFiles -contains $file.Name){

                # Highlight the file by adding an Percent before its name
                $fileList.Add("#" + $file.FullName) | Out-Null
                # Write-Host "Exception File Found: $($file.Name)"
            
            }
        }

        $currentFileNumber ++
    }

    # Save the file list to the output file
    (RemoveSpaces($fileList)) | Out-File -FilePath $global:fileScanOutput -Append
    Write-Progress -Activity "File Scanning" -Completed

    if ($Filter){
        RemoveDuplicateLines($global:fileScanOutput)
    }
}

# Does the important scan of the file system
function ImportantScan{

    # Only have the last scan filter out the output
    FindAndHighlightFiles -directory "/Program Files" -highlightedFiles (Get-Content -Path "./Data/FileFinder/BannedFiles.txt") -Filter $false -ClearFile $true
    FindAndHighlightFiles -directory "/Users" -highlightedFiles (Get-Content -Path "./Data/FileFinder/BannedFiles.txt") -Filter $false
    FindAndHighlightFiles -directory "/Program Files (x86)" -highlightedFiles (Get-Content -Path "./Data/FileFinder/BannedFiles.txt") -Filter $false

}

# Will print out Every File Found
function ShowFoundFiles{

    Clear-Host

    $files = Get-Content -Path $global:fileScanOutput
    $numBanned = 0
    $numDifference = 0
    $numException = 0

    Write-Host " `n `n `n `n ----Found Files---- `n "

    foreach ($file in $files){

        if ($file.Contains("*")){

            Write-Host $file.Split("*")[1] -ForegroundColor Red
            $numBanned ++
            
        }

        if ($file.Contains("%")){

            Write-Host $file.Split("%")[1] -ForegroundColor Yellow
            $numDifference ++
            
        }

        if ($file.Contains("#")){

            $numException ++
            
        }
    }

    Write-Host "Number Of Banned Files = $numBanned"
    Write-Host "Number Of Difference Files = $numDifference"
    Write-Host "Number Of Exception Files = $numException `n "

}

# Only shows the banned files
function ShowBannedFiles{
        
    Clear-Host

    $files = Get-Content -Path $global:fileScanOutput
    $numBanned = 0

    Write-Host " `n `n `n `n ----Prohibited Files---- `n "

    foreach ($file in $files){

        if ($file.Contains("*")){

            Write-Host $file.Split("*")[1] -ForegroundColor Red
            $numBanned ++
            
        }
    }

    Write-Host "Number Of Banned Files = $numBanned"
}

# Only shows the difference files
function ShowDifferenceFiles{
        
    Clear-Host

    $files = Get-Content -Path $global:fileScanOutput
    $numDifference = 0

    Write-Host " `n `n `n `n ----Difference Files---- `n "

    foreach ($file in $files){

        if ($file.Contains("%")){

            Write-Host $file.Split("%")[1] -ForegroundColor Yellow
            $numDifference ++
            
        }
    }

    Write-Host "Number Of Difference Files = $numDifference"

}