# This script is used to create a fancy CLI for the user to interact with
# Also contains the loading screen and all the Fancy looking stuff

# Gets how many options are in the menu
function GetMaxOptions{

    param(
        $Menu
    )

    # Extract all numbers from the string
    $numbers = [regex]::Matches(($Menu), '\d+\)').Count

    # Convert the extracted numbers to integers
    $intNumbers = $numbers | ForEach-Object { [int]$_ }

    # Find the highest number
    $maxNumber = $intNumbers | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum

    return [int]$maxNumber

}

# Little Helper Function to help format strings into the correct form for the menus
function FormatArrayToString{

    param(
        [Parameter(Mandatory = $true)]
        [Array]$Array # The string to be formatted
    )
        $userString  = ""

        # Fits them into a list capable of being displayed
        for ($i = 0; $i -lt $Array.Length; $i++){
                            
            if ($i -eq 0){
                $userString +=  " $($i + 1)) " + ($Array[$i])
            }
        
            else{
                $userString +=  "`n $($i + 1)) " + ($Array[$i])
            }
        }
    
    $userString += " `n $($Array.Length + 1)) Exit"
    return $userString

}

# Changes the selection position
function ChangeSelectionPosition{

    param (
        [Parameter(Mandatory = $true)]
        $Direction,
        $Menu
    )

    if ($Direction -eq "Up"){

        if ($global:SelectionPosition -eq 1){
            $global:SelectionPosition = (GetMaxOptions -Menu $Menu)
        }

        else{
            $global:SelectionPosition --
        }

    }

    elseif ($Direction -eq "Down"){

        if ($global:SelectionPosition -eq (GetMaxOptions -Menu $Menu)){
            $global:SelectionPosition = 1
        }

        else{
            $global:SelectionPosition ++
        }
    }
}

# Not really Efficient, but does not use any for loops and prints everything at once, so no more lag
# NOTE: Essentially the final version, not getting any better from here
function BuildMenuFrame{

    $mainMenuTitle = GetMenu($global:advanceView)
    $lines = $mainMenuTitle -split "`n"
    $lineIndex = 10
    $numberChar = 0
    $numberSpaces = 0

    # Gets the title
    $title = $lines[0..($lineIndex - 1)]

    # Gets the options, Black magic stuff, don't touch
    $options = $lines[$lineIndex..($lines.Length - 1)]
    $options = $options -join "`n"
    $highlight = $options -split [regex]::Escape([String]$global:SelectionPosition + ") ")
    $highlightOptions = ($highlight -split "`n")
    

    # Counts how many charters are in the string
    foreach($char in $highlightOptions[$global:SelectionPosition].ToCharArray()){

        if ($char -match "[a-zA-Z*/.]"){
            $numberChar ++
        }
    }

    # Gets the Start and The middle text
    $highlightOptionStart = $highlightOptions[[String]$global:SelectionPosition - 1]
    $highlightOptionText = (($highlightOptions[$global:SelectionPosition]).Substring(0, $numberChar + 5)).trimEnd()

    # Counts how many spaces are in the string
    foreach($char in $highlightOptionText.ToCharArray()){

        if ($char -match "[ ]"){
            $numberSpaces ++
        }
    }

    # Gets the end of the string
    $highlightOptionEnd = $highlightOptions[[String]$global:SelectionPosition].Substring($numberChar + $numberSpaces)


    $alreadySplit = $false
    $afterLines = ""

    # Gets all the lines after the option
    foreach ($line in $options -split "`n"){

        if ($alreadySplit -and -not $line.Contains("Choice")){
            $afterLines = $afterLines + $line + "`n"
        }

        if ($line.Contains([String]$global:SelectionPosition)){
            $alreadySplit = $true
        }
    }

    $optionsAfter = $afterLines
    $optionsBefore = $highlightOptions[0..($global:SelectionPosition - 2)] -join "`n"

    # Prints everything all at once
    Write-Host ($title -join "`n")

    if ($global:SelectionPosition -ne 1){
        Write-Host $optionsBefore
    }

    Write-Host ($highlightOptionStart + "$global:SelectionPosition) " ) -NoNewline
    Write-Host $highlightOptionText -BackgroundColor White -ForegroundColor Black -NoNewline
    Write-Host $highlightOptionEnd 
    Write-Host $optionsAfter

    # Prevents flickering, but adds input delay
    Start-Sleep -Milliseconds 40

}

# This is for the Sub options from the main menu, will essentially replace the BuildFrame
# NOTE: Can not have any of these Charters in the text: ( ) \
function BuildSubOptionFrame{

    param (
        [Parameter(Mandatory = $true)]
        $Text
    )

    # If the user wants the new CLI, handles all options and key presses
    if ((Config("new_CLI"))){

        # Now in a while loop, so it will only return the output when selected
        While ($true){

            ScreenClear
            
            # Eventually the same as the BuildMenuFrame, but with a few changes
            $mainMenuTitle = BuildFrame -Text $Text -NoOutput $true
            $lines = $mainMenuTitle -split "`n"
            $lineIndex = 1
            $numberChar = 0
            $numberSpaces = 0

            # Gets the title
            $title = $lines[0]
            
            # Gets the options, Black magic stuff, don't touch
            $options = $lines[$lineIndex..($lines.Length - 1)]
            $options = $options -join "`n"
            $highlight = $options -split [regex]::Escape([String]$global:SelectionPosition + ") ")
            $highlightOptions = ($highlight -split "`n")

            # Counts how many charters are in the string
            foreach($char in $highlightOptions[$global:SelectionPosition].ToCharArray()){

                if ($char -match "[a-zA-Z*/.1-9-_]"){
                    $numberChar ++
                }
            }

            # Gets the Start and The middle text
            $highlightOptionStart = $highlightOptions[[String]$global:SelectionPosition - 1]

            # Had to fix the bug that was here
            $highlightOptionText = (($highlightOptions[$global:SelectionPosition].Replace("|", "")).TrimEnd())
        
            # Counts how many spaces are in the string
            foreach($char in $highlightOptionText.ToCharArray()){

                if ($char -match "[ ]"){
                    $numberSpaces ++
                }
            }

            # Gets the end of the string
            $highlightOptionEnd = $highlightOptions[[String]$global:SelectionPosition].Substring($numberChar + $numberSpaces)

            $alreadySplit = $false
            $afterLines = ""

            # Gets all the lines after the option
            foreach ($line in $options -split "`n"){

                if ($alreadySplit -and -not $line.Contains("Choice")){
                    $afterLines = $afterLines + $line + "`n"
                }

                if ($line.Contains([String]$global:SelectionPosition + ")") ){
                    $alreadySplit = $true
                }
            }

            $optionsAfter = $afterLines
            $optionsBefore = $highlightOptions[0..($global:SelectionPosition - 2)] -join "`n"

            # This is how far out it goes till its in the middle of the terminal 
            $paddingX = " " * (GetCenterX -Text $mainMenuTitle)

            # This is how far down it goes till its in the middle of the terminal
            $paddingY = GetCenterY -Text $mainMenuTitle

            # Add padding to each line in optionsBefore
            $optionsBeforePadded = ""
            foreach ($line in $optionsBefore -split "`n") {
                $optionsBeforePadded +=  "`n" + $paddingX + $line 
                $optionsBeforePadded = $optionsBeforePadded.TrimStart("`n")
            }

            # Add padding to each line in optionsAfter
            $optionsAfterPadded = ""
            foreach ($line in $optionsAfter -split "`n") {
                $optionsAfterPadded +=  "`n" + $paddingX + $line 
                $optionsAfterPadded = $optionsAfterPadded.TrimStart("`n")
            }

            $optionsAfter = $optionsAfterPadded
            $optionsBefore = $optionsBeforePadded

            # Does the Top Padding
            Write-Host ("`n" * $paddingY) -NoNewline
            
            # Prints everything all at once
            Write-Host ($paddingX + ($title -join "`n"))

            if ($global:SelectionPosition -ne 1){
                Write-Host ( $optionsBefore)
            }

            Write-Host ($paddingX + $highlightOptionStart + "$global:SelectionPosition) ") -NoNewline
            Write-Host ($highlightOptionText) -BackgroundColor White -ForegroundColor Black -NoNewline
            Write-Host ($highlightOptionEnd) 
            Write-Host ($optionsAfter)
            

            $key = [Console]::ReadKey($true)

            # Switch statement to handle the key presses
            switch ($key.Key) {
                'UpArrow' {
                    ChangeSelectionPosition -Direction "Up" -Menu (BuildFrame -Text $Text -NoOutput $true)
                    
                }
                'DownArrow' {
                    ChangeSelectionPosition -Direction "Down" -Menu (BuildFrame -Text $Text -NoOutput $true)
                
                }
                'Enter' {

                    $choice = [string]$global:SelectionPosition
                    $global:SelectionPosition = 1
                    return $choice

                }
                'Escape'{

                    $exitNumber = (GetMaxOptions -Menu  (BuildFrame -Text $Text -NoOutput $true))
                    $global:SelectionPosition = 1
                    return $exitNumber
                    
                }

                default {

                    # If the key you press is a digit
                    if ($key.KeyChar -match '^\d$' -or $key.Modifiers -band [ConsoleModifiers]::Shift) {

                        # If the shift key is pressed
                        if ($key.Modifiers -band [ConsoleModifiers]::Shift -and $key.Key -ge 'D0' -and $key.Key -le 'D9') {

                            # Handle the case where Shift and a number are pressed
                            $shiftedNumber = ([int]([string]($key.Key)).replace("D", "")) + 10

                            if ($shiftedNumber -ge 1 -and $shiftedNumber -le (GetMaxOptions -Menu (BuildFrame -Text $Text -NoOutput $true))){

                                if ($shiftedNumber -eq $global:SelectionPosition){

                                    $choice = [string]$global:SelectionPosition
                                    $global:SelectionPosition = 1
                                    return $choice

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
                        if ($numberPressed -ge 1 -and $numberPressed -le (GetMaxOptions -Menu (BuildFrame -Text $Text -NoOutput $true))) {

                            # Will enter for you if you press the number while its already selected
                            if ($numberPressed -eq $global:SelectionPosition){

                                $choice = [string]$global:SelectionPosition
                                $global:SelectionPosition = 1
                                return $choice

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
            
            # Prevents Flickering, but adds input delay
            Start-Sleep -Milliseconds 30  
        
        }
    }

    # If the user does not want the new CLI
    else{

        # Must enter to have a return value
        While ($true){

            $frameText = BuildFrame -text $Text -NoOutput $true
            ScreenClear
            Write-Host $frameText
            $choice = Read-Host -Prompt "Choice"

            if ($choice.Length -gt 0){
                return $choice
            }

            Start-Sleep -Milliseconds 30 

        }
    }
}

# NOTE: If ya looking closely, its the same logic as Center Text, but with enough changes that I just could not call CenterText
# Essentially the same thing as BuildSubOptionFrame, but it prints text below the frame, There is no input handling
function BuildSubTerminalText{

    param(
        [Parameter(Mandatory = $true)]
        [string]$Text, # The text to be displayed
        
        [bool]$Border = $true # Adds a border
    )

    if ((Config("new_CLI"))){

        $text = $text + "`n`nPress Anything to Continue"

        $text = $text -replace "`t", "  "   

        $maxLength = ($Text -split "`n" | Measure-Object -Property Length -Maximum).Maximum
        $height = ($Text -split "`n").Count
        $centerX =  (GetCenterX -Text $Text) - 1
        $centerY = 5

        if ($Border){
            $borderText = '[' + ('-' * ($maxLength + 2)) + ']'
        }

        else{
            $borderText = '' + ('' * ($maxLength + 2)) + ''
        }

        $paddingX = ' ' * $centerX
        $paddingY = ("`n" * (([math]::Floor(($centerY - $height / 2))) - 2))


        $lines = $Text -split "`n"
        $paddedLines = $lines | ForEach-Object {  
            if ($_ -eq $lines[0]) {

                if ($Border){
                    ("| " + $_.PadRight($maxLength) + " |")
                }
                else{
                    (" " + $_.PadRight($maxLength) + " ")
                }
                    
            } 
            
            else {
                if ($Border){
                    ("`n$paddingX| " + $_.PadRight($maxLength) + " |")
                }
                else{
                    ("`n$paddingX " + $_.PadRight($maxLength) + " ")
                }
            } 
        }


        $centerXPadding = ' ' * ($centerX + [math]::Floor($maxLength / 2))

        # Animation Style boi
        for ($i = 0; $i -lt $centerY - 1; $i++) {

            
            Write-Host ($centerXPadding + "|" + "`n") -NoNewline
            
            Start-Sleep -Milliseconds 50
        }

        Write-Host $arrow

        # Writes everything out at once to prevent lagging
        Write-Host ($paddingX + $borderText) 
        Write-Host ($paddingX + $paddedLines)

        # Adds the bottom padding
        if ($BottomPadding){
            Write-Host ($paddingX + $borderText + $paddingY)
        }

        else{
            Write-Host ($paddingX + $borderText)
        }
        
        GetKeyInput -Return $false

    }

    else{
        
        Write-Host $Text
        Read-Host -Prompt "Press Enter to continue"

    }
}
