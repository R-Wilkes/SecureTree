
# The new CLI is fancy stuff
Import-Module -Name "./Data/FrameBuilder/CLIBuilder" -Force
Import-Module -Name "./Data/FrameBuilder/LoadingScreen" -Force

# Cool ass frame builder for text because why not, and as i said, im going all out

# Just in case I ever want to switch back
# ╔ ═ ╗ ║ ╚ ╝

# Used to build a frame around text, makes the script look cool, This is being Replace by the CLIBuilder, same function, but includes options for NEW CLI
function BuildFrame {
    
    param (
        [string]$Text, # Text to ouptut
        [bool]$NoOutput # Return the value rather than printing it
    )
    
    try{

        $fullString = ""

        # Split the text into lines
        $lines = $Text -split "`n"
        
        # Calculate the maximum length of the text
        $maxLength = ($lines | ForEach-Object { $_.Length }) | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum
        
        # Create the top border
        $borderTop = '[' + ('-' * ($maxLength + 2)) + ']' + "`n"
        

        if (-not $NoOutput){
            # Print the top border
            Write-Host $borderTop -NoNewline
        }

        else{
            $fullString += $borderTop
        }
        
        # Print each line with borders
        foreach ($line in $lines) {
            $paddedLine = $line.PadRight($maxLength)

            if (-not $NoOutput){
                Write-Host ('| ' + $paddedLine + ' |')
            }
            
            else{
                $fullString += ('| ' + $paddedLine + ' |' + "`n")
            }
        }
        
        # Create the bottom border
        $borderBottom = '[' + ('-' * ($maxLength + 2)) + ']'
        
         # Print the bottom border
        if (-not $NoOutput){
            Write-Host $borderBottom
        }
        
        else{
            
            $fullString += $borderBottom
            return $fullString

        }
    }

    # If fail
    catch{

        Write-Error "Set the 'fancy_boarder' in config to 'False' or 'Ask'"

    }
}

# No way to get points
function ProgressText {

    return "                     "
}

# Used to center text in the console
function CenterText {
    
    param (
        [Parameter(Mandatory = $true)]
        [string]$Text, # Text You want to center
        
        [bool]$Border = $false, # Adds a border around the text
        [bool]$FullBorder = $false, # Adds a border around the entire console
        [bool]$BottomPadding = $true, # Adds padding to the bottom of the text
        [bool]$ReturnOutput = $false, # Returns the output instead of printing it

        [string]$PromptString = "", # Prompts uses with this text, does not work with ReturnOutput or Border
        [bool]$SecureString = $false # Makes the prompt a secure string
    )
    
    # Prevents certain params from being used together
    if ($PromptString.Length -gt 0 -and $Border){
        Write-Error "You cannot use a prompt with a border, please remove the border or the prompt" -ErrorAction Stop
    }

    if ($PromptString.Length -gt 0 -and $ReturnOutput){
        Write-Error "You cannot use a prompt with return output, please remove the return output or the prompt" -ErrorAction Stop
    }

    # Remove tabs and new lines
    $Text = $Text -replace "`t", "  "
    $Text = $Text -replace "`r", ""

    # Borders the entire screen
    # TODO: Come back to this Possible, need to make it full border around the terminal
    if ($fullBorder){
        
        $consoleWidth = [Console]::WindowWidth
        $consoleHeight = [Console]::WindowHeight

        $borderTop = '+' + ('-' * ($consoleWidth - 2)) + '+'
        $borderBottom = '+' + ('-' * ($consoleWidth - 2)) + '+'
        $emptyLine = '|' + (' ' * ($consoleWidth - 2)) + '|'

        $centerX = [Math]::Floor(($consoleWidth - $maxLength) / 2)
        $centerY = [Math]::Floor(($consoleHeight - $height) / 2)

        Write-Host $borderTop
        for ($i = 1; $i -lt $centerY; $i++) {
            Write-Host $emptyLine
        }

        $lines = $Text -split "`n"
        foreach ($line in $lines) {
            $paddedLine = $line.PadRight($maxLength)
            Write-Host ('|' + (' ' * ($centerX - 1)) + $paddedLine + (' ' * ($consoleWidth - $centerX - $maxLength - 1)) + '|')
        }

        for ($i = ($centerY + $height); $i -lt ($consoleHeight - 1); $i++) {
            Write-Host $emptyLine
        }
        Write-Host $borderBottom

    }

    else{
        
        $maxLength = ($Text -split "`n" | Measure-Object -Property Length -Maximum).Maximum
        $height = ($Text -split "`n").Count
        $centerX = [Math]::Max([Math]::Floor(([Console]::WindowWidth - $maxLength) / 2), 0)
        $centerY = [Math]::Floor(([Console]::WindowHeight - 5) / 2)

        if ($Border){
            $borderText = '[' + ('-' * ($maxLength + 2)) + ']'
        }

        else{
            $borderText = '' + ('' * ($maxLength + 2)) + ''
        }

        $paddingX = ' ' * $centerX
        $paddingY = ("`n" * ([math]::Floor(($centerY - $height / 2))))


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

        # Will return the output instead of printing it
        if ($ReturnOutput){

            # Adds the bottom padding
            if ($BottomPadding){
                return ($paddingY + $paddingX + $borderText + "`n" + $paddingX + $paddedLines + "`n" + $paddingX + $borderText + $paddingY)
            }

            else{
                return ($paddingY + $paddingX + $borderText + "`n" + $paddingX + $paddedLines + "`n" + $paddingX + $borderText)
            }
        }

        else{

            # Adding this here so I don't have to keep screen clearing
            ScreenClear

            # Writes everything out at once to prevent lagging
            Write-Host ($paddingY + $paddingX + $borderText) 
            Write-Host ($paddingX + $paddedLines) 

            # Will print out input thingy
            if ($PromptString.Length -gt 0){

                if ($BottomPadding){

                    $inputX = [Math]::Floor(([Console]::WindowWidth - $PromptString.Length) / 2)
                    $inputY = [Math]::Floor(([Console]::WindowHeight) / 2)
                
                    # Set the cursor position to the calculated location
                    [Console]::SetCursorPosition($inputX, $inputY)

                    if ($SecureString){
                        $answer = Read-Host -Prompt ($PromptString) -AsSecureString
                    }

                    else{
                        $answer = Read-Host -Prompt ($PromptString)
                    }

                }

                else{

                    if ($SecureString){
                        $answer = Read-Host -Prompt ($paddingX + $PromptString) -AsSecureString
                    }

                    else{
                        $answer = Read-Host -Prompt ($paddingX + $PromptString)
                    }
                    
                }
                
                return $answer
               
            }

            # Adds the bottom padding
            if ($BottomPadding){
                Write-Host ($paddingX + $borderText + $paddingY)
            }

            else{
                Write-Host ($paddingX + $borderText)
            }
        }
    }
}

# Returns the center of the console Based on the Text
function GetCenterX {
    param (
        [string]$Text
    )

    $maxLength = ($Text -split "`n" | Measure-Object -Property Length -Maximum).Maximum
    $centerX = [Math]::Floor(([Console]::WindowWidth - $maxLength) / 2)

    return $centerX
}

# Returns the center of the console Based on the Text but for the Y value
function GetCenterY {
    param (
        [string]$Text
    )

    $height = ($Text -split "`n").Count
    $centerY = [Math]::Floor(([Console]::WindowHeight - $height) / 2)

    return $centerY
}