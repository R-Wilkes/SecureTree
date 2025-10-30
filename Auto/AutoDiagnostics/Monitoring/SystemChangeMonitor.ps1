

# Monitors all the system changes across all the computers

# IDK if logging needs to be on

# Needed to run properly
# -------------------------------------
$global:rootPath = $env:IRSec_RootPath
Set-Location -Path "$rootPath"

# Imports the functions needed
Import-Module -Name "./Data/CommonFunctions/CommonFunctions"

# Set as global variables in the new process
$global:version = $env:IRSec_Version
$global:curuser = $env:IRSec_CurUser
$global:computerName = $env:IRSec_ComputerName
# -------------------------------------

# Should monitor computers for system changes | AI
function Start-SystemChangeMonitor {
    param(
        [int]$RefreshInterval = 5,
        [string[]]$ComputerNames = @()  # Empty = all domain computers
    )

    $hour = (Get-Date).Hour
    $sec = (Get-Date).Second
    $min = (Get-Date).Minute

    $logPath = "./Logs/SystemChangeMonitorLog-$hour-$min-$sec.txt"
    CreatePath -DirectoryPath $logPath -Type "File"

    $date = Get-Date 
    "IRSec SystemChangeMonitor Log" >> $logPath
    "`nWritten On: $date" >> $logPath
    "`nProgram Version: $version" >> $logPath 
    "`nPowershell Version: $($PSVersionTable.PSVersion)" >> $logPath
    "`nUser Logged in: $curuser" >> $logPath
    "`nComputer Name: $computerName`n`n`n" >> $logPath
        
    
    Write-Host "Starting real-time system change monitor..." -ForegroundColor Green
    Write-Host "Monitoring: Services, Processes, Network Services (SSH, SMB, etc.)" -ForegroundColor Cyan
    Write-Host "Press Ctrl+C to stop monitoring`n" -ForegroundColor Yellow
    
    # Get domain computers if none specified
    if ($ComputerNames.Count -eq 0) {
        try {
            Import-Module ActiveDirectory
            $ComputerNames = Get-ADComputer -Filter {OperatingSystem -like "*Windows*"} | Select-Object -ExpandProperty Name
            Write-Host "Monitoring $($ComputerNames.Count) domain computers" -ForegroundColor Cyan
        } catch {
            Write-Error "Failed to get domain computers: $($_.Exception.Message)"
            return
        }
    }
    
    # Baseline data storage
    $serviceBaseline = @{}
    $processBaseline = @{}
    $networkBaseline = @{}
    $scanCount = 0
    
    # Key services to monitor
    $criticalServices = @(
        'SSH', 'SSHD', 'OpenSSH', 'LanmanServer', 'Server', 'Workstation',
        'RemoteRegistry', 'WinRM', 'TermService', 'RpcSs', 'Spooler',
        'BITS', 'Schedule', 'EventLog', 'Dhcp', 'DNS', 'W32Time',
        'Netlogon', 'NTDS', 'ADWS', 'KDC', 'FTP', 'IIS', 'Apache'
    )
    
    while ($true) {
        $scanCount++
        $computerIndex = 0
        
        foreach ($computer in $ComputerNames) {
            $computerIndex++
            
            # Update progress
            Write-Progress -Activity "System Change Monitor - Scan #$scanCount" -Status "Checking: $computer ($computerIndex of $($ComputerNames.Count))" -PercentComplete ([math]::Round(($computerIndex / $ComputerNames.Count) * 100))
            
            try {
                # Test connection first
                if (-not (Test-Connection -ComputerName $computer -Count 1 -Quiet)) {
                    continue
                }
                
                # Get current services
                $currentServices = Get-Service -ComputerName $computer | Where-Object {
                    $_.Name -in $criticalServices -or
                    $_.DisplayName -match "SSH|SMB|Remote|FTP|HTTP|Telnet|VNC|RDP"
                } | Select-Object Name, Status, StartType
                
                # Get current processes (executables)
                $currentProcesses = Get-Process -ComputerName $computer | Where-Object {
                    $_.ProcessName -match "ssh|smb|ftp|http|apache|nginx|iis|telnet|vnc|rdp|powershell|cmd|wmic"
                } | Select-Object ProcessName, Id, StartTime, Path
                
                # Get network connections
                $networkConnections = Invoke-Command -ComputerName $computer -ScriptBlock {
                    Get-NetTCPConnection | Where-Object {
                        $_.LocalPort -in @(22, 445, 139, 21, 80, 443, 3389, 5985, 5986, 23) -or
                        $_.RemotePort -in @(22, 445, 139, 21, 80, 443, 3389, 5985, 5986, 23)
                    } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
                } -ErrorAction SilentlyContinue
                
                # Initialize baseline if first scan
                if ($scanCount -eq 1) {
                    $serviceBaseline[$computer] = $currentServices
                    $processBaseline[$computer] = $currentProcesses
                    $networkBaseline[$computer] = $networkConnections
                    continue
                }
                
                # Compare services
                $serviceChanges = Compare-Object $serviceBaseline[$computer] $currentServices -Property Name, Status, StartType
                foreach ($change in $serviceChanges) {
                    Write-Progress -Activity "System Change Monitor" -Completed
                    
                    $changeType = if ($change.SideIndicator -eq '=>') { "NEW/CHANGED" } else { "REMOVED/CHANGED" }
                    $color = if ($change.SideIndicator -eq '=>') { 'Yellow' } else { 'Red' }
                    
                    $message = "[$(Get-Date)] SERVICE $changeType - $computer - $($change.Name) - Status: $($change.Status) - StartType: $($change.StartType)"
                    Write-Host $message -ForegroundColor $color
                }
                
                # Compare processes
                $processChanges = Compare-Object $processBaseline[$computer] $currentProcesses -Property ProcessName, Path
                foreach ($change in $processChanges) {
                    Write-Progress -Activity "System Change Monitor" -Completed
                    
                    $changeType = if ($change.SideIndicator -eq '=>') { "NEW PROCESS" } else { "PROCESS ENDED" }
                    $color = if ($change.SideIndicator -eq '=>') { 'Cyan' } else { 'Gray' }
                    
                    $message = "[$(Get-Date)] $changeType - $computer - $($change.ProcessName) - Path: $($change.Path)"
                    Write-Host $message -ForegroundColor $color
                }
                
                # Compare network connections
                $networkChanges = Compare-Object $networkBaseline[$computer] $networkConnections -Property LocalPort, RemoteAddress, RemotePort, State
                foreach ($change in $networkChanges) {
                    Write-Progress -Activity "System Change Monitor" -Completed
                    
                    $changeType = if ($change.SideIndicator -eq '=>') { "NEW CONNECTION" } else { "CONNECTION CLOSED" }
                    $color = if ($change.SideIndicator -eq '=>') { 'Magenta' } else { 'DarkGray' }
                    
                    $message = "[$(Get-Date)] $changeType - $computer - $($change.LocalAddress):$($change.LocalPort) -> $($change.RemoteAddress):$($change.RemotePort) - $($change.State)"
                    Write-Host $message -ForegroundColor $color
                }
                
                # Update baselines
                $serviceBaseline[$computer] = $currentServices
                $processBaseline[$computer] = $currentProcesses
                $networkBaseline[$computer] = $networkConnections
                
            } catch {
                # Skip unreachable computers silently
            }
        }
        
        Write-Progress -Activity "System Change Monitor - Scan #$scanCount" -Status "Scan complete - Waiting $RefreshInterval seconds" -PercentComplete 100
        Start-Sleep -Seconds $RefreshInterval
        Write-Progress -Activity "System Change Monitor" -Completed
    }
}

function Start-EventBasedSystemMonitor {
    param(
        [int]$RefreshInterval = 30,
        [string[]]$ComputerNames = @()
    )
    
    Write-Host "Starting event-based system monitor..." -ForegroundColor Green
    Write-Host "Monitoring: Service changes, Process creation, System modifications" -ForegroundColor Cyan
    
    if ($ComputerNames.Count -eq 0) {
        Import-Module ActiveDirectory
        $ComputerNames = Get-ADComputer -Filter {OperatingSystem -like "*Windows*"} | Select-Object -ExpandProperty Name
    }
    
    $lastCheck = Get-Date
    $scanCount = 0
    
    while ($true) {
        $scanCount++
        $computerIndex = 0
        
        foreach ($computer in $ComputerNames) {
            $computerIndex++
            
            Write-Progress -Activity "NOTE: NOT TESTED FULLY | Event Monitor - Scan #$scanCount" -Status "Checking: $computer ($computerIndex of $($ComputerNames.Count))" -PercentComplete ([math]::Round(($computerIndex / $ComputerNames.Count) * 100))
            
            try {
                # Service Control Manager events (7034, 7035, 7036, 7040)
                $serviceEvents = Get-WinEvent -ComputerName $computer -FilterHashtable @{
                    LogName = 'System'
                    ID = 7034, 7035, 7036, 7040
                    StartTime = $lastCheck
                } -ErrorAction SilentlyContinue
                
                # Process creation events (4688) - requires audit policy
                $processEvents = Get-WinEvent -ComputerName $computer -FilterHashtable @{
                    LogName = 'Security'
                    ID = 4688, 4689
                    StartTime = $lastCheck
                } -ErrorAction SilentlyContinue
                
                # System events
                $systemEvents = Get-WinEvent -ComputerName $computer -FilterHashtable @{
                    LogName = 'System'
                    ID = 1074, 6005, 6006, 6008, 6009
                    StartTime = $lastCheck
                } -ErrorAction SilentlyContinue
                
                # Process service events
                foreach ($localEvent in $serviceEvents) {
                    Write-Progress -Activity "Event Monitor" -Completed
                    
                    $eventData = $localEvent.Message
                    $serviceName = ""
                    
                    if ($eventData -match "service name is (.+?)\.") {
                        $serviceName = $matches[1]
                    }
                    
                    $eventType = switch ($localEvent.Id) {
                        7034 { "SERVICE CRASHED" }
                        7035 { "SERVICE CONTROL" }
                        7036 { "SERVICE STATE CHANGE" }
                        7040 { "SERVICE STARTUP TYPE CHANGED" }
                    }
                    
                    $color = switch ($localEvent.Id) {
                        7034 { 'Red' }
                        7040 { 'Yellow' }
                        default { 'Cyan' }
                    }

                    if ($serviceName = ""){
                        Write-Host $eventData
                    }
                    
                    $message = "[$(Get-Date)] $eventType - $computer - Service: $serviceName"
                    Write-Host $message -ForegroundColor $color
                }
                
                # Process creation/termination events
                foreach ($localEvent in $processEvents) {
                    Write-Progress -Activity "Event Monitor" -Completed
                    
                    $xml = [xml]$localEvent.ToXml()
                    $eventData = $xml.Event.EventData.Data
                    
                    $processName = ($eventData | Where-Object {$_.Name -eq 'NewProcessName'}).'#text'
                    $commandLine = ($eventData | Where-Object {$_.Name -eq 'CommandLine'}).'#text'
                    
                    if ($processName -match "ssh|smb|ftp|http|apache|nginx|powershell|cmd|wmic|net\.exe") {
                        $eventType = if ($localEvent.Id -eq 4688) { "PROCESS CREATED" } else { "PROCESS TERMINATED" }
                        $color = if ($localEvent.Id -eq 4688) { 'Green' } else { 'Gray' }
                        
                        $message = "[$(Get-Date)] $eventType - $computer - Process: $processName - Command: $commandLine"
                        Write-Host $message -ForegroundColor $color
                    }
                }
                
                # System events
                foreach ($localEvent in $systemEvents) {
                    Write-Progress -Activity "Event Monitor" -Completed
                    
                    $eventType = switch ($localEvent.Id) {
                        1074 { "SYSTEM SHUTDOWN" }
                        6005 { "EVENT LOG STARTED" }
                        6006 { "EVENT LOG STOPPED" }
                        6008 { "UNEXPECTED SHUTDOWN" }
                        6009 { "SYSTEM STARTED" }
                    }
                    
                    $message = "[$(Get-Date)] $eventType - $computer"
                    Write-Host $message -ForegroundColor Magenta
                }
                
            } catch {
                # Skip unreachable computers
            }
        }
        
        $lastCheck = Get-Date
        Write-Progress -Activity "Event Monitor - Scan #$scanCount" -Status "Complete - Waiting $RefreshInterval seconds" -PercentComplete 100
        Start-Sleep -Seconds $RefreshInterval
        Write-Progress -Activity "Event Monitor" -Completed
    }
}

# Start event-based monitoring
Start-EventBasedSystemMonitor

# Start monitoring (all domain computers)
# Start-SystemChangeMonitor

# Or monitor specific computers:
# Start-SystemChangeMonitor -ComputerNames @("SERVER1", "WORKSTATION1", "DC1")