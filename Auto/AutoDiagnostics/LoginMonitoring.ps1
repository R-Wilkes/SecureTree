# Monitors all the logging events for users 
# Only reports logged in, logged out, failure to login

# Must make sure all group logging is on, Red team def turns that off

# This is AI, lots of prompting tho | AI
function Start-DomainLogonMonitor {
    param(
        [int]$RefreshInterval = 2  # Check every 1 second
    )
    
    Write-Host "Starting real-time domain logon monitor..." -ForegroundColor Green
    Write-Host "Press Ctrl+C to stop monitoring`n" -ForegroundColor Yellow
    
    # Get only Domain Controllers instead of all computers
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $domainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
        Write-Host "Monitoring $($domainControllers.Count) Domain Controllers" -ForegroundColor Cyan
        foreach ($dc in $domainControllers) {
            Write-Host "  - $dc" -ForegroundColor Gray
        }
        
        # Get all AD users and admins for filtering
        Write-Host "Loading AD users and administrators..." -ForegroundColor Yellow
        $allADUsers = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
        $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" | Select-Object -ExpandProperty SamAccountName
        $enterpriseAdmins = Get-ADGroupMember -Identity "Enterprise Admins" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName
        $localAdmins = Get-ADGroupMember -Identity "Administrators" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName
        
        # Combine all admin accounts
        $allAdmins = @()
        if ($domainAdmins) { $allAdmins += $domainAdmins }
        if ($enterpriseAdmins) { $allAdmins += $enterpriseAdmins }
        if ($localAdmins) { $allAdmins += $localAdmins }
        $allAdmins = $allAdmins | Sort-Object -Unique
        
        Write-Host "Loaded $($allADUsers.Count) AD users and $($allAdmins.Count) admin accounts" -ForegroundColor Green
        
    }
    catch {
        Write-Error "Failed to get domain controllers or AD users: $($_.Exception.Message)"
        return
    }
    
    # Start checking from 2 seconds ago to ensure we don't miss any events
    $lastCheck = (Get-Date).AddSeconds(-2)
    $scanCount = 0
    $totalEvents = 0
    $totalLogins = 0
    $totalFailures = 0
    $totalKerberos = 0
    $processedEvents = @{}  # Track processed events to avoid duplicates
    
    while ($true) {
        $currentTime = Get-Date
        $scanCount++
        $dcIndex = 0
        
        foreach ($dc in $domainControllers) {
            $dcIndex++
            
            # Update progress bar
            Write-Progress -Activity "Domain Logon Monitor" -Status "Scan #$scanCount - Checking DC: $dc ($dcIndex of $($domainControllers.Count))" -PercentComplete ([math]::Round(($dcIndex / $domainControllers.Count) * 100)) -CurrentOperation "Events: $totalEvents | Logins: $totalLogins | Failures: $totalFailures | Kerberos: $totalKerberos"
            
            try {
                # Get recent logon events from Domain Controllers only
                # Added 4771 for Kerberos pre-authentication failures (invalid credentials)
                $events = Get-WinEvent -ComputerName $dc -FilterHashtable @{
                    LogName = 'Security'
                    ID = 4624, 4625, 4634, 4647, 4771  # 4771 = Kerberos pre-auth failure (invalid creds)
                    StartTime = $lastCheck
                } -ErrorAction SilentlyContinue
                
                foreach ($localEvent in $events) {
                    # Create unique event ID to avoid processing duplicates
                    $eventKey = "$($localEvent.Id)-$($localEvent.RecordId)-$($localEvent.TimeCreated.Ticks)"
                    
                    # Skip if we've already processed this event
                    if ($processedEvents.ContainsKey($eventKey)) {
                        continue
                    }
                    
                    # Mark event as processed
                    $processedEvents[$eventKey] = $true
                    
                    $xml = [xml]$localEvent.ToXml()
                    $eventData = $xml.Event.EventData.Data
                   
                    $username = ($eventData | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
                    $domain = ($eventData | Where-Object {$_.Name -eq 'TargetDomainName'}).'#text'
                    $logonType = ($eventData | Where-Object {$_.Name -eq 'LogonType'}).'#text'
                    $sourceIP = ($eventData | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
                    $workstation = ($eventData | Where-Object {$_.Name -eq 'WorkstationName'}).'#text'
                    
                    # Handle different event types
                    if ($localEvent.Id -eq 4625) {
                        $subStatus = ($eventData | Where-Object {$_.Name -eq 'SubStatus'}).'#text'
                        $failureReason = ($eventData | Where-Object {$_.Name -eq 'FailureReason'}).'#text'
                        $status = ($eventData | Where-Object {$_.Name -eq 'Status'}).'#text'
                    } elseif ($localEvent.Id -eq 4771) {
                        # Kerberos pre-authentication failure
                        $status = ($eventData | Where-Object {$_.Name -eq 'Status'}).'#text'
                        $preAuthType = ($eventData | Where-Object {$_.Name -eq 'PreAuthType'}).'#text' 
                        $serviceTicket = ($eventData | Where-Object {$_.Name -eq 'ServiceName'}).'#text' 
                        $clientAddress = ($eventData | Where-Object {$_.Name -eq 'IpAddress'}).'#text'

                        $preAuthType | Out-Null
                        $serviceTicket | Out-Null
                        
                        # For 4771, use client address if source IP not available
                        if (-not $sourceIP -and $clientAddress) {
                            $sourceIP = $clientAddress
                        }
                    }
                    
                    # Filter to only show AD users and admins (exclude system accounts, computer accounts, and non-AD users)
                    # Also show failed attempts for non-existent users (potential attacks)
                    if ($username -in $allADUsers -or ($localEvent.Id -in @(4625, 4771) -and $username -ne '')) {
                        
                        # Determine if user is an admin (only for existing users)
                        $isAdmin = $username -in $allAdmins
                        $userExists = $username -in $allADUsers
                        
                        if ($userExists) {
                            $userType = if ($isAdmin) { "[ADMIN]" } else { "[USER]" }
                        } else {
                            $userType = "[UNKNOWN]"
                        }
                        
                        $logonTypeText = switch ($logonType) {
                            '2' { 'Interactive' }
                            '3' { 'Network' }
                            '10' { 'RDP' }
                            '11' { 'Cached' }
                            default { "Type $logonType" }
                        }
                        
                        $sourceText = if ($sourceIP -and $sourceIP -ne '-') { " from $sourceIP" } else { "" }
                        $workstationText = if ($workstation -and $workstation -ne '-') { " (Workstation: $workstation)" } else { "" }
                        
                        # Clear progress bar for output
                        Write-Progress -Activity "Domain Logon Monitor" -Completed
                        
                        # Determine event type and set color/message
                        switch ($localEvent.Id) {
                            4624 {
                                # Successful login (only for existing AD users)
                                if ($userExists) {
                                    $statusText = "SUCCESS"
                                    $color = if ($isAdmin) { 'Magenta' } else { 'Green' }
                                    $message = "[$($localEvent.TimeCreated)] LOGIN $statusText - DC: $dc - $userType $domain\$username ($logonTypeText)$sourceText$workstationText"
                                    Write-Host $message -ForegroundColor $color
                                    $totalEvents++
                                    $totalLogins++
                                }
                            }
                            4625 {
                                # Failed login
                                $statusText = "FAILED"
                                
                                # Enhanced failure reason decoding with focus on password issues
                                $reasonText = switch ($subStatus) {
                                    '0xC0000064' { "User does not exist" }
                                    '0xC000006A' { "INVALID PASSWORD" }
                                    '0xC000006D' { "BAD USERNAME OR PASSWORD" }
                                    '0xC000006E' { "Account restriction" }
                                    '0xC000006F' { "Logon outside allowed time" }
                                    '0xC0000070' { "Workstation restriction" }
                                    '0xC0000071' { "Password expired" }
                                    '0xC0000072' { "Account disabled" }
                                    '0xC0000193' { "Account expired" }
                                    '0xC0000224' { "Password must change" }
                                    '0xC0000234' { "Account locked out" }
                                    '0xC000015B' { "Logon type not granted" }
                                    '0xC0000133' { "Time synchronization required" }
                                    '0xC000018C' { "Trust relationship failure" }
                                    '0xC0000413' { "Authentication firewall violation" }
                                    default { 
                                        if ($failureReason -and $failureReason -ne '') { 
                                            $failureReason 
                                        } elseif ($status -and $status -ne '') {
                                            "Status: $status, SubStatus: $subStatus"
                                        } else { 
                                            "SubStatus: $subStatus" 
                                        }
                                    }
                                }
                                
                                # Special highlighting for password-related failures
                                if ($subStatus -in @('0xC000006A', '0xC000006D')) {
                                    $color = 'DarkRed'
                                    $alertPrefix = "PASSWORD FAILURE"
                                } elseif ($subStatus -eq '0xC0000064') {
                                    $color = 'Red'
                                    $alertPrefix = "UNKNOWN USER"
                                } elseif ($subStatus -eq '0xC0000234') {
                                    $color = 'DarkRed'
                                    $alertPrefix = "ACCOUNT LOCKED"
                                } else {
                                    $color = 'Red'
                                    $alertPrefix = "LOGIN FAILED"
                                }
                                
                                $message = "[$($localEvent.TimeCreated)] $alertPrefix - DC: $dc - $userType $domain\$username ($logonTypeText)$sourceText$workstationText - $reasonText"
                                Write-Host $message -ForegroundColor $color
                                $totalEvents++
                                $totalFailures++
                            }
                            4771 {
                                # Kerberos pre-authentication failure (invalid credentials)
                                $statusText = "KERBEROS FAILURE"
                                $color = 'DarkRed'
                                
                                # Decode Kerberos failure status
                                $kerberosReason = switch ($status) {
                                    '0x18' { "WRONG PASSWORD" }
                                    '0x6' { "USER UNKNOWN" }
                                    '0x12' { "ACCOUNT DISABLED" }
                                    '0x17' { "PASSWORD EXPIRED" }
                                    '0x20' { "ACCOUNT LOCKED" }
                                    '0x25' { "CLOCK SKEW TOO GREAT" }
                                    default { "Status: $status" }
                                }
                                
                                $alertPrefix = if ($status -eq '0x18') { "KERBEROS PASSWORD FAILURE" } else { "KERBEROS FAILURE" }
                                
                                $message = "[$($localEvent.TimeCreated)] $alertPrefix - DC: $dc - $userType $domain\$username$sourceText$workstationText - $kerberosReason"
                                Write-Host $message -ForegroundColor $color
                                $totalEvents++
                                $totalKerberos++
                            }
                            4634 {
                                # Account logged off (only for existing AD users)
                                if ($userExists) {
                                    $statusText = "LOGOFF"
                                    $color = 'Yellow'
                                    $message = "[$($localEvent.TimeCreated)] $statusText - DC: $dc - $userType $domain\$username ($logonTypeText)$workstationText"
                                    Write-Host $message -ForegroundColor $color
                                    $totalEvents++
                                }
                            }
                            4647 {
                                # User initiated logoff (only for existing AD users)
                                if ($userExists) {
                                    $statusText = "USER LOGOFF"
                                    $color = 'Cyan'
                                    $message = "[$($localEvent.TimeCreated)] $statusText - DC: $dc - $userType $domain\$username$workstationText"
                                    Write-Host $message -ForegroundColor $color
                                    $totalEvents++
                                }
                            }
                        }
                    }
                }
            }
            catch {
                
            }
        }
        
        # Clean up old processed events (keep only last 1000 events to prevent memory issues)
        if ($processedEvents.Count -gt 1000) {
            $processedEvents = @{}
        }
        
        # Show final scan status
        Write-Progress -Activity "Domain Logon Monitor" -Status "Scan #$scanCount Complete - Waiting $RefreshInterval seconds" -PercentComplete 100 -CurrentOperation "Events: $totalEvents | Logins: $totalLogins | Failures: $totalFailures | Kerberos: $totalKerberos"
        
        # Update lastCheck to 1 second ago to ensure overlap and catch any missed events
        $lastCheck = $currentTime.AddSeconds(-1)
        Start-Sleep -Seconds $RefreshInterval
        
        # Clear progress for next scan
        Write-Progress -Activity "Domain Logon Monitor" -Completed
    }
}

# Start monitoring
Start-DomainLogonMonitor