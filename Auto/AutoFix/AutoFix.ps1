# Instead of reporting on issues, it actually fixes them, carful, very carful

# Just some info
ScreenClear
Write-Host "Starting AutoFix.ps1" -ForegroundColor Red
Write-Host "SCRIPT WILL MAKE CHANGES" -ForegroundColor Red
Start-Sleep $longSleep

$hour = (Get-Date).Hour
$sec = (Get-Date).Second
$min = (Get-Date).Minute

$logPath = ".\Logs\AutoFixLog-$hour-$min-$sec.txt"
CreatePath -DirectoryPath $logPath -Type "File"

# Out log file
$date = Get-Date 
"IRSec AutoFix Log" >> $logPath
"`nWritten On: $date" >> $logPath
"`nProgram Version: $version" >> $logPath 
"`nPowershell Version: $($PSVersionTable.PSVersion)" >> $logPath
"`nUser Logged in: $curuser" >> $logPath
"`nComputer Name: $computerName" >> $logPath

# Enables all of the firewall rules I have stolen
if ((Config("enable_firewall"))) {

    Write-Host "Setting Firewall Config..." -ForegroundColor Magenta
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True
    "`n Firewall: Enabled" >> $logPath

    # Stole this part of the code
    New-NetFirewallRule -DisplayName "Block Outbound Port 21" -Direction Inbound -LocalPort 21 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 22" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 23" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 25" -Direction Inbound -LocalPort 25 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 80" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 161" -Direction Inbound -LocalPort 161 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 162" -Direction Inbound -LocalPort 162 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 3389" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 4444" -Direction Inbound -LocalPort 4444 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 8080" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 8088" -Direction Inbound -LocalPort 8088 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound Port 8888" -Direction Inbound -LocalPort 8888 -Protocol TCP -Action Block
    "Disabled TCP 21, TCP 22, TCP 23, TCP 25, TCP 80, TCP 8080, TCP 3389, TCP 161 and 162, TCP and UDP on 389 and 636 from inbound rules" >> $logPath
    #UDP Ports
    New-NetFirewallRule -DisplayName "Block UDP Outbound Port 3389" -Direction Inbound -LocalPort 3389 -Protocol UDP -Action Block
    New-NetFirewallRule -DisplayName "Block UDP Outbound Port 161" -Direction Inbound -LocalPort 161 -Protocol UDP -Action Block
    New-NetFirewallRule -DisplayName "Block UDP Outbound Port 162" -Direction Inbound -LocalPort 162 -Protocol UDP -Action Block
    New-NetFirewallRule -DisplayName "Block UDP Outbound Port 389" -Direction Inbound -LocalPort 389 -Protocol UDP -Action Block
    New-NetFirewallRule -DisplayName "Block UDP Outbound Port 636" -Direction Inbound -LocalPort 636 -Protocol UDP -Action Block
    "Disabled UDP 3389, UDP 161, UDP 162, UDP 389, UDP 636" >> $logPath

    try {
        netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\SysWOW64\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\system32\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\SysWOW64\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\system32\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\SysWOW64\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\SysWOW64\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\system32\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\SysWOW64\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\system32\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\SysWOW64\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\system32\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\SysWOW64\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\system32\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\SysWOW64\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\SysWOW64\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\system32\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\SysWOW64\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\SysWOW64\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\system32\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\SysWOW64\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\system32\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\SysWOW64\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\SysWOW64\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\system32\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\SysWOW64\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\system32\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\SysWOW64\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\system32\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\SysWOW64\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\SysWOW64\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\system32\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\SysWOW64\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block rpcping.exe netconns" program="%systemroot%\SysWOW64\rpcping.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\system32\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\SysWOW64\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\SysWOW64\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\system32\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\SysWOW64\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\system32\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\system32\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\SysWOW64\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\SysWOW64\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        "Added a lot of firewall rules (I stole them)" >> $logPath

    }

    catch {

        Write-Output "$Error[0] $_" | Out-File "./Logs/ErrorLogs/FireWallError.txt"
        Write-host "Writing error to file" -ForegroundColor DarkYellow
        "ERRORS LOGGED for I have no clue what just happened" >> $logPath
        Start-Sleep 5

    }




}

# Sets passwords policy based on the config
if ((Config("set_password_policy"))) {

    Write-Host "Setting Password Policy Config..." -ForegroundColor Magenta
    Start-Sleep $shortSleep

    $minPasLen = Config("min_password_length")
    $minPasAge = Config("min_password_age")
    $maxPasAge = Config("max_password_age")
    $uniquePas = Config("unique_password")
    $lot = Config("lock_out_threshold")
    $lod = Config("lock_out_duration")

    # Sets Password Policys
    net accounts /minpwlen:$minPasLen
    net accounts /minpwage:$minPasAge
    net accounts /maxpwage:$maxPasAge
    net accounts /uniquepw:$uniquePas
    net accounts /lockoutthreshold:$lot
    net accounts /lockoutduration:$lod

    "`n Password Policy Config" >> $logPath
    " -Minimum Password Length: $minPasLen" >> $logPath
    " -Minimum Password Age: $minPasAge" >> $logPath
    " -Maximum Password Age: $maxPasAge" >> $logPath
    " -Unique Password: $uniquePas" >> $logPath
    " -Lock Out Threshold: $lot" >> $logPath
    " -Lock Out Duration: $lod" >> $logPath

}

# Auto Configs services that I stole from someone else
if ((Config("run_service_config"))) {

    # Doing this to prevent stupid errors and panicking the user
    # $ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    "`n Services: "  >> $logPath

    #Set Services
    $s = Get-Service -Name "TermService"
    Stop-Service -InputObject $s -Force
    Set-Service TermService -StartupType Disabled
    " Remote Desktop Services Stopped and Disabled"  >> $logPath

    $s2 = Get-Service -Name "RemoteRegistry"
    Stop-Service -InputObject $s2 -Force
    Set-Service RemoteRegistry -StartupType Disabled
    " Remote Registry Stopped and Disabled"  >> $logPath

    $s3 = Get-Service -Name "RpcLocator"
    Stop-Service -InputObject $s3 -Force
    Set-Service RpcLocator -StartupType Disabled
    " Remote Procedure Call (RPC) Locator Stopped and Disabled"  >> $logPath

    $s4 = Get-Service -Name "wuauserv"
    start-Service -InputObject $s4 
    Set-Service RpcLocator -StartupType Automatic
    " Windows Update is Started and Set to Automatic start" >> $logPath

    $s5 = Get-Service -Name "SharedAccess"
    Stop-Service -InputObject $s5 -Force
    Set-Service SharedAccess -StartupType Disabled
    " Internet Connection Sharing (ICS) Stopped and Disabled" >> $logPath

    $s6 = Get-Service -Name "SessionEnv"
    Stop-Service -InputObject $s6 -Force
    Set-Service SessionEnv -StartupType Disabled
    " Remote Desktop Configuration Stopped and Disabled"  >> $logPath

    $s7 = Get-Service -Name "SSDPSRV"
    Stop-Service -InputObject $s7 -Force
    Set-Service SSDPSRV -StartupType Disabled
    " SSDP Discovery Stopped and Disabled"  >> $logPath

    $s8 = Get-Service -Name "upnphost"
    Stop-Service -InputObject $s8 -Force
    Set-Service upnphost -StartupType Disabled
    " UPnP Device Host Stopped and Disabled" >> $logPath

    $s9 = Get-Service -Name "EventLog"
    start-Service -InputObject $s9 
    Set-Service EventLog -StartupType Automatic
    " Windows EventLog is Started and Set to Automatic start">> $logPath

    $s10 = Get-Service -Name "DcpSvc"
    Stop-Service -InputObject $s10 -Force
    Set-Service DcpSvc -StartupType Disabled
    " Data Collection and Publishing Service Stopped and Disabled">> $logPath

    $s11 = Get-Service -Name "DiagTrack"
    Stop-Service -InputObject $s11 -Force
    Set-Service DiagTrack -StartupType Disabled
    " Diagnostics Tracking Service Stopped and Disabled">> $logPath

    $s12 = Get-Service -Name "SensrSvc"
    Stop-Service -InputObject $s12 -Force
    Set-Service SensrSvc -StartupType Disabled
    " Monitors Various Sensors Stopped and Disabled">> $logPath

    $s13 = Get-Service -Name "dmwappushservice"
    Stop-Service -InputObject $s13  -Force
    Set-Service dmwappushservice -StartupType Disabled
    " Push Message Routing Service Stopped and Disabled">> $logPath

    $s14 = Get-Service -Name "lfsvc"
    Stop-Service -InputObject $s14  -Force
    Set-Service lfsvc -StartupType Disabled
    " Geolocation Service Stopped and Disabled">> $logPath

    $s15 = Get-Service -Name "MapsBroker"
    Stop-Service -InputObject $s15  -Force
    Set-Service MapsBroker -StartupType Disabled
    " Downloaded Maps Manager Stopped and Disabled">> $logPath

    $s16 = Get-Service -Name "NetTcpPortSharing"
    Stop-Service -InputObject $s16  -Force
    Set-Service NetTcpPortSharing -StartupType Disabled
    " Net.Tcp Port Sharing Service Stopped and Disabled">> $logPath

    $s17 = Get-Service -Name "RemoteAccess"
    Stop-Service -InputObject $s17  -Force
    Set-Service RemoteAccess -StartupType Disabled
    " Routing and Remote Access Stopped and Disabled">> $logPath

    $s18 = Get-Service -Name "TrkWks"
    Stop-Service -InputObject $s18  -Force
    Set-Service TrkWks -StartupType Disabled
    " Distributed Link Tracking Client Stopped and Disabled">> $logPath

    $s19 = Get-Service -Name "WbioSrvc"
    Stop-Service -InputObject $s19  -Force
    Set-Service WbioSrvc -StartupType Disabled
    " Windows Biometric Service Stopped and Disabled">> $logPath

    $s20 = Get-Service -Name "WMPNetworkSvc"
    Stop-Service -InputObject $s20  -Force
    Set-Service WMPNetworkSvc -StartupType Disabled
    " Windows Media Player Network Sharing Service Stopped and Disabled">> $logPath

    $s21 = Get-Service -Name "WSearch"
    Stop-Service -InputObject $s21  -Force
    Set-Service WSearch -StartupType Disabled
    " Windows Search Stopped and Disabled">> $logPath

    $s22 = Get-Service -Name "XblAuthManager"
    Stop-Service -InputObject $s22  -Force
    Set-Service XblAuthManager -StartupType Disabled
    " Xbox Live Auth Manager Stopped and Disabled">> $logPath

    $s23 = Get-Service -Name "XblGameSave"
    Stop-Service -InputObject $s23  -Force
    Set-Service XblGameSave -StartupType Disabled
    " Xbox Live Game Save Service Stopped and Disabled" >> $logPath

    $s24 = Get-Service -Name "XboxNetApiSvc"
    Stop-Service -InputObject $s24  -Force
    Set-Service XboxNetApiSvc -StartupType Disabled
    " Xbox Live Networking Service Stopped and Disabled" >> $logPath

    $s25 = Get-Service -Name "HomeGroupListener"
    Stop-Service -InputObject $s25  -Force
    Set-Service HomeGroupListener -StartupType Disabled
    " HomeGroup Listener Stopped and Disabled" >> $logPath

    $s26 = Get-Service -Name "HomeGroupProvider"
    Stop-Service -InputObject $s26  -Force
    Set-Service HomeGroupProvider -StartupType Disabled
    " HomeGroup Provider Stopped and Disabled" >> $logPath

    $s27 = Get-Service -Name "bthserv"
    Stop-Service -InputObject $s27  -Force
    Set-Service bthserv -StartupType Disabled
    " Bluetooth Support Service Stopped and Disabled" >> $logPath

    $s28 = Get-Service -Name "WinHttpAutoProxySvc"
    Stop-Service -InputObject $s28  -Force
    Set-Service WinHttpAutoProxySvc -StartupType Disabled
    " WinHTTP Web Proxy Auto-Discovery Stopped and Disabled" >> $logPath

    #  $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Continue

}

# Sets even more registry keys that I stole
if ((Config("set_registry_keys"))) {

    Write-Host "Setting Registry Keys" 
    Start-Sleep $shortSleep

    try {

        # Title
        "`n Setting Registry Keys" >> $logPath
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
        reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
        reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f
        reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f
        reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
        reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f   
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f 
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
        reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
        reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
        reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
        reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
        reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\access\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "excelbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "level" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\publisher\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "wordbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\common\security" /v "automationsecurity" /t REG_DWORD /d 3 /f
        reg ADD HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableTranscripting /t REG_DWORD /d 1 /f
        reg ADD HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f            

        # More stuff after
        "Added more keys than log could handle" >> $logPath

    }

    catch {

        Write-Output "$Error[0] $_" | Out-File "./Logs/ErrorLogs/RegistriesKeysError.txt"
        Write-host "Writing error to file" -ForegroundColor DarkYellow

        # Errors
        "`n Error occurred when setting Registry Keys" >> $logPath
        Start-Sleep $shortSleep

    }
}

# GL bro
if ((Config("run_policys"))){
    "`n Running policys.ps1, Lord help us all" >> $logPath
    & ./Auto/AutoFix/Policys.ps1
}