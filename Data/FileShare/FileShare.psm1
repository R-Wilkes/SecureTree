# ALL AI
# Here for the laughs, somehow now has a purpose

function Set-DomainWallpaperGPO {
    param(
        [string]$DesktopWallpaperFileName = "DesktopWallpaper.jpeg",
        [string]$LockScreenFileName = "LockScreen.jpeg",
        [string]$GPOName = "Domain Wallpaper Policy",
        [string]$WallpaperStyle = "Stretch", # Fill, Fit, Stretch, Tile, Center, Span
        [switch]$CreateNewGPO = $false
    )

    # Minimal installer: copy two images (desktop + lock screen) to SYSVOL and set GPO registry values

    # Resolve local source paths
    $currentDirectory = $global:rootPath + "/Data/FileShare/"
    $wallpaperDirectory = Join-Path $currentDirectory "Wallpaper"
    $desktopSource = Join-Path $wallpaperDirectory $DesktopWallpaperFileName
    $lockSource = Join-Path $wallpaperDirectory $LockScreenFileName

    if (-not (Test-Path $desktopSource)) {
        Throw "Desktop wallpaper not found: $desktopSource"
    }
    if (-not (Test-Path $lockSource)) {
        Throw "Lock screen image not found: $lockSource"
    }

    # Ensure modules
    Import-Module GroupPolicy -ErrorAction Stop
    Import-Module ActiveDirectory -ErrorAction Stop

    $domain = Get-ADDomain
    $domainName = $domain.DNSRoot
    $sysvolPath = "\\$domainName\SYSVOL\$domainName"
    $wallpaperSysvolDir = Join-Path $sysvolPath "Wallpaper"

    if (-not (Test-Path $wallpaperSysvolDir)) {
        New-Item -Path $wallpaperSysvolDir -ItemType Directory -Force | Out-Null
    }

    $desktopSysvolPath = Join-Path $wallpaperSysvolDir $DesktopWallpaperFileName
    $lockSysvolPath = Join-Path $wallpaperSysvolDir $LockScreenFileName

    Copy-Item -Path $desktopSource -Destination $desktopSysvolPath -Force
    Copy-Item -Path $lockSource -Destination $lockSysvolPath -Force

    $desktopUNC = $desktopSysvolPath
    $lockUNC = $lockSysvolPath

    # Create or reuse GPO
    $gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    if (-not $gpo -or $CreateNewGPO) {
        if ($gpo -and $CreateNewGPO) { Remove-GPO -Name $GPOName -Confirm:$false }
        $gpo = New-GPO -Name $GPOName -Comment "Enforces domain desktop wallpaper and lock screen via SYSVOL"
        $domainDN = $domain.DistinguishedName
        New-GPLink -Name $GPOName -Target $domainDN -LinkEnabled Yes
    }

    # Desktop wallpaper (HKCU)
    Set-GPRegistryValue -Name $GPOName -Key "HKCU\Control Panel\Desktop" -ValueName "Wallpaper" -Type String -Value $desktopUNC
    Set-GPRegistryValue -Name $GPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "Wallpaper" -Type String -Value $desktopUNC
    Set-GPRegistryValue -Name $GPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "WallpaperStyle" -Type String -Value (Get-WallpaperStyleValue $WallpaperStyle)
    Set-GPRegistryValue -Name $GPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -ValueName "NoChangingWallPaper" -Type DWord -Value 1

    # Lock screen (HKLM)
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ValueName "LockScreenImage" -Type String -Value $lockUNC
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -ValueName "LockScreenImagePath" -Type String -Value $lockUNC
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -ValueName "LockScreenImageUrl" -Type String -Value $lockUNC

    Write-Host "Desktop wallpaper set to: $desktopUNC"
    Write-Host "Lock screen set to: $lockUNC"
}

function Get-WallpaperStyleValue {
    param([string]$Style)
    
    switch ($Style.ToLower()) {
        "center" { return "0" }
        "tile" { return "1" }
        "stretch" { return "2" }
        "fit" { return "6" }
        "fill" { return "10" }
        "span" { return "22" }
        default { return "10" } # Default to Fill
    }
}

function Remove-DomainWallpaperGPO {
    param(
        [string]$GPOName = "Domain Wallpaper Policy",
        [string]$DesktopWallpaperFileName = "DesktopWallpaper.jpeg",
        [string]$LockScreenFileName = "LockScreen.jpeg",
        [string]$DefaultDesktopFileName = "DoNotSet.jpeg",   # file you want clients to use after reset
        [string]$DefaultLockFileName = "DoNotSet.jpeg", # optional lock screen default
        [switch]$ResetToDefault
    )

    Write-Host "Removing Domain Wallpaper Policy..." -ForegroundColor Yellow

    # Resolve domain & SYSVOL paths
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue

    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $domainName = $domain.DNSRoot
        $sysvolDir = "\\$domainName\SYSVOL\$domainName\Wallpaper"
    } catch {
        Write-Warning "Unable to determine domain or SYSVOL path: $($_.Exception.Message)"
        $domain = $null
        $domainName = $null
    }

    if ($ResetToDefault) {
        Write-Host "Step 1: Ensure default images exist in SYSVOL and create reset GPO" -ForegroundColor Cyan

        # Ensure local source default files exist and copy into SYSVOL if available
        $localWallpaperDir = Join-Path ($global:rootPath + "\Data\FileShare") "Wallpaper"
        $localDefaultDesktop = Join-Path $localWallpaperDir $DefaultDesktopFileName
        $localDefaultLock = Join-Path $localWallpaperDir $DefaultLockFileName

        if ($domainName) {
            if (-not (Test-Path $sysvolDir)) {
                try { New-Item -Path $sysvolDir -ItemType Directory -Force | Out-Null } catch {}
            }

            $defaultDesktopUNC = Join-Path $sysvolDir $DefaultDesktopFileName
            $defaultLockUNC = Join-Path $sysvolDir $DefaultLockFileName

            if (Test-Path $localDefaultDesktop) {
                Copy-Item -Path $localDefaultDesktop -Destination $defaultDesktopUNC -Force -ErrorAction SilentlyContinue
            } else {
                Write-Warning "Local default desktop image not found: $localDefaultDesktop. Clients may get a solid color if no accessible image exists."
                $defaultDesktopUNC = "%SystemRoot%\Web\Wallpaper\Windows\img0.jpg"
            }

            if (Test-Path $localDefaultLock) {
                Copy-Item -Path $localDefaultLock -Destination $defaultLockUNC -Force -ErrorAction SilentlyContinue
            } else {
                # if no separate lock default provided, use desktop default UNC if available
                if (Test-Path $defaultDesktopUNC) {
                    $defaultLockUNC = $defaultDesktopUNC
                } else {
                    $defaultLockUNC = ""
                }
            }

            # Create/reset the temporary GPO that forces clients to the SYSVOL default images
            try {
                $resetGPOName = "Reset Wallpaper to Default"
                $existingReset = Get-GPO -Name $resetGPOName -ErrorAction SilentlyContinue
                if ($existingReset) { Remove-GPO -Name $resetGPOName -Confirm:$false -ErrorAction SilentlyContinue }
                $resetGPO = New-GPO -Name $resetGPOName -Comment "Temporary reset to network default wallpaper and lock screen"

                # Link to domain root and set precedence high
                $domainDN = $domain.DistinguishedName
                New-GPLink -Name $resetGPOName -Target $domainDN -LinkEnabled Yes -ErrorAction SilentlyContinue
                Set-GPLink -Target $domainDN -Name $resetGPOName -Order 1 -ErrorAction SilentlyContinue

                # Set HKCU desktop wallpaper to the built-in Windows default (avoid pointing to SYSVOL UNC to prevent inaccessible UNC causing black desktop)
                $desktopValue = "%SystemRoot%\Web\Wallpaper\Windows\img0.jpg"
                Set-GPRegistryValue -Name $resetGPOName -Key "HKCU\Control Panel\Desktop" -ValueName "Wallpaper" -Type String -Value $desktopValue
                Set-GPRegistryValue -Name $resetGPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "Wallpaper" -Type String -Value $desktopValue
                Set-GPRegistryValue -Name $resetGPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "WallpaperStyle" -Type String -Value "10"
                Set-GPRegistryValue -Name $resetGPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -ValueName "NoChangingWallPaper" -Type DWord -Value 0
                Set-GPRegistryValue -Name $resetGPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "NoDispAppearancePage" -Type DWord -Value 0

                # Set lock screen to SYSVOL UNC (HKLM machine policy)
                if ($defaultLockUNC) {
                    Set-GPRegistryValue -Name $resetGPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ValueName "LockScreenImage" -Type String -Value $defaultLockUNC
                    Set-GPRegistryValue -Name $resetGPOName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -ValueName "LockScreenImagePath" -Type String -Value $defaultLockUNC
                    Set-GPRegistryValue -Name $resetGPOName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -ValueName "LockScreenImageUrl" -Type String -Value $defaultLockUNC
                } else {
                    # clear enforcement if no UNC
                    Set-GPRegistryValue -Name $resetGPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ValueName "LockScreenImage" -Type String -Value ""
                }

                Write-Host "Created temporary reset GPO pointing to SYSVOL defaults" -ForegroundColor Green
            } catch {
                Write-Warning "Failed to create reset GPO: $($_.Exception.Message)"
            }
        } else {
            Write-Warning "Domain not available; cannot create reset GPO."
        }
    }

    # Step 2: Remove original wallpaper GPO
    Write-Host "Step 2: Removing original wallpaper GPO..." -ForegroundColor Cyan
    try {
        $gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
        if ($gpo) {
            Remove-GPO -Name $GPOName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "Removed GPO: $GPOName" -ForegroundColor Green
        } else {
            Write-Host "GPO not found: $GPOName" -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "Failed to remove original GPO: $($_.Exception.Message)"
    }

    # Step 3: Remove wallpaper files from SYSVOL (desktop + lock) and per-DC copies
    if ($domainName) {
        Write-Host "Step 3: Removing wallpaper files from SYSVOL and DCs..." -ForegroundColor Cyan
        try {
            $desktopSysvolPath = Join-Path $sysvolDir $DesktopWallpaperFileName
            $lockSysvolPath = Join-Path $sysvolDir $LockScreenFileName

            if (Test-Path $desktopSysvolPath) {
                Remove-Item -Path $desktopSysvolPath -Force -ErrorAction SilentlyContinue
                Write-Host "Removed desktop wallpaper from SYSVOL: $desktopSysvolPath" -ForegroundColor Green
            }

            if ($LockScreenFileName -and (Test-Path $lockSysvolPath)) {
                Remove-Item -Path $lockSysvolPath -Force -ErrorAction SilentlyContinue
                Write-Host "Removed lock screen image from SYSVOL: $lockSysvolPath" -ForegroundColor Green
            }

            # Clean directory if empty
            $remaining = Get-ChildItem -Path $sysvolDir -ErrorAction SilentlyContinue
            if (-not $remaining) {
                Remove-Item -Path $sysvolDir -Force -ErrorAction SilentlyContinue
                Write-Host "Removed empty SYSVOL wallpaper directory" -ForegroundColor Green
            }

            # Remove copies on each DC
            try {
                $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
                foreach ($dc in $dcs) {
                    $dcDesktop = "\\$($dc.HostName)\SYSVOL\$domainName\Wallpaper\$DesktopWallpaperFileName"
                    $dcLock = "\\$($dc.HostName)\SYSVOL\$domainName\Wallpaper\$LockScreenFileName"
                    if (Test-Path $dcDesktop) {
                        Remove-Item -Path $dcDesktop -Force -ErrorAction SilentlyContinue
                        Write-Host "Removed desktop wallpaper from DC $($dc.HostName): $dcDesktop" -ForegroundColor Green
                    }
                    if ($LockScreenFileName -and (Test-Path $dcLock)) {
                        Remove-Item -Path $dcLock -Force -ErrorAction SilentlyContinue
                        Write-Host "Removed lock screen image from DC $($dc.HostName): $dcLock" -ForegroundColor Green
                    }
                }
            } catch {
                Write-Warning "Failed to remove wallpaper files from DCs: $($_.Exception.Message)"
            }
        } catch {
            Write-Warning "Failed during SYSVOL file removal: $($_.Exception.Message)"
        }
    }

    Write-Host "`n=== Removal Complete ===" -ForegroundColor Green
    Read-Host "Enter To Continue"
}

# Add a new function for cleanup
function Remove-WallpaperResetGPO {
    Write-Host "Removing temporary wallpaper reset GPO..." -ForegroundColor Yellow
    
    try {
        $resetGPO = Get-GPO -Name "Reset Wallpaper to Default" -ErrorAction SilentlyContinue
        if ($resetGPO) {
            Remove-GPO -Name "Reset Wallpaper to Default" -Confirm:$false
            Write-Host "Removed reset GPO successfully" -ForegroundColor Green
        } else {
            Write-Host "Reset GPO not found" -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "Failed to remove reset GPO: $($_.Exception.Message)"
    }
    
    Read-Host "Enter To Continue"
}

function Test-WallpaperDeployment {
    param(
        [string]$DesktopWallpaperFileName = "DesktopWallpaper.jpeg",
        [string]$LockScreenFileName = "LockScreen.jpeg",
        [string]$GPOName = "Domain Wallpaper Policy",
        [string]$ResetGPOName = "Reset Wallpaper to Default"
    )

    Write-Host "Testing Wallpaper Deployment (desktop + lock) ..." -ForegroundColor Cyan

    try {
        $domain = Get-ADDomain
        $domainName = $domain.DNSRoot

        $desktopSysvolPath = "\\$domainName\SYSVOL\$domainName\Wallpaper\$DesktopWallpaperFileName"
        $lockSysvolPath = "\\$domainName\SYSVOL\$domainName\Wallpaper\$LockScreenFileName"

        # Check desktop image in SYSVOL
        if (Test-Path $desktopSysvolPath) {
            Write-Host "Desktop wallpaper accessible via SYSVOL: $desktopSysvolPath" -ForegroundColor Green
            try { $di = Get-Item $desktopSysvolPath -ErrorAction SilentlyContinue; if ($di) { Write-Host "  Size: $($di.Length) bytes" -ForegroundColor Green } } catch {}
        } else {
            Write-Host "Desktop wallpaper NOT accessible via SYSVOL: $desktopSysvolPath" -ForegroundColor Red
        }

        # Check lock image in SYSVOL
        if ($LockScreenFileName) {
            if (Test-Path $lockSysvolPath) {
                Write-Host "Lock screen image accessible via SYSVOL: $lockSysvolPath" -ForegroundColor Green
                try { $li = Get-Item $lockSysvolPath -ErrorAction SilentlyContinue; if ($li) { Write-Host "  Size: $($li.Length) bytes" -ForegroundColor Green } } catch {}
            } else {
                Write-Host "Lock screen image NOT accessible via SYSVOL: $lockSysvolPath" -ForegroundColor Yellow
            }
        }

        # Test GPO existence and links
        try {
            $gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
            if ($gpo) {
                Write-Host "GPO exists: $($gpo.DisplayName)" -ForegroundColor Green
                $links = Get-GPInheritance -Target $domain.DistinguishedName
                $gpoLink = $links.GpoLinks | Where-Object { $_.DisplayName -eq $GPOName }
                if ($gpoLink) { Write-Host "GPO is linked to domain root" -ForegroundColor Green } else { Write-Host "GPO is NOT linked to domain root" -ForegroundColor Yellow }
            } else {
                Write-Host "GPO not found: $GPOName" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "GPO check failed: $($_.Exception.Message)" -ForegroundColor Red
        }

        # Check for reset GPO (if present)
        try {
            $resetGPO = Get-GPO -Name $ResetGPOName -ErrorAction SilentlyContinue
            if ($resetGPO) { Write-Host "Reset GPO exists: $ResetGPOName" -ForegroundColor Green } else { Write-Host "Reset GPO not found: $ResetGPOName" -ForegroundColor Yellow }
        } catch {
            Write-Host "Reset GPO check failed" -ForegroundColor Red
        }

        # Test per-DC SYSVOL replication for both files
        try {
            $domainControllers = Get-ADDomainController -Filter *
            Write-Host "Testing SYSVOL replication across $($domainControllers.Count) domain controllers:" -ForegroundColor Cyan
            foreach ($dc in $domainControllers) {
                $dcDesktop = "\\$($dc.HostName)\SYSVOL\$domainName\Wallpaper\$DesktopWallpaperFileName"
                $dcLock = "\\$($dc.HostName)\SYSVOL\$domainName\Wallpaper\$LockScreenFileName"
                $desktopOk = Test-Path $dcDesktop
                $lockOk = $false
                if ($LockScreenFileName) { $lockOk = Test-Path $dcLock }

                # PowerShell 5.1 doesn't support the ternary operator (? :), so use explicit if/else
                $desktopStatus = if ($desktopOk) { 'OK' } else { 'MISSING' }
                $line = "$($dc.HostName): Desktop=$desktopStatus"
                if ($LockScreenFileName) {
                    $lockStatus = if ($lockOk) { 'OK' } else { 'MISSING' }
                    $line += ", Lock=$lockStatus"
                }
                if ($desktopOk -and ($LockScreenFileName -eq $null -or $lockOk)) {
                    Write-Host $line -ForegroundColor Green
                } elseif ($desktopOk -or ($LockScreenFileName -and $lockOk)) {
                    Write-Host $line -ForegroundColor Yellow
                } else {
                    Write-Host $line -ForegroundColor Red
                }
            }
        } catch {
            Write-Host "SYSVOL replication check failed: $($_.Exception.Message)" -ForegroundColor Red
        }

    } catch {
        Write-Host "Domain information retrieval failed: $($_.Exception.Message)" -ForegroundColor Red
    }

    Read-Host "Enter To Continue"
}
