# ALL AI
# Here for the laughs

function Set-DomainWallpaperGPO {
    param(
        [string]$WallpaperFileName = "Wallpaper.jpeg",
        [string]$GPOName = "Domain Wallpaper Policy",
        [string]$WallpaperStyle = "Stretch", # Fill, Fit, Stretch, Tile, Center, Span
        [switch]$CreateNewGPO,
        [switch]$WhatIf,
        [switch]$SetLockScreen = $true  # New parameter to control lock screen setting
    )

    Write-Host "Setting up Domain Wallpaper and Lock Screen Policy using SYSVOL..." -ForegroundColor Green
    
    # Get current directory and wallpaper path
    $currentDirectory = $global:rootPath + "/Data/FileShare/"# It can do all this, but not file paths bro
    $wallpaperDirectory = Join-Path $currentDirectory "Wallpaper"
    $wallpaperPath = Join-Path $wallpaperDirectory $WallpaperFileName
    
    # Verify wallpaper file exists
    if (-not (Test-Path $wallpaperPath)) {
        Write-Error "Wallpaper file not found: $wallpaperPath"
        Write-Host "Please place your wallpaper file ($WallpaperFileName) in: $wallpaperDirectory" -ForegroundColor Yellow
        
        # Create the Wallpaper directory if it doesn't exist
        if (-not (Test-Path $wallpaperDirectory)) {
            try {
                New-Item -Path $wallpaperDirectory -ItemType Directory -Force | Out-Null
                Write-Host "Created directory: $wallpaperDirectory" -ForegroundColor Green
                Write-Host "Please place your wallpaper file in this directory and run the script again." -ForegroundColor Yellow
            } catch {
                Write-Error "Failed to create wallpaper directory: $($_.Exception.Message)"
            }
        }
        return
    }

    # Import required modules
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Host "Required modules loaded successfully" -ForegroundColor Green
    } catch {
        Write-Error "Failed to load required modules. Ensure RSAT tools are installed."
        return
    }

    # Get domain information
    try {
        $domain = Get-ADDomain
        $domainName = $domain.DNSRoot
        $sysvolPath = "\\$domainName\SYSVOL\$domainName"
        $wallpaperSysvolDir = Join-Path $sysvolPath "Wallpaper"
        $wallpaperSysvolPath = Join-Path $wallpaperSysvolDir $WallpaperFileName
        
        Write-Host "Domain: $domainName" -ForegroundColor Cyan
        Write-Host "SYSVOL Path: $sysvolPath" -ForegroundColor Cyan
    } catch {
        Write-Error "Failed to get domain information. Ensure this is run on a domain controller or domain-joined machine."
        return
    }

    if ($WhatIf) {
        Write-Host "WHATIF MODE - No changes will be made" -ForegroundColor Yellow
        Write-Host "Would copy wallpaper to: $wallpaperSysvolPath" -ForegroundColor Cyan
        Write-Host "Would create/update GPO: $GPOName" -ForegroundColor Cyan
        Write-Host "Would set wallpaper to: $wallpaperSysvolPath" -ForegroundColor Cyan
        if ($SetLockScreen) {
            Write-Host "Would set lock screen to: $wallpaperSysvolPath" -ForegroundColor Cyan
        }
        Write-Host "Source wallpaper: $wallpaperPath" -ForegroundColor Cyan
        return
    }

    # Step 1: Copy wallpaper to SYSVOL
    Write-Host "`nStep 1: Copying wallpaper to SYSVOL..." -ForegroundColor Cyan
    
    try {
        # Create Wallpaper directory in SYSVOL if it doesn't exist
        if (-not (Test-Path $wallpaperSysvolDir)) {
            New-Item -Path $wallpaperSysvolDir -ItemType Directory -Force | Out-Null
            Write-Host "Created directory in SYSVOL: $wallpaperSysvolDir" -ForegroundColor Green
        }

        # Copy wallpaper file to SYSVOL
        Copy-Item -Path $wallpaperPath -Destination $wallpaperSysvolPath -Force
        Write-Host "Copied wallpaper to SYSVOL: $wallpaperSysvolPath" -ForegroundColor Green
        
        # Verify the copy was successful
        if (Test-Path $wallpaperSysvolPath) {
            Write-Host "Wallpaper successfully accessible via SYSVOL" -ForegroundColor Green
        } else {
            Write-Error "Failed to verify wallpaper in SYSVOL"
            return
        }
        
    } catch {
        Write-Error "Failed to copy wallpaper to SYSVOL: $($_.Exception.Message)"
        return
    }

    # Step 2: Create or Update GPO
    Write-Host "`nStep 2: Configuring Group Policy..." -ForegroundColor Cyan
    
    try {
        # Check if GPO exists
        $gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
        
        if (-not $gpo -or $CreateNewGPO) {
            if ($gpo -and $CreateNewGPO) {
                Remove-GPO -Name $GPOName -Confirm:$false
                Write-Host "Removed existing GPO: $GPOName" -ForegroundColor Yellow
            }
            
            # Create new GPO
            $gpo = New-GPO -Name $GPOName -Comment "Enforces domain wallpaper and lock screen on all computers via SYSVOL"
            Write-Host "Created new GPO: $GPOName" -ForegroundColor Green
            
            # Link to Domain root
            $domainDN = $domain.DistinguishedName
            New-GPLink -Name $GPOName -Target $domainDN -LinkEnabled Yes
            Write-Host "Linked GPO to domain root" -ForegroundColor Green
        } else {
            Write-Host "Using existing GPO: $GPOName" -ForegroundColor Cyan
        }

        # Configure wallpaper settings in GPO using SYSVOL path
        $wallpaperUNC = $wallpaperSysvolPath
        
        # Set registry values for wallpaper
        Set-GPRegistryValue -Name $GPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "Wallpaper" -Type String -Value $wallpaperUNC
        Set-GPRegistryValue -Name $GPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "WallpaperStyle" -Type String -Value (Get-WallpaperStyleValue $WallpaperStyle)
        Set-GPRegistryValue -Name $GPOName -Key "HKCU\Control Panel\Desktop" -ValueName "Wallpaper" -Type String -Value $wallpaperUNC
        
        # Prevent users from changing wallpaper
        Set-GPRegistryValue -Name $GPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -ValueName "NoChangingWallPaper" -Type DWord -Value 1
        Set-GPRegistryValue -Name $GPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "NoDispAppearancePage" -Type DWord -Value 1
        
        Write-Host "Configured wallpaper settings in GPO" -ForegroundColor Green
        
        # NEW: Configure lock screen settings
        if ($SetLockScreen) {
            Write-Host "Configuring lock screen settings..." -ForegroundColor Cyan
            
            # Windows 10/11 Lock Screen settings
            Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ValueName "LockScreenImage" -Type String -Value $wallpaperUNC
            Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ValueName "NoLockScreen" -Type DWord -Value 0
            Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ValueName "NoChangingLockScreen" -Type DWord -Value 1
            
            # Additional lock screen enforcement for Windows 10/11
            Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ValueName "PersonalColors_Background" -Type DWord -Value 0
            Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ValueName "PersonalColors_Accent" -Type DWord -Value 0
            
            # Force lock screen image (Windows 10/11 specific)
            Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -ValueName "LockScreenImagePath" -Type String -Value $wallpaperUNC
            Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -ValueName "LockScreenImageUrl" -Type String -Value $wallpaperUNC
            
            # Disable lock screen slideshow and other features
            Set-GPRegistryValue -Name $GPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen" -ValueName "SlideshowEnabled" -Type DWord -Value 0
            Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "DisableLockScreenAppNotifications" -Type DWord -Value 1
            
            Write-Host "Configured lock screen settings in GPO" -ForegroundColor Green
        }
        
        Write-Host "Wallpaper path: $wallpaperUNC" -ForegroundColor White
        Write-Host "Wallpaper style: $WallpaperStyle" -ForegroundColor White
        if ($SetLockScreen) {
            Write-Host "Lock screen: $wallpaperUNC" -ForegroundColor White
        }
        
    } catch {
        Write-Error "Failed to configure GPO: $($_.Exception.Message)"
        return
    }

    # Step 3: Set proper SYSVOL permissions (SYSVOL already has proper permissions by default)
    Write-Host "`nStep 3: Verifying SYSVOL permissions..." -ForegroundColor Cyan
    
    try {
        # SYSVOL already has proper permissions, but we can verify the file is accessible
        if (Test-Path $wallpaperSysvolPath) {
            Write-Host "Wallpaper file accessible in SYSVOL with default permissions" -ForegroundColor Green
        } else {
            Write-Warning "Cannot verify wallpaper file accessibility in SYSVOL"
        }
        
    } catch {
        Write-Warning "Failed to verify SYSVOL permissions: $($_.Exception.Message)"
    }

    # Step 4: Summary and next steps
    Write-Host "`n=== Configuration Complete ===" -ForegroundColor Green
    Write-Host "SYSVOL Path: $wallpaperSysvolPath" -ForegroundColor White
    Write-Host "GPO Name: $GPOName" -ForegroundColor White
    Write-Host "Wallpaper: $wallpaperUNC" -ForegroundColor White
    if ($SetLockScreen) {
        Write-Host "Lock Screen: $wallpaperUNC" -ForegroundColor White
    }
    Write-Host "Local source: $wallpaperPath" -ForegroundColor White
    Write-Host "Policy applied to: Domain root (all computers)" -ForegroundColor White
    
    Write-Host "`nNext Steps:" -ForegroundColor Yellow
    Write-Host "1. Run 'gpupdate /force' on client machines" -ForegroundColor Gray
    Write-Host "2. Users may need to log off/on to see changes" -ForegroundColor Gray
    Write-Host "3. Lock screen changes require reboot on some systems" -ForegroundColor Gray
    Write-Host "4. Verify SYSVOL access: Test-Path '$wallpaperUNC'" -ForegroundColor Gray
    Write-Host "5. Check GPO application: gpresult /h gpreport.html" -ForegroundColor Gray
    Write-Host "6. SYSVOL replication will distribute to all DCs automatically" -ForegroundColor Gray

    Read-Host "Enter To Continue"
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
        [string]$WallpaperFileName = "Wallpaper.jpeg",
        [switch]$ResetToDefault
    )
    
    Write-Host "Removing Domain Wallpaper Policy..." -ForegroundColor Yellow
    
    if ($ResetToDefault) {
        # Step 1: Create temporary GPO to reset wallpaper to default
        Write-Host "`nStep 1: Creating temporary reset policy..." -ForegroundColor Cyan
        
        try {
            $resetGPOName = "Reset Wallpaper to Default"

            
            
            # Remove existing reset GPO if it exists
            $existingResetGPO = Get-GPO -Name $resetGPOName -ErrorAction SilentlyContinue
            if ($existingResetGPO) {
                Remove-GPO -Name $resetGPOName -Confirm:$false
            }
            
            # Create reset GPO
            $resetGPO = New-GPO -Name $resetGPOName -Comment "Temporarily resets wallpaper to Windows default"
            
            # Link to domain root with higher precedence
            $domain = Get-ADDomain
            $domainDN = $domain.DistinguishedName
            $resetLink = New-GPLink -Name $resetGPOName -Target $domainDN -LinkEnabled Yes
            
            # Set higher precedence (lower order number = higher precedence)
            Set-GPLink -Target $domainDN -Name $resetGPOName -Order 1
            
            # Configure reset to default Windows wallpaper
            $defaultWallpaper = "%SystemRoot%\Web\Wallpaper\Windows\img0.jpg"
            
            # In the Remove-DomainWallpaperGPO function, update the reset section:

# Configure reset to default Windows wallpaper AND lock screen
$defaultWallpaper = "%SystemRoot%\Web\Wallpaper\Windows\img0.jpg"

    # Clear custom wallpaper policies
    Set-GPRegistryValue -Name $resetGPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "Wallpaper" -Type String -Value $defaultWallpaper
    Set-GPRegistryValue -Name $resetGPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "WallpaperStyle" -Type String -Value "10"
    Set-GPRegistryValue -Name $resetGPOName -Key "HKCU\Control Panel\Desktop" -ValueName "Wallpaper" -Type String -Value $defaultWallpaper

    # Remove wallpaper restrictions
    Set-GPRegistryValue -Name $resetGPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -ValueName "NoChangingWallPaper" -Type DWord -Value 0
    Set-GPRegistryValue -Name $resetGPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "NoDispAppearancePage" -Type DWord -Value 0

    # NEW: Reset lock screen settings
    Set-GPRegistryValue -Name $resetGPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ValueName "NoChangingLockScreen" -Type DWord -Value 0
    Set-GPRegistryValue -Name $resetGPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ValueName "PersonalColors_Background" -Type DWord -Value 1
    Set-GPRegistryValue -Name $resetGPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ValueName "PersonalColors_Accent" -Type DWord -Value 1
    Set-GPRegistryValue -Name $resetGPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen" -ValueName "SlideshowEnabled" -Type DWord -Value 1
    Set-GPRegistryValue -Name $resetGPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "DisableLockScreenAppNotifications" -Type DWord -Value 0

    # Clear lock screen image enforcement
    Set-GPRegistryValue -Name $resetGPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ValueName "LockScreenImage" -Type String -Value ""
    Set-GPRegistryValue -Name $resetGPOName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -ValueName "LockScreenImagePath" -Type String -Value ""
    Set-GPRegistryValue -Name $resetGPOName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -ValueName "LockScreenImageUrl" -Type String -Value ""
            # Clear custom wallpaper policies
            Set-GPRegistryValue -Name $resetGPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "Wallpaper" -Type String -Value $defaultWallpaper
            Set-GPRegistryValue -Name $resetGPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "WallpaperStyle" -Type String -Value "10"
            Set-GPRegistryValue -Name $resetGPOName -Key "HKCU\Control Panel\Desktop" -ValueName "Wallpaper" -Type String -Value $defaultWallpaper
            
            # Remove wallpaper restrictions
            Set-GPRegistryValue -Name $resetGPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -ValueName "NoChangingWallPaper" -Type DWord -Value 0
            Set-GPRegistryValue -Name $resetGPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "NoDispAppearancePage" -Type DWord -Value 0
            
            Write-Host "Created temporary reset GPO with higher precedence" -ForegroundColor Green
            # Remove-WallpaperResetGPO

        } catch {
            Write-Warning "Failed to create reset GPO: $($_.Exception.Message)"
        }
    }
    
    # Step 2: Remove original wallpaper GPO
    Write-Host "`nStep 2: Removing original wallpaper GPO..." -ForegroundColor Cyan
    
    try {
        $gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
        if ($gpo) {
            Remove-GPO -Name $GPOName -Confirm:$false
            Write-Host "Removed GPO: $GPOName" -ForegroundColor Green
        } else {
            Write-Host "GPO not found: $GPOName" -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "Failed to remove GPO: $($_.Exception.Message)"
    }
    
    # Step 3: Remove wallpaper from SYSVOL
    Write-Host "`nStep 3: Removing wallpaper files from SYSVOL..." -ForegroundColor Cyan
    
    try {
        $domain = Get-ADDomain -ErrorAction SilentlyContinue
        if ($domain) {
            $domainName = $domain.DNSRoot
            $wallpaperSysvolPath = "\\$domainName\SYSVOL\$domainName\Wallpaper\$WallpaperFileName"
            $wallpaperSysvolDir = "\\$domainName\SYSVOL\$domainName\Wallpaper"
            
            if (Test-Path $wallpaperSysvolPath) {
                Remove-Item -Path $wallpaperSysvolPath -Force
                Write-Host "Removed wallpaper from SYSVOL: $wallpaperSysvolPath" -ForegroundColor Green
                
                # Remove directory if empty
                $remainingFiles = Get-ChildItem -Path $wallpaperSysvolDir -ErrorAction SilentlyContinue
                if (-not $remainingFiles) {
                    Remove-Item -Path $wallpaperSysvolDir -Force
                    Write-Host "Removed empty wallpaper directory from SYSVOL" -ForegroundColor Green
                }
            } else {
                Write-Host "Wallpaper file not found in SYSVOL" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Warning "Failed to remove wallpaper from SYSVOL: $($_.Exception.Message)"
    }
    
    if ($ResetToDefault) {
        # Step 4: Force Group Policy update and schedule cleanup
        Write-Host "`nStep 4: Applying reset policy..." -ForegroundColor Cyan
        
        Write-Host "Forcing Group Policy update on domain controllers..." -ForegroundColor Gray
        try {
            # Force GP update on local machine if it's a DC
            if ((Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4) {
                Start-Process "gpupdate" -ArgumentList "/force" -Wait -NoNewWindow
            }
        } catch {
            Write-Warning "Could not force local GP update"
        }
        
        Write-Host "`nIMPORTANT: The reset policy will remain active for 5 minutes to ensure all clients receive it." -ForegroundColor Yellow
        Write-Host "After 1 minute, run: Remove-DomainWallpaperGPO -GPOName 'Reset Wallpaper to Default'" -ForegroundColor Yellow
        Write-Host "Or schedule automatic cleanup..." -ForegroundColor Gray
        
        # Option to schedule automatic cleanup
        $scheduleCleanup = Read-Host "Schedule automatic cleanup of reset GPO in 1 minute? (Y/N)"
        if ($scheduleCleanup -eq "Y" -or $scheduleCleanup -eq "y") {
            $cleanupScript = @"
Start-Sleep -Seconds 60
Import-Module ActiveDirectory
Import-Module GroupPolicy
try {
    Remove-GPO -Name "Reset Wallpaper to Default" -Confirm:$false
    Write-Host "Automatically removed reset GPO" -ForegroundColor Green
} catch {
    Write-Warning "Failed to auto-remove reset GPO: $($_.Exception.Message)"
}
"@
            
            Start-Job -ScriptBlock ([ScriptBlock]::Create($cleanupScript)) -Name "WallpaperResetCleanup"
            Write-Host "Scheduled automatic cleanup in 1 minutes" -ForegroundColor Green
        }
    }
    
    Write-Host "`n=== Removal Complete ===" -ForegroundColor Green
    if ($ResetToDefault) {
        Write-Host "Users will receive default Windows wallpaper on next GP refresh" -ForegroundColor White
        Write-Host "Wallpaper restrictions have been removed" -ForegroundColor White
    } else {
        Write-Host "Users will keep current wallpaper until manually changed" -ForegroundColor White
    }

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
        [string]$WallpaperFileName = "Wallpaper.jpeg"
    )
    
    Write-Host "Testing Wallpaper Deployment..." -ForegroundColor Cyan
    
    try {
        $domain = Get-ADDomain
        $domainName = $domain.DNSRoot
        $wallpaperSysvolPath = "\\$domainName\SYSVOL\$domainName\Wallpaper\$WallpaperFileName"
        
        # Test SYSVOL accessibility
        if (Test-Path $wallpaperSysvolPath) {
            Write-Host "Wallpaper file accessible via SYSVOL: $wallpaperSysvolPath" -ForegroundColor Green
        } else {
            Write-Host "Wallpaper file NOT accessible via SYSVOL: $wallpaperSysvolPath" -ForegroundColor Red
        }
        
        # Test SYSVOL permissions (should be accessible to Domain Users by default)
        try {
            $fileInfo = Get-Item $wallpaperSysvolPath -ErrorAction SilentlyContinue
            if ($fileInfo) {
                Write-Host "SYSVOL file info accessible - Size: $($fileInfo.Length) bytes" -ForegroundColor Green
            }
        } catch {
            Write-Host "SYSVOL file access check failed" -ForegroundColor Red
        }
        
        # Test GPO
        try {
            $gpo = Get-GPO -Name "Domain Wallpaper Policy"
            Write-Host "GPO exists: $($gpo.DisplayName)" -ForegroundColor Green
            
            # Check GPO links
            $links = Get-GPInheritance -Target $domain.DistinguishedName
            $wallpaperLink = $links.GpoLinks | Where-Object { $_.DisplayName -eq "Domain Wallpaper Policy" }
            if ($wallpaperLink) {
                Write-Host "GPO is linked to domain root" -ForegroundColor Green
            } 
            else {
                Write-Host "GPO is NOT linked to domain root" -ForegroundColor Red
            }
        } catch {
            Write-Host "GPO check failed" -ForegroundColor Red
        }
        
        # Test SYSVOL replication status
        try {
            $domainControllers = Get-ADDomainController -Filter *
            Write-Host "Testing SYSVOL replication across $($domainControllers.Count) domain controllers:" -ForegroundColor Cyan
            
            foreach ($dc in $domainControllers) {
                $dcWallpaperPath = "\\$($dc.HostName)\SYSVOL\$domainName\Wallpaper\$WallpaperFileName"
                if (Test-Path $dcWallpaperPath) {
                    Write-Host "$($dc.HostName): Wallpaper accessible" -ForegroundColor Green
                } else {
                    Write-Host "$($dc.HostName): Wallpaper NOT accessible (replication pending?)" -ForegroundColor Yellow
                }
            }
        } catch {
            Write-Host "SYSVOL replication check failed" -ForegroundColor Red
        }
        
    } catch {
        Write-Host "Domain information retrieval failed" -ForegroundColor Red
    }
    
    Read-Host "Enter To Continue"
}

# Export functions for module use
# Export-ModuleMember -Function Set-DomainWallpaperGPO, Get-WallpaperStyleValue, Remove-DomainWallpaperGPO, Test-WallpaperDeployment