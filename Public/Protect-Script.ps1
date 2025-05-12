function Protect-Script {
    <#
    .SYNOPSIS
        Signs PowerShell scripts using a code signing certificate.
        
    .DESCRIPTION
        The Protect-Script function allows you to sign PowerShell scripts using a code signing certificate.
        It can use certificates from the certificate store or from PFX files.
        
    .PARAMETER ScriptPath
        Path to the PowerShell script or folder containing scripts to sign.
        
    .PARAMETER CertificateThumbprint
        Thumbprint of the code signing certificate to use from the certificate store.
        
    .PARAMETER CertificatePath
        Path to a PFX certificate file.
        
    .PARAMETER CertificatePassword
        Secure string password for the PFX certificate file.
        
    .PARAMETER CertificateFolder
        Folder containing certificate files. The function will look for code signing certificates in this folder.
        
    .PARAMETER ScriptFilter
        Filter to use when ScriptPath is a folder. Default is "*.ps1".
        
    .PARAMETER TimestampServer
        URL of the timestamp server to use. Default is "http://timestamp.digicert.com".
        
    .PARAMETER SkipRevocationCheck
        Switch to skip the revocation check during signing.
        
    .PARAMETER SkipChainValidation
        Switch to skip certificate chain validation. Use with caution and only in test environments.
        
    .PARAMETER Force
        Switch to force signing even if the script is already signed.
        
    .PARAMETER ReturnDetails
        Switch to return detailed result objects with success/failure information for each script.
        
    .EXAMPLE
        Protect-Script -ScriptPath "C:\Scripts\MyScript.ps1" -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678"
        
        Signs the specified PowerShell script using the certificate with the given thumbprint.
        
    .EXAMPLE
        Protect-Script -ScriptPath "C:\Scripts" -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678"
        
        Signs all PowerShell scripts in the specified folder using the certificate with the given thumbprint.
        
    .EXAMPLE
        $securePassword = ConvertTo-SecureString -String "YourPassword" -AsPlainText -Force
        Protect-Script -ScriptPath "C:\Scripts\MyScript.ps1" -CertificatePath "C:\temp\certs\CodeSigningCert.pfx" -CertificatePassword $securePassword
        
        Signs the specified PowerShell script using a PFX certificate file with the given password.
        
    .EXAMPLE
        Protect-Script -ScriptPath "C:\Scripts\PowerShell" -CertificateFolder "C:\temp\certs"
        
        Signs all PowerShell scripts in the specified folder using the first valid code signing certificate found in the certificate folder.
        
    .NOTES
        Requires administrator privileges to access certain certificate stores (LocalMachine).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        
        [Parameter(Mandatory = $false)]
        [string]$CertificateThumbprint = "",
        
        [Parameter(Mandatory = $false)]
        [string]$CertificatePath = "",
        
        [Parameter(Mandatory = $false)]
        [System.Security.SecureString]$CertificatePassword,
        
        [Parameter(Mandatory = $false)]
        [string]$CertificateFolder = "C:\temp\certs",
        
        [Parameter(Mandatory = $false)]
        [string]$ScriptFilter = "*.ps1",
        
        [Parameter(Mandatory = $false)]
        [string]$TimestampServer = "http://timestamp.digicert.com",
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipRevocationCheck,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipChainValidation,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [switch]$ReturnDetails
    )
    
    begin {
        # Check PowerShell version for compatibility
        $isPSCore = $PSVersionTable.PSEdition -eq "Core"
        $usePSFallback = $false
        
        # Initialize result tracking
        $results = @{
            TotalCount = 0
            SuccessCount = 0
            FailureCount = 0
            SuccessScripts = @()
            FailureScripts = @()
            VerificationResults = @()
            CertificateInfo = $null
            Errors = @()
        }
        
        # Create timestamp parameters based on options
        $_timestampServer = $TimestampServer
        $revocationMode = if ($SkipRevocationCheck) { "NoCheck" } else { "Online" }
        
        # PowerShell Core fallback preparation for signing operations
        if ($isPSCore) {
            Write-Host "Detected PowerShell Core. Code signing operations work more reliably in Windows PowerShell 5.1." -ForegroundColor Yellow
            Write-Host "Will attempt to use Windows PowerShell 5.1 for signing operations." -ForegroundColor Yellow
            
            # Check if powershell.exe is available
            if (Get-Command "powershell.exe" -ErrorAction SilentlyContinue) {
                $usePSFallback = $true
                
                # Temporary script content for Windows PowerShell fallback
@'
param (
    [string]$ScriptPath,
    [string]$CertPath,
    [string]$CertPass,
    [string]$Thumbprint,
    [string]$TimestampServer,
    [string]$RevocationMode,
    [switch]$Force
)

function Sign-Script {
    param (
        [string]$Path,
        [string]$CertPath,
        [string]$CertPass,
        [string]$Thumbprint,
        [string]$TimestampServer,
        [string]$RevocationMode,
        [switch]$Force
    )
    
    $cert = $null
    $result = @{
        Path = $Path
        Success = $false
        ErrorMessage = ""
        SignatureStatus = "NotSigned"
        Certificate = $null
    }
    
    try {
        # Get the certificate
        if ($Thumbprint) {
            $cert = Get-Item -Path "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction Stop
            $result.Certificate = @{
                Subject = $cert.Subject
                Thumbprint = $cert.Thumbprint
                NotBefore = $cert.NotBefore
                NotAfter = $cert.NotAfter
            }
        }
        elseif ($CertPath) {
            if ($CertPass) {
                $password = ConvertTo-SecureString -String $CertPass -Force -AsPlainText
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath, $password, "Exportable")
            }
            else {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
            }
            $result.Certificate = @{
                Subject = $cert.Subject
                Thumbprint = $cert.Thumbprint
                NotBefore = $cert.NotBefore
                NotAfter = $cert.NotAfter
            }
        }
        
        if (-not $cert) {
            $result.ErrorMessage = "No valid certificate found"
            return $result
        }
        
        # Check if script is already signed and needs force
        $sig = Get-AuthenticodeSignature -FilePath $Path
        $result.SignatureStatus = $sig.Status
        
        if ($sig.Status -eq "Valid" -and -not $Force) {
            $result.ErrorMessage = "Script is already signed and Force was not specified"
            return $result
        }
        
        # Sign the script
        $signParams = @{
            FilePath = $Path
            Certificate = $cert
            TimestampServer = $TimestampServer
        }
        
        # Set revocation flag if needed
        if ($RevocationMode -eq "NoCheck") {
            $signParams.Add("IncludeChain", "NotRoot")
        }
        
        $null = Set-AuthenticodeSignature @signParams
        
        # Verify the signature
        $verification = Get-AuthenticodeSignature -FilePath $Path
        $result.SignatureStatus = $verification.Status
        
        if ($verification.Status -eq "Valid") {
            $result.Success = $true
        }
        else {
            $result.ErrorMessage = "Signature verification failed: $($verification.StatusMessage)"
        }
    }
    catch {
        $result.ErrorMessage = "Signing error: $_"
    }
    
    return $result | ConvertTo-Json -Compress
}

# Execute the signing operation
$result = Sign-Script -Path $ScriptPath -CertPath $CertPath -CertPass $CertPass -Thumbprint $Thumbprint -TimestampServer $TimestampServer -RevocationMode $RevocationMode -Force:$Force
Write-Output $result
'@ | Out-File -FilePath $tempScript -Encoding UTF8
                    
                    # Prepare parameters based on what we have
                    $scriptParams = @("-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", "`"$tempScript`"", 
                                      "-ScriptPath", "`"$Script`"", "-TimestampServer", "`"$_timestampServer`"")
                    
                    if (-not [string]::IsNullOrEmpty($CertificateThumbprint)) {
                        $scriptParams += "-Thumbprint"
                        $scriptParams += "`"$CertificateThumbprint`""
                    }
                    
                    if (-not [string]::IsNullOrEmpty($CertificatePath)) {
                        $scriptParams += "-CertPath"
                        $scriptParams += "`"$CertificatePath`""
                        
                        if ($null -ne $CertificatePassword) {
                            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertificatePassword)
                            $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
                            
                            $scriptParams += "-CertPass"
                            $scriptParams += "`"$plainPassword`""
                        }
                    }
                    
                    if ($SkipRevocationCheck) {
                        $scriptParams += "-RevocationMode"
                        $scriptParams += "NoCheck"
                    }
                    
                    if ($Force) {
                        $scriptParams += "-Force"
                    }
                }
                else {
                    Write-Warning "Windows PowerShell 5.1 (powershell.exe) not found. Attempting to use PowerShell Core for signing."
                    $usePSFallback = $false
                }
            }
        }
        
    process {
        try {
            # Find the code signing certificate
            $cert = $null
            
            if (-not [string]::IsNullOrEmpty($CertificateThumbprint)) {
                Write-Host "Looking for certificate with thumbprint $CertificateThumbprint..." -ForegroundColor Yellow
                
                try {
                    # Try CurrentUser first
                    $cert = Get-Item -Path "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
                }
                catch {
                    Write-Verbose "Certificate not found in CurrentUser\My store: $_"
                }
                
                if ($null -eq $cert) {
                    try {
                        # Try LocalMachine if CurrentUser failed
                        $cert = Get-Item -Path "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-Verbose "Certificate not found in LocalMachine\My store: $_"
                    }
                }
                
                if ($null -eq $cert) {
                    $errorMsg = "Certificate with thumbprint $CertificateThumbprint not found in certificate stores. " +
                                "Please check the thumbprint and ensure the certificate is installed in the CurrentUser\My or LocalMachine\My store."
                    $results.Errors += $errorMsg
                    if ($ReturnDetails) {
                        return $results
                    } else {
                        throw $errorMsg
                    }
                }
            }
            elseif (-not [string]::IsNullOrEmpty($CertificatePath)) {
                Write-Host "Loading certificate from $CertificatePath..." -ForegroundColor Yellow
                
                if (-not (Test-Path -Path $CertificatePath)) {
                    $errorMsg = "Certificate file not found at $CertificatePath. Please check the path and try again."
                    $results.Errors += $errorMsg
                    if ($ReturnDetails) {
                        return $results
                    } else {
                        throw $errorMsg
                    }
                }
                
                try {
                    if ($null -ne $CertificatePassword) {
                        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath, $CertificatePassword, "Exportable")
                    }
                    else {
                        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath)
                    }
                }
                catch {
                    $errorMsg = "Error loading certificate from file: $_. Please check the file and password if provided."
                    $results.Errors += $errorMsg
                    if ($ReturnDetails) {
                        return $results
                    } else {
                        throw $errorMsg
                    }
                }
            }
            else {
                Write-Host "No specific certificate provided, looking for code signing certificates in certificate store..." -ForegroundColor Yellow
                
                # Find all code signing certificates in CurrentUser\My
                $certs = Get-CodeSigningCertificate -ValidOnly
                
                if ($certs.Count -eq 0) {
                    Write-Host "No code signing certificates found in certificate store. Looking in certificate folder..." -ForegroundColor Yellow
                    
                    if (-not (Test-Path -Path $CertificateFolder)) {
                        $errorMsg = "Certificate folder not found at $CertificateFolder. Please check the path and try again."
                        $results.Errors += $errorMsg
                        if ($ReturnDetails) {
                            return $results
                        } else {
                            throw $errorMsg
                        }
                    }
                    
                    $certs = Get-CodeSigningCertificate -CertificateFolder $CertificateFolder -ValidOnly
                    
                    if ($certs.Count -eq 0) {
                        $errorMsg = "No valid code signing certificates found in certificate store or folder."
                        $results.Errors += $errorMsg
                        if ($ReturnDetails) {
                            return $results
                        } else {
                            throw $errorMsg
                        }
                    }
                }
                
                # Use the first certificate
                $cert = $certs[0]
            }
            
            # Validate the certificate for code signing
            if (-not (Test-CodeSigningCertificate -Certificate $cert)) {
                $errorMsg = "Certificate $($cert.Subject) is not valid for code signing. Please use a valid code signing certificate."
                $results.Errors += $errorMsg
                if ($ReturnDetails) {
                    return $results
                } else {
                    throw $errorMsg
                }
            }
            
            # Store certificate info in results
            $results.CertificateInfo = @{
                Subject = $cert.Subject
                Thumbprint = $cert.Thumbprint
                NotBefore = $cert.NotBefore
                NotAfter = $cert.NotAfter
                HasPrivateKey = $cert.HasPrivateKey
            }
            
            Write-Host "Using certificate: $($cert.Subject) ($($cert.Thumbprint))" -ForegroundColor Green
            
            # Validate certificate chain if not skipping
            if (-not $SkipChainValidation) {
                $chainValid = Confirm-CodeSigningChain -Certificate $cert -SkipRevocationCheck:$SkipRevocationCheck
                
                if (-not $chainValid) {
                    Write-Warning "Certificate chain validation failed. To proceed anyway, use -SkipChainValidation"
                    $confirmContinue = Read-Host "Do you want to continue with signing anyway? (Y/N)"
                    
                    if ($confirmContinue -ne "Y") {
                        $errorMsg = "Certificate chain validation failed and operation was canceled by user."
                        $results.Errors += $errorMsg
                        if ($ReturnDetails) {
                            return $results
                        } else {
                            throw $errorMsg
                        }
                    }
                }
            }
            
            # Determine which scripts to sign
            $scripts = @()
            
            if (Test-Path -Path $ScriptPath -PathType Leaf) {
                # Single script
                $scripts = @(Get-Item -Path $ScriptPath)
            }
            elseif (Test-Path -Path $ScriptPath -PathType Container) {
                # Folder with scripts
                $scripts = @(Get-ChildItem -Path $ScriptPath -Filter $ScriptFilter -Recurse)
            }
            else {
                $errorMsg = "Script path not found: $ScriptPath. Please check the path and try again."
                $results.Errors += $errorMsg
                if ($ReturnDetails) {
                    return $results
                } else {
                    throw $errorMsg
                }
            }
            
            if ($scripts.Count -eq 0) {
                $errorMsg = "No scripts found to sign at: $ScriptPath. Please check the path and filter."
                $results.Errors += $errorMsg
                if ($ReturnDetails) {
                    return $results
                } else {
                    throw $errorMsg
                }
            }
            
            $results.TotalCount = $scripts.Count
            
            # Sign each script
            foreach ($script in $scripts) {
                Write-Host "Signing script: $($script.Name)" -ForegroundColor Yellow
                
                try {
                    # Check if script is already signed
                    $sig = Get-AuthenticodeSignature -FilePath $script.FullName
                    
                    if ($sig.Status -eq "Valid" -and -not $Force) {
                        Write-Host "  Script is already signed and -Force was not specified. Skipping." -ForegroundColor Cyan
                        
                        $scriptResult = @{
                            Path = $script.FullName
                            SignatureStatus = $sig.Status
                            Success = $true
                            Skipped = $true
                            ErrorMessage = "Already signed"
                        }
                        
                        $results.SuccessCount++
                        $results.SuccessScripts += $script.FullName
                        $results.VerificationResults += $scriptResult
                        continue
                    }
                    
                    # Sign the script
                    if ($usePSFallback) {
                        # Use Windows PowerShell for signing
                        $tempScript = [System.IO.Path]::GetTempFileName() + ".ps1"
                        
                        try {
                            # Create the temporary script for Windows PowerShell
                            # (Script content defined in Begin block)
                            
                            # Execute the script with Windows PowerShell
                            $psExitCode = 0
                            $psOutput = & powershell.exe @scriptParams 2>&1
                            $psExitCode = $LASTEXITCODE
                            
                            if ($psExitCode -ne 0) {
                                throw "PowerShell.exe exited with code $psExitCode $psOutput"
                            }
                            
                            $jsonResult = $psOutput | Out-String | ConvertFrom-Json
                            
                            if ($jsonResult.Success) {
                                Write-Host "  Successfully signed script with certificate: $($cert.Subject)" -ForegroundColor Green
                                Write-Host "  Certificate thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
                                
                                $results.SuccessCount++
                                $results.SuccessScripts += $script.FullName
                                
                                $scriptResult = @{
                                    Path = $script.FullName
                                    SignatureStatus = $jsonResult.SignatureStatus
                                    Success = $true
                                    ErrorMessage = ""
                                }
                                $results.VerificationResults += $scriptResult
                            }
                            else {
                                Write-Host "  Failed to sign script: $($jsonResult.ErrorMessage)" -ForegroundColor Red
                                
                                $results.FailureCount++
                                $results.FailureScripts += $script.FullName
                                
                                $scriptResult = @{
                                    Path = $script.FullName
                                    SignatureStatus = $jsonResult.SignatureStatus
                                    Success = $false
                                    ErrorMessage = $jsonResult.ErrorMessage
                                }
                                $results.VerificationResults += $scriptResult
                                $results.Errors += "Failed to sign $($script.FullName): $($jsonResult.ErrorMessage)"
                            }
                        }
                        finally {
                            # Clean up the temporary script
                            if (Test-Path -Path $tempScript) {
                                Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }
                    else {
                        # Use native PowerShell for signing
                        $signParams = @{
                            FilePath = $script.FullName
                            Certificate = $cert
                            TimestampServer = $_timestampServer
                        }
                        
                        # Set revocation flag if needed
                        if ($SkipRevocationCheck) {
                            $signParams.Add("IncludeChain", "NotRoot")
                        }
                        
                        $sig = Set-AuthenticodeSignature @signParams
                        
                        if ($sig.Status -eq "Valid") {
                            Write-Host "  Successfully signed script with certificate: $($cert.Subject)" -ForegroundColor Green
                            Write-Host "  Certificate thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
                            
                            $results.SuccessCount++
                            $results.SuccessScripts += $script.FullName
                            
                            $scriptResult = @{
                                Path = $script.FullName
                                SignatureStatus = $sig.Status
                                Success = $true
                                ErrorMessage = ""
                            }
                            $results.VerificationResults += $scriptResult
                        }
                        else {
                            Write-Host "  Failed to sign script: Status is $($sig.Status): $($sig.StatusMessage)" -ForegroundColor Red
                            
                            $results.FailureCount++
                            $results.FailureScripts += $script.FullName
                            
                            $scriptResult = @{
                                Path = $script.FullName
                                SignatureStatus = $sig.Status
                                Success = $false
                                ErrorMessage = $sig.StatusMessage
                            }
                            $results.VerificationResults += $scriptResult
                            $results.Errors += "Failed to sign $($script.FullName): Status is $($sig.Status): $($sig.StatusMessage)"
                        }
                    }
                }
                catch {
                    Write-Host "  Error signing script: $_" -ForegroundColor Red
                    
                    $results.FailureCount++
                    $results.FailureScripts += $script.FullName
                    
                    $scriptResult = @{
                        Path = $script.FullName
                        SignatureStatus = "NotSigned"
                        Success = $false
                        ErrorMessage = $_
                    }
                    $results.VerificationResults += $scriptResult
                    $results.Errors += "Error signing $($script.FullName): $_"
                }
            }
            
            # Display summary if not returning details
            if (-not $ReturnDetails) {
                Write-Host "`nSigning Summary:" -ForegroundColor Cyan
                Write-Host "Total scripts processed: $($results.TotalCount)" -ForegroundColor White
                Write-Host "Successfully signed: $($results.SuccessCount)" -ForegroundColor Green
                Write-Host "Failed to sign: $($results.FailureCount)" -ForegroundColor Red
                
                if ($results.FailureCount -gt 0) {
                    Write-Host "`nFailed scripts:" -ForegroundColor Red
                    foreach ($failedScript in $results.FailureScripts) {
                        Write-Host "  - $failedScript" -ForegroundColor Red
                    }
                }
                
                if ($results.SuccessCount -eq $results.TotalCount) {
                    Write-Host "`nScript signing completed successfully." -ForegroundColor Green
                }
                else {
                    Write-Host "`nScript signing completed with errors." -ForegroundColor Yellow
                }
            }
            
            # Return results if requested
            if ($ReturnDetails) {
                return $results
            }
        }
        catch {
            Write-Error "Error in Protect-Script: $_"
            if ($ReturnDetails) {
                $results.Errors += "Error in Protect-Script: $_"
                return $results
            }
        }
    }
}

# Export this function
Export-ModuleMember -Function Protect-Script
