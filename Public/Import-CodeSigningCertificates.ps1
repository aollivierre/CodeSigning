function Import-CodeSigningCertificates {
    <#
    .SYNOPSIS
    Imports code signing certificates into the appropriate certificate stores.
    
    .DESCRIPTION
    This function imports code signing certificates from the specified folder and verifies they were imported correctly.
    It handles Windows security dialogs and prompts for user interaction when needed, with timeout handling.
    
    .PARAMETER CertPath
    The path to the directory containing certificate files. Default is "C:\temp\certs".
    
    .PARAMETER RootCertFile
    The filename of the root CA certificate. Default is "root.cer".
    
    .PARAMETER IssuingCertFile
    The filename of the issuing CA certificate. Default is "issuing.cer".
    
    .PARAMETER CodeSigningCertFile
    The filename of the code signing certificate (without private key). Default is "ConfigMgrCodeSigning.cer".
    
    .PARAMETER CodeSigningPfxFile
    The filename of the code signing certificate with private key. Default is "ConfigMgrCodeSigning.pfx".
    
    .PARAMETER PfxPassword
    The password for the PFX file, if required. If not provided, a Windows dialog will prompt for it.
    
    .PARAMETER TimeoutSeconds
    The number of seconds to wait for user confirmation when prompted. Default is 60 seconds.
    
    .PARAMETER Force
    Force reimport of certificates even if they already exist in the stores.
    
    .EXAMPLE
    Import-CodeSigningCertificates -CertPath "C:\temp\certs"
    
    .EXAMPLE
    Import-CodeSigningCertificates -CertPath "C:\my-certs" -Force
    
    .NOTES
    This function requires administrative privileges for importing to LocalMachine stores.
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$CertPath = "C:\temp\certs",
        
        [Parameter(Mandatory=$false)]
        [string]$RootCertFile = "root.cer",
        
        [Parameter(Mandatory=$false)]
        [string]$IssuingCertFile = "issuing.cer",
        
        [Parameter(Mandatory=$false)]
        [string]$CodeSigningCertFile = "ConfigMgrCodeSigning.cer",
        
        [Parameter(Mandatory=$false)]
        [string]$CodeSigningPfxFile = "ConfigMgrCodeSigning.pfx",
        
        [Parameter(Mandatory=$false)]
        [securestring]$PfxPassword,
        
        [Parameter(Mandatory=$false)]
        [int]$TimeoutSeconds = 60,
        
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )
    
    # Check if running as administrator
    function Test-AdminPrivileges {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    
    if (-not (Test-AdminPrivileges)) {
        Write-Warning "This function requires administrative privileges to import certificates to LocalMachine stores."
        Write-Warning "Please run PowerShell as Administrator and try again."
        return $false
    }
    
    # Verify certificate files exist
    $rootCertPath = Join-Path -Path $CertPath -ChildPath $RootCertFile
    $issuingCertPath = Join-Path -Path $CertPath -ChildPath $IssuingCertFile
    $codeCertPath = Join-Path -Path $CertPath -ChildPath $CodeSigningCertFile
    $codeCertPfxPath = Join-Path -Path $CertPath -ChildPath $CodeSigningPfxFile
    
    $missingFiles = @()
    if (-not (Test-Path $rootCertPath)) { $missingFiles += $RootCertFile }
    if (-not (Test-Path $issuingCertPath)) { $missingFiles += $IssuingCertFile }
    if (-not (Test-Path $codeCertPath)) { $missingFiles += $CodeSigningCertFile }
    if (-not (Test-Path $codeCertPfxPath)) { $missingFiles += $CodeSigningPfxFile }
    
    if ($missingFiles.Count -gt 0) {
        Write-Error "The following required certificate files are missing from $CertPath`: $($missingFiles -join ', ')"
        return $false
    }
    
    # Function to check if a certificate is already in the store
    function Test-CertificateInStore {
        param (
            [Parameter(Mandatory=$true)]
            [string]$Thumbprint,
            
            [Parameter(Mandatory=$true)]
            [string]$StoreName,
            
            [Parameter(Mandatory=$true)]
            [string]$StoreLocation
        )
        
        try {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $StoreLocation)
            $store.Open("ReadOnly")
            $cert = $store.Certificates | Where-Object { $_.Thumbprint -eq $Thumbprint }
            $store.Close()
            
            return ($cert -ne $null)
        } catch {
            Write-Error "Error checking certificate in store`: $_"
            return $false
        }
    }
    
    # Function to get certificate thumbprint
    function Get-CertThumbprint {
        param (
            [Parameter(Mandatory=$true)]
            [string]$CertPath
        )
        
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($CertPath)
            return $cert.Thumbprint
        } catch {
            Write-Error "Error reading certificate from $CertPath`: $_"
            return $null
        }
    }
    
    # Function to import certificate
    function Import-CertWithVerification {
        param (
            [Parameter(Mandatory=$true)]
            [string]$CertPath,
            
            [Parameter(Mandatory=$true)]
            [string]$StoreName,
            
            [Parameter(Mandatory=$true)]
            [string]$StoreLocation,
            
            [Parameter(Mandatory=$false)]
            [string]$CertType,
            
            [Parameter(Mandatory=$false)]
            [string]$FriendlyName,
            
            [Parameter(Mandatory=$false)]
            [securestring]$Password
        )
        
        # Get certificate thumbprint before import
        $thumbprint = Get-CertThumbprint -CertPath $CertPath
        if (-not $thumbprint) {
            Write-Error "Failed to read certificate from $CertPath"
            return $false
        }
        
        # Check if certificate is already in the store
        $alreadyExists = Test-CertificateInStore -Thumbprint $thumbprint -StoreName $StoreName -StoreLocation $StoreLocation
        if ($alreadyExists -and -not $Force) {
            Write-Host "Certificate $CertType ($FriendlyName) is already in the $StoreLocation\$StoreName store." -ForegroundColor Green
            return $true
        } elseif ($alreadyExists -and $Force) {
            Write-Host "Certificate $CertType ($FriendlyName) is already in the $StoreLocation\$StoreName store but will be reimported due to -Force." -ForegroundColor Yellow
        }
        
        # Display certificate details
        Write-Host "Processing $CertType certificate:" -ForegroundColor Cyan
        Write-Host "  - Path: $CertPath" -ForegroundColor White
        Write-Host "  - Target Store: $StoreLocation\$StoreName" -ForegroundColor White
        Write-Host "  - Thumbprint: $thumbprint" -ForegroundColor White
        
        # Import the certificate
        $importSuccess = $false
        try {
            if ($CertPath.EndsWith(".pfx")) {
                # For PFX, we need to handle password
                if (-not $Password) {
                    Write-Host "A Windows security dialog may appear to prompt for the PFX password." -ForegroundColor Yellow
                    Write-Host "   Please respond to this dialog to continue with the import." -ForegroundColor Yellow
                    
                    # Using certutil to import the PFX because it handles the Windows prompt properly
                    $result = certutil -importpfx -user -p "" $CertPath NoRoot,NoExport
                    $importSuccess = $result -match "CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES"
                } else {
                    # Import with provided password
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $cert.Import($CertPath, $Password, "PersistKeySet,Exportable")
                    
                    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $StoreLocation)
                    $store.Open("ReadWrite")
                    $store.Add($cert)
                    $store.Close()
                    
                    $importSuccess = $true
                }
            } else {
                # For regular certificates (.cer files)
                Write-Host "A Windows security dialog may appear to confirm certificate import." -ForegroundColor Yellow
                Write-Host "   Please respond to this dialog to continue with the import." -ForegroundColor Yellow
                
                # Use certutil for .cer files too, as it handles the Windows UI prompts properly
                $result = if ($StoreLocation -eq "LocalMachine") {
                    certutil -addstore $StoreName $CertPath
                } else {
                    certutil -user -addstore $StoreName $CertPath
                }
                
                $importSuccess = $result -match "added to store" -or $result -match "Certificate "
            }
        } catch {
            Write-Error "Error importing certificate`: $_"
            $importSuccess = $false
        }
        
        # Verify if the certificate was imported successfully
        if ($importSuccess) {
            # Wait a moment for the import to complete
            Start-Sleep -Seconds 2
            
            # Verify the certificate is in the store
            $verifyExists = Test-CertificateInStore -Thumbprint $thumbprint -StoreName $StoreName -StoreLocation $StoreLocation
            
            if ($verifyExists) {
                Write-Host "Certificate $CertType was successfully imported into $StoreLocation\$StoreName" -ForegroundColor Green
                return $true
            } else {
                Write-Warning "Certificate appears to have been imported but could not be verified in the store."
                Write-Host "   This could mean you need to manually complete the import in the security dialog." -ForegroundColor Yellow
                
                # Start a countdown timer for user to confirm manual action
                Write-Host "`nPlease confirm when you have completed the manual import:" -ForegroundColor Cyan
                Write-Host "1. Respond to any Windows security dialogs" -ForegroundColor White
                Write-Host "2. Type 'Y' and press Enter when complete, or wait $TimeoutSeconds seconds for timeout" -ForegroundColor White
                
                $timeoutTime = (Get-Date).AddSeconds($TimeoutSeconds)
                $completed = $false
                
                while ((Get-Date) -lt $timeoutTime -and -not $completed) {
                    if ([Console]::KeyAvailable) {
                        $key = [Console]::ReadKey($true)
                        if ($key.Key -eq "Y") {
                            $completed = $true
                            Write-Host "User confirmed manual import completion." -ForegroundColor Green
                        }
                    }
                    
                    # Check again if certificate is in store
                    $verifyExists = Test-CertificateInStore -Thumbprint $thumbprint -StoreName $StoreName -StoreLocation $StoreLocation
                    if ($verifyExists) {
                        $completed = $true
                        Write-Host "Certificate import verified in store!" -ForegroundColor Green
                        return $true
                    }
                    
                    Start-Sleep -Seconds 1
                    $remainingTime = [Math]::Ceiling(($timeoutTime - (Get-Date)).TotalSeconds)
                    Write-Host "`rWaiting for confirmation or verification: $remainingTime seconds remaining..." -NoNewline -ForegroundColor Yellow
                }
                
                Write-Host "`r                                                                               " -NoNewline
                
                # One final check
                $verifyExists = Test-CertificateInStore -Thumbprint $thumbprint -StoreName $StoreName -StoreLocation $StoreLocation
                if ($verifyExists) {
                    Write-Host "Certificate $CertType was successfully imported into $StoreLocation\$StoreName" -ForegroundColor Green
                    return $true
                } else {
                    Write-Warning "Certificate import could not be verified after timeout period."
                    return $false
                }
            }
        } else {
            Write-Error "Failed to import certificate $CertType into $StoreLocation\$StoreName store."
            return $false
        }
    }
    
    # Begin the import process
    Write-Host "=======================================================" -ForegroundColor White
    Write-Host "CERTIFICATE IMPORT PROCESS" -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor White
    Write-Host "This function will import code signing certificates" -ForegroundColor Yellow
    Write-Host "You may see Windows security dialogs during this process" -ForegroundColor Yellow
    Write-Host "Please respond to these dialogs to continue" -ForegroundColor Yellow
    Write-Host "=======================================================" -ForegroundColor White
    
    # Import the root certificate to the Trusted Root CA store
    $rootSuccess = Import-CertWithVerification -CertPath $rootCertPath -StoreName "Root" -StoreLocation "LocalMachine" -CertType "Root CA" -FriendlyName "Root CA Certificate"
    
    # Import the issuing CA certificate to the Intermediate CA store
    $issuingSuccess = Import-CertWithVerification -CertPath $issuingCertPath -StoreName "CA" -StoreLocation "LocalMachine" -CertType "Issuing CA" -FriendlyName "Issuing CA Certificate"
    
    # Import the leaf certificate without private key to the Trusted Publishers store
    $codeSuccess = Import-CertWithVerification -CertPath $codeCertPath -StoreName "TrustedPublisher" -StoreLocation "LocalMachine" -CertType "Code Signing" -FriendlyName "Code Signing Certificate"
    
    # Import the PFX (with private key) to the Personal store
    $pfxSuccess = Import-CertWithVerification -CertPath $codeCertPfxPath -StoreName "My" -StoreLocation "CurrentUser" -CertType "Code Signing (with private key)" -FriendlyName "Code Signing Certificate (with private key)" -Password $PfxPassword
    
    # Summary
    Write-Host "`n=======================================================" -ForegroundColor White
    Write-Host "CERTIFICATE IMPORT SUMMARY" -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor White
    Write-Host "Root CA Certificate     : $(if ($rootSuccess) { "Imported [OK]" } else { "Failed [FAIL]" })" -ForegroundColor $(if ($rootSuccess) { "Green" } else { "Red" })
    Write-Host "Issuing CA Certificate  : $(if ($issuingSuccess) { "Imported [OK]" } else { "Failed [FAIL]" })" -ForegroundColor $(if ($issuingSuccess) { "Green" } else { "Red" })
    Write-Host "Code Signing Certificate: $(if ($codeSuccess) { "Imported [OK]" } else { "Failed [FAIL]" })" -ForegroundColor $(if ($codeSuccess) { "Green" } else { "Red" })
    Write-Host "Code Signing PFX        : $(if ($pfxSuccess) { "Imported [OK]" } else { "Failed [FAIL]" })" -ForegroundColor $(if ($pfxSuccess) { "Green" } else { "Red" })
    Write-Host "=======================================================" -ForegroundColor White
    
    # Final certificate store verification
    Write-Host "`nVerifying certificate stores..." -ForegroundColor Cyan
    
    # Create a result object
    $result = [PSCustomObject]@{
        Success = $rootSuccess -and $issuingSuccess -and $codeSuccess -and $pfxSuccess
        RootCertImported = $rootSuccess
        IssuingCertImported = $issuingSuccess
        CodeSigningCertImported = $codeSuccess
        CodeSigningPfxImported = $pfxSuccess
        RootCerts = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*$($RootCertFile.Replace('.cer', ''))*" }
        IssuingCerts = Get-ChildItem -Path Cert:\LocalMachine\CA | Where-Object { $_.Subject -like "*$($IssuingCertFile.Replace('.cer', ''))*" }
        TrustedPublisherCerts = Get-ChildItem -Path Cert:\LocalMachine\TrustedPublisher | Where-Object { $_.Subject -like "*$($CodeSigningCertFile.Replace('.cer', ''))*" }
        PersonalCerts = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*$($CodeSigningPfxFile.Replace('.pfx', ''))*" }
    }
    
    # Display certificates in the stores
    if ($result.RootCerts) {
        Write-Host "Certificates in LocalMachine\Root:" -ForegroundColor Yellow
        $result.RootCerts | Format-Table -Property Thumbprint, Subject, NotBefore, NotAfter
    }
    
    if ($result.IssuingCerts) {
        Write-Host "`nCertificates in LocalMachine\CA:" -ForegroundColor Yellow
        $result.IssuingCerts | Format-Table -Property Thumbprint, Subject, NotBefore, NotAfter
    }
    
    if ($result.TrustedPublisherCerts) {
        Write-Host "`nCertificates in LocalMachine\TrustedPublisher:" -ForegroundColor Yellow
        $result.TrustedPublisherCerts | Format-Table -Property Thumbprint, Subject, NotBefore, NotAfter
    }
    
    if ($result.PersonalCerts) {
        Write-Host "`nCertificates in CurrentUser\My:" -ForegroundColor Yellow
        $result.PersonalCerts | Format-Table -Property Thumbprint, Subject, NotBefore, NotAfter, HasPrivateKey
    }
    
    # Next steps
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Run Test-ScriptSignature to validate signed scripts" -ForegroundColor Yellow
    Write-Host "2. If validation issues persist, check if certificates were imported with correct permissions" -ForegroundColor Yellow
    Write-Host "3. For PFX files, ensure the password used during import was correct" -ForegroundColor Yellow
    
    return $result
} 