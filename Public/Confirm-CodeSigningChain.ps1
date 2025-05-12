function Confirm-CodeSigningChain {
    <#
    .SYNOPSIS
        Verifies and installs the certificate chain for a code signing certificate.
        
    .DESCRIPTION
        This function checks if a certificate's chain is complete and trusted. If issues are found,
        it offers to install missing certificates in the chain to the appropriate certificate stores.
        
    .PARAMETER Certificate
        The code signing certificate object to verify the chain for.
        
    .PARAMETER AutoInstall
        If specified, automatically installs missing certificates without prompting.
        
    .PARAMETER SkipPrompt
        If specified, doesn't prompt for installation of missing certificates. 
        Useful for automation scenarios.
        
    .PARAMETER SkipRevocationCheck
        If specified, skips online revocation checking which can fail when revocation servers are unavailable.
        
    .PARAMETER SkipChainValidation
        If specified, completely bypasses certificate chain validation.
        
    .PARAMETER ReturnDetails
        If specified, returns a detailed object with the validation results.
        
    .EXAMPLE
        $cert = Get-Item -Path "Cert:\CurrentUser\My\1234567890ABCDEF1234567890ABCDEF12345678"
        Confirm-CodeSigningChain -Certificate $cert
        
        Checks if the certificate chain is valid and prompts to install missing certificates if needed.
        
    .EXAMPLE
        $cert = Get-Item -Path "Cert:\CurrentUser\My\1234567890ABCDEF1234567890ABCDEF12345678"
        Confirm-CodeSigningChain -Certificate $cert -AutoInstall
        
        Checks if the certificate chain is valid and automatically installs missing certificates.

    .EXAMPLE
        $cert = Get-Item -Path "Cert:\CurrentUser\My\1234567890ABCDEF1234567890ABCDEF12345678"
        Confirm-CodeSigningChain -Certificate $cert -SkipRevocationCheck
        
        Checks if the certificate chain is valid without performing online revocation checks.
        
    .EXAMPLE
        $cert = Get-Item -Path "Cert:\CurrentUser\My\1234567890ABCDEF1234567890ABCDEF12345678"
        Confirm-CodeSigningChain -Certificate $cert -SkipChainValidation
        
        Completely bypasses certificate chain validation. Useful for test environments with self-signed 
        certificates or in environments where chain validation is not possible.
        
    .EXAMPLE
        $cert = Get-Item -Path "Cert:\CurrentUser\My\1234567890ABCDEF1234567890ABCDEF12345678"
        $result = Confirm-CodeSigningChain -Certificate $cert -ReturnDetails
        $result | Format-List
        
        Returns a detailed object with validation results instead of a simple boolean.
        
    .NOTES
        This function helps ensure that code signing operations don't fail due to certificate chain issues.
        
    .OUTPUTS
        [bool] or [PSCustomObject] depending on -ReturnDetails parameter.
        Without -ReturnDetails: True if the certificate chain is valid or was successfully installed, False otherwise.
        With -ReturnDetails: A custom object with detailed information about the chain validation.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        
        [Parameter(Mandatory = $false)]
        [switch]$AutoInstall,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipPrompt,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipRevocationCheck,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipChainValidation,
        
        [Parameter(Mandatory = $false)]
        [switch]$ReturnDetails
    )
    
    # Define a standardized result object
    $result = [PSCustomObject]@{
        Success = $false
        CertificateSubject = $Certificate.Subject
        CertificateThumbprint = $Certificate.Thumbprint
        CertificateIssuer = $Certificate.Issuer
        ValidationSkipped = $false
        ValidationSucceeded = $false
        ChainStatus = @()
        ChainElements = @()
        InstalledCertificates = @()
        ErrorDetails = $null
    }
    
    try {
        if ($SkipChainValidation) {
            Write-Host "Certificate chain validation skipped" -ForegroundColor Yellow
            $result.ValidationSkipped = $true
            $result.Success = $true
            
            if ($ReturnDetails) {
                return $result
            } else {
                return $true
            }
        }
        
        Write-Verbose "Checking certificate chain for $($Certificate.Subject) (Thumbprint $($Certificate.Thumbprint))"
        
        # Create a new chain object
        $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
        
        # Configure chain building parameters
        if ($SkipRevocationCheck) {
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            Write-Verbose "Skipping revocation checking as requested"
        } else {
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        }
        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        
        # Build the chain
        $chainBuilt = $chain.Build($Certificate)
        
        # Track chain elements for details
        $chainElements = @()
        for ($i = 0; $i -lt $chain.ChainElements.Count; $i++) {
            $element = $chain.ChainElements[$i]
            $chainElements += [PSCustomObject]@{
                Subject = $element.Certificate.Subject
                Issuer = $element.Certificate.Issuer
                Thumbprint = $element.Certificate.Thumbprint
                NotBefore = $element.Certificate.NotBefore
                NotAfter = $element.Certificate.NotAfter
                Position = if ($i -eq 0) { "Leaf" } elseif ($i -eq ($chain.ChainElements.Count - 1)) { "Root" } else { "Intermediate" }
                StatusFlags = @($element.ChainElementStatus | ForEach-Object { $_.Status.ToString() })
            }
        }
        $result.ChainElements = $chainElements
        
        # If chain built successfully with no issues
        if ($chainBuilt -and $chain.ChainStatus.Length -eq 0) {
            Write-Verbose "Certificate chain is valid and trusted"
            $result.ValidationSucceeded = $true
            $result.Success = $true
            
            if ($ReturnDetails) {
                return $result
            } else {
                return $true
            }
        }
        
        # Chain has issues
        Write-Warning "Certificate chain has issues"
        
        # Store chain status information
        foreach ($status in $chain.ChainStatus) {
            $statusInfo = [PSCustomObject]@{
                Status = $status.Status.ToString()
                StatusInformation = $status.StatusInformation.Trim()
            }
            $result.ChainStatus += $statusInfo
            Write-Warning "  - $($statusInfo.StatusInformation)"
        }
        
        # Check if we should proceed with installation
        $shouldInstall = $false
        
        if ($AutoInstall) {
            $shouldInstall = $true
        }
        elseif (-not $SkipPrompt) {
            $response = Read-Host "Do you want to install missing certificates in the chain? (Y/N)"
            $shouldInstall = ($response -eq 'Y' -or $response -eq 'y')
        }
        
        # Install certificates if needed
        if ($shouldInstall) {
            Write-Host "Installing certificates in the chain..." -ForegroundColor Yellow
            
            $installedCount = 0
            
            # Skip the first certificate (that's the one we're checking)
            for ($i = 1; $i -lt $chain.ChainElements.Count; $i++) {
                $cert = $chain.ChainElements[$i].Certificate
                
                # Determine appropriate store based on certificate type
                $store = if ($cert.Subject -match "Root" -or
                          ([string]::IsNullOrEmpty($cert.Subject) -and [string]::IsNullOrEmpty($cert.Issuer)) -or
                          ($cert.Subject -eq $cert.Issuer)) {
                    # This is likely a root certificate
                    "Root"
                }
                else {
                    # This is likely an intermediate certificate
                    "CA"
                }
                
                Write-Verbose "Certificate $($cert.Subject) will be installed to $store store"
                
                # Open certificate store
                $certStore = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $store, "CurrentUser"
                $certStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                
                # Check if certificate is already in the store
                $existingCert = $certStore.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
                
                if ($existingCert) {
                    Write-Verbose "Certificate already exists in store $($cert.Subject) (Thumbprint $($cert.Thumbprint))"
                }
                else {
                    # Install certificate
                    $certStore.Add($cert)
                    $installedCount++
                    
                    $certInfo = [PSCustomObject]@{
                        Subject = $cert.Subject
                        Issuer = $cert.Issuer
                        Thumbprint = $cert.Thumbprint
                        Store = "CurrentUser\$store"
                        ExpirationDate = $cert.NotAfter
                    }
                    $result.InstalledCertificates += $certInfo
                    
                    Write-Host "Installed certificate to CurrentUser\$store store $($cert.Subject)" -ForegroundColor Green
                    Write-Host "  Thumbprint $($cert.Thumbprint)" -ForegroundColor Green
                }
                
                $certStore.Close()
            }
            
            if ($installedCount -gt 0) {
                Write-Host "Installed $installedCount certificates to complete the chain" -ForegroundColor Green
                
                # Verify the chain again
                $newChain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
                if ($SkipRevocationCheck) {
                    $newChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                }
                $newChainBuilt = $newChain.Build($Certificate)
                
                if ($newChainBuilt -and $newChain.ChainStatus.Length -eq 0) {
                    Write-Host "Certificate chain is now valid and trusted" -ForegroundColor Green
                    $result.ValidationSucceeded = $true
                    $result.Success = $true
                    
                    if ($ReturnDetails) {
                        return $result
                    } else {
                        return $true
                    }
                }
                else {
                    Write-Warning "Certificate chain still has issues after installing certificates"
                    
                    # Update chain status information
                    $result.ChainStatus = @()
                    foreach ($status in $newChain.ChainStatus) {
                        $statusInfo = [PSCustomObject]@{
                            Status = $status.Status.ToString()
                            StatusInformation = $status.StatusInformation.Trim()
                        }
                        $result.ChainStatus += $statusInfo
                        Write-Warning "  - $($statusInfo.StatusInformation)"
                    }
                    
                    if ($ReturnDetails) {
                        return $result
                    } else {
                        return $false
                    }
                }
            }
            else {
                Write-Host "No new certificates were installed" -ForegroundColor Yellow
                
                if ($ReturnDetails) {
                    return $result
                } else {
                    return $false
                }
            }
        }
        else {
            Write-Warning "Certificate chain validation failed and no certificates were installed"
            
            if ($ReturnDetails) {
                return $result
            } else {
                return $false
            }
        }
    }
    catch {
        $errorMessage = "Error verifying certificate chain: $_"
        Write-Error $errorMessage
        
        $result.ErrorDetails = [PSCustomObject]@{
            Message = $errorMessage
            Exception = $_.Exception.GetType().Name
            StackTrace = $_.ScriptStackTrace
        }
        
        if ($ReturnDetails) {
            return $result
        } else {
            return $false
        }
    }
}

# Export this function
Export-ModuleMember -Function Confirm-CodeSigningChain
