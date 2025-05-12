function Test-CodeSigningCertificate {
    <#
    .SYNOPSIS
        Tests if a certificate is valid for code signing.
        
    .DESCRIPTION
        This function checks if a certificate is valid for code signing by verifying:
        1. It has the Code Signing Enhanced Key Usage extension
        2. It is valid for the current date and time
        3. It has a private key associated with it
        
    .PARAMETER Certificate
        The certificate object to test.

    .PARAMETER Thumbprint
        The thumbprint of a certificate to test from the certificate store.
        
    .PARAMETER Path
        The path to a PFX certificate file to test.
        
    .PARAMETER Password
        The password for the PFX certificate file.
        
    .PARAMETER StoreLocation
        The certificate store location to search when using Thumbprint.
        Default is CurrentUser. Valid values are CurrentUser or LocalMachine.
        
    .PARAMETER Detailed
        If specified, returns a detailed report with specific test results rather than a boolean value.
        
    .EXAMPLE
        $cert = Get-Item -Path "Cert:\CurrentUser\My\1234567890ABCDEF1234567890ABCDEF12345678"
        Test-CodeSigningCertificate -Certificate $cert
        
        Tests if the specified certificate is valid for code signing.
        
    .EXAMPLE
        Test-CodeSigningCertificate -Thumbprint "1234567890ABCDEF1234567890ABCDEF12345678" -Detailed
        
        Tests a certificate by thumbprint and returns a detailed report.
        
    .EXAMPLE
        Test-CodeSigningCertificate -Path "C:\temp\certs\CodeSigningCert.pfx" -Password (ConvertTo-SecureString -String "Password123" -AsPlainText -Force)
        
        Tests a certificate from a PFX file with the specified password.
        
    .OUTPUTS
        Boolean if Detailed is not specified, PSObject with test results if Detailed is specified.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Certificate')]
    [OutputType([bool], ParameterSetName = 'Certificate')]
    [OutputType([bool], ParameterSetName = 'Thumbprint')]
    [OutputType([bool], ParameterSetName = 'Path')]
    [OutputType([PSObject], ParameterSetName = 'Certificate')]
    [OutputType([PSObject], ParameterSetName = 'Thumbprint')]
    [OutputType([PSObject], ParameterSetName = 'Path')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate', Position = 0)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [string]$Thumbprint,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
        [string]$Path,
        
        [Parameter(Mandatory = $false, ParameterSetName = 'Path')]
        [System.Security.SecureString]$Password,
        
        [Parameter(Mandatory = $false, ParameterSetName = 'Thumbprint')]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$StoreLocation = 'CurrentUser',
        
        [Parameter(Mandatory = $false)]
        [switch]$Detailed
    )
    
    try {
        # Get the certificate object based on parameter set
        switch ($PSCmdlet.ParameterSetName) {
            'Thumbprint' {
                $Certificate = Get-Item -Path "Cert:\$StoreLocation\My\$Thumbprint" -ErrorAction Stop
            }
            'Path' {
                if (-not (Test-Path -Path $Path)) {
                    Write-Error "Certificate file not found: $Path"
                    return $false
                }
                
                if ($Password) {
                    $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                        $Path,
                        $Password,
                        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor
                        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
                    )
                }
                else {
                    $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                        $Path,
                        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor
                        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
                    )
                }
            }
        }
        
        # Check if certificate has Code Signing EKU
        $hasCodeSigningEKU = $false
        $codeSigningOID = "1.3.6.1.5.5.7.3.3"  # Code Signing OID
        
        if ($Certificate.Extensions) {
            foreach ($extension in $Certificate.Extensions) {
                if ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
                    foreach ($eku in $extension.EnhancedKeyUsages) {
                        if ($eku.Value -eq $codeSigningOID) {
                            $hasCodeSigningEKU = $true
                            break
                        }
                    }
                }
            }
        }
        
        # Check certificate validity period
        $now = Get-Date
        $notBefore = $Certificate.NotBefore
        $notAfter = $Certificate.NotAfter
        $isTimeValid = ($now -ge $notBefore) -and ($now -le $notAfter)
        
        # Check private key
        $hasPrivateKey = $Certificate.HasPrivateKey
        
        # Check if time is close to expiration (within 30 days)
        $isNearExpiration = ($notAfter - $now).TotalDays -le 30
        
        # Overall validity
        $isValid = $hasCodeSigningEKU -and $isTimeValid -and $hasPrivateKey
        
        # Return detailed results if requested
        if ($Detailed) {
            $result = [PSCustomObject]@{
                Subject = $Certificate.Subject
                Thumbprint = $Certificate.Thumbprint
                Issuer = $Certificate.Issuer
                ValidFrom = $notBefore
                ValidTo = $notAfter
                HasPrivateKey = $hasPrivateKey
                HasCodeSigningEKU = $hasCodeSigningEKU
                IsTimeValid = $isTimeValid
                IsNearExpiration = $isNearExpiration
                IsValid = $isValid
            }
            
            return $result
        }
        else {
            return $isValid
        }
    }
    catch {
        Write-Error "Error testing code signing certificate: $_"
        return $false
    }
}

# Export this function
Export-ModuleMember -Function Test-CodeSigningCertificate
