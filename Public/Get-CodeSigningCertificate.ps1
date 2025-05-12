function Get-CodeSigningCertificate {
    <#
    .SYNOPSIS
        Gets code signing certificates from the certificate store or a file.
        
    .DESCRIPTION
        This function retrieves code signing certificates from various sources, including
        the certificate store, a PFX file, or a folder containing PFX files.
        
    .PARAMETER Thumbprint
        The thumbprint of the code signing certificate to retrieve from the certificate store.
        
    .PARAMETER Path
        The path to a PFX certificate file.
        
    .PARAMETER Password
        The password for the PFX certificate file.
        
    .PARAMETER CertificateFolder
        The folder containing certificate files to search for code signing certificates.
        Default is "C:\temp\certs".
        
    .PARAMETER StoreLocation
        The certificate store location to search. Default is CurrentUser.
        Valid values are CurrentUser or LocalMachine.
        
    .PARAMETER ValidOnly
        If specified, only returns certificates that are valid for the current date and time.
        
    .PARAMETER ReturnDetails
        If specified, returns detailed certificate information including validity status
        and error details rather than just the certificate objects.
        
    .EXAMPLE
        Get-CodeSigningCertificate
        
        Searches for all code signing certificates in the CurrentUser\My store.
        
    .EXAMPLE
        Get-CodeSigningCertificate -Thumbprint "1234567890ABCDEF1234567890ABCDEF12345678"
        
        Retrieves a specific certificate by thumbprint from certificate stores.
        
    .EXAMPLE
        Get-CodeSigningCertificate -Path "C:\temp\certs\CodeSigningCert.pfx" -Password (ConvertTo-SecureString -String "Password123" -AsPlainText -Force)
        
        Retrieves a certificate from a PFX file with the specified password.
        
    .EXAMPLE
        Get-CodeSigningCertificate -CertificateFolder "C:\temp\certificates"
        
        Searches for all PFX files in the specified folder and returns valid code signing certificates.
        
    .EXAMPLE
        Get-CodeSigningCertificate -ReturnDetails
        
        Returns detailed information about certificates, including validity checks and error messages.
        
    .OUTPUTS
        Without ReturnDetails: System.Security.Cryptography.X509Certificates.X509Certificate2[] - A collection of certificate objects.
        With ReturnDetails: PSCustomObject - A custom object with detailed information about the certificates.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Store')]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2[]], [PSCustomObject])]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Thumbprint')]
        [string]$Thumbprint,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
        [string]$Path,
        
        [Parameter(Mandatory = $false, ParameterSetName = 'Path')]
        [System.Security.SecureString]$Password,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'Folder')]
        [string]$CertificateFolder = "C:\temp\certs",
        
        [Parameter(Mandatory = $false, ParameterSetName = 'Store')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Thumbprint')]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$StoreLocation = 'CurrentUser',
        
        [Parameter(Mandatory = $false)]
        [switch]$ValidOnly,
        
        [Parameter(Mandatory = $false)]
        [switch]$ReturnDetails
    )
    
    # Function to check if a certificate is valid for code signing
    function Test-CodeSigningCertificate {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
        )
        
        $result = [PSCustomObject]@{
            IsValid = $false
            HasCodeSigningEKU = $false
            IsTimeValid = $false
            HasPrivateKey = $false
            ValidationDetails = [PSCustomObject]@{
                Subject = $Certificate.Subject
                Issuer = $Certificate.Issuer
                Thumbprint = $Certificate.Thumbprint
                NotBefore = $Certificate.NotBefore
                NotAfter = $Certificate.NotAfter
                KeyUsage = ""
                EnhancedKeyUsage = @()
            }
        }
        
        # Check if certificate has Code Signing EKU
        if ($Certificate.Extensions) {
            foreach ($extension in $Certificate.Extensions) {
                if ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
                    foreach ($eku in $extension.EnhancedKeyUsages) {
                        $result.ValidationDetails.EnhancedKeyUsage += $eku.FriendlyName
                        if ($eku.Value -eq "1.3.6.1.5.5.7.3.3") {  # Code Signing OID
                            $result.HasCodeSigningEKU = $true
                        }
                    }
                }
                
                if ($extension -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {
                    $result.ValidationDetails.KeyUsage = $extension.KeyUsages.ToString()
                }
            }
        }
        
        # Check if certificate is valid for current date
        $now = Get-Date
        $notBefore = $Certificate.NotBefore
        $notAfter = $Certificate.NotAfter
        $result.IsTimeValid = ($now -ge $notBefore) -and ($now -le $notAfter)
        
        # Check if certificate has private key
        $result.HasPrivateKey = $Certificate.HasPrivateKey
        
        # Overall validity
        $result.IsValid = $result.HasCodeSigningEKU -and $result.IsTimeValid -and $result.HasPrivateKey
        
        return $result
    }
    
    # Initialize detailed result object if ReturnDetails is specified
    if ($ReturnDetails) {
        $detailedResult = [PSCustomObject]@{
            Success = $false
            Certificates = @()
            InvalidCertificates = @()
            TotalFound = 0
            ValidCount = 0
            InvalidCount = 0
            Source = $PSCmdlet.ParameterSetName
            ErrorDetails = $null
        }
    }
    
    $certificates = @()
    
    try {
        switch ($PSCmdlet.ParameterSetName) {
            'Thumbprint' {
                Write-Verbose "Searching for certificate with thumbprint $Thumbprint"
                
                # Try to find in specified store location
                $cert = Get-Item -Path "Cert:\$StoreLocation\My\$Thumbprint" -ErrorAction SilentlyContinue
                
                if ($cert) {
                    $certificates += $cert
                    if ($ReturnDetails) {
                        $detailedResult.Source = "Cert:\$StoreLocation\My"
                    }
                }
                else {
                    $errorMsg = "Certificate with thumbprint $Thumbprint not found in $StoreLocation\My store."
                    Write-Warning $errorMsg
                    if ($ReturnDetails) {
                        $detailedResult.ErrorDetails = [PSCustomObject]@{
                            Message = $errorMsg
                            Type = "NotFound"
                        }
                    }
                }
            }
            'Path' {
                if (-not (Test-Path -Path $Path)) {
                    $errorMsg = "Certificate file not found: $Path"
                    Write-Error $errorMsg
                    if ($ReturnDetails) {
                        $detailedResult.ErrorDetails = [PSCustomObject]@{
                            Message = $errorMsg
                            Type = "FileNotFound"
                        }
                    }
                    if (-not $ReturnDetails) { return }
                }
                else {
                    Write-Verbose "Loading certificate from file: $Path"
                    
                    try {
                        if ($Password) {
                            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                                $Path,
                                $Password,
                                ([System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor 
                                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
                            )
                        }
                        else {
                            # When not using a password, we need to use a different constructor overload
                            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                                $Path
                            )
                        }
                        
                        $certificates += $cert
                        if ($ReturnDetails) {
                            $detailedResult.Source = "File: $Path"
                        }
                    }
                    catch {
                        $errorMsg = "Failed to load certificate from file: $_"
                        Write-Error $errorMsg
                        if ($ReturnDetails) {
                            $detailedResult.ErrorDetails = [PSCustomObject]@{
                                Message = $errorMsg
                                Type = "LoadError"
                                Exception = $_.Exception.GetType().Name
                            }
                        }
                        if (-not $ReturnDetails) { return }
                    }
                }
            }
            'Folder' {
                if (-not (Test-Path -Path $CertificateFolder)) {
                    $errorMsg = "Certificate folder not found: $CertificateFolder"
                    Write-Error $errorMsg
                    if ($ReturnDetails) {
                        $detailedResult.ErrorDetails = [PSCustomObject]@{
                            Message = $errorMsg
                            Type = "FolderNotFound"
                        }
                    }
                    if (-not $ReturnDetails) { return }
                }
                else {
                    Write-Verbose "Searching for certificate files in folder: $CertificateFolder"
                    
                    $pfxFiles = Get-ChildItem -Path $CertificateFolder -Filter "*.pfx" -ErrorAction SilentlyContinue
                    
                    if ($pfxFiles.Count -eq 0) {
                        $warnMsg = "No .pfx certificate files found in $CertificateFolder"
                        Write-Warning $warnMsg
                        if ($ReturnDetails) {
                            $detailedResult.ErrorDetails = [PSCustomObject]@{
                                Message = $warnMsg
                                Type = "NoFilesFound"
                            }
                        }
                        if (-not $ReturnDetails) { return }
                    }
                    else {
                        $certErrors = @()
                        foreach ($pfxFile in $pfxFiles) {
                            $certAttempt = [PSCustomObject]@{
                                File = $pfxFile.FullName
                                Success = $false
                                ErrorMessage = $null
                            }
                            
                            try {
                                # Try without a password first
                                try {
                                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                                        $pfxFile.FullName,
                                        $null,
                                        ([System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor 
                                        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
                                    )
                                    $certificates += $cert
                                    $certAttempt.Success = $true
                                }
                                catch {
                                    # If loading without password fails, log the error
                                    $certAttempt.ErrorMessage = "Failed to load certificate without password: $_"
                                    Write-Verbose $certAttempt.ErrorMessage
                                }
                            }
                            catch {
                                $certAttempt.ErrorMessage = "Failed to load certificate from $($pfxFile.FullName): $_"
                                Write-Verbose $certAttempt.ErrorMessage
                            }
                            
                            if (-not $certAttempt.Success) {
                                $certErrors += $certAttempt
                            }
                        }
                        
                        if ($ReturnDetails) {
                            $detailedResult.Source = "Folder: $CertificateFolder"
                            $detailedResult.CertificateLoadErrors = $certErrors
                        }
                    }
                }
            }
            'Store' {
                Write-Verbose "Searching for code signing certificates in $StoreLocation\My store"
                
                $storeCerts = Get-ChildItem -Path "Cert:\$StoreLocation\My" -ErrorAction SilentlyContinue
                
                if ($storeCerts.Count -eq 0) {
                    $warnMsg = "No certificates found in $StoreLocation\My store"
                    Write-Warning $warnMsg
                    if ($ReturnDetails) {
                        $detailedResult.ErrorDetails = [PSCustomObject]@{
                            Message = $warnMsg
                            Type = "NoStoreContent"
                        }
                    }
                    if (-not $ReturnDetails) { return }
                }
                else {
                    $certificates += $storeCerts
                    if ($ReturnDetails) {
                        $detailedResult.Source = "Cert:\$StoreLocation\My"
                    }
                }
            }
        }
        
        if ($ReturnDetails) {
            $detailedResult.TotalFound = $certificates.Count
        }
        
        # Filter certificates if needed
        if ($ValidOnly -or $PSCmdlet.ParameterSetName -eq 'Store') {
            $validCertificates = @()
            $invalidCertificates = @()
            
            foreach ($cert in $certificates) {
                $validationResult = Test-CodeSigningCertificate -Certificate $cert
                
                if ($ReturnDetails) {
                    $certDetails = [PSCustomObject]@{
                        Certificate = $cert
                        Subject = $cert.Subject
                        Issuer = $cert.Issuer
                        Thumbprint = $cert.Thumbprint
                        NotBefore = $cert.NotBefore
                        NotAfter = $cert.NotAfter
                        HasPrivateKey = $cert.HasPrivateKey
                        IsValid = $validationResult.IsValid
                        ValidationDetails = $validationResult.ValidationDetails
                        IssuerName = if ($cert.IssuerName) { $cert.IssuerName.Name } else { $null }
                        SubjectName = if ($cert.SubjectName) { $cert.SubjectName.Name } else { $null }
                        SerialNumber = $cert.SerialNumber
                        FriendlyName = $cert.FriendlyName
                    }
                    
                    if ($validationResult.IsValid) {
                        $detailedResult.Certificates += $certDetails
                    }
                    else {
                        $detailedResult.InvalidCertificates += $certDetails
                    }
                }
                
                if ($validationResult.IsValid) {
                    $validCertificates += $cert
                }
                else {
                    $invalidCertificates += $cert
                }
            }
            
            $certificates = $validCertificates
            
            if ($ReturnDetails) {
                $detailedResult.ValidCount = $validCertificates.Count
                $detailedResult.InvalidCount = $invalidCertificates.Count
            }
        }
        elseif ($ReturnDetails) {
            # If not filtering but ReturnDetails requested, still populate the details
            foreach ($cert in $certificates) {
                $validationResult = Test-CodeSigningCertificate -Certificate $cert
                
                $certDetails = [PSCustomObject]@{
                    Certificate = $cert
                    Subject = $cert.Subject
                    Issuer = $cert.Issuer
                    Thumbprint = $cert.Thumbprint
                    NotBefore = $cert.NotBefore
                    NotAfter = $cert.NotAfter
                    HasPrivateKey = $cert.HasPrivateKey
                    IsValid = $validationResult.IsValid
                    ValidationDetails = $validationResult.ValidationDetails
                    IssuerName = if ($cert.IssuerName) { $cert.IssuerName.Name } else { $null }
                    SubjectName = if ($cert.SubjectName) { $cert.SubjectName.Name } else { $null }
                    SerialNumber = $cert.SerialNumber
                    FriendlyName = $cert.FriendlyName
                }
                
                if ($validationResult.IsValid) {
                    $detailedResult.Certificates += $certDetails
                    $detailedResult.ValidCount++
                }
                else {
                    $detailedResult.InvalidCertificates += $certDetails
                    $detailedResult.InvalidCount++
                }
            }
        }
        
        if ($certificates.Count -eq 0) {
            $warnMsg = "No valid code signing certificates found."
            Write-Warning $warnMsg
            if ($ReturnDetails) {
                if (-not $detailedResult.ErrorDetails) {
                    $detailedResult.ErrorDetails = [PSCustomObject]@{
                        Message = $warnMsg
                        Type = "NoValidCertificates"
                    }
                }
            }
        }
        else {
            if ($ReturnDetails) {
                $detailedResult.Success = $true
            }
        }
        
        if ($ReturnDetails) {
            return $detailedResult
        }
        else {
            return $certificates
        }
    }
    catch {
        $errorMsg = "Error retrieving code signing certificates: $_"
        Write-Error $errorMsg
        
        if ($ReturnDetails) {
            $detailedResult.ErrorDetails = [PSCustomObject]@{
                Message = $errorMsg
                Exception = $_.Exception.GetType().Name
                StackTrace = $_.ScriptStackTrace
            }
            return $detailedResult
        }
    }
}

# Export this function
Export-ModuleMember -Function Get-CodeSigningCertificate
