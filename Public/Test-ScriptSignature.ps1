function Test-ScriptSignature {
    <#
    .SYNONOPSIS
        Validates script signatures and execution policy compatibility.
        
    .DESCRIPTION
        This function performs comprehensive validation of script signatures, including:
        1. Signature presence and validity
        2. Content modification detection
        3. Execution policy compatibility
        4. Certificate chain validation
        5. External time validation (optional)
        
    .PARAMETER Path
        The path to the script file to validate.
        
    .PARAMETER ExecutionPolicy
        The execution policy to test against. Default is 'AllSigned'.
        Valid values: 'AllSigned', 'RemoteSigned', 'Restricted', 'Unrestricted', 'Bypass'
        
    .PARAMETER SkipExecutionPolicyCheck
        If specified, skips the execution policy validation.
        
    .PARAMETER SkipRevocationCheck
        If specified, skips online revocation checking when validating certificates.
        Useful in environments with restricted internet access or when revocation servers are unavailable.
        
    .PARAMETER UseExternalTimeValidation
        If specified, the function will validate certificate validity against trusted external time sources
        in addition to the local system time. This is useful in environments where the system clock
        may be incorrect.
        
    .PARAMETER TimeServers
        Optional array of time server API endpoints to query for external time validation.
        Only used if UseExternalTimeValidation is specified.
        
    .PARAMETER TimeoutSeconds
        Timeout in seconds for each external time API call. Default is 5 seconds.
        Only used if UseExternalTimeValidation is specified.
        
    .PARAMETER Detailed
        If specified, returns a detailed report with specific test results.
        
    .EXAMPLE
        Test-ScriptSignature -Path "C:\Scripts\MyScript.ps1"
        
        Validates the script signature and execution policy compatibility.
        
    .EXAMPLE
        Test-ScriptSignature -Path "C:\Scripts\MyScript.ps1" -ExecutionPolicy AllSigned -Detailed
        
        Validates the script with AllSigned execution policy and returns detailed results.
        
    .EXAMPLE
        Test-ScriptSignature -Path "C:\Scripts\MyScript.ps1" -UseExternalTimeValidation -Detailed
        
        Validates the script signature using both local and external trusted time sources.
        
    .EXAMPLE
        Test-ScriptSignature -Path "C:\Scripts\MyScript.ps1" -UseExternalTimeValidation -TimeoutSeconds 10
        
        Validates the script signature with external time validation and increased timeout of 10 seconds.
        
    .EXAMPLE
        Test-ScriptSignature -Path "C:\Scripts\MyScript.ps1" -SkipRevocationCheck
        
        Validates the script signature without performing online revocation checks.
        Useful in environments where revocation servers are not accessible.
        
    .OUTPUTS
        Boolean if Detailed is not specified, PSObject with test results if Detailed is specified.
    #>
    [CmdletBinding()]
    [OutputType([bool], [PSObject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if (-not (Test-Path -Path $_)) {
                throw "File not found: $_"
            }
            if (-not (Test-Path -Path $_ -PathType Leaf)) {
                throw "Path must be a file: $_"
            }
            return $true
        })]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('AllSigned', 'RemoteSigned', 'Restricted', 'Unrestricted', 'Bypass')]
        [string]$ExecutionPolicy = 'AllSigned',
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipExecutionPolicyCheck,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipRevocationCheck,
        
        [Parameter(Mandatory = $false)]
        [switch]$UseExternalTimeValidation,
        
        [Parameter(Mandatory = $false)]
        [string[]]$TimeServers,
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 5,
        
        [Parameter(Mandatory = $false)]
        [switch]$Detailed
    )
    
    try {
        # Initialize result object
        $result = [PSCustomObject]@{
            Path = $Path
            HasSignature = $false
            SignatureValid = $false
            ContentModified = $false
            ExecutionPolicyCompatible = $false
            CertificateValid = $false
            CertificateValidWithExternalTime = $null
            ChainValid = $false
            ChainValidWithExternalTime = $null
            ErrorDetails = $null
            SignatureDetails = $null
            ExecutionPolicyDetails = $null
            RevocationCheckSkipped = $SkipRevocationCheck
            ExternalTimeValidation = $null
        }
        
        # Get script content and signature
        $scriptContent = Get-Content -Path $Path -Raw
        $signature = Get-AuthenticodeSignature -FilePath $Path
        
        # Check if script has a signature
        $result.HasSignature = $signature.Status -ne 'NotSigned'
        
        # Get external time validation if requested
        $externalTimeResult = $null
        if ($UseExternalTimeValidation) {
            Write-Verbose "Performing external time validation..."
            $externalTimeParams = @{
                Verbose = $false
            }
            
            if ($TimeServers) {
                $externalTimeParams.TimeServers = $TimeServers
            }
            
            if ($TimeoutSeconds -ne 5) {
                $externalTimeParams.TimeoutSeconds = $TimeoutSeconds
            }
            
            $externalTimeResult = Get-ExternalTrustedTime @externalTimeParams
            
            # Store external time validation results
            $result.ExternalTimeValidation = [PSCustomObject]@{
                Success = $externalTimeResult.Success
                LocalTime = $externalTimeResult.LocalUtcTime
                ExternalTime = $externalTimeResult.ExternalUtcTime
                DeltaSeconds = $externalTimeResult.DeltaSeconds
                ClockSkewed = $externalTimeResult.ClockSkewed
                Sources = $externalTimeResult.Sources
                SourceCount = $externalTimeResult.SourceCount
            }
        }
        
        if ($result.HasSignature) {
            # Check signature validity
            $result.SignatureValid = $signature.Status -eq 'Valid'
            
            # Get signature details
            $result.SignatureDetails = [PSCustomObject]@{
                Status = $signature.Status
                SignerCertificate = $signature.SignerCertificate
                TimeStamperCertificate = $signature.TimeStamperCertificate
                StatusMessage = $signature.StatusMessage
            }
            
            # Check if content has been modified
            $result.ContentModified = $signature.Status -eq 'HashMismatch'
            
            # Validate certificate if signature exists
            if ($signature.SignerCertificate) {
                # Get current time information
                $now = [DateTime]::Now
                $notBefore = $signature.SignerCertificate.NotBefore
                $notAfter = $signature.SignerCertificate.NotAfter
                
                # Setup for certificate validation
                $codeSigningOID = "1.3.6.1.5.5.7.3.3"  # Code Signing OID
                $hasCodeSigningEKU = $false
                
                if ($signature.SignerCertificate.Extensions) {
                    foreach ($extension in $signature.SignerCertificate.Extensions) {
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
                
                # Create chain policy
                $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
                if ($SkipRevocationCheck) {
                    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                    $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
                }
                
                # Validate with local time
                $isLocalTimeValid = ($now -ge $notBefore) -and ($now -le $notAfter)
                $result.CertificateValid = $hasCodeSigningEKU -and $isLocalTimeValid
                
                # Build chain with local time
                $chainValid = $chain.Build($signature.SignerCertificate)
                $result.ChainValid = $chainValid
                
                # If external time validation was requested, check validity with external time
                if ($UseExternalTimeValidation -and $externalTimeResult -and $externalTimeResult.Success) {
                    # Convert external UTC time to local time
                    $externalNow = $externalTimeResult.ExternalUtcTime.ToLocalTime()
                    
                    # Check certificate validity with external time
                    $isExternalTimeValid = ($externalNow -ge $notBefore) -and ($externalNow -le $notAfter)
                    $result.CertificateValidWithExternalTime = $hasCodeSigningEKU -and $isExternalTimeValid
                    
                    # Try to build chain with external time
                    try {
                        # Create a separate chain for external time validation
                        $externalChain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
                        if ($SkipRevocationCheck) {
                            $externalChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                            $externalChain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
                        }
                        
                        # Attempt to set verification time using reflection (if possible)
                        $chainPolicyType = [System.Security.Cryptography.X509Certificates.X509ChainPolicy].GetType()
                        $verificationTimeProperty = $chainPolicyType.GetProperty('VerificationTime', [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Instance)
                        
                        if ($verificationTimeProperty) {
                            $verificationTimeProperty.SetValue($externalChain.ChainPolicy, $externalNow)
                            $externalChainValid = $externalChain.Build($signature.SignerCertificate)
                            $result.ChainValidWithExternalTime = $externalChainValid
                            Write-Verbose "Successfully validated chain with external time."
                        } else {
                            # If reflection fails, just use the regular chain result
                            $result.ChainValidWithExternalTime = $result.ChainValid
                            Write-Verbose "Could not set external verification time - using local time chain validation result."
                        }
                    } catch {
                        Write-Verbose "Error during external time chain validation: $_"
                        $result.ChainValidWithExternalTime = $result.ChainValid
                    }
                }
            }
        }
        
        # Check execution policy compatibility
        if (-not $SkipExecutionPolicyCheck) {
            $currentPolicy = Get-ExecutionPolicy -Scope Process
            $result.ExecutionPolicyCompatible = switch ($ExecutionPolicy) {
                'AllSigned' { $result.HasSignature -and $result.SignatureValid }
                'RemoteSigned' { $result.HasSignature -or (-not $Path.StartsWith('\\')) }
                'Restricted' { $false }
                'Unrestricted' { $true }
                'Bypass' { $true }
                default { $false }
            }
            
            $result.ExecutionPolicyDetails = [PSCustomObject]@{
                RequiredPolicy = $ExecutionPolicy
                CurrentPolicy = $currentPolicy
                IsCompatible = $result.ExecutionPolicyCompatible
            }
        }
        
        # Return results
        if ($Detailed) {
            return $result
        }
        else {
            # For non-detailed output, prefer external time validation if available and different from local time
            if ($UseExternalTimeValidation -and $externalTimeResult -and $externalTimeResult.Success -and 
                ($result.CertificateValidWithExternalTime -ne $null) -and ($result.ChainValidWithExternalTime -ne $null)) {
                
                # If local time validation fails but external time validation passes, use external validation results
                if ((-not $result.CertificateValid -or -not $result.ChainValid) -and 
                    ($result.CertificateValidWithExternalTime -and $result.ChainValidWithExternalTime)) {
                    
                    Write-Verbose "Using external time validation results (external valid, local invalid)."
                    $certificateValid = $result.CertificateValidWithExternalTime
                    $chainValid = $result.ChainValidWithExternalTime
                }
                # If both validations pass, use local validation
                elseif (($result.CertificateValid -and $result.ChainValid) -and 
                        ($result.CertificateValidWithExternalTime -and $result.ChainValidWithExternalTime)) {
                    
                    Write-Verbose "Using local time validation results (both valid)."
                    $certificateValid = $result.CertificateValid
                    $chainValid = $result.ChainValid
                }
                # If both validations fail, use local validation
                elseif ((-not $result.CertificateValid -or -not $result.ChainValid) -and 
                        (-not $result.CertificateValidWithExternalTime -or -not $result.ChainValidWithExternalTime)) {
                    
                    Write-Verbose "Using local time validation results (both invalid)."
                    $certificateValid = $result.CertificateValid
                    $chainValid = $result.ChainValid
                }
                # If local time validation passes but external validation fails, check if system time is skewed
                elseif (($result.CertificateValid -and $result.ChainValid) -and 
                        (-not $result.CertificateValidWithExternalTime -or -not $result.ChainValidWithExternalTime)) {
                    
                    # If system clock is significantly skewed, trust external time
                    if ($externalTimeResult.ClockSkewed) {
                        Write-Verbose "Using external time validation results (system clock skewed)."
                        $certificateValid = $result.CertificateValidWithExternalTime
                        $chainValid = $result.ChainValidWithExternalTime
                    }
                    else {
                        Write-Verbose "Using local time validation results (local valid, external invalid, clock not skewed)."
                        $certificateValid = $result.CertificateValid
                        $chainValid = $result.ChainValid
                    }
                }
                else {
                    # Default to local time validation
                    $certificateValid = $result.CertificateValid
                    $chainValid = $result.ChainValid
                }
            }
            else {
                # If external time validation wasn't used or failed, use local time validation
                $certificateValid = $result.CertificateValid
                $chainValid = $result.ChainValid
            }
            
            return $result.SignatureValid -and 
                   (-not $result.ContentModified) -and 
                   $certificateValid -and 
                   $chainValid -and 
                   ($SkipExecutionPolicyCheck -or $result.ExecutionPolicyCompatible)
        }
    }
    catch {
        $result.ErrorDetails = $_.Exception.Message
        Write-Error "Error validating script signature: $_"
        
        if ($Detailed) {
            return $result
        }
        else {
            return $false
        }
    }
}

# Export this function
Export-ModuleMember -Function Test-ScriptSignature 