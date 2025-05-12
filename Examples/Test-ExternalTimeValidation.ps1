#Requires -Version 5.1
<#
.SYNOPSIS
    Demonstrates the use of external time validation for certificate operations.

.DESCRIPTION
    This script shows how to use the Get-ExternalTrustedTime function to validate certificates
    against trusted external time sources rather than relying solely on the local system clock.
    
.NOTES
    File Name      : Test-ExternalTimeValidation.ps1
    Author         : PowerShell Administrator
    Prerequisite   : PowerShell 5.1 or later
    Copyright      : (c) 2025 Your Company
#>

[CmdletBinding()]
param()

#region Initialize
# Check if running in elevated mode which is required for some cert operations
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "This script is not running with administrative privileges. Some certificate operations may fail."
}

# Import the CodeSigning module
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath ".." -Resolve
if (-not (Get-Module -Name CodeSigning)) {
    try {
        Import-Module -Name $modulePath -ErrorAction Stop
        Write-Host "Successfully imported CodeSigning module from $modulePath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to import CodeSigning module: $_"
        exit 1
    }
}
#endregion Initialize

#region Functions
function Format-TimeDelta {
    param (
        [int]$Seconds
    )
    
    if ($Seconds -eq 0) {
        return "No time difference"
    }
    
    $prefix = if ($Seconds -gt 0) { "ahead by" } else { "behind by" }
    $absSeconds = [Math]::Abs($Seconds)
    
    if ($absSeconds -lt 60) {
        return "$prefix $absSeconds seconds"
    }
    elseif ($absSeconds -lt 3600) {
        $minutes = [Math]::Floor($absSeconds / 60)
        $remainingSeconds = $absSeconds % 60
        return "$prefix $minutes minutes, $remainingSeconds seconds"
    }
    else {
        $hours = [Math]::Floor($absSeconds / 3600)
        $remainingMinutes = [Math]::Floor(($absSeconds % 3600) / 60)
        return "$prefix $hours hours, $remainingMinutes minutes"
    }
}

function Test-CertificateAgainstExternalTime {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        
        [switch]$SkipRevocationCheck
    )
    
    # Get external trusted time
    Write-Host "`n# Getting external trusted time..." -ForegroundColor Cyan
    $trustedTime = Get-ExternalTrustedTime -Verbose
    
    if (-not $trustedTime.Success) {
        Write-Warning "Failed to retrieve external trusted time. Using local system time."
        return
    }
    
    # Display time information
    Write-Host "`n# Time Information:" -ForegroundColor Cyan
    Write-Host "  Local System Time (UTC): $($trustedTime.LocalUtcTime)"
    Write-Host "  External Trusted Time (UTC): $($trustedTime.ExternalUtcTime)"
    Write-Host "  Time Difference: $(Format-TimeDelta -Seconds $trustedTime.DeltaSeconds)"
    
    if ($trustedTime.ClockSkewed) {
        Write-Host "  [WARNING] System clock is significantly skewed (>5 minutes)!" -ForegroundColor Yellow
    }
    else {
        Write-Host "  [OK] System clock is within acceptable range." -ForegroundColor Green
    }
    
    Write-Host "`n# Time Sources Used:" -ForegroundColor Cyan
    foreach ($source in $trustedTime.Details) {
        Write-Host "  - $($source.Source): $(Format-TimeDelta -Seconds $source.DeltaSeconds)"
    }
    
    # Check certificate validity against both local and external time
    Write-Host "`n# Certificate Validation:" -ForegroundColor Cyan
    Write-Host "  Subject: $($Certificate.Subject)"
    Write-Host "  Thumbprint: $($Certificate.Thumbprint)"
    Write-Host "  Not Before: $($Certificate.NotBefore) (UTC: $($Certificate.NotBefore.ToUniversalTime()))"
    Write-Host "  Not After: $($Certificate.NotAfter) (UTC: $($Certificate.NotAfter.ToUniversalTime()))"
    
    # Check against local time
    $localTimeValid = ($Certificate.NotBefore -le [DateTime]::Now) -and ([DateTime]::Now -le $Certificate.NotAfter)
    
    # Convert external time to local timezone for comparison
    $externalTimeLocal = $trustedTime.ExternalUtcTime.ToLocalTime()
    $externalTimeValid = ($Certificate.NotBefore -le $externalTimeLocal) -and ($externalTimeLocal -le $Certificate.NotAfter)
    
    Write-Host "`n# Validity Results:" -ForegroundColor Cyan
    if ($localTimeValid) {
        Write-Host "  [PASSED] Certificate is valid according to LOCAL system time." -ForegroundColor Green
    }
    else {
        Write-Host "  [FAILED] Certificate is NOT valid according to LOCAL system time!" -ForegroundColor Red
        
        if ([DateTime]::Now -lt $Certificate.NotBefore) {
            Write-Host "           - Current time is BEFORE the certificate's validity period." -ForegroundColor Red
            Write-Host "           - Certificate will become valid in $([Math]::Round(($Certificate.NotBefore - [DateTime]::Now).TotalDays)) days." -ForegroundColor Red
        }
        elseif ([DateTime]::Now -gt $Certificate.NotAfter) {
            Write-Host "           - Current time is AFTER the certificate's validity period." -ForegroundColor Red
            Write-Host "           - Certificate expired $([Math]::Round(([DateTime]::Now - $Certificate.NotAfter).TotalDays)) days ago." -ForegroundColor Red
        }
    }
    
    if ($externalTimeValid) {
        Write-Host "  [PASSED] Certificate is valid according to EXTERNAL trusted time." -ForegroundColor Green
    }
    else {
        Write-Host "  [FAILED] Certificate is NOT valid according to EXTERNAL trusted time!" -ForegroundColor Red
        
        if ($externalTimeLocal -lt $Certificate.NotBefore) {
            Write-Host "           - External time is BEFORE the certificate's validity period." -ForegroundColor Red
            Write-Host "           - Certificate will become valid in $([Math]::Round(($Certificate.NotBefore - $externalTimeLocal).TotalDays)) days." -ForegroundColor Red
        }
        elseif ($externalTimeLocal -gt $Certificate.NotAfter) {
            Write-Host "           - External time is AFTER the certificate's validity period." -ForegroundColor Red
            Write-Host "           - Certificate expired $([Math]::Round(($externalTimeLocal - $Certificate.NotAfter).TotalDays)) days ago." -ForegroundColor Red
        }
    }
    
    # Additional chain validation
    Write-Host "`n# Certificate Chain Validation:" -ForegroundColor Cyan
    
    $chainPolicy = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509ChainPolicy
    if ($SkipRevocationCheck) {
        $chainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    }
    
    $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy = $chainPolicy
    
    # First validate with system time
    $systemResult = $chain.Build($Certificate)
    
    # Hack to use external time for validation - create a new chain with the external time
    $externalChain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
    $externalChain.ChainPolicy = $chainPolicy
    
    try {
        # Use reflection to access a private property to set verification time
        $chainPolicyType = [System.Security.Cryptography.X509Certificates.X509ChainPolicy].GetType()
        $verificationTimeProperty = $chainPolicyType.GetProperty('VerificationTime', [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Instance)
        
        if ($verificationTimeProperty) {
            $verificationTimeProperty.SetValue($externalChain.ChainPolicy, $trustedTime.ExternalUtcTime.ToLocalTime())
            $externalResult = $externalChain.Build($Certificate)
            $externalTimeUsed = $true
        }
        else {
            Write-Warning "Could not set external verification time - this is only supported in newer .NET versions"
            $externalResult = $systemResult
            $externalTimeUsed = $false
        }
    }
    catch {
        Write-Warning "Error setting external verification time: $_"
        $externalResult = $systemResult
        $externalTimeUsed = $false
    }
    
    # Display results for system time validation
    Write-Host "  Chain validation using LOCAL system time: $(if ($systemResult) { 'PASSED' } else { 'FAILED' })" -ForegroundColor $(if ($systemResult) { 'Green' } else { 'Red' })
    
    if (-not $systemResult) {
        Write-Host "  Chain status flags:" -ForegroundColor Yellow
        foreach ($element in $chain.ChainStatus) {
            Write-Host "   - $($element.StatusInformation.Trim())" -ForegroundColor Yellow
        }
    }
    
    # Display results for external time validation, if different
    if ($externalTimeUsed) {
        Write-Host "  Chain validation using EXTERNAL trusted time: $(if ($externalResult) { 'PASSED' } else { 'FAILED' })" -ForegroundColor $(if ($externalResult) { 'Green' } else { 'Red' })
        
        if (-not $externalResult) {
            Write-Host "  Chain status flags:" -ForegroundColor Yellow
            foreach ($element in $externalChain.ChainStatus) {
                Write-Host "   - $($element.StatusInformation.Trim())" -ForegroundColor Yellow
            }
        }
    }
    
    # Return combined result
    return [PSCustomObject]@{
        Certificate = $Certificate
        LocalSystemTime = [DateTime]::Now
        ExternalTrustedTime = $trustedTime.ExternalUtcTime.ToLocalTime()
        TimeDeltaSeconds = $trustedTime.DeltaSeconds
        ClockSkewed = $trustedTime.ClockSkewed
        ValidWithLocalTime = $localTimeValid
        ValidWithExternalTime = $externalTimeValid
        ChainValidWithLocalTime = $systemResult
        ChainValidWithExternalTime = $externalResult
        ExternalTimeUsedForChain = $externalTimeUsed
    }
}
#endregion Functions

#region Main Execution
Write-Host "`n===== EXTERNAL TIME VALIDATION DEMO =====" -ForegroundColor Cyan

# Find code signing certificates
Write-Host "`n# Searching for code signing certificates..." -ForegroundColor Cyan
$certs = Get-CodeSigningCertificate

if (-not $certs) {
    Write-Warning "No code signing certificates found. Please import a certificate and try again."
    exit
}

Write-Host "Found $($certs.Count) code signing certificate(s)" -ForegroundColor Green

# Test each certificate against external time
foreach ($cert in $certs) {
    Write-Host "`n===== TESTING CERTIFICATE: $($cert.Subject) =====" -ForegroundColor Magenta
    $result = Test-CertificateAgainstExternalTime -Certificate $cert -SkipRevocationCheck:$(-not $isAdmin)
    
    # Additional logic based on results could be added here
}

Write-Host "`n===== EXTERNAL TIME VALIDATION COMPLETE =====" -ForegroundColor Cyan
#endregion Main Execution 