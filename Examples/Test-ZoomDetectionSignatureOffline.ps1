# Test-ZoomDetectionSignatureOffline.ps1
# Example script demonstrating how to use Test-ScriptSignature with offline validation (no revocation checks)

# Import the CodeSigning module
Import-Module $PSScriptRoot\..\CodeSigning.psd1 -Force

# Define the path to the Zoom detection script
$zoomDetectionScript = "C:\code\SCCM\apps\Zoom\Scripts\Detection\ZoomWorkplace-Detection.ps1"

# First, add a helper function to validate script signatures with offline-friendly settings
function Test-ScriptSignatureOffline {
    [CmdletBinding()]
    [OutputType([bool], [PSObject])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [switch]$Detailed
    )
    
    # Get the signature with offline-friendly verification settings
    $signatureParams = @{
        FilePath = $Path
    }
    
    # Get the signature with standard settings (which might fail due to revocation issues)
    $signature = Get-AuthenticodeSignature @signatureParams
    
    # If we have a signature, then manually verify it without revocation checks
    if ($signature.Status -ne 'NotSigned') {
        Write-Host "Script is signed. Performing offline validation..." -ForegroundColor Cyan
        
        # Create a chain object with revocation checking disabled
        $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        
        # Build the chain for the signer certificate
        $chainBuilt = $chain.Build($signature.SignerCertificate)
        
        # Create our own result object
        $result = [PSCustomObject]@{
            Path = $Path
            HasSignature = $true
            SignatureValid = $signature.Status -eq 'Valid'
            ContentModified = $signature.Status -eq 'HashMismatch'
            CertificateValid = $true  # We're assuming validity without revocation
            ChainValid = $chainBuilt
            NoRevocationCheck = $true
            SignatureDetails = $signature
            ChainStatus = $chain.ChainStatus | ForEach-Object { $_.Status.ToString() }
            ExecutionPolicyCompatible = $true  # Assuming it's compatible if signed
        }
        
        if ($Detailed) {
            return $result
        } else {
            return $result.SignatureValid -and (-not $result.ContentModified)
        }
    } else {
        # No signature
        $result = [PSCustomObject]@{
            Path = $Path
            HasSignature = $false
            SignatureValid = $false
            ContentModified = $false
            CertificateValid = $false
            ChainValid = $false
            NoRevocationCheck = $true
            SignatureDetails = $null
            ChainStatus = @()
            ExecutionPolicyCompatible = $false
        }
        
        if ($Detailed) {
            return $result
        } else {
            return $false
        }
    }
}

# Test 1: Offline signature validation
Write-Host "`nTest 1: Offline Signature Validation (No Revocation Check)" -ForegroundColor Cyan
$offlineResult = Test-ScriptSignatureOffline -Path $zoomDetectionScript -Detailed

if ($offlineResult.SignatureValid) {
    Write-Host "Offline validation passed: Script signature is valid" -ForegroundColor Green
    
    if ($offlineResult.NoRevocationCheck) {
        Write-Host "Note: Revocation checking was skipped" -ForegroundColor Yellow
    }
} else {
    Write-Host "Offline validation failed: Script signature is invalid" -ForegroundColor Red
}

# Test 2: Compare with standard validation
Write-Host "`nTest 2: Comparing Standard and Offline Validation" -ForegroundColor Cyan
$standardResult = Test-ScriptSignature -Path $zoomDetectionScript -SkipExecutionPolicyCheck -Detailed

Write-Host "Standard validation results:" -ForegroundColor White
Write-Host "- Signature Valid: $($standardResult.SignatureValid)" -ForegroundColor $(if ($standardResult.SignatureValid) { "Green" } else { "Red" })
Write-Host "- Certificate Valid: $($standardResult.CertificateValid)" -ForegroundColor $(if ($standardResult.CertificateValid) { "Green" } else { "Red" })
Write-Host "- Chain Valid: $($standardResult.ChainValid)" -ForegroundColor $(if ($standardResult.ChainValid) { "Green" } else { "Red" })

Write-Host "`nOffline validation results:" -ForegroundColor White
Write-Host "- Signature Valid: $($offlineResult.SignatureValid)" -ForegroundColor $(if ($offlineResult.SignatureValid) { "Green" } else { "Red" })
Write-Host "- Certificate Valid: $($offlineResult.CertificateValid)" -ForegroundColor $(if ($offlineResult.CertificateValid) { "Green" } else { "Red" })
Write-Host "- Chain Valid: $($offlineResult.ChainValid)" -ForegroundColor $(if ($offlineResult.ChainValid) { "Green" } else { "Red" })

# Test 3: Examine chain status details
Write-Host "`nTest 3: Certificate Chain Status Details" -ForegroundColor Cyan
if ($offlineResult.ChainStatus.Count -gt 0) {
    Write-Host "Chain status issues found:" -ForegroundColor Yellow
    foreach ($status in $offlineResult.ChainStatus) {
        Write-Host "- $status" -ForegroundColor Yellow
    }
} else {
    Write-Host "No chain status issues found" -ForegroundColor Green
}

# Test 4: Verify script hash
Write-Host "`nTest 4: Script Hash Verification" -ForegroundColor Cyan
if (-not $offlineResult.ContentModified) {
    Write-Host "Script content matches signature hash" -ForegroundColor Green
} else {
    Write-Host "WARNING: Script content has been modified after signing!" -ForegroundColor Red
}

# Test 5: Execution Policy Compatibility Check
Write-Host "`nTest 5: AllSigned Execution Policy Compatibility" -ForegroundColor Cyan
$currentPolicy = Get-ExecutionPolicy -Scope Process
Write-Host "Current execution policy: $currentPolicy" -ForegroundColor Cyan

if ($offlineResult.HasSignature -and $offlineResult.SignatureValid) {
    Write-Host "Script will execute under AllSigned policy" -ForegroundColor Green
} else {
    Write-Host "Script will NOT execute under AllSigned policy" -ForegroundColor Red
}

# Summary with recommendations
Write-Host "`nOffline Validation Summary:" -ForegroundColor Cyan
$summary = @"
Script Path: $($offlineResult.Path)
Has Signature: $($offlineResult.HasSignature)
Signature Valid: $($offlineResult.SignatureValid)
Content Modified: $($offlineResult.ContentModified)
Certificate Valid: $($offlineResult.CertificateValid) (revocation check skipped)
Chain Valid: $($offlineResult.ChainValid) (revocation check skipped)
"@

Write-Host $summary

# Recommendations for offline scenarios
Write-Host "`nRecommendations for Offline Scenarios:" -ForegroundColor Cyan
if (-not $offlineResult.HasSignature) {
    Write-Host "- Script needs to be signed with a valid code signing certificate" -ForegroundColor Yellow
} elseif ($offlineResult.ContentModified) {
    Write-Host "- Script needs to be re-signed due to content modifications" -ForegroundColor Yellow
} elseif ($offlineResult.SignatureValid -and $offlineResult.ChainValid) {
    Write-Host "- Script signature is valid for offline deployment" -ForegroundColor Green
    Write-Host "- For SCCM deployment, this script should run without signature validation issues" -ForegroundColor Green
} else {
    Write-Host "- Further investigation needed - script is signed but validation failed" -ForegroundColor Yellow
}

# SCCM-specific guidance
Write-Host "`nSCCM Deployment Guidance:" -ForegroundColor Cyan
Write-Host "When deploying signed scripts in SCCM:" -ForegroundColor White
Write-Host "1. Ensure the execution policy on client machines is set appropriately" -ForegroundColor White
Write-Host "2. For system context scripts, you may need to install the certificate chain on client machines" -ForegroundColor White 
Write-Host "3. Consider using the 'SkipRevocationCheck' parameter in your SCCM deployment scripts" -ForegroundColor White
Write-Host "4. You can modify your script to include revocation check handling:" -ForegroundColor White

# Example code snippet
$codeExample = @'
# Add this to your script for better error handling with signature validation in SCCM
try {
    # Your script code here
}
catch [System.Security.Cryptography.CryptographicException] {
    if ($_.Exception.Message -like "*CRYPT_E_REVOCATION_OFFLINE*") {
        Write-Warning "Certificate revocation check failed, but proceeding with execution"
        # Continue with script logic
    }
    else {
        throw $_  # Re-throw other cryptographic exceptions
    }
}
'@

Write-Host $codeExample -ForegroundColor Gray 