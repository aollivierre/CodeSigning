# Test-ZoomDetectionSignature.ps1
# Example script demonstrating how to use Test-ScriptSignature with the Zoom detection script

# Import the CodeSigning module
Import-Module $PSScriptRoot\..\CodeSigning.psd1 -Force

# Define the path to the Zoom detection script
$zoomDetectionScript = "C:\code\SCCM\apps\Zoom\Scripts\Detection\ZoomWorkplace-Detection.ps1"

# Test 1: Basic validation
Write-Host "`nTest 1: Basic Signature Validation" -ForegroundColor Cyan
$basicResult = Test-ScriptSignature -Path $zoomDetectionScript
if ($basicResult) {
    Write-Host "Basic validation passed: Script signature is valid" -ForegroundColor Green
} else {
    Write-Host "Basic validation failed: Script signature is invalid" -ForegroundColor Red
}

# Test 2: Detailed validation with AllSigned policy
Write-Host "`nTest 2: Detailed Validation with AllSigned Policy" -ForegroundColor Cyan
$detailedResult = Test-ScriptSignature -Path $zoomDetectionScript -ExecutionPolicy AllSigned -Detailed
$detailedResult | Format-List

# Test 3: Check for content modifications
Write-Host "`nTest 3: Content Modification Check" -ForegroundColor Cyan
if ($detailedResult.ContentModified) {
    Write-Host "WARNING: Script content has been modified after signing!" -ForegroundColor Red
    Write-Host "This could indicate tampering or accidental changes." -ForegroundColor Yellow
} else {
    Write-Host "Script content has not been modified since signing" -ForegroundColor Green
}

# Test 4: Certificate and Chain Validation
Write-Host "`nTest 4: Certificate and Chain Validation" -ForegroundColor Cyan
if ($detailedResult.CertificateValid -and $detailedResult.ChainValid) {
    Write-Host "Certificate and chain validation passed" -ForegroundColor Green
    Write-Host "Certificate Subject: $($detailedResult.SignatureDetails.SignerCertificate.Subject)"
    Write-Host "Certificate Issuer: $($detailedResult.SignatureDetails.SignerCertificate.Issuer)"
    Write-Host "Certificate Expiration: $($detailedResult.SignatureDetails.SignerCertificate.NotAfter)"
} else {
    Write-Host "Certificate or chain validation failed" -ForegroundColor Red
    if (-not $detailedResult.CertificateValid) {
        Write-Host "Certificate validation failed" -ForegroundColor Red
    }
    if (-not $detailedResult.ChainValid) {
        Write-Host "Certificate chain validation failed" -ForegroundColor Red
    }
}

# Test 5: Execution Policy Compatibility
Write-Host "`nTest 5: Execution Policy Compatibility" -ForegroundColor Cyan
if ($detailedResult.ExecutionPolicyCompatible) {
    Write-Host "Script is compatible with AllSigned execution policy" -ForegroundColor Green
} else {
    Write-Host "Script is NOT compatible with AllSigned execution policy" -ForegroundColor Red
    Write-Host "Current execution policy: $($detailedResult.ExecutionPolicyDetails.CurrentPolicy)"
    Write-Host "Required execution policy: $($detailedResult.ExecutionPolicyDetails.RequiredPolicy)"
}

# Summary
Write-Host "`nValidation Summary:" -ForegroundColor Cyan
$summary = @"
Script Path: $($detailedResult.Path)
Has Signature: $($detailedResult.HasSignature)
Signature Valid: $($detailedResult.SignatureValid)
Content Modified: $($detailedResult.ContentModified)
Certificate Valid: $($detailedResult.CertificateValid)
Chain Valid: $($detailedResult.ChainValid)
Execution Policy Compatible: $($detailedResult.ExecutionPolicyCompatible)
"@

Write-Host $summary

# Recommendations
Write-Host "`nRecommendations:" -ForegroundColor Cyan
if (-not $detailedResult.SignatureValid) {
    Write-Host "- Script needs to be signed with a valid code signing certificate" -ForegroundColor Yellow
}
if ($detailedResult.ContentModified) {
    Write-Host "- Script needs to be re-signed due to content modifications" -ForegroundColor Yellow
}
if (-not $detailedResult.CertificateValid) {
    Write-Host "- Check the code signing certificate validity and expiration" -ForegroundColor Yellow
}
if (-not $detailedResult.ChainValid) {
    Write-Host "- Install missing certificates in the chain using Confirm-CodeSigningChain" -ForegroundColor Yellow
}
if (-not $detailedResult.ExecutionPolicyCompatible) {
    Write-Host "- Adjust execution policy or ensure script is properly signed" -ForegroundColor Yellow
} 