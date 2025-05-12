# Test-SCCMScriptSignature.ps1
# Script for validating signatures in SCCM deployment scenarios
# Specifically handles offline environments and revocation checking issues

param (
    [Parameter(Mandatory = $true)]
    [string]$ScriptPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$Verbose
)

# Determine the module path relative to this script
$moduleRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$modulePath = Join-Path -Path $moduleRoot -ChildPath "CodeSigning.psd1"

# Import the CodeSigning module
try {
    Import-Module $modulePath -ErrorAction Stop
    if ($Verbose) {
        Write-Host "Successfully imported CodeSigning module from $modulePath" -ForegroundColor Green
    }
} 
catch {
    Write-Host "Failed to import CodeSigning module: $_" -ForegroundColor Red
    exit 1
}

# Validate the script exists
if (-not (Test-Path -Path $ScriptPath -PathType Leaf)) {
    Write-Host "Script not found: $ScriptPath" -ForegroundColor Red
    exit 1
}

# Perform signature validation with revocation checking disabled
# This is crucial for SCCM environments where revocation checking often fails
$result = Test-ScriptSignature -Path $ScriptPath -SkipRevocationCheck -Detailed

# Output results in a format suitable for SCCM logging
Write-Host "========== SCCM Script Signature Validation ==========" -ForegroundColor Cyan
Write-Host "Script: $ScriptPath" -ForegroundColor Cyan
Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "Revocation Check: Skipped (SCCM deployment mode)" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# Summary of validation results
Write-Host "Signature Present: $($result.HasSignature)" -ForegroundColor $(if ($result.HasSignature) { "Green" } else { "Red" })
Write-Host "Signature Valid: $($result.SignatureValid)" -ForegroundColor $(if ($result.SignatureValid) { "Green" } else { "Red" })
Write-Host "Content Modified: $($result.ContentModified)" -ForegroundColor $(if (-not $result.ContentModified) { "Green" } else { "Red" })
Write-Host "Certificate Valid: $($result.CertificateValid)" -ForegroundColor $(if ($result.CertificateValid) { "Green" } else { "Red" })
Write-Host "Chain Valid: $($result.ChainValid)" -ForegroundColor $(if ($result.ChainValid) { "Green" } else { "Red" })

# Certificate details if available
if ($result.SignatureDetails -and $result.SignatureDetails.SignerCertificate) {
    $cert = $result.SignatureDetails.SignerCertificate
    
    Write-Host "`nCertificate Details:" -ForegroundColor Cyan
    Write-Host "Subject: $($cert.Subject)" -ForegroundColor White
    Write-Host "Issuer: $($cert.Issuer)" -ForegroundColor White
    Write-Host "Valid Until: $($cert.NotAfter)" -ForegroundColor White
    Write-Host "Thumbprint: $($cert.Thumbprint)" -ForegroundColor White
}

# Return code for automation
$exitCode = if ($result.SignatureValid -and (-not $result.ContentModified) -and $result.CertificateValid -and $result.ChainValid) {
    0  # All validations passed
} elseif ($result.SignatureValid -and (-not $result.ContentModified)) {
    1  # Basic validation passed, but certificate or chain issues
} else {
    2  # Signature invalid or content modified
}

# Provide guidance based on exit code
switch ($exitCode) {
    0 {
        Write-Host "`nValidation Result: PASSED" -ForegroundColor Green
        Write-Host "This script has a valid signature and can be safely used in SCCM deployments." -ForegroundColor Green
    }
    1 {
        Write-Host "`nValidation Result: WARNING" -ForegroundColor Yellow
        Write-Host "The script has a valid signature, but there may be certificate chain issues." -ForegroundColor Yellow
        Write-Host "This is often acceptable in SCCM deployments when using enterprise certificates." -ForegroundColor Yellow
        Write-Host "Recommendation: If this script comes from a trusted source, it can be used." -ForegroundColor Yellow
    }
    2 {
        Write-Host "`nValidation Result: FAILED" -ForegroundColor Red
        Write-Host "The script signature is invalid or the content has been modified after signing." -ForegroundColor Red
        Write-Host "Recommendation: Do not use this script until it is properly signed." -ForegroundColor Red
    }
}

# Exit with appropriate code for automation purposes
exit $exitCode 