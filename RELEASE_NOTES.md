# CodeSigning Module Release Notes

## Version 1.2.0 (March 25, 2025)

We're excited to announce the release of CodeSigning module version 1.2.0, bringing significant improvements to error handling, certificate validation, and certificate chain management. This release focuses on providing more detailed information to users and improving the robustness of the signing process.

### Key Highlights

#### 🔍 Enhanced Certificate Validation
- **Detailed Return Information**: New `ReturnDetails` parameter in key functions provides comprehensive validation results
- **Improved Chain Validation**: Better certificate chain validation with detailed chain element reporting
- **Extended Certificate Testing**: More thorough validation with detailed status reporting

#### 🛡️ Robust Error Handling
- **Structured Error Objects**: Consistent error reporting with detailed context information
- **Better Recovery Options**: Improved error handling with clearer next steps for users
- **Comprehensive Validation Results**: Detailed property reporting across all functions

#### 📊 Detailed Reporting
- **Chain Elements Property**: Fixed missing property to ensure complete chain validation reporting
- **Consistent Result Objects**: Standardized result objects across all functions
- **Improved Status Messages**: Better feedback during signing and validation processes

### Usage Examples

#### Getting Detailed Certificate Information
```powershell
# Get detailed information about a certificate
$certDetails = Get-CodeSigningCertificate -Thumbprint "YOUR_THUMBPRINT_HERE" -ReturnDetails
$certDetails.Certificate           # View the certificate object
$certDetails.ValidationDetails     # View detailed validation results
$certDetails.IsValid               # Quick check if certificate is valid
```

#### Detailed Chain Validation
```powershell
# Validate a certificate chain with detailed results
$chainResults = Confirm-CodeSigningChain -Certificate $cert -ReturnDetails
$chainResults.IsValid              # Quick check if chain is valid
$chainResults.ChainElements        # Examine individual chain elements
$chainResults.ChainStatus          # View detailed chain status information
```

#### Error Handling with Detailed Results
```powershell
# Get detailed results when signing scripts
$signingResults = Protect-Script -ScriptPath "C:\Scripts\MyScript.ps1" `
                 -CertificateThumbprint "YOUR_THUMBPRINT_HERE" `
                 -ReturnDetails

# Check for errors
if ($signingResults.Errors.Count -gt 0) {
    $signingResults.Errors | ForEach-Object { Write-Warning $_ }
}
```

### Compatibility

All enhancements maintain backward compatibility with existing scripts and workflows. The module continues to support:
- PowerShell 5.1 and later
- Windows 10/11 and Windows Server environments
- Both standalone and domain-joined scenarios

### Known Issues
- Revocation checks may fail in offline environments. Use `-SkipRevocationCheck` in these cases.
- Some test certificates without complete trust chains may require `-SkipChainValidation` for signing.

### Acknowledgements
Special thanks to all users who provided feedback and testing to help improve error handling and certificate validation throughout the module.

---

## Version 1.1.0 (March 24, 2025)

We're excited to announce the release of CodeSigning module version 1.1.0, bringing significant improvements to PowerShell code signing workflows. This release focuses on enhanced security, improved batch operations, and robust testing capabilities.

### Key Highlights

#### 🔐 Enhanced Certificate Security
- **Password-protected PFX Support**: Securely use certificates protected with passwords while maintaining best security practices
- **Improved Certificate Chain Handling**: More reliable installation and validation of certificate chains
- **Skip Chain Validation Option**: New testing parameter for development environments that bypasses certificate chain validation

#### ⚡ Streamlined Batch Operations
- **Efficient Batch Signing**: Sign multiple scripts with a single command
- **Optimized Performance**: Reduced overhead when signing multiple files
- **Pipeline Support**: Easily process collections of scripts through PowerShell pipelines

#### 🛠️ Comprehensive Testing
- **Complete Test Suite**: Validate all aspects of the module's functionality
- **Specialized Test Cases**: Dedicated tests for password-protected PFX files and batch signing
- **Clear Test Reporting**: Enhanced output to quickly identify successes and failures

### Usability Improvements

- **Improved Error Messages**: More descriptive errors to help troubleshoot signing issues
- **Enhanced Console Output**: Clearer status messages during signing operations
- **Streamlined Certificate Management**: Better handling of root, intermediate, and leaf certificates

### Getting Started with New Features

#### Batch Signing Example
```powershell
# Get all scripts in a directory
$scripts = Get-ChildItem -Path "C:\Scripts\*.ps1"

# Sign them all with a single certificate
$scripts | ForEach-Object { 
    Protect-Script -ScriptPath $_ -CertificateThumbprint "YOUR_THUMBPRINT_HERE" 
}
```

#### Password-Protected Certificate Example
```powershell
# Create a secure password
$securePassword = ConvertTo-SecureString -String "YourPassword" -AsPlainText -Force

# Sign using a password-protected PFX file
Protect-Script -ScriptPath "C:\Scripts\MyScript.ps1" `
               -CertificatePath "C:\certs\ProtectedCert.pfx" `
               -CertificatePassword $securePassword
```

#### Testing Certificate Chain Validation
```powershell
# For test environments where chain validation isn't needed
Protect-Script -ScriptPath "C:\Scripts\MyScript.ps1" `
               -CertificateThumbprint "YOUR_THUMBPRINT_HERE" `
               -SkipChainValidation
```

### Known Issues
- Revocation checks may fail in offline environments. Use `-SkipRevocationCheck` in these cases.
- Some test certificates without complete trust chains may require `-SkipChainValidation` for signing.

### Acknowledgements
Special thanks to all contributors who helped improve the CodeSigning module with their valuable feedback and testing.

---

For detailed technical changes, please refer to the [Changelog](./CHANGELOG.md).
