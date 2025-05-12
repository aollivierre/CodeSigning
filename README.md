# CodeSigning PowerShell Module

## Overview

The CodeSigning module provides easy-to-use functions for code signing PowerShell scripts and modules. It handles certificate management, chain verification, and script signing using industry best practices.

## Features

- **Script Signing**: Sign individual scripts or entire directories of scripts
- **Certificate Management**: Find, validate, and manage code signing certificates
- **Certificate Chain Verification**: Automatically verify and install certificate chains
- **Cross-Version Compatibility**: Works in both Windows PowerShell 5.1 and PowerShell Core
- **Batch Signing Support**: Sign multiple scripts efficiently with a single command
- **Password-Protected PFX Support**: Securely use certificates protected with passwords

## Key Findings and Best Practices

### Certificate Validation and Management

1. **Private Key Access is Critical**
   - Certificate validation will fail even with a valid signature if the private key is not accessible
   - The error `Has Private Key: False` in chain validation can occur even when a certificate is properly imported
   - Solutions:
     - Import the PFX file with proper flags: `PersistKeySet` and `Exportable`
     - Use `Import-PfxCertificate` cmdlet with `-Password` parameter for password-protected PFX files
     - Ensure the certificate is imported to the correct store (CurrentUser\My)

2. **Certificate Chain Integrity**
   - All certificates in the chain (root, intermediate, leaf) must be properly installed
   - The root CA must be in the `Cert:\LocalMachine\Root` store
   - Intermediate CAs must be in the `Cert:\LocalMachine\CA` store
   - The code signing certificate should be in both `Cert:\LocalMachine\TrustedPublisher` and `Cert:\CurrentUser\My` (with private key)

3. **Certificate Date Validation**
   - Certificates with future validity dates (`NotBefore` dates in the future) will fail validation
   - System time must be within the certificate's validity period (`NotBefore` and `NotAfter`)
   - External time validation may be needed in environments with incorrect system times

4. **Certificate Requirements for Code Signing**
   - Must have the Code Signing Enhanced Key Usage (EKU) extension (OID 1.3.6.1.5.5.7.3.3)
   - Digital Signature key usage bit must be set
   - Certificate must not be revoked

### Script Signature Validation

1. **Signature Invalidation on Edit**
   - **CRITICAL FINDING**: Any modification to a signed script, even if reverted, will invalidate the signature
   - Even opening and saving a file without visible changes can break the signature due to:
     - Potential changes in line endings (CR+LF vs LF)
     - UTF-8 encoding markers
     - Whitespace or other invisible characters
   - Solution: Always re-sign scripts after any modification

2. **Validation Discrepancies**
   - Different PowerShell validation mechanisms may give different results
   - `Get-AuthenticodeSignature` may report `Valid` while `Test-ScriptSignature` reports failures
   - `Test-ScriptSignature` performs deeper validation including certificate chain checking
   - Best practice: Use both validation methods to get complete validation coverage

3. **Execution Policy Compatibility**
   - Signatures must be valid to work with AllSigned execution policy
   - All scripts in a module must be signed for module import to succeed
   - Check for script compatibility with desired execution policy using `-ExecutionPolicy AllSigned` parameter

### Certificate Import Best Practices

1. **PFX Import for Password-Protected Certificates**
   - Always prompt securely for certificate passwords: `Read-Host -AsSecureString`
   - For automation, retrieve passwords from secure vaults instead of hardcoding:
     ```powershell
     # Using SecretManagement module (recommended)
     $securePassword = Get-Secret -Name "CodeSigningCertPassword" -Vault "MySecretVault"
     
     # Using Windows Credential Manager
     $credential = Get-StoredCredential -Target "CodeSigningCert"
     $securePassword = $credential.Password
     
     # Using encrypted files
     $securePassword = Get-Content "C:\SecurePath\cert-password.txt" | ConvertTo-SecureString
     ```
   - Use multiple import methods for robustness:
     ```powershell
     # Method 1: Import-PfxCertificate cmdlet
     Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\CurrentUser\My -Password $securePassword -Exportable

     # Method 2: X509Certificate2 with proper flags
     $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
         $pfxPath, 
         $securePassword, 
         [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor 
         [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
     )
     $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
     $store.Open("ReadWrite")
     $store.Add($cert)
     $store.Close()

     # Method 3: certutil for difficult cases
     certutil -user -p * -importpfx $pfxPath NoRoot
     ```

2. **Administrative Privileges**
   - Required for importing to LocalMachine stores
   - Always check for admin privileges before attempting LocalMachine cert operations
   ```powershell
   $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
   ```

3. **Certificate Store Verification**
   - Always verify that imported certificates are in the correct stores with the right attributes
   - Check for private key access after import
   ```powershell
   $cert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $targetThumbprint }
   if ($cert -and $cert.HasPrivateKey) {
       # Certificate properly imported with private key
   }
   ```

### PowerShell Coding Best Practices

1. **Avoiding Parser Errors with Variable References**
   - NEVER place colons directly after variable names in any context
   - Incorrect: `Write-Verbose "Failed to import VPN module from $path: $($_.Exception.Message)"`
   - Correct: `Write-Verbose "Failed to import VPN module from $path" + ": " + "$($_.Exception.Message)"`
   - Alternative: `Write-Verbose "Failed to import VPN module from $path : $($_.Exception.Message)"`
   - PowerShell may interpret the colon as part of a variable scope modifier

2. **Using Conditional Expressions**
   - For maximum compatibility across PowerShell versions, use:
   ```powershell
   $result = if ($condition) { $trueValue } else { $falseValue }
   ```
   - Instead of PowerShell 7+ ternary operator: `$condition ? $trueValue : $falseValue`

3. **String Output Formatting**
   - Use ASCII-compatible characters in scripts
   - Avoid Unicode symbols like checkmarks (✓) or cross marks (❌)
   - Use plain text alternatives like "[OK]" or "[ERROR]" for status indicators

## Installation

### Manual Installation

1. Clone or download this repository
2. Copy the `CodeSigning` folder to one of your PowerShell module paths:
   - `$Home\Documents\WindowsPowerShell\Modules` (for current user)
   - `$env:ProgramFiles\WindowsPowerShell\Modules` (for all users)

### PowerShell Gallery (Coming Soon)

```powershell
Install-Module -Name CodeSigning -Scope CurrentUser
```

## Quick Start

### 1. Import the Module

```powershell
Import-Module CodeSigning
```

### 2. Find and Test Available Certificates

```powershell
# Get all valid code signing certificates
Get-CodeSigningCertificate

# Test if a specific certificate is valid for code signing
$cert = Get-Item -Path "Cert:\CurrentUser\My\YOUR_THUMBPRINT_HERE"
Test-CodeSigningCertificate -Certificate $cert -Detailed
```

### 3. Sign a Script

```powershell
# Sign a script with a specific certificate by thumbprint
Protect-Script -ScriptPath "C:\Scripts\MyScript.ps1" -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678"

# Sign all scripts in a directory
Protect-Script -ScriptPath "C:\Scripts" -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678"

# Sign a script using a PFX certificate file
$securePassword = ConvertTo-SecureString -String "YourPassword" -AsPlainText -Force
Protect-Script -ScriptPath "C:\Scripts\MyScript.ps1" -CertificatePath "C:\temp\certs\CodeSigningCert.pfx" -CertificatePassword $securePassword

# Batch sign multiple scripts
$scripts = Get-ChildItem -Path "C:\Scripts\*.ps1"
$scripts | ForEach-Object { Protect-Script -ScriptPath $_ -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678" }
```

### 4. Verify and Install Certificate Chains

If you encounter certificate chain issues during signing, use:

```powershell
# Check a certificate's chain and offer to install missing certificates
$cert = Get-Item -Path "Cert:\CurrentUser\My\YOUR_THUMBPRINT_HERE"
Confirm-CodeSigningChain -Certificate $cert

# Automatically install missing certificates without prompting
Confirm-CodeSigningChain -Certificate $cert -AutoInstall

# Skip revocation checks (useful when offline)
Confirm-CodeSigningChain -Certificate $cert -SkipRevocationCheck

# Skip chain validation entirely (for test environments)
Confirm-CodeSigningChain -Certificate $cert -SkipChainValidation
```

## Certificate Chain Requirements

For code signing to work properly, Windows needs the complete certificate chain installed:

1. **Code Signing Certificate**: Your certificate with private key (.pfx file)
2. **Intermediate CA Certificate**: The issuing authority's certificate
3. **Root CA Certificate**: The root certificate authority's certificate

If signing fails with "UnknownError" or "A certificate chain could not be built to a trusted root authority" error, use the `Confirm-CodeSigningChain` function to resolve the issue.

## Common Issues and Troubleshooting

### Certificate Not Found

If you receive "Certificate not found" errors, ensure:
- The thumbprint is correct (check for hidden characters)
- The certificate is installed in the correct store (CurrentUser\My or LocalMachine\My)
- You have sufficient permissions to access the certificate

### Signing Fails with "UnknownError"

This often indicates a certificate chain issue. Try:
```powershell
$cert = Get-Item -Path "Cert:\CurrentUser\My\YOUR_THUMBPRINT_HERE"
Confirm-CodeSigningChain -Certificate $cert -AutoInstall
```

### Certificate Chain Validation Issues

When working with test certificates or in environments with limited internet access:
```powershell
# Skip revocation checks for offline environments
Protect-Script -ScriptPath "C:\Scripts\MyScript.ps1" -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678" -SkipRevocationCheck

# Skip chain validation entirely for test environments
Protect-Script -ScriptPath "C:\Scripts\MyScript.ps1" -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678" -SkipChainValidation
```

### PowerShell Core Compatibility

Code signing works more reliably in Windows PowerShell 5.1. When using this module in PowerShell Core, it will automatically attempt to use Windows PowerShell 5.1 for the actual signing operations.

### Script Signature Invalidation

If your script signature becomes invalid after editing:
- This is normal behavior - ANY change to a signed file (even reverting changes) invalidates the signature
- You must re-sign the script after any modification
- Consider adding signing to your workflow automation to minimize manual signing

### Private Key Not Available

If validation fails with "Has Private Key: False":
- Import the certificate with all private key flags:
  ```powershell
  Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\CurrentUser\My -Password $securePassword -Exportable
  ```
- Verify the certificate was imported correctly:
  ```powershell
  $cert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $thumbprint }
  $cert.HasPrivateKey  # Should return True
  ```

### Password Protected PFX Files

When working with password-protected PFX files:
- Never hardcode passwords in scripts
- For interactive use, prompt securely: `$securePassword = Read-Host -AsSecureString "Enter certificate password"`
- For automation scenarios:
  - Use a secure credential vault (SecretManagement, Windows Credential Manager)
  - Consider certificate stores with hardware security (TPM protection)
  - Use Windows DPAPI to encrypt password files with machine or user context
  - Set appropriate NTFS permissions on any files containing encrypted passwords
- Test password retrieval before deployment to ensure automation workflows can access credentials

## Module Functions

### Certificate Management
- **Get-CodeSigningCertificate**: Finds code signing certificates in certificate stores or from PFX files
- **Test-CodeSigningCertificate**: Tests if a certificate is valid for code signing
- **Import-CodeSigningCertificates**: Imports certificates from files with proper chain validation

### Certificate Chain Verification
- **Confirm-CodeSigningChain**: Verifies and installs certificate chains for code signing certificates

### Script Signing
- **Protect-Script**: Signs PowerShell scripts with code signing certificates

### Script Validation
- **Test-ScriptSignature**: Validates signatures on PowerShell scripts with detailed output

## Testing

The module includes a comprehensive test suite that ensures all functionality works as expected:

```powershell
# Run all tests
C:\Code\Modulesv2\CodeSigning\Tests\Test-CodeSigning.ps1 -CertificateFolder "C:\temp\certs"

# Run a specific test
C:\Code\Modulesv2\CodeSigning\Tests\Test-CodeSigning.ps1 -CertificateFolder "C:\temp\certs" -Menu 9  # For batch signing test
```

### Tested Functionality
- Certificate retrieval from multiple sources
- Certificate validation including chain verification
- Script signing with various parameters
- Password-protected PFX certificate handling
- Batch signing capability
- Pipeline input support

## Recent Enhancements

### March 2025 Updates
- Added support for password-protected PFX files with secure password handling
- Enhanced batch signing capabilities for processing multiple scripts efficiently
- Improved certificate chain installation and validation
- Fixed issues with certificate store management
- Enhanced test suite with comprehensive test coverage
- Added `-SkipChainValidation` parameter for test environments
- Fixed bitwise OR operator issues in certificate handling
- Added external trusted time validation for environments with incorrect system time
- Implemented comprehensive certificate chain analysis
- Added automatic detection of SYSTEM vs actual user context
- Improved VPN connectivity detection for corporate environments
- Enhanced PFX password handling with secure prompting

## Notes

- Always ensure your code signing certificate has not expired
- Store your certificate private keys securely
- Consider using a timestamp server when signing to ensure the signature remains valid after the certificate expires
- When batch signing, consider certificate chain installation to avoid repeated validation errors
- Always re-sign scripts after ANY modification, even if changes are reverted
- Use multiple validation methods to ensure complete coverage of potential issues