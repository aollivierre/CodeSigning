# Changelog

All notable changes to the CodeSigning module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2025-03-25

### Added
- Added `ReturnDetails` parameter to `Confirm-CodeSigningChain` function for detailed certificate chain validation results
- Added `ReturnDetails` parameter to `Get-CodeSigningCertificate` function for comprehensive certificate information
- Enhanced structured result objects with detailed property reporting across all functions
- Extended validation reporting for certificate testing functions

### Fixed
- Fixed missing `ChainElements` property in certificate chain validation results
- Improved error handling throughout the module with better context and recovery options
- Enhanced error reporting consistency across all functions

### Changed
- Restructured error objects for more detailed information
- Improved certificate validation logic with extended reporting

## [1.1.0] - 2025-03-24

### Added
- Support for password-protected PFX files with secure password handling
- Enhanced batch signing capabilities for processing multiple scripts efficiently
- New parameter `-SkipChainValidation` for bypassing certificate chain validation in test environments
- Comprehensive test suite with coverage for all module functionality
- Test-BatchSigning function in the test suite to validate batch signing operations
- Test-PasswordProtectedPFX function to ensure secure handling of password-protected certificates

### Fixed
- Improved certificate chain installation and management
- Fixed incorrect parameter binding in batch signing scenarios
- Resolved bitwise OR operator issues in certificate handling functions
- Enhanced error handling and reporting throughout the module
- Corrected pipeline input handling for batch signing operations

### Changed
- Restructured certificate store operations for better reliability
- Enhanced output messages to provide more detailed information about signing operations
- Improved test suite organization with dedicated test options for specialized scenarios
- Updated certificate management to properly handle root, intermediate, and leaf certificates

## [1.0.0] - 2025-03-24

### Added
- Initial release of the CodeSigning module
- Core functionality for code signing PowerShell scripts
- Get-CodeSigningCertificate function to find code signing certificates
- Test-CodeSigningCertificate function to validate certificates
- Confirm-CodeSigningChain function to verify and install certificate chains
- Protect-Script function to sign PowerShell scripts
- Basic test suite to validate core functionality
