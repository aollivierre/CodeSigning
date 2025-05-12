@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'CodeSigning.psm1'
    
    # Version number of this module.
    ModuleVersion = '1.2.0'
    
    # ID used to uniquely identify this module
    GUID = '7b6d5422-81a6-4f22-9d17-eb6e7d9c8d29'
    
    # Author of this module
    Author = 'PowerShell Administrator'
    
    # Company or vendor of this module
    CompanyName = 'Your Company'
    
    # Copyright statement for this module
    Copyright = '(c) 2025 Your Company. All rights reserved.'
    
    # Description of the functionality provided by this module
    Description = 'PowerShell module for code signing scripts and files with enhanced error handling and certificate validation'
    
    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'
        
    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @(
        # Code Signing Functions
        'Protect-Script',
        'Confirm-CodeSigningChain',
        'Get-CodeSigningCertificate',
        'Test-CodeSigningCertificate',
        'Test-ScriptSignature',
        'Import-CodeSigningCertificates',
        'Get-ExternalTrustedTime'
    )
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('CodeSigning', 'Security', 'Certificate', 'PowerShell')
            
            # A URL to the license for this module.
            LicenseUri = 'https://github.com/YourRepo/CodeSigning/blob/main/LICENSE'
            
            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/YourRepo/CodeSigning'
            
            # ReleaseNotes of this module
            ReleaseNotes = 'Enhanced error handling, detailed certificate validation, and improved certificate chain management'
        }
    }
}
