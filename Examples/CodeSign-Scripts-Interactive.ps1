# CodeSign-Scripts-Interactive
# Script to sign all PowerShell scripts in the Zoom project
# Uses the CodeSigning module and certificates in c:\temp\certs

# Set error action preference
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

# Function to write colored output
function Write-SigningLog {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        "INFO"    { "White" }
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        default   { "White" }
    }
    
    Write-Host "[$timestamp][$Level] $Message" -ForegroundColor $color
}

# Step 1: Import the CodeSigning Module
try {
    Write-SigningLog "Importing CodeSigning module from C:\Code\Modulesv2\CodeSigning\CodeSigning.psd1..." 
    Import-Module "C:\Code\Modulesv2\CodeSigning\CodeSigning.psd1" -ErrorAction Stop
    Write-SigningLog "CodeSigning module imported successfully" "SUCCESS"
}
catch {
    Write-SigningLog "Failed to import CodeSigning module: $_" "ERROR"
    exit 1
}

# Step 1b: Import PSSecretsAO Module for secrets management
try {
    $secretsModulePath = "C:\Code\Modulesv2\PSSecretsAO\PSSecretsAO.psd1"
    Write-SigningLog "Importing PSSecretsAO module from $secretsModulePath..."
    Import-Module $secretsModulePath -Force -ErrorAction Stop
    Write-SigningLog "PSSecretsAO module imported successfully" "SUCCESS"
}
catch {
    Write-SigningLog "Failed to import PSSecretsAO module: $_" "ERROR"
    exit 1
}

# Step 2: Define scripts to sign - Allow user to select a path
Write-SigningLog "Select a path containing scripts to sign" "INFO"

function Show-FolderBrowserDialog {
    [CmdletBinding()]
    param(
        [string]$Description = "Select a folder containing scripts to sign"
    )

    Add-Type -AssemblyName System.Windows.Forms
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = $Description
    $folderBrowser.ShowNewFolderButton = $true
    
    if ($folderBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        return $folderBrowser.SelectedPath
    }
    return $null
}

# Ask user for path selection method
Write-SigningLog "How would you like to specify the path to scripts?" "INFO"
Write-Host "1. Enter path manually"
Write-Host "2. Open folder browser dialog"
$pathSelectionMethod = Read-Host "Enter your choice (1 or 2)"

$scriptRoot = $null
if ($pathSelectionMethod -eq "1") {
    $scriptRoot = Read-Host "Enter the full path to the folder containing scripts to sign"
} elseif ($pathSelectionMethod -eq "2") {
    $scriptRoot = Show-FolderBrowserDialog
} else {
    Write-SigningLog "Invalid selection. Please enter 1 or 2." "ERROR"
    exit 1
}

if (-not $scriptRoot -or -not (Test-Path -Path $scriptRoot)) {
    Write-SigningLog "Invalid path or no path selected: $scriptRoot" "ERROR"
    exit 1
}

Write-SigningLog "Identifying scripts to sign in $scriptRoot"

# Get all PowerShell scripts (.ps1 files) from the selected path
$psScripts = @(
    Get-ChildItem -Path "$scriptRoot" -Filter "*.ps1" -Recurse
)
Write-SigningLog "Found $($psScripts.Count) PowerShell scripts (.ps1 files)" "INFO"

# Get all PowerShell modules (.psm1 files) from the selected path
$psModules = @(
    Get-ChildItem -Path "$scriptRoot" -Filter "*.psm1" -Recurse
)
Write-SigningLog "Found $($psModules.Count) PowerShell modules (.psm1 files)" "INFO"

# Combine scripts to sign
$scriptsToSign = @($psScripts) + @($psModules)
Write-SigningLog "Total files to sign: $($scriptsToSign.Count)" "INFO"

# Step 3: Load and verify the code signing certificate
try {
    $certFolder = "C:\temp\certs"
    Write-SigningLog "Loading certificate from $certFolder"
    
    # Check if certificate folder exists
    if (-not (Test-Path -Path $certFolder)) {
        Write-SigningLog "Certificate folder not found: $certFolder" "ERROR"
        exit 1
    }
    
    # Look specifically for the ConfigMgrCodeSigning.pfx file
    $pfxPath = Join-Path -Path $certFolder -ChildPath "ConfigMgrCodeSigning.pfx"
    if (-not (Test-Path -Path $pfxPath)) {
        Write-SigningLog "ConfigMgrCodeSigning.pfx not found in $certFolder" "ERROR"
        
        # List available certificates
        $availableCerts = Get-ChildItem -Path $certFolder -Filter "*.pfx" | Select-Object -ExpandProperty Name
        if ($availableCerts.Count -gt 0) {
            Write-SigningLog "Available certificates in folder:" "INFO"
            foreach ($availableCert in $availableCerts) {
                Write-SigningLog " - $availableCert" "INFO"
            }
            
            # Ask user which certificate to use
            $certToUse = Read-Host "Enter the name of the certificate to use (including .pfx extension)"
            $pfxPath = Join-Path -Path $certFolder -ChildPath $certToUse
            
            if (-not (Test-Path -Path $pfxPath)) {
                Write-SigningLog "Selected certificate not found: $pfxPath" "ERROR"
                exit 1
            }
        } else {
            Write-SigningLog "No .pfx certificate files found in $certFolder" "ERROR"
            exit 1
        }
    }
    else {
        Write-SigningLog "Found certificate: $pfxPath" "SUCCESS"
    }
    
    # Verify the file is an actual PFX file (quick check)
    try {
        $fileBytes = [System.IO.File]::ReadAllBytes($pfxPath)
        # Simple PFX validation - check for PKCS#12 header
        if ($fileBytes.Length -lt 4 -or -not ($fileBytes[0] -eq 48 -and $fileBytes[1] -eq 130)) {
            Write-SigningLog "Warning: The file at $pfxPath may not be a valid PFX certificate" "WARNING"
            $continueWithFile = Read-Host "Continue with this file? (Y/N)"
            if ($continueWithFile -ne "Y" -and $continueWithFile -ne "y") {
                Write-SigningLog "User chose to abort operation" "ERROR"
                exit 1
            }
        }
        else {
            Write-SigningLog "Certificate file passed basic validation" "INFO"
        }
    }
    catch {
        Write-SigningLog "Warning: Could not validate certificate file: $_" "WARNING"
    }
    
    # Get certificate password from encrypted secrets file
    # Define the path for the secrets file
    $secretsDir = Join-Path -Path $PSScriptRoot -ChildPath ".secrets"
    $secretsFilePath = Join-Path -Path $secretsDir -ChildPath "codesigning-secrets.psd1"
    
    # Ensure secrets directory exists
    if (-not (Test-Path -Path $secretsDir)) {
        Write-SigningLog "Creating secrets directory: $secretsDir" "INFO"
        New-Item -Path $secretsDir -ItemType Directory -Force | Out-Null
    }
    
    Write-SigningLog "Checking for encrypted secrets file at $secretsFilePath" "INFO"
    
    # Variable to hold the secrets
    $secrets = $null
    $securePassword = $null
    
    if (Test-Path -Path $secretsFilePath) {
        # Secrets file exists - Import it
        Write-SigningLog "Secrets file found. Importing..." "INFO"
        try {
            # Import-Secretsfile decrypts the values
            $secrets = Import-Secretsfile -FilePath $secretsFilePath -ErrorAction Stop
            
            # Check which encryption method was used (metadata key)
            $metadataKey = '_PSSecretsAO_EncryptionMethod'
            $encryptionUsed = "Unknown (likely older format)"
            
            if ($secrets.ContainsKey($metadataKey)) {
                $encryptionUsed = $secrets[$metadataKey]
                # Remove metadata from working secrets
                $secrets.Remove($metadataKey) | Out-Null
            }
            
            Write-SigningLog "Secrets file is using $encryptionUsed encryption method" "INFO"
            
            if ($null -ne $secrets -and $null -ne $secrets.CertPassword) {
                Write-SigningLog "Certificate password loaded from encrypted secrets file" "SUCCESS"
                $securePassword = ConvertTo-SecureString -String $secrets.CertPassword -AsPlainText -Force
            }
            else {
                Write-SigningLog "Certificate password not found in secrets file" "WARNING"
                $securePassword = Read-Host "Enter certificate password" -AsSecureString
            }
        }
        catch {
            Write-SigningLog "Failed to import secrets file: $_" "ERROR"
            $securePassword = Read-Host "Enter certificate password" -AsSecureString
        }
    }
    else {
        # Secrets file doesn't exist - Create it interactively
        Write-SigningLog "Encrypted secrets file not found. We need to create it." "WARNING"
        Write-SigningLog "You will be prompted for the certificate password." "WARNING"
        
        try {
            # Prompt for certificate password directly instead of using interactive mode
            $certPassword = Read-Host "Enter certificate password" -AsSecureString
            $certPasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($certPassword)
            )
            
            # Create data object with just the certificate password
            $secretsData = @{
                CertPassword = $certPasswordPlain
            }
            
            # Let the user choose the encryption method
            Write-SigningLog "Select encryption method:" "INFO"
            Write-Host "1. DPAPI (More secure, tied to this user/machine)"
            Write-Host "2. Portable (Less secure, can be used on other machines)"
            $encryptionChoice = Read-Host "Enter your choice (1 or 2)"
            
            $encryptionMethod = if ($encryptionChoice -eq "2") { "Portable" } else { "DPAPI" }
            Write-SigningLog "Using encryption method: $encryptionMethod" "INFO"
            
            # Create encrypted secrets file with the password data and specified encryption method
            $secrets = New-SecretsFile -FilePath $secretsFilePath -Data $secretsData -EncryptionMethod $encryptionMethod -ErrorAction Stop
            
            if ($null -ne $secrets -and $null -ne $secrets.CertPassword) {
                Write-SigningLog "New secrets file created at '$secretsFilePath' using $encryptionMethod encryption" "SUCCESS"
                $securePassword = ConvertTo-SecureString -String $secrets.CertPassword -AsPlainText -Force
            }
            else {
                Write-SigningLog "Certificate password not stored properly" "WARNING"
                $securePassword = $certPassword  # Use the password we already collected
            }
        }
        catch {
            Write-SigningLog "Failed to create secrets file: $_" "ERROR"
            $securePassword = Read-Host "Enter certificate password" -AsSecureString
        }
    }
    
    # Load the certificate with the password - with retry logic
    $maxRetries = 3
    $retryCount = 0
    $certLoadSuccess = $false
    
    while (-not $certLoadSuccess -and $retryCount -lt $maxRetries) {
        try {
            Write-SigningLog "Attempting to load certificate (Attempt $(($retryCount + 1)))" "INFO"
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($pfxPath, $securePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            
            if ($null -eq $cert -or $cert.Subject -eq "") {
                throw "Certificate loaded but appears to be invalid (empty subject)"
            }
            
            $certLoadSuccess = $true
            Write-SigningLog "Certificate loaded successfully" "SUCCESS"
            Write-SigningLog "Subject: $($cert.Subject)" "SUCCESS"
            Write-SigningLog "Thumbprint: $($cert.Thumbprint)" "SUCCESS"
            Write-SigningLog "Valid from: $($cert.NotBefore) to $($cert.NotAfter)" "INFO"
        }
        catch {
            $retryCount++
            Write-SigningLog "Failed to load certificate (Attempt $retryCount): $_" "ERROR"
            
            if ($retryCount -lt $maxRetries) {
                Write-SigningLog "The password may be incorrect. Please try again." "WARNING"
                $securePassword = Read-Host "Enter certificate password" -AsSecureString
                
                # Update the secrets file with the new password?
                $updateSecretsFile = Read-Host "Update saved password in secrets file? (Y/N)"
                if ($updateSecretsFile -eq "Y" -or $updateSecretsFile -eq "y") {
                    try {
                        $certPasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
                        )
                        $secretsData = @{
                            CertPassword = $certPasswordPlain
                        }
                        $secrets = New-SecretsFile -FilePath $secretsFilePath -Data $secretsData -ErrorAction Stop
                        Write-SigningLog "Updated secrets file with new password" "SUCCESS"
                    }
                    catch {
                        Write-SigningLog "Failed to update secrets file: $_" "WARNING"
                    }
                }
            }
            else {
                Write-SigningLog "Maximum retry attempts reached. Cannot load certificate." "ERROR"
                exit 1
            }
        }
    }
    
    if (-not $certLoadSuccess) {
        Write-SigningLog "Failed to load certificate after $maxRetries attempts" "ERROR"
        exit 1
    }
    
    # Check if it's a code signing certificate
    if ($cert.EnhancedKeyUsageList.Count -eq 0 -or -not ($cert.EnhancedKeyUsageList | Where-Object { $_.FriendlyName -eq "Code Signing" })) {
        Write-SigningLog "Warning: Certificate may not be a code signing certificate" "WARNING"
    }
    
    # Verify certificate is valid for current date
    $now = Get-Date
    if ($now -lt $cert.NotBefore -or $now -gt $cert.NotAfter) {
        Write-SigningLog "Certificate is not valid at the current date/time" "ERROR"
        exit 1
    }
    
    Write-SigningLog "Certificate date validation passed" "SUCCESS"
}
catch {
    Write-SigningLog "Error loading or verifying certificate: $_" "ERROR"
    exit 1
}

# Step 4: No need to explicitly install the certificate chain when using Set-AuthenticodeSignature directly
# The verification of the certificate is already done in the previous step
Write-SigningLog "Certificate is ready for code signing" "SUCCESS"

# Step 5: Sign all scripts
Write-SigningLog "Beginning script signing process" "INFO"
$signedCount = 0
$failedCount = 0
$failedScripts = @()

foreach ($script in $scriptsToSign) {
    Write-SigningLog "Signing script: $($script.FullName)" "INFO"
    
    try {
        # Direct signing using Set-AuthenticodeSignature instead of Protect-Script
        $signResult = Set-AuthenticodeSignature -FilePath $script.FullName -Certificate $cert -TimestampServer "http://timestamp.digicert.com"
        
        if ($signResult.Status -eq "Valid") {
            $signedCount++
            Write-SigningLog "Successfully signed: $($script.FullName)" "SUCCESS"
        }
        else {
            Write-SigningLog "Signature status issue: $($signResult.Status) - $($script.FullName)" "WARNING"
            
            # Try with alternative timestamp server
            Write-SigningLog "Attempting alternative timestamp server..." "WARNING"
            $signResult = Set-AuthenticodeSignature -FilePath $script.FullName -Certificate $cert -TimestampServer "http://timestamp.sectigo.com"
            
            if ($signResult.Status -eq "Valid") {
                $signedCount++
                Write-SigningLog "Successfully signed with alternative timestamp server: $($script.FullName)" "SUCCESS"
            }
            else {
                $failedCount++
                $failedScripts += $script.FullName
                Write-SigningLog "Failed to sign after retry: $($script.FullName)" "ERROR"
            }
        }
    }
    catch {
        Write-SigningLog "Error signing: $($script.FullName)" "ERROR"
        Write-SigningLog "Error details: $_" "ERROR"
        $failedCount++
        $failedScripts += $script.FullName
    }
}

# Step 6: Verify signatures
Write-SigningLog "Verifying all script signatures" "INFO"
$verifiedCount = 0
$invalidCount = 0
$invalidScripts = @()

foreach ($script in $scriptsToSign) {
    $sig = Get-AuthenticodeSignature -FilePath $script.FullName
    
    if ($sig.Status -eq "Valid") {
        $verifiedCount++
        Write-SigningLog "Verified signature: $($script.FullName) - Status: $($sig.Status)" "SUCCESS"
    }
    else {
        $invalidCount++
        $invalidScripts += $script.FullName
        Write-SigningLog "Invalid signature: $($script.FullName) - Status: $($sig.Status)" "ERROR"
    }
}

# Display summary
Write-SigningLog "===== Signing Summary =====" "INFO"
Write-SigningLog "Total scripts processed: $($scriptsToSign.Count)" "INFO"
Write-SigningLog "Successfully signed: $signedCount" "SUCCESS"
Write-SigningLog "Failed to sign: $failedCount" "INFO"
Write-SigningLog "Verified valid signatures: $verifiedCount" "SUCCESS"
Write-SigningLog "Invalid signatures: $invalidCount" "INFO"

# Display any failed scripts
if ($failedScripts.Count -gt 0) {
    Write-SigningLog "The following scripts failed to sign:" "WARNING"
    foreach ($script in $failedScripts) {
        Write-SigningLog " - $script" "WARNING"
    }
}

# Display any invalid signatures
if ($invalidScripts.Count -gt 0) {
    Write-SigningLog "The following scripts have invalid signatures:" "WARNING"
    foreach ($script in $invalidScripts) {
        Write-SigningLog " - $script" "WARNING"
    }
}

Write-SigningLog "Script signing process completed" "SUCCESS"