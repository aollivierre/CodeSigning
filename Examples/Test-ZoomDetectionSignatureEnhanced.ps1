# Test-ZoomDetectionSignatureEnhanced.ps1
# Example script demonstrating how to use Test-ScriptSignature with the Zoom detection script
# Enhanced with system information, VPN connectivity checks, and external time validation
#
# This script demonstrates how to validate PowerShell script signatures with external time validation
# to ensure certificates are valid regardless of local system clock accuracy.
#
# Usage:
#   1. Run the script directly: 
#      & "C:\code\Modulesv2\CodeSigning\Examples\Test-ZoomDetectionSignatureEnhanced.ps1"
#
#   2. If you want to change the script path being validated:
#      - Edit the $zoomDetectionScript variable to point to your script path
#
# Features:
#   - External time validation from multiple trusted time sources
#   - Automatic certificate import from C:\temp\certs if needed
#   - Detailed signature validation with clear status messages
#   - System information collection including VPN status
#   - ASCII-safe output for compatibility with all PowerShell environments
#
# Requirements:
#   - PowerShell 5.1 or later
#   - Internet connectivity for external time validation
#   - Certificate files in C:\temp\certs (if using auto-import feature)

# Import the CodeSigning module
Import-Module $PSScriptRoot\..\CodeSigning.psd1 -Force

# Check current execution policy
$currentExecutionPolicy = Get-ExecutionPolicy
$scopedPolicies = Get-ExecutionPolicy -List

# Check if the certificates need to be imported
$certPath = "C:\temp\certs"
$rootCertFile = Join-Path -Path $certPath -ChildPath "root.cer"
$issuingCertFile = Join-Path -Path $certPath -ChildPath "issuing.cer"
$codeCertFile = Join-Path -Path $certPath -ChildPath "ConfigMgrCodeSigning.cer"
$codeCertPfxFile = Join-Path -Path $certPath -ChildPath "ConfigMgrCodeSigning.pfx"

$allCertFilesExist = (Test-Path $rootCertFile) -and (Test-Path $issuingCertFile) -and 
                    (Test-Path $codeCertFile) -and (Test-Path $codeCertPfxFile)

# Check if we need to import certificates
$needsImport = $false

if ($allCertFilesExist) {
    # Check if the leaf certificate is already in the personal store with private key
    $leafThumbprint = $null
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($codeCertFile)
        $leafThumbprint = $cert.Thumbprint
        
        # Check if cert with private key exists in personal store
        $personalStore = Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction SilentlyContinue | 
                         Where-Object { $_.Thumbprint -eq $leafThumbprint -and $_.HasPrivateKey -eq $true }
        
        if (-not $personalStore) {
            $needsImport = $true
        }
    }
    catch {
        $needsImport = $true
        Write-Warning "Error checking certificate status: $_"
    }
}

# Auto-import certificates if needed
if ($allCertFilesExist -and $needsImport) {
    Write-Host "`n===================================================" -ForegroundColor White
    Write-Host "CERTIFICATE IMPORT" -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor White
    Write-Host "Certificates found in $certPath that need to be imported" -ForegroundColor Yellow
    Write-Host "The script will attempt to import them now." -ForegroundColor Yellow
    Write-Host "NOTE: You may see Windows security dialogs - please respond to them" -ForegroundColor Yellow
    Write-Host "===================================================" -ForegroundColor White
    
    # Check if running as administrator for LocalMachine stores
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Warning "Not running as administrator - certificate import to LocalMachine stores may fail"
        Write-Host "Consider re-running this script as Administrator if certificate validation fails" -ForegroundColor Yellow
    }
    
    # Fallback to direct import logic using reliable methods
    Write-Host "Using direct certificate import logic..." -ForegroundColor Yellow
    
    # Import root certificate
    Write-Host "Importing Root CA certificate..." -ForegroundColor Yellow
    try {
        if ($isAdmin) {
            $rootResult = certutil -addstore Root $rootCertFile
            Write-Host "  Root CA certificate imported to LocalMachine\Root" -ForegroundColor $(if ($rootResult -match "added to store") { "Green" } else { "Red" })
        }
        else {
            Write-Warning "Skipping Root CA import - requires admin privileges"
        }
    } catch {
        Write-Error "Failed to import Root CA: $_"
    }
    
    # Import issuing CA certificate
    Write-Host "Importing Issuing CA certificate..." -ForegroundColor Yellow
    try {
        if ($isAdmin) {
            $issuingResult = certutil -addstore CA $issuingCertFile
            Write-Host "  Issuing CA certificate imported to LocalMachine\CA" -ForegroundColor $(if ($issuingResult -match "added to store") { "Green" } else { "Red" })
        }
        else {
            Write-Warning "Skipping Issuing CA import - requires admin privileges"
        }
    } catch {
        Write-Error "Failed to import Issuing CA: $_"
    }
    
    # Import code signing certificate to Trusted Publishers
    Write-Host "Importing Code Signing certificate to Trusted Publishers..." -ForegroundColor Yellow
    try {
        if ($isAdmin) {
            $codeResult = certutil -addstore TrustedPublisher $codeCertFile
            Write-Host "  Code Signing certificate imported to LocalMachine\TrustedPublisher" -ForegroundColor $(if ($codeResult -match "added to store") { "Green" } else { "Red" })
        }
        else {
            Write-Warning "Skipping TrustedPublisher import - requires admin privileges"
        }
    } catch {
        Write-Error "Failed to import Code Signing cert to TrustedPublisher: $_"
    }
    
    # Import PFX with private key to personal store - using a direct and reliable approach
    Write-Host "Importing Code Signing PFX with private key..." -ForegroundColor Yellow

    # Get password for PFX from user
    Write-Host "The PFX file appears to be password protected." -ForegroundColor Yellow
    $pfxPassword = Read-Host "Please enter the password for the PFX file" -AsSecureString
    $pfxImported = $false

    try {
        # First try Import-PfxCertificate with the provided password
        try {
            Write-Host "  Trying to import with Import-PfxCertificate..." -ForegroundColor Yellow
            Import-PfxCertificate -FilePath $codeCertPfxFile -CertStoreLocation Cert:\CurrentUser\My -Password $pfxPassword -Exportable | Out-Null
            $pfxImported = $true
            Write-Host "  Code Signing PFX imported successfully to CurrentUser\My" -ForegroundColor Green
        } catch {
            Write-Warning "  Could not import PFX using Import-PfxCertificate: $_"
            $pfxImported = $false
        }
        
        # If first method failed, try direct .NET method
        if (-not $pfxImported) {
            try {
                Write-Host "  Trying direct .NET import method..." -ForegroundColor Yellow
                $certStoreFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor 
                                  [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor
                                  [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
                
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($codeCertPfxFile, $pfxPassword, $certStoreFlags)
                
                # Add to personal store
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
                $store.Open("ReadWrite")
                $store.Add($cert)
                $store.Close()
                
                Write-Host "  Code Signing PFX imported to CurrentUser\My using direct .NET method" -ForegroundColor Green
                $pfxImported = $true
            } catch {
                Write-Warning "  Could not import PFX using direct .NET method: $_"
                $pfxImported = $false
            }
        }
        
        # If both methods failed, try certutil as a last resort
        if (-not $pfxImported) {
            Write-Host "  Trying certutil import method (you may see a password prompt)..." -ForegroundColor Yellow
            $pfxResult = certutil -user -p * -importpfx $codeCertPfxFile NoRoot
            $pfxImported = $pfxResult -match "CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES"
            Write-Host "  Code Signing PFX imported to CurrentUser\My using certutil" -ForegroundColor $(if ($pfxImported) { "Green" } else { "Red" })
        }
        
        if (-not $pfxImported) {
            Write-Warning "All PFX import methods failed. The certificate validation will likely fail."
        }
    } catch {
        Write-Error "Failed to import Code Signing PFX: $_"
    }
    
    # Verify imports
    Write-Host "`nVerifying certificate imports..." -ForegroundColor Yellow
    $personalCert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $leafThumbprint }
    if ($personalCert -and $personalCert.HasPrivateKey) {
        Write-Host "  Code Signing certificate found in personal store with private key!" -ForegroundColor Green
        Write-Host "  Certificate should now be usable for validation." -ForegroundColor Green
    } else {
        Write-Warning "  Code Signing certificate not properly imported with private key"
        Write-Warning "  Certificate validation will likely fail due to missing private key"
        Write-Host "  Please ensure you entered the correct password for the PFX file." -ForegroundColor Yellow
    }
}

# Try to import the Cisco VPN Detection module - using approach from Connect-MECM.ps1
$vpnModuleAvailable = $false
$vpnModuleImported = $false
Write-Verbose "Checking for VPN detection module..."

# First try specific path where user has the module
$vpnModulePaths = @(
    "C:\code\Modulesv2\VPN\CiscoVPNDetection.psd1",  # Primary location
    "C:\code\CB\VPN\CiscoVPNDetection.psd1",         # Alternative location
    (Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath "CiscoVPNDetection\CiscoVPNDetection.psd1")  # Relative location
)

foreach ($path in $vpnModulePaths) {
    if (Test-Path $path) {
        try {
            Write-Verbose "Attempting to import VPN module from: $path"
            Import-Module $path -ErrorAction Stop
            $vpnModuleAvailable = $true
            $vpnModuleImported = $true
            Write-Verbose "Successfully imported CiscoVPNDetection module from $path"
            break
        }
        catch {
            Write-Verbose "Failed to import VPN module from $path" + ": " + "$($_.Exception.Message)"
        }
    }
}

# Try system module path as last resort
if (-not $vpnModuleImported) {
    try {
        Import-Module CiscoVPNDetection -ErrorAction Stop
        $vpnModuleAvailable = $true
        Write-Verbose "Successfully imported CiscoVPNDetection module from system module path"
    }
    catch {
        Write-Verbose "Could not import VPN Detection module: $($_.Exception.Message)"
        # Don't show a warning as this is optional functionality
    }
}

# Define the path to the Zoom detection script - set correct path based on user's environment
$zoomDetectionScript = "C:\code\SCCM\apps_v1\Zoom-NoMSI\Scripts\Detection\ZoomWorkplace-Detection.ps1"

# Function to get the current user
function Get-CurrentUser {
    try {
        # First try Windows identity
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        if (-not [string]::IsNullOrEmpty($currentUser)) {
            return $currentUser
        }
    }
    catch {
        Write-Verbose "Error getting Windows identity: $($_.Exception.Message)"
    }

    # Fallback to environment variables
    if (-not [string]::IsNullOrEmpty($env:USERNAME)) {
        $domain = if (-not [string]::IsNullOrEmpty($env:USERDOMAIN)) { $env:USERDOMAIN } else { $env:COMPUTERNAME }
        return "$domain\$env:USERNAME"
    }

    # Last resort
    return "Unknown"
}

# Display script banner
Write-Host "`n===================================================" -ForegroundColor White
Write-Host "TEST ZOOM DETECTION SCRIPT SIGNATURE" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor White

# Show Execution Policy
Write-Host "`nEXECUTION POLICY:" -ForegroundColor Green
Write-Host "Current Execution Policy: $currentExecutionPolicy" -ForegroundColor Yellow

Write-Host "Execution Policy by Scope:" -ForegroundColor Yellow
foreach ($policy in $scopedPolicies) {
    $scope = $policy.Scope
    $policyValue = $policy.ExecutionPolicy
    
    # Highlight the effective policy
    if ($scope -eq "MachinePolicy" -or 
        ($scope -eq "UserPolicy" -and $currentExecutionPolicy -eq $policyValue) -or
        ($scope -eq "Process" -and $currentExecutionPolicy -eq $policyValue) -or
        ($scope -eq "CurrentUser" -and $currentExecutionPolicy -eq $policyValue) -or
        ($scope -eq "LocalMachine" -and $currentExecutionPolicy -eq $policyValue)) {
        
        Write-Host "  $scope : $policyValue" -ForegroundColor $(if ($policyValue -eq "Restricted" -or $policyValue -eq "AllSigned") { "Red" } elseif ($policyValue -eq "RemoteSigned") { "Yellow" } else { "Green" })
    } else {
        Write-Host "  $scope : $policyValue" -ForegroundColor Gray
    }
}

# Show System Information
$currentUser = Get-CurrentUser
$computerName = $env:COMPUTERNAME
$domainName = $env:USERDOMAIN
$currentDate = Get-Date
$vpnConnected = $false

Write-Host "`nSYSTEM INFORMATION:" -ForegroundColor Green
Write-Host "Computer Name: $computerName" -ForegroundColor Yellow
Write-Host "Domain Name:   $domainName" -ForegroundColor Yellow
Write-Host "Current User:  $currentUser" -ForegroundColor Yellow
Write-Host "Current Date:  $currentDate" -ForegroundColor Yellow

# Get and display network adapter information
Write-Host "`nNETWORK CONNECTION:" -ForegroundColor Green
$networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

foreach ($adapter in $networkAdapters) {
    $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex
    $ipAddress = $ipConfig.IPv4Address.IPAddress
    Write-Host "$($adapter.Name): $($adapter.InterfaceDescription)" -ForegroundColor Yellow
    Write-Host "  Status: $($adapter.Status), IP: $ipAddress" -ForegroundColor Yellow
}

# Check VPN Connection if module is available
if ($vpnModuleAvailable) {
    Write-Host "`nVPN STATUS:" -ForegroundColor Green
    try {
        # Use the correct function that exists in the module
        $vpnConnected = Test-CiscoVPNConnected -ErrorAction Stop
        
        # Get more details if available
        $vpnDetails = Get-VPNStatus -ErrorAction SilentlyContinue
        
        if ($vpnConnected) {
            Write-Host "VPN is CONNECTED" -ForegroundColor Green
            
            # Display additional details if available
            if ($vpnDetails) {
                if ($vpnDetails.ConnectionName) {
                    Write-Host "  Connection Name: $($vpnDetails.ConnectionName)" -ForegroundColor Yellow
                }
                if ($vpnDetails.PublicIP) {
                    Write-Host "  Public IP: $($vpnDetails.PublicIP)" -ForegroundColor Yellow
                }
                if ($vpnDetails.Adapter) {
                    Write-Host "  VPN Adapter: $($vpnDetails.Adapter)" -ForegroundColor Yellow
                }
            }
        } else {
            Write-Host "VPN is DISCONNECTED" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Error checking VPN status: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "`nVPN STATUS:" -ForegroundColor Green
    Write-Host "VPN detection module not available" -ForegroundColor Yellow
    Write-Host "  To enable VPN detection, install the CiscoVPNDetection module" -ForegroundColor Gray
    
    # Check if any VPN adapters exist using a different method
    $vpnAdapters = Get-NetAdapter | Where-Object { 
        $_.InterfaceDescription -like "*VPN*" -or 
        $_.InterfaceDescription -like "*Cisco*" -or 
        $_.InterfaceDescription -like "*AnyConnect*" 
    }
    
    if ($vpnAdapters) {
        Write-Host "  Potential VPN adapters detected:" -ForegroundColor Yellow
        foreach ($adapter in $vpnAdapters) {
            $status = if ($adapter.Status -eq "Up") { "CONNECTED" } else { "DISCONNECTED" }
            Write-Host "  - $($adapter.Name): $status" -ForegroundColor $(if ($adapter.Status -eq "Up") { "Green" } else { "Gray" })
        }
    }
}

# Get trusted time from external sources
Write-Host "`nEXTERNAL TIME VALIDATION:" -ForegroundColor Green

try {
    # Import the module with force to get the latest version
    Import-Module $PSScriptRoot\..\CodeSigning.psd1 -Force
    
    # Get trusted time from explicit UTC source only
    $timeServer = 'https://worldtimeapi.org/api/timezone/Etc/UTC'
    
    Write-Host "Using trusted time source: $timeServer" -ForegroundColor Yellow
    $trustedTime = Get-ExternalTrustedTime -TimeServers @($timeServer) -TimeoutSeconds 10 -Verbose
    
    if ($trustedTime.Success) {
        # Display times in both UTC and local format for clarity
        $localTimeUTC = $trustedTime.LocalUtcTime
        $localTime = $localTimeUTC.ToLocalTime()
        $externalTimeUTC = $trustedTime.ExternalUtcTime
        $externalTime = $externalTimeUTC.ToLocalTime()
        
        Write-Host "Successfully retrieved trusted UTC time" -ForegroundColor Green
        Write-Host "  Local System Time (UTC): $localTimeUTC" -ForegroundColor Yellow
        Write-Host "  Local System Time (Your timezone): $localTime" -ForegroundColor Yellow
        Write-Host "  External Trusted Time (UTC): $externalTimeUTC" -ForegroundColor Yellow
        Write-Host "  External Trusted Time (Your timezone): $externalTime" -ForegroundColor Yellow
        
        $timeDiff = $trustedTime.DeltaSeconds
        $absTimeDiff = $trustedTime.AbsoluteDeltaSeconds
        
        # Display time difference
        if ($absTimeDiff -gt 300) {
            Write-Host "  [WARNING] System clock is off by $absTimeDiff seconds (>5 minutes)!" -ForegroundColor Red
            if ($timeDiff -gt 0) {
                Write-Host "  System time is BEHIND trusted time" -ForegroundColor Red
            } else {
                Write-Host "  System time is AHEAD OF trusted time" -ForegroundColor Red
            }
        } else {
            Write-Host "  [OK] System time is within acceptable range ($absTimeDiff seconds difference)" -ForegroundColor Green
        }
        
        Write-Host "`n  Sources used for time validation:" -ForegroundColor Yellow
        foreach ($source in $trustedTime.Sources) {
            Write-Host "   - $source" -ForegroundColor Gray
        }
    } else {
        Write-Warning "Failed to get external trusted time. Validation will use local system time only."
        Write-Host "  Error: $($trustedTime.LastError)" -ForegroundColor Red
    }
} catch {
    Write-Warning "Error during external time validation: $($_.Exception.Message)"
    Write-Warning "Stack trace: $($_.ScriptStackTrace)"
}

# Check if the script exists
if (-not (Test-Path -Path $zoomDetectionScript)) {
    Write-Error "Zoom detection script not found at $zoomDetectionScript"
    exit
}

# Basic signature validation
Write-Host "`n===================================================" -ForegroundColor White
Write-Host "BASIC SIGNATURE VALIDATION" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor White

# Use only UTC-specific time source with increased timeout
$timeServer = 'https://worldtimeapi.org/api/timezone/Etc/UTC'
$basicSignatureValid = Test-ScriptSignature -Path $zoomDetectionScript -UseExternalTimeValidation -TimeServers @($timeServer) -TimeoutSeconds 10

if ($basicSignatureValid) {
    Write-Host "Script signature is valid." -ForegroundColor Green
} else {
    Write-Host "Script signature is invalid." -ForegroundColor Red
}

# Detailed validation
Write-Host "`n===================================================" -ForegroundColor White
Write-Host "DETAILED SIGNATURE VALIDATION" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor White

# Use ONLY the explicit UTC time server for validation
$timeServer = 'https://worldtimeapi.org/api/timezone/Etc/UTC'
$detailedValidation = Test-ScriptSignature -Path $zoomDetectionScript -Detailed -UseExternalTimeValidation -TimeServers @($timeServer) -TimeoutSeconds 10

# Display detailed results
Write-Host "Script path: $($detailedValidation.Path)" -ForegroundColor Yellow
Write-Host "Has signature: $($detailedValidation.HasSignature)" -ForegroundColor $(if ($detailedValidation.HasSignature) { "Green" } else { "Red" })

if ($detailedValidation.HasSignature) {
    Write-Host "Signature valid: $($detailedValidation.SignatureValid)" -ForegroundColor $(if ($detailedValidation.SignatureValid) { "Green" } else { "Red" })
    Write-Host "Content modified: $($detailedValidation.ContentModified)" -ForegroundColor $(if (-not $detailedValidation.ContentModified) { "Green" } else { "Red" })
    
    # Cert details
    $signerCert = $detailedValidation.SignatureDetails.SignerCertificate
    Write-Host "`nCERTIFICATE DETAILS:" -ForegroundColor Green
    Write-Host "Subject: $($signerCert.Subject)" -ForegroundColor Yellow
    Write-Host "Issuer: $($signerCert.Issuer)" -ForegroundColor Yellow
    Write-Host "Valid from: $($signerCert.NotBefore) to $($signerCert.NotAfter)" -ForegroundColor Yellow
    Write-Host "Thumbprint: $($signerCert.Thumbprint)" -ForegroundColor Yellow
    
    # Show if cert is in valid date range - comparing with external time if available
    $localTimeValid = ($signerCert.NotBefore -le [DateTime]::Now) -and ([DateTime]::Now -le $signerCert.NotAfter)
    
    Write-Host "`nCERTIFICATE VALIDATION:" -ForegroundColor Green
    Write-Host "Certificate valid (local time): $($detailedValidation.CertificateValid)" -ForegroundColor $(if ($detailedValidation.CertificateValid) { "Green" } else { "Red" })
    
    if ($detailedValidation.ExternalTimeValidation -ne $null -and $detailedValidation.ExternalTimeValidation.Success) {
        Write-Host "Certificate valid (external time): $($detailedValidation.CertificateValidWithExternalTime)" -ForegroundColor $(if ($detailedValidation.CertificateValidWithExternalTime) { "Green" } else { "Red" })
    }
    
    Write-Host "Certificate chain valid: $($detailedValidation.ChainValid)" -ForegroundColor $(if ($detailedValidation.ChainValid) { "Green" } else { "Red" })
    
    # Certificate store presence and validation
    $foundInPersonalStore = $false
    $hasPrivateKey = $false
    
    $personalCert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $signerCert.Thumbprint }
    if ($personalCert) {
        $foundInPersonalStore = $true
        $hasPrivateKey = $personalCert.HasPrivateKey
    }
    
    Write-Host "`nCERTIFICATE STORE STATUS:" -ForegroundColor Green
    Write-Host "Found in personal store: $foundInPersonalStore" -ForegroundColor $(if ($foundInPersonalStore) { "Green" } else { "Yellow" })
    Write-Host "Has private key: $hasPrivateKey" -ForegroundColor $(if ($hasPrivateKey) { "Green" } else { "Yellow" })
    
    # Display full certificate chain - get it from the signature details or build it from the store
    Write-Host "`nCERTIFICATE CHAIN:" -ForegroundColor Green
    
    # Try to get the chain from the signature details first
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chainValid = $chain.Build($signerCert)
    
    if ($chain.ChainElements.Count -gt 0) {
        Write-Host "Chain contains $($chain.ChainElements.Count) certificates:" -ForegroundColor Yellow
        
        # Display each certificate in the chain (from leaf to root)
        for ($i = 0; $i -lt $chain.ChainElements.Count; $i++) {
            $cert = $chain.ChainElements[$i].Certificate
            $level = if ($i -eq 0) { "Leaf" } elseif ($i -eq $chain.ChainElements.Count - 1) { "Root" } else { "Intermediate" }
            $indent = " " * (4 * $i)  # Indent to show hierarchy
            
            Write-Host "`n${indent}[$level] Certificate Details:" -ForegroundColor $(if ($i -eq 0) { "Yellow" } elseif ($i -eq $chain.ChainElements.Count - 1) { "Cyan" } else { "Gray" })
            Write-Host "${indent}Subject: $($cert.Subject)" -ForegroundColor $(if ($i -eq 0) { "Yellow" } elseif ($i -eq $chain.ChainElements.Count - 1) { "Cyan" } else { "Gray" })
            Write-Host "${indent}Issuer: $($cert.Issuer)" -ForegroundColor $(if ($i -eq 0) { "Yellow" } elseif ($i -eq $chain.ChainElements.Count - 1) { "Cyan" } else { "Gray" })
            Write-Host "${indent}Valid from: $($cert.NotBefore) to $($cert.NotAfter)" -ForegroundColor $(if ($i -eq 0) { "Yellow" } elseif ($i -eq $chain.ChainElements.Count - 1) { "Cyan" } else { "Gray" })
            Write-Host "${indent}Thumbprint: $($cert.Thumbprint)" -ForegroundColor $(if ($i -eq 0) { "Yellow" } elseif ($i -eq $chain.ChainElements.Count - 1) { "Cyan" } else { "Gray" })
            
            # Check if certificate is in trusted roots
            $inTrustedRoots = $false
            $inIntermediateCAs = $false
            $inTrustedPublishers = $false
            
            if ($cert.Subject -ne $cert.Issuer) {  # Not self-signed
                $inIntermediateCAs = [bool](Get-ChildItem -Path "Cert:\LocalMachine\CA" -Recurse | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })
            } else {  # Root cert
                $inTrustedRoots = [bool](Get-ChildItem -Path "Cert:\LocalMachine\Root" -Recurse | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })
            }
            
            if ($cert.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq "1.3.6.1.5.5.7.3.3" }) {  # Code Signing EKU
                $inTrustedPublishers = [bool](Get-ChildItem -Path "Cert:\LocalMachine\TrustedPublisher" -Recurse | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })
            }
            
            # Check cert status
            $status = @()
            
            if ($inTrustedRoots) { $status += "In Trusted Roots" }
            if ($inIntermediateCAs) { $status += "In Intermediate CAs" }
            if ($inTrustedPublishers) { $status += "In Trusted Publishers" }
            
            if ($status.Count -gt 0) {
                Write-Host "${indent}Store Status: $($status -join ", ")" -ForegroundColor Green
            } else {
                Write-Host "${indent}Store Status: Not found in certificate stores" -ForegroundColor Yellow
            }
            
            # If there are any chain status issues, show them
            $chainStatus = $chain.ChainElements[$i].ChainElementStatus
            if ($chainStatus -and $chainStatus.Length -gt 0) {
                Write-Host "${indent}Chain Status Issues:" -ForegroundColor $(if ($chainStatus.Length -gt 0) { "Red" } else { "Green" })
                foreach ($status in $chainStatus) {
                    Write-Host "${indent}- $($status.StatusInformation.Trim())" -ForegroundColor Red
                }
            }
        }
    } else {
        Write-Host "Unable to build certificate chain. Certificate may not be trusted." -ForegroundColor Red
    }
}

# Final recommendations based on validation results
Write-Host "`n===================================================" -ForegroundColor White
Write-Host "VALIDATION RESULTS & RECOMMENDATIONS" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor White

if ($basicSignatureValid) {
    Write-Host "[OK] The Zoom detection script signature is VALID" -ForegroundColor Green
    Write-Host "     Script can be used in environments with AllSigned execution policy" -ForegroundColor Green
} else {
    Write-Host "[ERROR] The Zoom detection script signature is NOT VALID" -ForegroundColor Red
    
    if (-not $detailedValidation.HasSignature) {
        Write-Host "     Script is not signed. It needs to be signed with a valid code signing certificate." -ForegroundColor Yellow
    }
    elseif ($detailedValidation.ContentModified) {
        Write-Host "     Script content has been modified after signing. The script needs to be re-signed." -ForegroundColor Yellow
    }
    elseif (-not $detailedValidation.CertificateValid) {
        if ($signerCert.NotBefore -gt [DateTime]::Now) {
            Write-Host "     Certificate is not yet valid (becomes valid on $($signerCert.NotBefore))" -ForegroundColor Yellow
            Write-Host "     Check system date or wait until certificate becomes valid" -ForegroundColor Yellow
        }
        elseif ([DateTime]::Now -gt $signerCert.NotAfter) {
            Write-Host "     Certificate has expired (expired on $($signerCert.NotAfter))" -ForegroundColor Yellow
            Write-Host "     Obtain a new certificate and re-sign the script" -ForegroundColor Yellow
        }
        else {
            Write-Host "     Certificate is not valid for code signing" -ForegroundColor Yellow
            Write-Host "     Use a certificate with Code Signing enhanced key usage" -ForegroundColor Yellow
        }
    }
    elseif (-not $detailedValidation.ChainValid) {
        Write-Host "     Certificate chain validation failed" -ForegroundColor Yellow
        Write-Host "     Ensure all certificates in the chain are properly installed" -ForegroundColor Yellow
    }
    
    Write-Host "`n     Recommendations:" -ForegroundColor Yellow
    Write-Host "     1. Check the code signing certificate's validity and expiration" -ForegroundColor Yellow
    Write-Host "     2. Ensure the certificate is properly installed with its private key" -ForegroundColor Yellow
    Write-Host "     3. Verify the certificate chain is valid and all CA certificates are installed" -ForegroundColor Yellow
    Write-Host "     4. Re-sign the script with a valid certificate" -ForegroundColor Yellow
} 