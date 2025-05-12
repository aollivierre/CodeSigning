# CodeSigning.psm1
# Main module loader for CodeSigning module

# Get the current script path
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Load all public functions
$publicFunctions = Get-ChildItem -Path "$scriptPath\Public\*.ps1" -ErrorAction SilentlyContinue
foreach ($function in $publicFunctions) {
    try {
        . $function.FullName
        Write-Verbose "Imported function $($function.BaseName)"
    } catch {
        Write-Error "Failed to import function $($function.FullName): $_"
    }
}

# Load all private functions
$privateFunctions = Get-ChildItem -Path "$scriptPath\Private\*.ps1" -ErrorAction SilentlyContinue
foreach ($function in $privateFunctions) {
    try {
        . $function.FullName
        Write-Verbose "Imported private function $($function.BaseName)"
    } catch {
        Write-Error "Failed to import private function $($function.FullName): $_"
    }
}

# Export public functions
Export-ModuleMember -Function $publicFunctions.BaseName
