function Get-ExternalTrustedTime {
    <#
    .SYNOPSIS
        Gets trusted time from multiple external time sources.
    
    .DESCRIPTION
        This function queries multiple external time APIs to get a reliable time source independent
        of the local system clock. It calculates the delta between local time and trusted external time,
        helping detect system clock issues that could affect certificate validation.
        
        The function tries multiple time sources with fallback mechanisms to ensure high availability.
    
    .PARAMETER TimeServers
        Optional array of time server API endpoints to query. If not specified, the function uses
        a predefined list of reliable time sources.
    
    .PARAMETER TimeoutSeconds
        Timeout in seconds for each API call. Default is 5 seconds.
    
    .PARAMETER SkipAverageDelta
        If specified, the function won't calculate average delta from multiple sources and will
        return the first successful time source.
        
    .PARAMETER MaxTimeDiscrepancyMinutes
        Maximum allowed time discrepancy between sources in minutes. Sources that differ by more than
        this amount will be considered outliers and excluded. Default is 15 minutes.
    
    .EXAMPLE
        Get-ExternalTrustedTime
        
        Returns trusted time information from default time servers.
    
    .EXAMPLE
        Get-ExternalTrustedTime -TimeServers @('https://worldtimeapi.org/api/timezone/Etc/UTC') -TimeoutSeconds 10
        
        Queries a specific time server with a 10 second timeout.
    
    .NOTES
        Requires internet connectivity to function properly.
        If all time sources fail, the function returns the local system time with an error flag.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [string[]]$TimeServers,
        
        [int]$TimeoutSeconds = 5,
        
        [switch]$SkipAverageDelta,
        
        [int]$MaxTimeDiscrepancyMinutes = 15
    )
    
    begin {
        # Default time server APIs if none specified - focusing on high reliability ones
        # ONLY use the UTC-specific endpoints to avoid timezone issues
        if (-not $TimeServers) {
            $TimeServers = @(
                # Primary high-reliability time source - explicitly UTC 
                'https://worldtimeapi.org/api/timezone/Etc/UTC'  # Most reliable & explicitly UTC
            )
        }
        
        # Current system time in UTC
        $localUtcNow = [System.DateTime]::UtcNow
        Write-Verbose "Current local UTC time: $localUtcNow"
        
        # Store successful time queries
        $successfulTimeQueries = @()
        
        # Error tracking
        $errorCount = 0
        $lastError = $null
        
        # Convert max discrepancy to seconds
        $maxDiscrepancySeconds = $MaxTimeDiscrepancyMinutes * 60
        
        # Function to parse time from WorldTimeAPI
        function Parse-WorldTimeAPI {
            param ($Response)
            try {
                if ($Response.datetime) {
                    # Log the raw response to help debug timezone issues
                    Write-Verbose "WorldTimeAPI raw datetime: $($Response.datetime)"
                    Write-Verbose "WorldTimeAPI timezone: $($Response.timezone)"
                    Write-Verbose "WorldTimeAPI utc_offset: $($Response.utc_offset)"
                    
                    # Parse datetime from WorldTimeAPI - this already includes timezone offset in ISO8601 format
                    # Example: "2023-05-18T12:34:56.789012+00:00"
                    $timeStr = $Response.datetime -replace 'T', ' ' -replace '\..*$', ''
                    Write-Verbose "Extracted time string: $timeStr"
                    
                    # If we're using the Etc/UTC endpoint, we should get +00:00 offset (UTC)
                    # We can parse directly without timezone conversion
                    if ($Response.timezone -eq "Etc/UTC" -or $Response.utc_offset -eq "+00:00") {
                        Write-Verbose "UTC time detected from timezone or offset - parsing directly"
                        $parsedTime = [DateTime]::ParseExact($timeStr, 'yyyy-MM-dd HH:mm:ss', $null)
                        Write-Verbose "Parsed UTC time without conversion: $parsedTime"
                        return $parsedTime
                    }
                    
                    # If not UTC, we need to convert to UTC
                    Write-Verbose "Non-UTC time detected! Offset: $($Response.utc_offset) - converting to UTC"
                    $parsedTime = [DateTime]::ParseExact($timeStr, 'yyyy-MM-dd HH:mm:ss', $null)
                    
                    # Apply the UTC offset if not already UTC
                    $offsetHours = [int]($Response.utc_offset.Substring(0, 3))
                    # Use if-else instead of ternary operator for compatibility
                    $signMultiplier = if ($offsetHours -ge 0) { 1 } else { -1 }
                    $offsetMinutes = [int]($Response.utc_offset.Substring(4, 2)) * $signMultiplier
                    $parsedTime = $parsedTime.AddHours(-$offsetHours).AddMinutes(-$offsetMinutes)
                    
                    Write-Verbose "Converted time to UTC: $parsedTime"
                    return $parsedTime
                }
                else {
                    Write-Verbose "WorldTimeAPI response missing datetime field"
                    return $null
                }
            }
            catch {
                Write-Verbose "Error parsing WorldTimeAPI time: $_"
                return $null
            }
        }
        
        # Function to parse time from TimeAPI.io
        function Parse-TimeAPI {
            param ($Response)
            try {
                if ($Response.dateTime) {
                    Write-Verbose "TimeAPI raw datetime: $($Response.dateTime)"
                    $timeStr = $Response.dateTime -replace 'T', ' ' -replace '\..*$', ''
                    Write-Verbose "Extracted time string: $timeStr"
                    
                    $parsedTime = [DateTime]::ParseExact($timeStr, 'yyyy-MM-dd HH:mm:ss', $null)
                    Write-Verbose "Parsed time: $parsedTime"
                    return $parsedTime
                }
                else {
                    Write-Verbose "TimeAPI response missing dateTime field"
                    return $null
                }
            }
            catch {
                Write-Verbose "Error parsing TimeAPI time: $_"
                return $null
            }
        }
    }
    
    process {
        foreach ($server in $TimeServers) {
            try {
                Write-Verbose "Querying time server: $server"
                
                $params = @{
                    Uri = $server
                    Method = 'GET'
                    TimeoutSec = $TimeoutSeconds
                    UseBasicParsing = $true
                    ErrorAction = 'Stop'
                }
                
                $response = Invoke-RestMethod @params
                
                # DEBUG: Print the entire response object for troubleshooting
                # Convert response to JSON and output
                $responseJson = $response | ConvertTo-Json
                Write-Verbose "Full API response: $responseJson"
                
                # Determine which type of API we're working with
                $externalUtcTime = if ($server -match 'worldtimeapi\.org') {
                    Parse-WorldTimeAPI -Response $response
                }
                elseif ($server -match 'timeapi\.io') {
                    Parse-TimeAPI -Response $response
                }
                else {
                    Write-Warning "Unknown time server format: $server - skipping"
                    continue
                }
                
                # Skip if parsing failed
                if ($null -eq $externalUtcTime) {
                    Write-Verbose "Failed to parse time from $server"
                    continue
                }
                
                # Ensure time is in UTC format
                if ($externalUtcTime.Kind -ne [DateTimeKind]::Utc) {
                    Write-Verbose "Setting DateTimeKind to UTC - original Kind was: $($externalUtcTime.Kind)"
                    # Use this method instead of ToUniversalTime to avoid conversions
                    # We're just ensuring the Kind property is set correctly
                    $externalUtcTime = [DateTime]::SpecifyKind($externalUtcTime, [DateTimeKind]::Utc)
                }
                
                Write-Verbose "Final external UTC time: $externalUtcTime (Kind: $($externalUtcTime.Kind))"
                
                $deltaSeconds = [math]::Round(($externalUtcTime - $localUtcNow).TotalSeconds)
                $absoluteDeltaSeconds = [math]::Abs($deltaSeconds)
                
                Write-Verbose "Time delta: $deltaSeconds seconds ($absoluteDeltaSeconds absolute)"
                
                # If delta is very large (>12 hours), it's likely a timezone issue
                if ($absoluteDeltaSeconds -gt 43200) {
                    Write-Verbose "Large time delta detected ($absoluteDeltaSeconds seconds) - likely timezone issue, skipping"
                    continue
                }
                
                $timeInfo = [PSCustomObject]@{
                    Source = $server
                    ExternalUtcTime = $externalUtcTime
                    LocalUtcTime = $localUtcNow
                    DeltaSeconds = $deltaSeconds
                    AbsoluteDeltaSeconds = $absoluteDeltaSeconds
                    Success = $true
                }
                
                $successfulTimeQueries += $timeInfo
                
                # Return first success if requested
                if ($SkipAverageDelta) {
                    $avgDelta = $deltaSeconds
                    $maxDelta = $absoluteDeltaSeconds
                    $sources = @($server)
                    
                    # Only return if the delta is within reason (less than 12 hours)
                    if ($absoluteDeltaSeconds -lt 43200) {
                        return [PSCustomObject]@{
                            ExternalUtcTime = $externalUtcTime
                            LocalUtcTime = $localUtcNow
                            DeltaSeconds = $avgDelta
                            AbsoluteDeltaSeconds = $maxDelta
                            ClockSkewed = $absoluteDeltaSeconds -gt 300
                            Sources = $sources
                            SourceCount = 1
                            Details = $successfulTimeQueries
                            Success = $true
                            ErrorCount = 0
                            LastError = $null
                        }
                    }
                }
            }
            catch {
                $errorCount++
                $lastError = $_
                Write-Verbose "Failed to query time server $server`: $_"
            }
        }
    }
    
    end {
        # If no successful queries, return local time with error flag
        if ($successfulTimeQueries.Count -eq 0) {
            Write-Warning "Failed to query any external time sources. Using local system time."
            
            return [PSCustomObject]@{
                ExternalUtcTime = $localUtcNow
                LocalUtcTime = $localUtcNow
                DeltaSeconds = 0
                AbsoluteDeltaSeconds = 0
                ClockSkewed = $false
                Sources = @()
                SourceCount = 0
                Details = @()
                Success = $false
                ErrorCount = $errorCount
                LastError = $lastError
            }
        }
        
        # If there's only one successful query, use that directly
        if ($successfulTimeQueries.Count -eq 1) {
            $singleResult = $successfulTimeQueries[0]
            
            Write-Verbose "Using single time source: $($singleResult.Source)"
            Write-Verbose "External time: $($singleResult.ExternalUtcTime) (UTC)"
            Write-Verbose "Local time: $($singleResult.LocalUtcTime) (UTC)"
            Write-Verbose "Delta: $($singleResult.DeltaSeconds) seconds"
            
            return [PSCustomObject]@{
                ExternalUtcTime = $singleResult.ExternalUtcTime
                LocalUtcTime = $localUtcNow
                DeltaSeconds = $singleResult.DeltaSeconds
                AbsoluteDeltaSeconds = $singleResult.AbsoluteDeltaSeconds
                ClockSkewed = $singleResult.AbsoluteDeltaSeconds -gt 300
                Sources = @($singleResult.Source)
                SourceCount = 1
                Details = $successfulTimeQueries
                Success = $true
                ErrorCount = $errorCount
                LastError = $lastError
            }
        }
        
        # For multiple sources, we need to identify and exclude outliers
        Write-Verbose "Processing $($successfulTimeQueries.Count) successful time sources"
        
        # First, use WorldTimeAPI/UTC as the reference if available, as it's typically most reliable
        $worldTimeResult = $successfulTimeQueries | Where-Object { $_.Source -match 'worldtimeapi\.org/api/timezone/Etc/UTC' } | Select-Object -First 1
        $referenceTime = if ($worldTimeResult) { 
            Write-Verbose "Using WorldTimeAPI UTC as reference time"
            $worldTimeResult.ExternalUtcTime 
        } else { 
            Write-Verbose "No WorldTimeAPI UTC result, using first successful query as reference"
            $successfulTimeQueries[0].ExternalUtcTime 
        }
        
        # Identify outliers - sources that differ significantly from the reference
        $validSources = @()
        $outlierSources = @()
        
        foreach ($result in $successfulTimeQueries) {
            $diffSeconds = [math]::Abs(($result.ExternalUtcTime - $referenceTime).TotalSeconds)
            
            if ($diffSeconds -le $maxDiscrepancySeconds) {
                Write-Verbose "Source $($result.Source) is within acceptable range ($diffSeconds seconds from reference)"
                $validSources += $result
            } else {
                Write-Verbose "Source $($result.Source) is an outlier ($diffSeconds seconds from reference) - excluding"
                $outlierSources += $result
            }
        }
        
        # If no valid sources (all outliers), use the reference (original selection logic)
        if ($validSources.Count -eq 0) {
            Write-Warning "All time sources are outliers compared to reference. Using reference time."
            $validSources = @($worldTimeResult -or $successfulTimeQueries[0])
        }
        
        # Calculate average time from valid sources - avoid using Measure-Object with DateTime objects
        try {
            # Use proper datetime average calculation
            $totalTicks = 0
            foreach ($source in $validSources) {
                $totalTicks += $source.ExternalUtcTime.Ticks
            }
            $averageTicks = $totalTicks / $validSources.Count
            $averageTime = [DateTime]::new([long]$averageTicks)
        }
        catch {
            Write-Verbose "Error calculating average time: $_"
            # Fallback to reference time if average calculation fails
            $averageTime = $referenceTime
            Write-Verbose "Using reference time as fallback: $referenceTime"
        }
        
        # Calculate time difference from local time
        $deltaSeconds = [math]::Round(($averageTime - $localUtcNow).TotalSeconds)
        $absoluteDeltaSeconds = [math]::Abs($deltaSeconds)
        
        # Collect source names for reporting
        $sourceNames = $validSources | ForEach-Object { $_.Source }
        
        # When clock is skewed by more than 5 minutes, it's significant
        $clockSkewed = $absoluteDeltaSeconds -gt 300
        
        return [PSCustomObject]@{
            ExternalUtcTime = $averageTime
            LocalUtcTime = $localUtcNow
            DeltaSeconds = $deltaSeconds
            AbsoluteDeltaSeconds = $absoluteDeltaSeconds
            ClockSkewed = $clockSkewed
            Sources = $sourceNames
            ValidSourceCount = $validSources.Count
            OutlierSourceCount = $outlierSources.Count
            AllSourceCount = $successfulTimeQueries.Count
            Details = $successfulTimeQueries
            Success = $true
            ErrorCount = $errorCount
            LastError = $lastError
        }
    }
}

Export-ModuleMember -Function Get-ExternalTrustedTime 