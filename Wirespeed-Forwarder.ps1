# Wirespeed-Forwarder.ps1
# Minimum supported version: Windows Server 2016 with PowerShell 5.1

param (
    [string]$UpstreamUrl = "https://upstream-server",  # Upstream server URL parameter
    [string]$Install,                           # Install parameter to embed a custom URL (required for install)
    [switch]$DebugMode                          # Debug mode to send last 10 events individually with verbose output
)

# If no parameters are provided, enable DebugMode
if ($PSBoundParameters.Count -eq 0) {
    $DebugMode = $true
}

# Check for admin privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as an administrator. Exiting."
    exit 1
}

# Define paths and variables
$installDir = "$env:ProgramFiles\Wirespeed"
$scriptName = "Wirespeed-Forwarder.ps1"
$scriptPath = Join-Path $installDir $scriptName
$logPath = Join-Path $installDir "wirespeed-forwarder.log"
$maxLogSize = 10MB  # Max log size before rotation
$batchSize = 100    # Configurable batch size for event forwarding

# Logging function with rotation (limited to 1 .bak file)
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    if (Test-Path $logPath) {
        $logSize = (Get-Item $logPath).Length
        if ($logSize -ge $maxLogSize) {
            if (Test-Path "$installDir\wirespeed-forwarder.log.bak") {
                Remove-Item -Path "$installDir\wirespeed-forwarder.log.bak" -Force
            }
            Rename-Item -Path $logPath -NewName "wirespeed-forwarder.log.bak" -Force
        }
    }
    Add-Content -Path $logPath -Value $logEntry -ErrorAction SilentlyContinue
}

# Self-install only if -Install is provided
if ($Install) {
    try {
        if (-not (Test-Path $installDir)) {
            New-Item -Path $installDir -ItemType Directory -Force
        }
        $scriptContent = Get-Content -Path $PSCommandPath -Raw
        $updatedContent = $scriptContent -replace '\[string\]\$UpstreamUrl = "https://upstream-server"', "[string]`$UpstreamUrl = `"$Install`""
        Set-Content -Path $scriptPath -Value $updatedContent -Force
        Write-Log "Script updated with custom URL '$Install' and installed to $scriptPath"
        
        # Configure WEC Server during install
        Write-Log "Configuring WEC server..."

        $winrmStatus = winrm qc /q 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to enable WinRM: $winrmStatus" "ERROR"
            throw "WinRM configuration failed. Ensure the WinRM service can start and port 5985 is available."
        }
        Write-Log "WinRM enabled."

        $wecStatus = wecutil qc /q 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to enable WEC service: $wecStatus" "ERROR"
            throw "WEC service configuration failed. Check if the Windows Event Collector service is installed and can start."
        }
        Write-Log "WEC service enabled."

        # Replace net localgroup with PowerShell cmdlets
        $group = "Event Log Readers"
        $account = "NT AUTHORITY\Network Service"
        $isMember = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $account }
        if (-not $isMember) {
            Add-LocalGroupMember -Group $group -Member $account -ErrorAction Stop
            Write-Log "Added $account to $group."
        } else {
            Write-Log "$account is already a member of $group."
        }

        $firewallRule = Get-NetFirewallRule -Name "WinRM HTTP for WEF" -ErrorAction SilentlyContinue
        if (-not $firewallRule) {
            New-NetFirewallRule -Name "WinRM HTTP for WEF" -DisplayName "WinRM HTTP for WEF" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -ErrorAction Stop
        }
        Write-Log "Firewall port 5985 opened."

        $subscriptionName = "Security and PowerShell Events"
        $subscription = wecutil es | Where-Object { $_ -eq $subscriptionName }
        if (-not $subscription) {
            $subscriptionXml = @"
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
    <SubscriptionId>$subscriptionName</SubscriptionId>
    <SubscriptionType>SourceInitiated</SubscriptionType>
    <Description>Collects security and PowerShell events</Description>
    <Enabled>true</Enabled>
    <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
    <ConfigurationMode>Custom</ConfigurationMode>
    <Delivery Mode="Push">
        <Batching>
            <MaxLatencyTime>60000</MaxLatencyTime>
        </Batching>
    </Delivery>
    <Query>
        <![CDATA[
            <QueryList>
                <Query Id="0" Path="Security">
                    <Select Path="Security">*</Select>
                </Query>
                <Query Id="1" Path="Microsoft-Windows-PowerShell/Operational">
                    <Select Path="Microsoft-Windows-PowerShell/Operational">*</Select>
                </Query>
                <Query Id="2" Path="Windows PowerShell">
                    <Select Path="Windows PowerShell">*</Select>
                </Query>
            </QueryList>
        ]]>
    </Query>
    <ReadExistingEvents>false</ReadExistingEvents>
    <TransportName>HTTP</TransportName>
    <ContentFormat>RenderedText</ContentFormat>
    <Locale Language="en-US"/>
    <LogFile>ForwardedEvents</LogFile>
</Subscription>
"@
            $tempFile = "$env:TEMP\wef_subscription.xml"
            Set-Content -Path $tempFile -Value $subscriptionXml -Force
            Write-Log "Creating subscription with XML at $tempFile"
            $wecutilOutput = wecutil cs $tempFile 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Log "Failed to create WEF subscription. Wecutil output: $wecutilOutput" "ERROR"
                throw "Subscription creation failed. Ensure wecutil is available and the XML is valid. Output: $wecutilOutput"
            }
            Remove-Item $tempFile
            Write-Log "WEF subscription '$subscriptionName' created."
        }

        # Install scheduled task during install
        $taskName = "Wirespeed-Forwarder"
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if (-not $task) {
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -UpstreamUrl `"$Install`""
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description "Forwards WEC events to upstream server" -RunLevel Highest -ErrorAction Stop
            Write-Log "Scheduled task '$taskName' created to run every minute."
            Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
            Write-Log "Scheduled task '$taskName' started."
        }
        Write-Log "Installation completed successfully."
        exit 0
    }
    catch {
        $errorEvent = [PSCustomObject]@{
            Title = "WIRESPEED ERROR"
            Timestamp = (Get-Date).ToUniversalTime().ToString("o")
            Hostname = $env:COMPUTERNAME
            Message = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
        } | ConvertTo-Json -Compress
        
        Write-Log "Error: $($_.Exception.Message) - Stack: $($_.ScriptStackTrace)" "ERROR"
        Write-Error "WIRESPEED ERROR: $($_.Exception.Message)`nStack Trace: $($_.ScriptStackTrace)"
        
        if ($UpstreamUrl -eq "https://upstream-server") {
            Write-Log "Skipping error event POST due to default UpstreamUrl: $UpstreamUrl" "WARNING"
        } else {
            try {
                $params = @{
                    Uri = $UpstreamUrl
                    Method = "Post"
                    Body = $errorEvent
                    ContentType = "application/json"
                    ErrorAction = "Stop"
                }
                if ($credential) {
                    $params["Credential"] = $credential
                }
                $response = Invoke-WebRequest @params
                Write-Log "Sent error event to ${UpstreamUrl}. Status: $($response.StatusCode)"
            }
            catch {
                Write-Log "Failed to send error event to ${UpstreamUrl}: $($_.Exception.Message)" "ERROR"
                Write-Error "Failed to send error event: $($_.Exception.Message)"
            }
        }
        exit 1
    }
}

# Configuration
$credential = $null  # Optional: Set to [PSCredential], e.g., New-Object PSCredential("username", (ConvertTo-SecureString "password" -AsPlainText -Force))

# Generate robust test events using PowerShell cmdlets (run once after subscription setup, only if not installing)
if (-not $Install -and -not (Test-Path "$installDir\test_events_generated.txt")) {
    try {
        Write-Log "Generating test events..."
        $testUserName = "wirespeed_testuser_$((New-Guid).Guid.Substring(0,8))"
        $password = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
        New-LocalUser -Name $testUserName -Password $password -FullName "Wirespeed Test User" -Description "Temporary user for Wirespeed testing" -ErrorAction Stop
        Remove-LocalUser -Name $testUserName -ErrorAction Stop
        IEX "Write-Host 'Test script block for Wirespeed'"
        Set-Content -Path "$installDir\test_events_generated.txt" -Value (Get-Date).ToString()
        Write-Log "Test events generated."
    }
    catch {
        Write-Log "Failed to generate test events: $($_.Exception.Message)" "WARNING"
    }
}

# Main event forwarding (only if not installing)
if (-not $Install) {
    try {
        Write-Log "Starting event forwarding to $UpstreamUrl"

        if ($DebugMode) {
            $events = Get-WinEvent -LogName "ForwardedEvents" -ErrorAction SilentlyContinue | 
                      Select-Object -First 10
            
            if ($events.Count -eq 0) {
                Write-Log "No events available for debug mode." "WARNING"
                Write-Host "No events available in 'ForwardedEvents' for debug mode."
                exit 0
            }

            foreach ($event in $events) {
                $jsonEvent = [PSCustomObject]@{
                    TimeCreated = $event.TimeCreated.ToString("o")
                    Id = $event.Id
                    ProviderName = $event.ProviderName
                    Message = $event.Message
                    Properties = $event.Properties | ForEach-Object { $_.Value }
                } | ConvertTo-Json -Compress

                Write-Host "Sending event ID $($event.Id) to $UpstreamUrl"
                Write-Host "JSON Payload: $jsonEvent"
                Write-Host "HTTP/S Connection Details:"

                $params = @{
                    Uri = $UpstreamUrl
                    Method = "Post"
                    Body = $jsonEvent
                    ContentType = "application/json"
                    ErrorAction = "Stop"
                    Verbose = $true
                }
                if ($credential) {
                    $params["Credential"] = $credential
                }

                try {
                    $response = Invoke-WebRequest @params
                    Write-Host "Status Code: $($response.StatusCode)"
                    Write-Host "Response Headers: $($response.Headers | Out-String)"
                    Write-Host "Response Content: $($response.Content)"
                    Write-Log "Debug: Sent event ID $($event.Id) successfully. Status: $($response.StatusCode)"
                }
                catch {
                    Write-Host "Error: $($_.Exception.Message)"
                    Write-Log "Debug: Failed to send event ID $($event.Id): $($_.Exception.Message)" "ERROR"
                }
                Write-Host "--------------------------------"
            }
            exit 0
        }

        # Normal mode: Batch forwarding
        $stateFile = Join-Path $installDir "last_event_time.txt"
        $lastTime = if (Test-Path $stateFile) { Get-Content $stateFile | Get-Date -ErrorAction SilentlyContinue } else { (Get-Date).AddHours(-72) }
        
        $events = Get-WinEvent -LogName "ForwardedEvents" -ErrorAction SilentlyContinue | 
                  Where-Object { $_.TimeCreated -gt $lastTime } | 
                  Select-Object -First $batchSize
        
        if ($events.Count -eq 0) {
            Write-Log "No new events to forward."
            exit 0
        }

        $jsonEvents = $events | ForEach-Object {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated.ToString("o")
                Id = $_.Id
                ProviderName = $_.ProviderName
                Message = $_.Message
                Properties = $_.Properties | ForEach-Object { $_.Value }
            }
        } | ConvertTo-Json -Compress

        $params = @{
            Uri = $UpstreamUrl
            Method = "Post"
            Body = $jsonEvents
            ContentType = "application/json"
            ErrorAction = "Stop"
        }
        if ($credential) {
            $params["Credential"] = $credential
        }
        $response = Invoke-WebRequest @params
        
        Write-Log "Sent $($events.Count) events to $UpstreamUrl. Status: $($response.StatusCode)"
        $events[-1].TimeCreated | Out-File $stateFile
    }
    catch {
        $errorEvent = [PSCustomObject]@{
            Title = "WIRESPEED ERROR"
            Timestamp = (Get-Date).ToUniversalTime().ToString("o")
            Hostname = $env:COMPUTERNAME
            Message = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
        } | ConvertTo-Json -Compress
        
        Write-Log "Error: $($_.Exception.Message) - Stack: $($_.ScriptStackTrace)" "ERROR"
        Write-Error "WIRESPEED ERROR: $($_.Exception.Message)`nStack Trace: $($_.ScriptStackTrace)"
        
        if ($UpstreamUrl -eq "https://upstream-server") {
            Write-Log "Skipping error event POST due to default UpstreamUrl: $UpstreamUrl" "WARNING"
        } else {
            try {
                $params = @{
                    Uri = $UpstreamUrl
                    Method = "Post"
                    Body = $errorEvent
                    ContentType = "application/json"
                    ErrorAction = "Stop"
                }
                if ($credential) {
                    $params["Credential"] = $credential
                }
                $response = Invoke-WebRequest @params
                Write-Log "Sent error event to ${UpstreamUrl}. Status: $($response.StatusCode)"
            }
            catch {
                Write-Log "Failed to send error event to ${UpstreamUrl}: $($_.Exception.Message)" "ERROR"
                Write-Error "Failed to send error event: $($_.Exception.Message)"
            }
        }
        exit 1
    }
}

Write-Log "Event forwarding cycle completed."