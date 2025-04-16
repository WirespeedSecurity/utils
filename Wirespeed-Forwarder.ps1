# Wirespeed-Forwarder.ps1
# Minimum supported version: Windows Server 2016 with PowerShell 5.1

param (
    [string]$UpstreamUrl = "https://upstream-server",  # Upstream server URL parameter
    [string]$Install,                           # Install parameter to embed a custom URL (required for install)
    [switch]$Debug                              # Debug mode to send last 10 events individually with verbose output
)

# If no parameters are provided, run primary forwarding function (batch mode)
if ($PSBoundParameters.Count -eq 0) {
    $Debug = $false
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
        # Always overwrite the script file in the install directory
        New-Item -Path $installDir -ItemType Directory -Force | Out-Null  # Ensure directory exists
        $scriptContent = Get-Content -Path $PSCommandPath -Raw
        $updatedContent = $scriptContent -replace '\[string\]\$UpstreamUrl = "https://upstream-server"', "[string]`$UpstreamUrl = `"$Install`""
        Set-Content -Path $scriptPath -Value $updatedContent -Force
        Write-Log "Script overwritten with custom URL '$Install' at $scriptPath"
        
        # Configure WEC Server during install
        Write-Log "Configuring WEC server..."

        $winrmStatus = winrm qc /q 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to enable WinRM: $winrmStatus" "ERROR"
            throw "WinRM configuration failed. Ensure the WinRM service can start and ports 5985/5986 are available."
        }
        Write-Log "WinRM enabled."

        $wecStatus = wecutil qc /q 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to enable WEC service: $wecStatus" "ERROR"
            throw "WEC service configuration failed. Check if the Windows Event Collector service is installed and can start."
        }
        Write-Log "WEC service enabled."

        $group = "Event Log Readers"
        $account = "NT AUTHORITY\Network Service"
        $isMember = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $account }
        if (-not $isMember) {
            Add-LocalGroupMember -Group $group -Member $account -ErrorAction Stop
            Write-Log "Added $account to $group."
        } else {
            Write-Log "$account is already a member of $group."
        }

        $firewallRuleHttp = Get-NetFirewallRule -Name "WinRM HTTP for WEF" -ErrorAction SilentlyContinue
        if (-not $firewallRuleHttp) {
            New-NetFirewallRule -Name "WinRM HTTP for WEF" -DisplayName "WinRM HTTP for WEF" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -ErrorAction Stop
        }
        $firewallRuleHttps = Get-NetFirewallRule -Name "WinRM HTTPS for WEF" -ErrorAction SilentlyContinue
        if (-not $firewallRuleHttps) {
            New-NetFirewallRule -Name "WinRM HTTPS for WEF" -DisplayName "WinRM HTTPS for WEF" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow -ErrorAction Stop
        }
        Write-Log "Firewall ports 5985 (HTTP) and 5986 (HTTPS) opened."

        # Configure WEF to forward to itself
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "1" -Value "Server=http://localhost:5985/wsman/,Refresh=60" -Type String -Force
        Write-Log "Configured WEF to forward events to localhost."

        $subscriptionName = "Security and PowerShell Events"
        $subscription = wecutil es | Where-Object { $_ -eq $subscriptionName }
        if (-not $subscription) {
            $subscriptionXml = @"
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
    <SubscriptionId>$subscriptionName</SubscriptionId>
    <SubscriptionType>SourceInitiated</SubscriptionType>
    <Description>Collects security, PowerShell, system, and application events</Description>
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
                <Query Id="3" Path="System">
                    <Select Path="System">*</Select>
                </Query>
                <Query Id="4" Path="Application">
                    <Select Path="Application">*</Select>
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

        # Simulate events for ForwardedEvents during install
        if (-not (Test-Path "$installDir\test_events_generated.txt")) {
            Write-Log "Simulating initial events for ForwardedEvents..."
            $testUserName = "wef_test_$((New-Guid).Guid.Substring(0,8))"
            $randomPassword = (New-Guid).Guid  # Random GUID as password
            $password = ConvertTo-SecureString $randomPassword -AsPlainText -Force
            New-LocalUser -Name $testUserName -Password $password -FullName "WEF Test User" -Description "Test user for WEF simulation" -ErrorAction Stop
            Remove-LocalUser -Name $testUserName -ErrorAction Stop
            Write-EventLog -LogName "Windows PowerShell" -Source "PowerShell" -EventId 999 -EntryType Information -Message "Simulated PowerShell event for WEF testing during install." -ErrorAction Stop
            Start-Sleep -Seconds 5  # Wait for WEF to process
            Set-Content -Path "$installDir\test_events_generated.txt" -Value (Get-Date).ToString()
            Write-Log "Simulated events generated during install."
        }

        # Install scheduled task during install
        $taskName = "Wirespeed-Forwarder"
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($task) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            Write-Log "Existing scheduled task '$taskName' deleted."
        }
        
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Forwards WEC events to upstream server" -ErrorAction Stop
        Write-Log "Scheduled task '$taskName' created to run every minute as SYSTEM."
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
        Write-Log "Scheduled task '$taskName' started."
        
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
                    UseBasicParsing = $true  # Add this for error handling and parsing
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

# Main event forwarding (only if not installing)
if (-not $Install) {
    try {
        Write-Log "Starting event forwarding to $UpstreamUrl"

        if ($Debug) {
            # Simulate events in debug mode
            Write-Log "Simulating test events for ForwardedEvents in debug mode..."
            $testUserName = "wef_test_$((New-Guid).Guid.Substring(0,8))"
            $randomPassword = (New-Guid).Guid  # Random GUID as password
            $password = ConvertTo-SecureString $randomPassword -AsPlainText -Force
            New-LocalUser -Name $testUserName -Password $password -FullName "WEF Test User" -Description "Test user for WEF debug simulation" -ErrorAction Stop
            Remove-LocalUser -Name $testUserName -ErrorAction Stop
            Write-EventLog -LogName "Windows PowerShell" -Source "PowerShell" -EventId 999 -EntryType Information -Message "Simulated PowerShell event for WEF debug testing." -ErrorAction Stop
            Start-Sleep -Seconds 5  # Wait for WEF to process

            $events = Get-WinEvent -LogName "ForwardedEvents" -ErrorAction SilentlyContinue | 
                      Select-Object -First 10
            
            if ($events.Count -eq 0) {
                Write-Log "No events available in ForwardedEvents for debug mode after simulation." "WARNING"
                Write-Host "No events available in 'ForwardedEvents'."
                $response = Read-Host "Would you like to send the last 10 Security events instead to test connectivity? (Y/N)"
                if ($response -eq "Y" -or $response -eq "y") {
                    $events = Get-WinEvent -LogName "Security" -ErrorAction Stop | 
                              Select-Object -First 10
                    if ($events.Count -eq 0) {
                        Write-Log "No Security events available to send." "ERROR"
                        Write-Host "No Security events available to send. Exiting."
                        exit 1
                    }
                    Write-Log "User opted to send last 10 Security events for connectivity test."
                    Write-Host "Sending last 10 Security events instead."
                } else {
                    Write-Log "User declined to send Security events. Exiting debug mode."
                    Write-Host "Exiting debug mode."
                    exit 0
                }
            }

            foreach ($event in $events) {
                # Get event XML to extract property names
                $eventXml = [xml]$event.ToXml()
                $eventData = $eventXml.Event.EventData.Data

                # Map properties to their names and types
                $properties = @{}
                for ($i = 0; $i -lt $event.Properties.Count; $i++) {
                    # Check if $eventData exists, is not empty, and has an element at index $i
                    $propName = if ($eventData -and $eventData.Count -gt $i -and $null -ne $eventData[$i].Name) {
                        $eventData[$i].Name
                    } else {
                        Write-Log "Using fallback name 'Property$i' for event ID $($event.Id) due to missing or invalid EventData." "WARNING"
                        "Property$i"
                    }
                    $propValue = $event.Properties[$i].Value
                    $propType = if ($null -eq $propValue) { "Null" } else { $propValue.GetType().Name }
                    $properties[$propName] = [PSCustomObject]@{
                        Value = $propValue
                        Type = $propType
                    }
                }

                $jsonEvent = [PSCustomObject]@{
                    TimeCreated = $event.TimeCreated.ToString("o")
                    Id = $event.Id
                    ProviderName = $event.ProviderName
                    Message = $event.Message
                    Properties = $properties
                } | ConvertTo-Json -Compress -Depth 4

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
                    UseBasicParsing = $true  # Add this for error handling and parsing
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

        # Normal mode: Batch forwarding (default when no params)
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
            # Get event XML to extract property names
            $eventXml = [xml]$_.ToXml()
            $eventData = $eventXml.Event.EventData.Data

            # Map properties to their names and types
            $properties = @{}
            for ($i = 0; $i -lt $_.Properties.Count; $i++) {
                # Check if $eventData exists, is not empty, and has an element at index $i
                $propName = if ($eventData -and $eventData.Count -gt $i -and $null -ne $eventData[$i].Name) {
                    $eventData[$i].Name
                } else {
                    Write-Log "Using fallback name 'Property$i' for event ID $($_.Id) due to missing or invalid EventData." "WARNING"
                    "Property$i"
                }
                $propValue = $_.Properties[$i].Value
                $propType = if ($null -eq $propValue) { "Null" } else { $propValue.GetType().Name }
                $properties[$propName] = [PSCustomObject]@{
                    Value = $propValue
                    Type = $propType
                }
            }

            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated.ToString("o")
                Id = $_.Id
                ProviderName = $_.ProviderName
                Message = $_.Message
                Properties = $properties
            }
        } | ConvertTo-Json -Compress -Depth 4

        $params = @{
            Uri = $UpstreamUrl
            Method = "Post"
            Body = $jsonEvents
            ContentType = "application/json"
            ErrorAction = "Stop"
            UseBasicParsing = $true  # Add this for error handling and parsing
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
                    UseBasicParsing = $true  # Add this for error handling and parsing
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