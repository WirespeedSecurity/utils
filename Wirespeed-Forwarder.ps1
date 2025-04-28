# Wirespeed-Forwarder.ps1
# Purpose: Forward Windows Event Log events to an upstream server with performance monitoring and reliability.
# Minimum supported version: Windows Server 2016 with PowerShell 5.1

param (
    [Parameter(Position=0)][string]$UpstreamUrl = "https://upstream-server", # Upstream server URL
    [Alias("i")][string]$Install,                                          # Install with custom URL
    [Alias("t")][switch]$Test,                                            # Test mode: send last 10 events individually
    [Alias("lt")][int]$loadtest = 0,                                       # Load test: generate fake events
    [Alias("h")][switch]$Help
)

$scriptVersion = "1.0.2"

if  (($PSBoundParameters.Count -eq 0) -and $UpstreamUrl -eq "https://upstream-server") {
    Write-Host ""
    Write-Host "-----------------------------------------------------------------"
    Write-Warning "Cannot forward events without a configured upstream URL."
    Write-Host "-----------------------------------------------------------------"
    Write-Host ""
    $Help = $True
}

# Display help guide if -Help or -h is provided
if ($Help) {
    Write-Host "Wirespeed-Forwarder.ps1 - Forward Windows Event Log events to an upstream server"
    Write-Host "Version: $scriptVersion"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\Wirespeed-Forwarder.ps1 [options] [<UpstreamUrl>]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Install, -i <url>      Install script with custom upstream URL"
    Write-Host "  -Test, -t               Send last 10 events individually with verbose output"
    Write-Host "  -loadtest, -lt <number> Generate <number> fake events for load testing"
    Write-Host "  <UpstreamUrl>           Optional URL for events (default: https://upstream-server)"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\Wirespeed-Forwarder.ps1                        # Forward events normally"
    Write-Host "  .\Wirespeed-Forwarder.ps1 -i https://server      # Install with custom URL"
    Write-Host "  .\Wirespeed-Forwarder.ps1 -d http://localhost:8080/ # Debug with custom URL"
    Write-Host "  .\Wirespeed-Forwarder.ps1 -lt 1024               # Load test with 1,024 fake events"
    exit 0
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
$logPath = Join-Path $installDir "forwarder.log"
$maxLogSize = 10MB
$stateFile = Join-Path $installDir "last_event_time.txt"
$lockFile = Join-Path $installDir "forwarder.lock"
$perfFile = Join-Path $installDir "perf.json"
$registrationStateFile = Join-Path $installDir "registration.txt"
$chunkSize = 500
$maxBatchSize = 50000
$credential = $null # Optional: Set to [PSCredential]

# Logging function with rotation
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
            if (Test-Path "$installDir\forwarder.log.bak") {
                Remove-Item -Path "$installDir\forwarder.log.bak" -Force
            }
            Rename-Item -Path $logPath -NewName "forwarder.log.bak" -Force
        }
    }
    Add-Content -Path $logPath -Value $logEntry -ErrorAction SilentlyContinue
}

# Generate fake events for -loadtest
function Generate-FakeEvents {
    param ([int]$Count)
    $startTime = (Get-Date).AddSeconds(-59)
    $eventTypes = @(
        # Security Event: Logon (ID 4624, ~10 KB)
        { param($index)
            $ticks = [math]::Round(($_ * 59 * 10000000) / $Count)
            $userId = 3000 + $index
            [PSCustomObject]@{
                TimeCreated = $startTime.AddTicks($ticks)
                Id = 4624
                ProviderName = "Microsoft-Windows-Security-Auditing"
                Message = "An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tSYSTEM\r\n\tAccount Domain:\t\tNT AUTHORITY\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Information:\r\n\tLogon Type:\t\t3\r\n\tRestricted Admin Mode:\t-\r\n\tVirtual Account:\t\tNo\r\n\tElevated Token:\t\tYes\r\n\r\nImpersonation Level:\t\tImpersonation\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\tS-1-5-80-1234567890-0987654321-1122334455-6677889900-$userId\r\n\tAccount Name:\t\tUser$userId\r\n\tAccount Domain:\t\tCORP\r\n\tLogon ID:\t\t0xB524F$userId\r\n\tLinked Logon ID:\t0x0\r\n\tNetwork Account Name:\t-\r\n\tNetwork Account Domain:\t-\r\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x4E8\r\n\tProcess Name:\t\tC:\\Windows\\System32\\svchost.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\tSERVER01\r\n\tSource Network Address:\t192.168.1.10\r\n\tSource Port:\t\t49312\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tKerberos\r\n\tAuthentication Package:\tKerberos\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0"
                Properties = @{
                    SubjectUserSid = @{ Value = "S-1-5-18"; Type = "String" }
                    SubjectUserName = @{ Value = "SYSTEM"; Type = "String" }
                    SubjectDomainName = @{ Value = "NT AUTHORITY"; Type = "String" }
                    SubjectLogonId = @{ Value = "0x3e7"; Type = "String" }
                    TargetUserSid = @{ Value = "S-1-5-80-1234567890-0987654321-1122334455-6677889900-$userId"; Type = "String" }
                    TargetUserName = @{ Value = "User$userId"; Type = "String" }
                    TargetDomainName = @{ Value = "CORP"; Type = "String" }
                    TargetLogonId = @{ Value = "0xb524f$userId"; Type = "String" }
                    LogonType = @{ Value = 3; Type = "Int32" }
                }
            }
        },
        # System Event: Service Install (ID 7045, ~15 KB)
        { param($index)
            $ticks = [math]::Round(($_ * 59 * 10000000) / $Count)
            $userId = 3000 + $index
            [PSCustomObject]@{
                TimeCreated = $startTime.AddTicks($ticks)
                Id = 7045
                ProviderName = "Service Control Manager"
                Message = "A service was installed in the system.\r\n\r\nService Name:  MyService$userId\r\nService File Name:  C:\\Program Files\\MyService\\MyService.exe /run\r\nService Type:  User mode service\r\nService Start Type:  Auto start\r\nService Account:  CORP\\ServiceAccount$userId\r\n\r\nAdditional Information:\r\n\tInstall Date:\t2025-04-27\r\n\tDescription:\tThis service monitors system performance and reports metrics.\r\n\tDependencies:\tRPCSS, EventLog\r\n\tService SID:\tS-1-5-80-1234567890-0987654321-1122334455-6677889900-$userId\r\n\tRequired Privileges:\tSeChangeNotifyPrivilege, SeImpersonatePrivilege\r\n\tConfiguration Source:\tRegistry (HKLM\\System\\CurrentControlSet\\Services)"
                Properties = @{
                    ServiceName = @{ Value = "MyService$userId"; Type = "String" }
                    ServiceFileName = @{ Value = "C:\\Program Files\\MyService\\MyService.exe /run"; Type = "String" }
                    ServiceType = @{ Value = "User mode service"; Type = "String" }
                    ServiceStartType = @{ Value = "Auto start"; Type = "String" }
                    ServiceAccount = @{ Value = "CORP\\ServiceAccount$userId"; Type = "String" }
                    ServiceSid = @{ Value = "S-1-5-80-1234567890-0987654321-1122334455-6677889900-$userId"; Type = "String" }
                }
            }
        },
        # Security Event: Password Change (ID 4724, ~8 KB)
        { param($index)
            $ticks = [math]::Round(($_ * 59 * 10000000) / $Count)
            $userId = 3000 + $index
            [PSCustomObject]@{
                TimeCreated = $startTime.AddTicks($ticks)
                Id = 4724
                ProviderName = "Microsoft-Windows-Security-Auditing"
                Message = "An attempt was made to reset an account's password.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tAdministrator\r\n\tAccount Domain:\t\tCORP\r\n\tLogon ID:\t\t0x3E7\r\n\r\nTarget Account:\r\n\tSecurity ID:\t\tS-1-5-80-1234567890-0987654321-1122334455-6677889900-$userId\r\n\tAccount Name:\t\tUser$userId\r\n\tAccount Domain:\t\tCORP"
                Properties = @{
                    SubjectUserSid = @{ Value = "S-1-5-18"; Type = "String" }
                    SubjectUserName = @{ Value = "Administrator"; Type = "String" }
                    SubjectDomainName = @{ Value = "CORP"; Type = "String" }
                    SubjectLogonId = @{ Value = "0x3e7"; Type = "String" }
                    TargetUserSid = @{ Value = "S-1-5-80-1234567890-0987654321-1122334455-6677889900-$userId"; Type = "String" }
                    TargetUserName = @{ Value = "User$userId"; Type = "String" }
                    TargetDomainName = @{ Value = "CORP"; Type = "String" }
                }
            }
        }
    )
    # Generate $Count fake events, randomly selecting event type
    0..($Count - 1) | ForEach-Object {
        $eventTypes[(Get-Random -Maximum $eventTypes.Count)].Invoke($_)
    }
}

# Generate and send a Registration event
function Generate-RegistrationEvent {
    $timestamp = (Get-Date).ToUniversalTime().ToString("o")
    $hostname = $env:COMPUTERNAME
    try {
        $adDomain = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop).Domain
    } catch {
        $adDomain = "N/A"
        Write-Log "Failed to retrieve AD domain: $($_.Exception.Message)" "WARNING"
    }
    try {
        $ipAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" } | Select-Object -First 1).IPAddress
        if (-not $ipAddress) { $ipAddress = "N/A" }
    } catch {
        $ipAddress = "N/A"
        Write-Log "Failed to retrieve IP address: $($_.Exception.Message)" "WARNING"
    }
    try {
        $cpu = (Get-WmiObject -Class Win32_Processor -ErrorAction Stop | Select-Object -First 1).Name
    } catch {
        $cpu = "N/A"
        Write-Log "Failed to retrieve CPU info: $($_.Exception.Message)" "WARNING"
    }
    try {
        $ramGB = [math]::Round((Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory / 1GB, 2)
    } catch {
        $ramGB = "N/A"
        Write-Log "Failed to retrieve RAM info: $($_.Exception.Message)" "WARNING"
    }
    try {
        $disks = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop
        $diskInfo = $disks | ForEach-Object {
            "$($_.DeviceID) $([math]::Round($_.Size / 1GB, 2))GB (Free: $([math]::Round($_.FreeSpace / 1GB, 2))GB)"
        } | Join-String -Separator ", "
        if (-not $diskInfo) { $diskInfo = "N/A" }
    } catch {
        $diskInfo = "N/A"
        Write-Log "Failed to retrieve disk info: $($_.Exception.Message)" "WARNING"
    }
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        $osName = $os.Caption
        $osBuild = $os.BuildNumber
        $osVersion = [System.Environment]::OSVersion.Version.ToString()
    } catch {
        $osName = "N/A"
        $osBuild = "N/A"
        $osVersion = "N/A"
        Write-Log "Failed to retrieve OS info: $($_.Exception.Message)" "WARNING"
    }
    try {
        $timeZone = (Get-TimeZone -ErrorAction Stop).Id
    } catch {
        $timeZone = "N/A"
        Write-Log "Failed to retrieve time zone: $($_.Exception.Message)" "WARNING"
    }
    try {
        $wecService = Get-Service -Name "Wecsvc" -ErrorAction Stop
        $wecStatus = if ($wecService.Status -eq "Running") { "Running" } else { "Not Running ($($wecService.Status))" }
    } catch {
        $wecStatus = "N/A"
        Write-Log "Failed to retrieve WEC service status: $($_.Exception.Message)" "WARNING"
    }
    try {
        $winrmService = Get-Service -Name "WinRM" -ErrorAction Stop
        $winrmStatus = if ($winrmService.Status -eq "Running") { "Running" } else { "Not Running ($($winrmService.Status))" }
    } catch {
        $winrmStatus = "N/A"
        Write-Log "Failed to retrieve WinRM service status: $($_.Exception.Message)" "WARNING"
    }
    try {
        $taskName = "Wirespeed-Forwarder"
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
        $taskHealthy = if ($task -and $task.State -eq "Ready") { "Healthy (Present, Enabled)" } else { "Unhealthy (Not present or disabled)" }
    } catch {
        $taskHealthy = "N/A"
        Write-Log "Failed to retrieve scheduled task status: $($_.Exception.Message)" "WARNING"
    }

    $registrationEvent = [PSCustomObject]@{
        Title = "Wirespeed Registration"
        Version = $scriptVersion
        Timestamp = $timestamp
        Hostname = $hostname
        ADDomain = $adDomain
        IPAddress = $ipAddress
        Hardware = [PSCustomObject]@{
            CPU = $cpu
            RAM_GB = $ramGB
            Disks = $diskInfo
        }
        OperatingSystem = [PSCustomObject]@{
            Name = $osName
            Build = $osBuild
            Version = $osVersion
        }
        TimeZone = $timeZone
        WECStatus = $wecStatus
        WinRMStatus = $winrmStatus
        ScheduledTaskStatus = $taskHealthy
    } | ConvertTo-Json -Compress -Depth 4

    try {
        $params = @{
            Uri = $UpstreamUrl
            Method = "Post"
            Body = $registrationEvent
            ContentType = "application/json"
            ErrorAction = "Stop"
            UseBasicParsing = $true
        }
        if ($credential) { $params["Credential"] = $credential }
        $response = Invoke-WebRequest @params
        Write-Log "Sent Registration event to ${UpstreamUrl}. Status: $($response.StatusCode)"
    } catch {
        Write-Log "Failed to send Registration event to ${UpstreamUrl}: $($_.Exception.Message)" "ERROR"
    }
}

# Self-install with custom URL
if ($Install) {
    try {
        New-Item -Path $installDir -ItemType Directory -Force | Out-Null
        $scriptContent = Get-Content -Path $PSCommandPath -Raw
        $updatedContent = $scriptContent -replace '\[Parameter\(Position=0\)\]\[string\]\$UpstreamUrl = "https://upstream-server"', "[Parameter(Position=0)][string]`$UpstreamUrl = `"$Install`""
        Set-Content -Path $scriptPath -Value $updatedContent -Force
        Write-Log "Script overwritten with custom URL '$Install' at $scriptPath"

        Write-Log "Configuring WEC server..."
        $winrmStatus = winrm qc /q 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to enable WinRM: $winrmStatus" "ERROR"
            throw "WinRM configuration failed."
        }
        Write-Log "WinRM enabled."

        Set-Service -Name wecsvc -StartupType Automatic
        Start-Service -Name wecsvc

        $wecStatus = wecutil qc /q 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to enable WEC service: $wecStatus" "ERROR"
            throw "WEC service configuration failed."
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

        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "1" -Value "Server=http://localhost:5985/wsman/,Refresh=60" -Type String -Force
        Write-Log "Configured WEF to forward events to localhost."

        $subscriptionName = "Security and PowerShell Events"
        wecutil ds $subscriptionName 2>&1
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
        <PushSettings>
            <Heartbeat Interval='60000'/>
        </PushSettings>
    </Delivery>
    <AllowedSourceDomainComputers>
        O:BAG:SYD:(A;;GA;;;WD)
    </AllowedSourceDomainComputers>
    <Query>
        <![CDATA[
            <QueryList>
                <Query Id="0">
                    <Select Path="Security">*</Select>
                    <Select Path="Microsoft-Windows-PowerShell/Operational">*</Select>
                    <Select Path="Windows PowerShell">*</Select>
                    <Select Path="System">*</Select>
                    <Select Path="Application">*</Select>
                </Query>
            </QueryList>
        ]]>
    </Query>
    <ReadExistingEvents>true</ReadExistingEvents>
    <TransportName>HTTP</TransportName>
    <ContentFormat>RenderedText</ContentFormat>
    <Locale Language="en-US"/>
    <LogFile>ForwardedEvents</LogFile>
</Subscription>
"@
        $tempFile = "$env:TEMP\wef_subscription.xml"
        Set-Content -Path $tempFile -Value $subscriptionXml -Force
        Write-Log "Creating subscription with XML at $tempFile"
        $wecutilOutput = wecutil cs $tempFile
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to create WEF subscription. Wecutil output: $wecutilOutput" "ERROR"
            throw "Subscription creation failed."
        }
        Remove-Item $tempFile
        Write-Log "WEF subscription '$subscriptionName' created."
        
        if (-not (Test-Path "$installDir\test_events_generated.txt")) {
            Write-Log "Simulating initial events for ForwardedEvents..."
            $testUserName = "wef_test_$((New-Guid).Guid.Substring(0,8))"
            $randomPassword = (New-Guid).Guid
            $password = ConvertTo-SecureString $randomPassword -AsPlainText -Force
            New-LocalUser -Name $testUserName -Password $password -FullName "WEF Test User" -Description "Test user for WEF simulation" -ErrorAction Stop
            Remove-LocalUser -Name $testUserName -ErrorAction Stop
            Write-EventLog -LogName "Windows PowerShell" -Source "PowerShell" -EventId 999 -EntryType Information -Message "Simulated PowerShell event for WEF testing during install." -ErrorAction Stop
            Start-Sleep -Seconds 5
            Set-Content -Path "$installDir\test_events_generated.txt" -Value (Get-Date).ToString()
            Write-Log "Simulated events generated during install."
        }

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
    } catch {
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
            Write-Log "Skipping error event POST due to default UpstreamUrl: ${UpstreamUrl}" "WARNING"
        } else {
            try {
                $params = @{
                    Uri = $UpstreamUrl
                    Method = "Post"
                    Body = $errorEvent
                    ContentType = "application/json"
                    ErrorAction = "Stop"
                    UseBasicParsing = $true
                }
                if ($credential) { $params["Credential"] = $credential }
                $response = Invoke-WebRequest @params
                Write-Log "Sent error event to ${UpstreamUrl}. Status: $($response.StatusCode)"
            } catch {
                Write-Log "Failed to send error event to ${UpstreamUrl}: $($_.Exception.Message)" "ERROR"
                Write-Error "Failed to send error event: $($_.Exception.Message)"
            }
        }
        exit 1
    }
}

# Main event forwarding
if (-not $Install) {
    try {
        Write-Log "Starting event forwarding to ${UpstreamUrl}"

        # Check for registration event (every 24 hours)
        $sendRegistration = $false
        $lastRegistration = if (Test-Path $registrationStateFile) {
            Get-Content $registrationStateFile | Get-Date -ErrorAction SilentlyContinue
        } else { $null }
        $currentTime = Get-Date
        if (-not $lastRegistration -or ($currentTime - $lastRegistration).TotalHours -ge 24) {
            $sendRegistration = $true
            $currentTime | Out-File $registrationStateFile -Force
        }
        if ($sendRegistration -and $UpstreamUrl -ne "https://upstream-server") {
            Generate-RegistrationEvent
        }

        # Test mode: Send last 10 events individually
        if ($Test) {
            Write-Log "Simulating test events for ForwardedEvents in debug mode..."
            $testUserName = "wef_test_$((New-Guid).Guid.Substring(0,8))"
            $randomPassword = (New-Guid).Guid
            $password = ConvertTo-SecureString $randomPassword -AsPlainText -Force
            New-LocalUser -Name $testUserName -Password $password -FullName "WEF Test User" -Description "Test user for WEF debug simulation" -ErrorAction Stop
            Remove-LocalUser -Name $testUserName -ErrorAction Stop
            Write-EventLog -LogName "Windows PowerShell" -Source "PowerShell" -EventId 999 -EntryType Information -Message "Simulated PowerShell event for WEF debug testing." -ErrorAction Stop
            Start-Sleep -Seconds 5

            $events = Get-WinEvent -LogName "ForwardedEvents" -ErrorAction SilentlyContinue | Select-Object -First 10
            if ($events.Count -eq 0) {
                Write-Log "No events available in ForwardedEvents for debug mode." "WARNING"
                Write-Host "No events available in 'ForwardedEvents'."
                $response = Read-Host "Would you like to send the last 10 Security events instead to test connectivity? (Y/N)"
                if ($response -eq "Y" -or $response -eq "y") {
                    $events = Get-WinEvent -LogName "Security" -ErrorAction Stop | Select-Object -First 10
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
                $eventXml = [xml]$event.ToXml()
                $eventData = $eventXml.Event.EventData.Data
                $properties = @{}
                for ($i = 0; $i -lt $event.Properties.Count; $i++) {
                    $propName = if ($eventData -and $eventData.Count -gt $i -and $null -ne $eventData[$i].Name) {
                        $eventData[$i].Name
                    } else {
                        Write-Log "Using fallback name 'Property$i' for event ID $($event.Id)." "WARNING"
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

                Write-Host "Sending event ID $($event.Id) to ${UpstreamUrl}"
                Write-Host "JSON Payload: $jsonEvent"
                Write-Host "HTTP/S Connection Details:"
                $params = @{
                    Uri = $UpstreamUrl
                    Method = "Post"
                    Body = $jsonEvent
                    ContentType = "application/json"
                    ErrorAction = "Stop"
                    Verbose = $true
                    UseBasicParsing = $true
                }
                if ($credential) { $params["Credential"] = $credential }
                try {
                    $response = Invoke-WebRequest @params
                    Write-Host "Status Code: $($response.StatusCode)"
                    Write-Host "Response Headers: $($response.Headers | Out-String)"
                    Write-Host "Response Content: $($response.Content)"
                    Write-Log "Debug: Sent event ID $($event.Id) successfully. Status: $($response.StatusCode)"
                } catch {
                    Write-Host "Error: $($_.Exception.Message)"
                    Write-Log "Debug: Failed to send event ID $($event.Id): $($_.Exception.Message)" "ERROR"
                }
                Write-Host "--------------------------------"
            }
            exit 0
        }

        # Normal or load test mode
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $postTimes = @()

        # Handle lock file with 10-second retry
        $waitTime = 0
        $lockWait = 0
        while (Test-Path $lockFile) {
            while ($waitTime -lt 10) {
                $fileAge = (Get-Date) - (Get-Item $lockFile).LastWriteTime
                if ($fileAge.TotalMinutes -gt 5) {
                    Remove-Item $lockFile -Force
                    Write-Log "Removed stale lock file older than 5 minutes." "WARNING"
                    break
                }
                Start-Sleep -Seconds 2
                $waitTime += 2
                $lockWait = $waitTime
            }
        }
        if (Test-Path $lockFile) {
            Write-Log "Lock file still present after 10 seconds. Exiting." "ERROR"
            exit
        }
        New-Item $lockFile -ItemType File | Out-Null

        # Load performance data as ArrayList
        $perfData = New-Object System.Collections.ArrayList
        if (Test-Path $perfFile) {
            try {
                $jsonContent = Get-Content $perfFile -Raw
                if (-not $jsonContent.Trim()) {
                    Write-Log "perfFile is empty. Initializing empty ArrayList." "WARNING"
                    New-Object System.Collections.ArrayList
                } else {
                    $jsonData = $jsonContent | ConvertFrom-Json -ErrorAction Stop
                    if ($jsonData) {
                        $items = if ($jsonData -is [System.Array]) { $jsonData } else { @($jsonData) }
                        foreach ($item in $items) {
                            $null = $perfData.Add($item)
                        }
                    }
                }
            } catch {
                Write-Log "Failed to parse $($perfFile): $($_.Exception)." "ERROR"
            }
        } else {
            Write-Log "No perfFile found at $($perfFile). Initialized empty ArrayList." "DEBUG"
        }
        $avgRuntime = if ($perfData.Count -gt 0) { [math]::Round(($perfData | Measure-Object -Property RuntimeSeconds -Average).Average, 2) } else { 0 }

        # Get system information
        $hostname = [System.Net.Dns]::GetHostName()
        $adDomain = (Get-CimInstance Win32_ComputerSystem).Domain
        $ipAddress = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Ethernet" -ErrorAction SilentlyContinue).IPAddress
        $timeZone = [System.TimeZoneInfo]::Local.Id

        # Read last processed timestamp
        $lastTime = if (Test-Path $stateFile) { [datetime]::Parse((Get-Content $stateFile)) } else { (Get-Date).AddHours(-72) }

        # Count batch size without ingesting
        $batchSize = if ($loadtest) { $loadtest } else {
            (Get-WinEvent -FilterHashtable @{ LogName = "ForwardedEvents"; StartTime = $lastTime } -MaxEvents 1 -ErrorAction SilentlyContinue | Measure-Object).Count
        }

        # Check for zero events in normal mode
        if (-not $loadtest -and $batchSize -eq 0) {
            Write-Log "No events available in ForwardedEvents to forward." "WARNING"
            if (Test-Path $lockFile) { Remove-Item $lockFile -Force }
            exit 0
        }

        if ($batchSize -gt $maxBatchSize) {
            Write-Log "Batch size exceeds $maxBatchSize events. Truncating." "WARNING"
            $batchSize = $maxBatchSize
        }

        # Retrieve events
        $events = if ($loadtest) {
            Write-Log "Generating $loadtest fake events for load test." "INFO"
            Generate-FakeEvents -Count $loadtest
        } else {
            Get-WinEvent -FilterHashtable @{ LogName = "ForwardedEvents"; StartTime = $lastTime } -MaxEvents $batchSize -ErrorAction SilentlyContinue | Sort-Object TimeCreated
        }

        if ($events.Count -eq 0) {
            Write-Log "No new events to forward." "INFO"
            if ($loadtest) { Write-Output ($wirespeed | ConvertTo-Json -Depth 4) }
            exit 0
        }

        # Process events in chunks
        $chunkIndex = 0
        $partialEvents = New-Object System.Collections.ArrayList
        foreach ($event in $events) {
            if ($stopwatch.Elapsed.TotalSeconds -gt 54) {
                Write-Log "Reached 54-second timeout. Spilling remaining events to next cycle." "INFO"
                break
            }
            if ($null -eq $event) {
                Write-Log "Encountered null event. Skipping." "WARNING"
                continue
            }
            try {
                $null = $partialEvents.Add($event)
            } catch {
                Write-Log "Failed to append event ID: $($event.Id) - Error: $($_.Exception.Message)" "ERROR"
                continue
            }
            if ($partialEvents.Count -ge $chunkSize -or $event -eq $events[-1]) {
                $partialEventsArray = @($partialEvents)
                $cpu = (Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name = '_Total'").PercentProcessorTime
                $mem = Get-CimInstance Win32_OperatingSystem
                $memoryUtilization = [math]::Round((($mem.TotalVisibleMemorySize - $mem.FreePhysicalMemory) / $mem.TotalVisibleMemorySize) * 100, 2)
                $collectedAt = (Get-Date).ToUniversalTime()
                $ingestionDelay = [math]::Round(($collectedAt - $lastTime).TotalSeconds, 2)

                $wirespeed = [PSCustomObject]@{
                    Version = $scriptVersion
                    Hostname = $hostname
                    Domain = $adDomain
                    IPAddress = $ipAddress
                    TimeZone = $timeZone
                    Batch = [PSCustomObject]@{
                        BeginningAt = $lastTime.ToString("o")
                        CollectedAt = $collectedAt.ToString("o")
                        IngestionDelay = $ingestionDelay
                        LockFileWait = $lockWait
                        Size = $batchSize
                        Index = $chunkIndex
                        Count = $partialEventsArray.Count
                        Stopwatch = [math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
                        EventsPerSecond = [math]::Round($partialEventsArray.Count / $stopwatch.Elapsed.TotalSeconds, 2)
                        AvgServerResponse = [math]::Round(($postTimes | Measure-Object -Average).Average, 3)
                        AvgRuntime = $avgRuntime
                        CPU = $cpu
                        Memory = [PSCustomObject]@{
                            Utilization = $memoryUtilization
                            Total = $mem.TotalVisibleMemorySize * 1024
                            Free = $mem.FreePhysicalMemory * 1024
                        }
                    }
                }

                $payload = [PSCustomObject]@{ Wirespeed = $wirespeed; Events = $partialEventsArray }
                $json = $payload | ConvertTo-Json -Compress -Depth 4
                if ($json.Length -gt 10485760) {
                    Write-Log "Payload exceeds 10 MB, reducing chunk size." "WARNING"
                    $chunkSize = [math]::Floor($chunkSize * 0.8)
                    $partialEvents.Clear()
                    continue
                }

                $retryDelays = @(0, 2, 8)
                $success = $false
                foreach ($delay in $retryDelays) {
                    if ($stopwatch.Elapsed.TotalSeconds -gt 54) {
                        Write-Log "Exceeded 54-second timeout during retries. Quitting." "WARNING"
                        break
                    }
                    try {
                        $postStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                        $response = Invoke-WebRequest -Uri $UpstreamUrl -Method Post -Body $json -ContentType "application/json" -ErrorAction Stop -UseBasicParsing
                        $postTimes += $postStopwatch.Elapsed.TotalSeconds
                        $success = $true
                        if (-not $loadtest) {
                            $partialEventsArray[-1].TimeCreated | Out-File $stateFile
                        }
                        break
                    } catch {
                        Write-Log "POST failed: $($_.Exception.Message). Retrying after $delay seconds." "WARNING"
                        Start-Sleep -Seconds $delay
                    }
                }
                if (-not $success) {
                    Write-Log "All retries failed. Skipping chunk." "ERROR"
                    $partialEvents.Clear()
                    continue
                }

                $partialEvents.Clear()
                [System.GC]::Collect()
                $chunkIndex += $partialEventsArray.Count
            }
        }

        # Update performance data
        $newEntry = [PSCustomObject]@{
            Timestamp = (Get-Date).ToUniversalTime().ToString("o")
            BatchSize = $batchSize
            ProcessingTimeSeconds = $stopwatch.Elapsed.TotalSeconds
            RuntimeSeconds = $stopwatch.Elapsed.TotalSeconds
            EventsPerSecond = [math]::Round($batchSize / $stopwatch.Elapsed.TotalSeconds, 2)
            AvgServerResponse = [math]::Round(($postTimes | Measure-Object -Average).Average, 3)
            AvgRuntime = $avgRuntime
        }
        if ($perfData -isnot [System.Collections.ArrayList]) {
            Write-Log "perfData is not an ArrayList (Type: $($perfData.GetType().FullName)). Reinitializing." "ERROR"
            $perfData = New-Object System.Collections.ArrayList
        }
        $perfData.Add([PSCustomObject]@{
            Timestamp = (Get-Date).ToUniversalTime().ToString("o")
            BatchSize = $batchSize
            ProcessingTimeSeconds = $stopwatch.Elapsed.TotalSeconds
            RuntimeSeconds = $stopwatch.Elapsed.TotalSeconds
            EventsPerSecond = [math]::Round($batchSize / $stopwatch.Elapsed.TotalSeconds, 2)
            AvgServerResponse = [math]::Round(($postTimes | Measure-Object -Average).Average, 3)
            AvgRuntime = $avgRuntime
        })
        # Trim to last 30 entries, keeping as ArrayList
        $trimmedList = New-Object System.Collections.ArrayList
        $lastEntries = if ($perfData.Count -gt 30) { $perfData.GetRange($perfData.Count - 30, 30) } else { $perfData }
        foreach ($entry in $lastEntries) {
            $trimmedList.Add($entry)
        }
        $perfData = $trimmedList
        # Ensure perfData is saved as a JSON array
        $perfDataJson = @($perfData) | ConvertTo-Json -Depth 4
        $perfDataJson | Set-Content $perfFile

        if ($loadtest) {
            Write-Output ($wirespeed | ConvertTo-Json -Depth 4)
        }
    } catch {
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
            Write-Log "Skipping error event POST due to default UpstreamUrl: ${UpstreamUrl}" "WARNING"
        } else {
            try {
                $params = @{
                    Uri = $UpstreamUrl
                    Method = "Post"
                    Body = $errorEvent
                    ContentType = "application/json"
                    ErrorAction = "Stop"
                    UseBasicParsing = $true
                }
                if ($credential) { $params["Credential"] = $credential }
                $response = Invoke-WebRequest @params
                Write-Log "Sent error event to ${UpstreamUrl}. Status: $($response.StatusCode)"
            } catch {
                Write-Log "Failed to send error event to ${UpstreamUrl}: $($_.Exception.Message)" "ERROR"
                Write-Error "Failed to send error event: $($_.Exception.Message)"
            }
        }
        exit 1
    } finally {
        if (Test-Path $lockFile) { Remove-Item $lockFile -Force }
        $stopwatch.Stop()
    }
}

Write-Log "Event forwarding cycle completed."