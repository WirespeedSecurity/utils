# Wirespeed-ADSync.ps1
param (
    [switch]$Install,
    [string]$Url
)

# Define the default API URL at the top
$ApiUrl = "http://localhost/api/on-prem-sync"

# If install mode is specified, update the script with the new URL and schedule it
if ($Install) {
    # Ensure URL is provided when installing
    if (-not $Url) {
        Write-Host "Error: The -Url parameter is required when using -Install."
        exit 1
    }

    # Define paths
    $scriptPath = $PSCommandPath
    $newScriptPath = "$PSScriptRoot\Wirespeed-ADSync-Configured.ps1"

    # Read the original script content
    $scriptContent = Get-Content $scriptPath -Raw

    # Replace the API URL in the script
    $updatedContent = $scriptContent -replace '\$ApiUrl = "http://localhost/api/on-prem-sync"', "\$ApiUrl = `"$Url`""

    # Write the updated script to a new file
    Set-Content -Path $newScriptPath -Value $updatedContent -Force
    Write-Host "Updated script with API URL: $Url and saved as $newScriptPath"

    # Define the scheduled task details
    $taskName = "Wirespeed-ADSyncHourly"
    $taskDescription = "Hourly sync of AD computers and users to SaaS API"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration ([TimeSpan]::MaxValue)
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$newScriptPath`""
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    # Register the scheduled task
    try {
        Register-ScheduledTask -TaskName $taskName -Description $taskDescription -Trigger $trigger -Action $action -Settings $settings -Force -ErrorAction Stop
        Write-Host "Scheduled task '$taskName' created to run hourly starting now."
    } catch {
        Write-Host "Failed to create scheduled task. Error: $($_.Exception.Message)"
        exit 1
    }

    # Exit after installation
    exit 0
}

# Import the Active Directory module
Import-Module ActiveDirectory

# Function to get nested group memberships for an object (user or computer)
function Get-NestedGroupMemberships {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName
    )
    $groups = [System.Collections.Generic.HashSet[PSObject]]::new()
    
    # Get direct group memberships with both DN and Name
    $directGroups = Get-ADGroup -Filter "Members -eq '$DistinguishedName'" -Properties DistinguishedName, Name
    
    foreach ($group in $directGroups) {
        $groupInfo = [PSCustomObject]@{
            DistinguishedName = $group.DistinguishedName
            Name              = $group.Name
        }
        if ($groups.Add($groupInfo)) {
            # Recursively get nested groups
            $nestedGroups = Get-NestedGroupMemberships -DistinguishedName $group.DistinguishedName
            foreach ($nestedGroup in $nestedGroups) {
                $groups.Add($nestedGroup) | Out-Null
            }
        }
    }
    
    return $groups
}

# Collect all computers with standard metadata and nested group memberships
$computers = Get-ADComputer -Filter * -Properties Name, OperatingSystem, OperatingSystemVersion, LastLogonDate, whenCreated, whenChanged, DistinguishedName | 
    ForEach-Object {
        $nestedGroups = Get-NestedGroupMemberships -DistinguishedName $_.DistinguishedName
        [PSCustomObject]@{
            Name                  = $_.Name
            OperatingSystem       = $_.OperatingSystem
            OperatingSystemVersion= $_.OperatingSystemVersion
            LastLogonDate         = $_.LastLogonDate
            WhenCreated           = $_.whenCreated
            WhenChanged           = $_.whenChanged
            SID                   = $_.SID.Value
            GroupMemberships      = @($nestedGroups | Select-Object DistinguishedName, Name)
        }
    }

# Collect all users with all properties and nested group memberships
$users = Get-ADUser -Filter * -Properties * | 
    ForEach-Object {
        $nestedGroups = Get-NestedGroupMemberships -DistinguishedName $_.DistinguishedName
        
        # Expand Manager field to include DN, SamAccountName, and UPN
        $managerInfo = $null
        if ($_.Manager) {
            try {
                $manager = Get-ADUser -Identity $_.Manager -Properties SamAccountName, UserPrincipalName -ErrorAction Stop
                $managerInfo = [PSCustomObject]@{
                    DistinguishedName  = $manager.DistinguishedName
                    SamAccountName     = $manager.SamAccountName
                    UserPrincipalName  = $manager.UserPrincipalName
                }
            } catch {
                Write-Host "Warning: Could not retrieve manager details for $($_.SamAccountName). Error: $($_.Exception.Message)"
                $managerInfo = [PSCustomObject]@{
                    DistinguishedName  = $_.Manager
                    SamAccountName     = $null
                    UserPrincipalName  = $null
                }
            }
        }

        # Create user object with all properties
        [PSCustomObject]@{
            DistinguishedName     = $_.DistinguishedName
            Enabled               = $_.Enabled
            GivenName             = $_.GivenName
            Name                  = $_.Name
            ObjectClass           = $_.ObjectClass
            ObjectGUID            = $_.ObjectGUID
            SamAccountName        = $_.SamAccountName
            SID                   = $_.SID.Value
            Surname               = $_.Surname
            UserPrincipalName     = $_.UserPrincipalName
            CN                    = $_.CN
            DisplayName           = $_.DisplayName
            Initials              = $_.Initials
            Mail                  = $_.Mail
            TelephoneNumber       = $_.TelephoneNumber
            Mobile                = $_.Mobile
            HomePhone             = $_.HomePhone
            IpPhone               = $_.IpPhone
            Fax                   = $_.Fax
            Pager                 = $_.Pager
            OtherTelephone        = $_.OtherTelephone
            OtherMobile           = $_.OtherMobile
            OtherHomePhone        = $_.OtherHomePhone
            OtherIpPhone          = $_.OtherIpPhone
            OtherFax              = $_.OtherFax
            OtherPager            = $_.OtherPager
            Department            = $_.Department
            Title                 = $_.Title
            Company               = $_.Company
            Division              = $_.Division
            EmployeeID            = $_.EmployeeID
            EmployeeNumber        = $_.EmployeeNumber
            EmployeeType          = $_.EmployeeType
            Manager               = $managerInfo
            Office                = $_.Office
            StreetAddress         = $_.StreetAddress
            POBox                 = $_.POBox
            City                  = $_.City
            State                 = $_.State
            PostalCode            = $_.PostalCode
            Country               = $_.Country
            CountryCode           = $_.CountryCode
            c                     = $_.c
            AccountExpirationDate = $_.AccountExpirationDate
            LastLogonDate         = $_.LastLogonDate
            LastLogon             = $_.LastLogon
            LastLogonTimestamp    = $_.LastLogonTimestamp
            whenCreated           = $_.whenCreated
            whenChanged           = $_.whenChanged
            PasswordLastSet       = $_.PasswordLastSet
            PasswordNeverExpires  = $_.PasswordNeverExpires
            LockedOut             = $_.LockedOut
            AccountLockoutTime    = $_.AccountLockoutTime
            MemberOf              = $_.MemberOf
            UserAccountControl    = $_.UserAccountControl
            PrimaryGroupID        = $_.PrimaryGroupID
            BadLogonCount         = $_.BadLogonCount
            BadPwdCount           = $_.BadPwdCount
            LogonCount            = $_.LogonCount
            Description           = $_.Description
            Info                  = $_.Info
            ProfilePath           = $_.ProfilePath
            HomeDirectory         = $_.HomeDirectory
            HomeDrive             = $_.HomeDrive
            ScriptPath            = $_.ScriptPath
            ThumbnailPhoto        = $_.ThumbnailPhoto
            "msDS-UserPasswordExpiryTimeComputed" = $_."msDS-UserPasswordExpiryTimeComputed"
            GroupMemberships      = @($nestedGroups | Select-Object DistinguishedName, Name)
        }
    }

# Combine data into a single object and convert to JSON
$data = @{
    Computers = $computers
    Users     = $users
} | ConvertTo-Json -Depth 10

# Output JSON to console
Write-Host "Collected AD Data in JSON format:"
Write-Host $data

# Attempt to send data to the API endpoint
try {
    $response = Invoke-WebRequest -Uri $ApiUrl -Method Post -Body $data -ContentType "application/json" -UseBasicParsing -ErrorAction Stop
    Write-Host "Data successfully sent to $ApiUrl. Status: $($response.StatusCode)"
} catch {
    Write-Host "Failed to send data to $ApiUrl. Error: $($_.Exception.Message)"
}

