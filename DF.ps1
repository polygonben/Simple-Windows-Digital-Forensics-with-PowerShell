$ErrorActionPreference = "SilentlyContinue"

$cwd = Get-Location
New-Item -Path "$cwd\DF_Findings" -ItemType Directory -Force | Out-Null
Write-Host "Findings folder created: $cwd\DF_Findings`n"

function Get-AllUsers {
    mkdir -Path "$cwd\DF_Findings\Users" -Force | Out-Null
    $userList = "$cwd\DF_Findings\Users\localUserList.txt" 
    $users = Get-LocalUser | Where-Object {$_.Enabled -eq $true} | Select Name, FullName, SID, PasswordLastSet | Format-Table | Out-File -FilePath $userList -Force
    Write-Host "User list created: $userList `n"
    Get-LocalUser | Where-Object {$_.Enabled -eq $true} | ForEach-Object {
        Get-UserPSHistory -username $_.Name
        Get-Persistence-StartupFolder -username $_.Name
        Get-JumpList -username $_.Name
    }

}

function Get-UserPSHistory {
    param (
        $username
    )
    mkdir -Path "$cwd\DF_Findings\Users\$username" -Force | Out-Null
    $PSHistoryPath = "$cwd\DF_Findings\Users\$username\PSHistory.txt"
    Copy-Item "C:\Users\$username\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt" -Destination $PSHistoryPath -Force
    Write-Host "Powershell history file for $username created: $PSHistoryPath `n"
    
}

function Get-NetworkInformation {
     mkdir -Path "$cwd\DF_Findings\Network" -Force | Out-Null

     $NetIPAddress = "$cwd\DF_Findings\Network\NetIPAddress.txt"
     Get-NetIPAddress | Format-Table | Out-File -FilePath $NetIPAddress -Force
     Write-Host "IP interface file created: $NetIPAddress`n" 

     $GetAllEstablishedInternetComms = "$cwd\DF_Findings\Network\EstablishedTCPConnections.txt"
     Get-NetTCPConnection -State Established | Out-File -Force -FilePath $GetAllEstablishedInternetComms
     Write-Host "Established TCP connections file created: $GetAllEstablishedInternetComms`n"

     $LocalDNSCache = "$cwd\DF_Findings\Network\DnsClientCache.txt"
     Get-DnsClientCache | Format-Table | Out-File -FilePath $LocalDNSCache
     Write-Host "Local DNS cache file created: $LocalDNSCache `n" 

     $hostsFile = "$cwd\DF_Findings\Network\hosts.txt"
     Copy-Item "c:\Windows\System32\Drivers\etc\hosts" -Destination $hostsFile -Force
     Write-Host "Windows local hosts file copied to: $hostsFile`n"

}

function Get-ProccessInfo {
    $ProcessInfo = "$cwd\DF_Findings\Processes.txt"
    Get-WmiObject Win32_Process | Select Name, ParentProcessId, ProcessId, ExecutablePath | Out-File -FilePath $ProcessInfo -Force
    Write-Host "Current running processes file created: $ProcessInfo`n"
}

function Get-Persistence {
    mkdir -Path "$cwd\DF_Findings\Persistence" -Force | Out-Null
    
    $AutoServices = "$cwd\DF_Findings\Persistence\Auto_Services.txt"
    Get-WmiObject win32_service | Select Name, PathName, StartMode | Where-Object {$_.StartMode -eq 'Auto'} | Out-File -FilePath $AutoServices -Force
    Write-Host "Automatic running services file created: $AutoServices`n"

    $LOCALRunRegistryPath = "$cwd\DF_Findings\Persistence\LOCAL_RunRegistry.txt"
    $LOCAL_RunRegistry = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run | Out-File -FilePath $LOCALRunRegistryPath -Force
    Write-Host "HKEY_LOCAL_MACHINE Run registry entries created: $LOCALRunRegistryPath `n"

    $CurrentUserRunRegistryPath = "$cwd\DF_Findings\Persistence\CurrentUser_RunRegistry.txt"
    $CurrentUser_RunRegistry = Get-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run | Out-File -FilePath $CurrentUserRunRegistryPath -Force
    Write-Host "HKEY_CURRENT_USER Run registry entries created: $CurrentUserRunRegistryPath `n"

    $ScheduledTasks = "$cwd\DF_Findings\Persistence\ScheduledTasks.txt"
    Get-ScheduledTask | Select TaskName, URI, State, Triggers | Format-Table | Out-File -FilePath $ScheduledTasks -Force
    Write-Host "Scheduled tasks created: $ScheduledTasks`n"

}


function Get-Persistence-StartupFolder {
    param (
            $username
        )
    mkdir -Path "$cwd\DF_Findings\Persistence\$username\" -Force | Out-Null
    $StartUpFolder = "$cwd\DF_Findings\Persistence\$username\StartUpFolder.txt"
    Get-ChildItem -Path "C:\Users\$username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" | Out-File -FilePath $StartUpFolder
    Write-Host "Startup folder for $username created: $StartUpFolder`n"

}

function Get-CopyEventLogs {
    mkdir -Path "$cwd\DF_Findings\Logs" -Force | Out-Null
    $log = @('Security.evtx', 'System.evtx', 'Microsoft-Windows-PowerShell%4Operational.evtx', 'Windows PowerShell.evtx' ,'Application.evtx') #Feel free to edit this line to add more log files!
    
    ForEach ($logFileName in $log) {
        Copy-Item -Path "C:\Windows\System32\winevt\Logs\$logFileName" -Destination "$cwd\DF_Findings\Logs\$logFileName" -Force

    }
    Write-Host "Log files copied to: $cwd\DF_Findings\Log`n"

}

function Get-Prefetch {
    Copy-Item -Path "C:\Windows\Prefetch" -Destination "$cwd\DF_Findings\" -Recurse   
    Write-Host "Prefetch folder created: $cwd\DF_Findings\Prefetch`n"
    
}

function Get-Srum {
    Copy-Item -Path "C:\Windows\System32\sru\SRUDB.dat" -Destination "$cwd\DF_Findings\SRUDB.dat"
    Write-Host "System Resource Usage Monitor log file created: $cwd\DF_Findings\SRUDB.dat`n"
}

function Get-JumpList {
    param (
        $username
    )
    Copy-Item -Path "C:\Users\$username\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" -Destination "$cwd\DF_Findings\Users\$username\" -Force -Recurse
    Write-Host "$username Jump List file created: $cwd\DF_Findings\Users\$username\AutomaticDestinations`n"
}



Get-Persistence
Get-AllUsers
Get-NetworkInformation
Get-ProccessInfo
Get-CopyEventLogs
Get-Prefetch
Get-Srum
