# Simple-Windows-Digital-Forensics-with-PowerShell
A basic PowerShell script to automate the checking of common places forensic artefacts may lay. This is not a thorough script, however, it can help speed up finding any quick-wins. Make sure to run this under the Local Administrator account as some features will not work otherwise. 

# What does this script collect?

- Local users
  - PowerShell command history for each user 
  - Contents of the 'Startup' folder for each user (Persistence)
- Network information
  - Local IP information
  - Established TCP connections
  - DNS cache
  - Hosts file
- Process information    
- Persistence 
  - Grabs registry entries for HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run & HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
  - Scheduled tasks
  - Startup folder for each user 
- Event Logs
  - Copies Security, System & Microsoft-Windows-PowerShell Operational event logs files 

... To do ...

- Take a memory dump
- Log past RDP sessions & SMB shares  
- Log installed software
- Automatic querying of Event Logs with Get-WinEvent

# Expected output 

All these findings are sorted neatly into sub-folders of a DF_Findings folder. Typical output may look like the below
  - ....\DF_Findings\
    -  Processes.txt
    - Logs\
      - Security.evtx
      - System.evtx
      - Microsoft-Windows-PowerShell%4Operational.evtx    
    - Network\
      - DnsClientCache.txt
      - EstablishedTCPConnections.txt
      - hosts.txt
      - NetIPAddress.txt   
    - Persistence\
      - user01\
        - StartUpFolder.txt
      - user02\
        - StartUpFolder.txt
      - Auto_services.txt
      - CurrentUser_RunRegistry.txt
      - LOCAL_RunRegistry.txt
      - ScheduledTasks.txt
    - Users\
      - user01\
        - PSHistory.txt
      - user02\
        - PSHistory.txt
      - localUserList.txt
