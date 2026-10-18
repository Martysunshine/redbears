<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/win_security_remote_powershell_session.yml -->
title: Remote PowerShell Sessions Network Connections (WinRM)
id: 13acf386-b8c6-4fe0-9a6e-c4756b974698
status: test
description: Detects basic PowerShell Remoting (WinRM) by monitoring for network inbound connections to ports 5985 OR 5986
references:
    - https://threathunterplaybook.com/hunts/windows/190511-RemotePwshExecution/notebook.html
author: Roberto Rodriguez @Cyb3rWard0g
date: 2019-09-12
modified: 2022-10-09
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5156
        DestPort:
            - 5985
            - 5986
        LayerRTID: 44
    condition: selection
falsepositives:
    - Legitimate use of remote PowerShell execution
level: high
