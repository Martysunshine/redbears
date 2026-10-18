<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/pipe_created/pipe_created_pua_paexec_default_pipe.yml -->
title: PUA - PAExec Default Named Pipe
id: f6451de4-df0a-41fa-8d72-b39f54a08db5
status: test
description: Detects PAExec default named pipe
references:
    - https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/efa17a600b43c897b4b7463cc8541daa1987eeb4/Command%20and%20Control/C2-NamedPipe.md
    - https://github.com/poweradminllc/PAExec
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-26
tags:
    - attack.execution
    - attack.t1569.002
logsource:
    category: pipe_created
    product: windows
    definition: 'Note that you have to configure logging for Named Pipe Events in Sysmon config (Event ID 17 and Event ID 18). The basic configuration is in popular sysmon configuration (https://github.com/SwiftOnSecurity/sysmon-config), but it is worth verifying. You can also use other repo, e.g. https://github.com/Neo23x0/sysmon-config, https://github.com/olafhartong/sysmon-modular. How to test detection? You can check powershell script from this site https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575'
detection:
    selection:
        PipeName|startswith: '\PAExec'
    condition: selection
falsepositives:
    - Unknown
level: medium
