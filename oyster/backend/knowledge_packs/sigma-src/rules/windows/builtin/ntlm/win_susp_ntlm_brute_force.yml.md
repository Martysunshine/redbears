<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/ntlm/win_susp_ntlm_brute_force.yml -->
title: NTLM Brute Force
id: 9c8acf1a-cbf9-4db6-b63c-74baabe03e59
status: test
description: Detects common NTLM brute force device names
references:
    - https://www.varonis.com/blog/investigate-ntlm-brute-force
author: Jerry Shockley '@jsh0x'
date: 2022-02-02
tags:
    - attack.credential-access
    - attack.t1110
logsource:
    product: windows
    service: ntlm
    definition: Requires events from Microsoft-Windows-NTLM/Operational
detection:
    selection:
        EventID: 8004
    devicename:
        WorkstationName:
            - 'Rdesktop'
            - 'Remmina'
            - 'Freerdp'
            - 'Windows7'
            - 'Windows8'
            - 'Windows2012'
            - 'Windows2016'
            - 'Windows2019'
    condition: selection and devicename
falsepositives:
    - Systems with names equal to the spoofed ones used by the brute force tools
level: medium
