<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/create_remote_thread/create_remote_thread_win_susp_password_dumper_lsass.yml -->
title: Password Dumper Remote Thread in LSASS
id: f239b326-2f41-4d6b-9dfa-c846a60ef505
status: stable
description: |
    Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage.
    The process in field Process is the malicious program. A single execution can lead to hundreds of events.
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/WCE.htm
author: Thomas Patzke
date: 2017-02-19
modified: 2021-06-21
tags:
    - attack.credential-access
    - attack.s0005
    - attack.t1003.001
logsource:
    product: windows
    category: create_remote_thread
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        StartModule: ''
    condition: selection
falsepositives:
    - Antivirus products
level: high
