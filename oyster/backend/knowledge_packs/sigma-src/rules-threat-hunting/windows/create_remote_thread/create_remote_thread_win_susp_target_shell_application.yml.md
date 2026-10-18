<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/windows/create_remote_thread/create_remote_thread_win_susp_target_shell_application.yml -->
title: Remote Thread Created In Shell Application
id: a9d4d3fa-8fc0-41bc-80b1-30b9fda79d6f
status: test
description: |
    Detects remote thread creation in command shell applications, such as "Cmd.EXE" and "PowerShell.EXE".
    It is a common technique used by malware, such as IcedID, to inject malicious code and execute it within legitimate processes.
references:
    - https://research.splunk.com/endpoint/10399c1e-f51e-11eb-b920-acde48001122/
    - https://www.binarydefense.com/resources/blog/icedid-gziploader-analysis/
author: Splunk Research Team
date: 2024-07-29
modified: 2025-07-04
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1055
    - detection.threat-hunting
logsource:
    product: windows
    category: create_remote_thread
detection:
    selection:
        TargetImage|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    filter_main_system:
        SourceImage|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Program Files (x86)\'
            - 'C:\Program Files\'
    filter_optional_defender:
        SourceImage|endswith: '\MsMpEng.exe'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: medium
