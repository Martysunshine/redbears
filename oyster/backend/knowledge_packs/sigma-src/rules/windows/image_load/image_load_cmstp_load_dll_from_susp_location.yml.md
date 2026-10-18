<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/image_load/image_load_cmstp_load_dll_from_susp_location.yml -->
title: DLL Loaded From Suspicious Location Via Cmspt.EXE
id: 75e508f7-932d-4ebc-af77-269237a84ce1
status: test
description: Detects cmstp loading "dll" or "ocx" files from suspicious locations
references:
    - https://github.com/vadim-hunter/Detection-Ideas-Rules/blob/02bcbfc2bfb8b4da601bb30de0344ae453aa1afe/TTPs/Defense%20Evasion/T1218%20-%20Signed%20Binary%20Proxy%20Execution/T1218.003%20-%20CMSTP/Procedures.yaml
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-30
modified: 2023-02-17
tags:
    - attack.stealth
    - attack.t1218.003
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\cmstp.exe'
        ImageLoaded|contains:
            # Add more suspicious paths as you see fit in your env
            - '\PerfLogs\'
            - '\ProgramData\'
            - '\Users\'
            - '\Windows\Temp\'
            - 'C:\Temp\'
        ImageLoaded|endswith:
            - '.dll'
            - '.ocx'
    condition: selection
falsepositives:
    - Unikely
level: high
