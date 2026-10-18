<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_hktl_soaphound_execution.yml -->
title: HackTool - SOAPHound Execution
id: e92a4287-e072-4a40-9739-370c106bb750
status: test
description: |
    Detects the execution of SOAPHound, a .NET tool for collecting Active Directory data, using specific command-line arguments that may indicate an attempt to extract sensitive AD information.
references:
    - https://github.com/FalconForceTeam/SOAPHound
    - https://medium.com/falconforce/soaphound-tool-to-collect-active-directory-data-via-adws-165aca78288c
author: '@kostastsale'
date: 2024-01-26
tags:
    - attack.discovery
    - attack.t1087
logsource:
    product: windows
    category: process_creation
detection:
    selection_1:
        CommandLine|contains:
            - ' --buildcache '
            - ' --bhdump '
            - ' --certdump '
            - ' --dnsdump '
    selection_2:
        CommandLine|contains:
            - ' -c '
            - ' --cachefilename '
            - ' -o '
            - ' --outputdirectory'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
