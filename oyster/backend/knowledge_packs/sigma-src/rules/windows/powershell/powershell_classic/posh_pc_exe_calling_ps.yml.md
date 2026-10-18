<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml -->
title: PowerShell Called from an Executable Version Mismatch
id: c70e019b-1479-4b65-b0cc-cd0c6093a599
status: test
description: Detects PowerShell called from an executable by the version mismatch method
references:
    - https://adsecurity.org/?p=2921
author: Sean Metcalf (source), Florian Roth (Nextron Systems)
date: 2017-03-05
modified: 2023-10-27
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_classic_start
detection:
    selection_engine:
        Data|contains:
            - 'EngineVersion=2.'
            - 'EngineVersion=4.'
            - 'EngineVersion=5.'
    selection_host:
        Data|contains: 'HostVersion=3.'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
