<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_script/posh_ps_amsi_bypass_pattern_nov22.yml -->
title: AMSI Bypass Pattern Assembly GetType
id: e0d6c087-2d1c-47fd-8799-3904103c5a98
status: test
description: Detects code fragments found in small and obfuscated AMSI bypass PowerShell scripts
references:
    - https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/
    - https://twitter.com/cyb3rops/status/1588574518057979905?s=20&t=A7hh93ONM7ni1Rj1jO5OaA
author: Florian Roth (Nextron Systems)
date: 2022-11-09
tags:
    - attack.defense-impairment
    - attack.t1685
    - attack.execution
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - '[Ref].Assembly.GetType'
            - 'SetValue($null,$true)'
            - 'NonPublic,Static'
    condition: selection
falsepositives:
    - Unknown
level: high
