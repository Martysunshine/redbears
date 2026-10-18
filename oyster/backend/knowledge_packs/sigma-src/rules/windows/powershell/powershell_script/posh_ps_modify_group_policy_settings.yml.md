<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/powershell/powershell_script/posh_ps_modify_group_policy_settings.yml -->
title: Modify Group Policy Settings - ScriptBlockLogging
id: b7216a7d-687e-4c8d-82b1-3080b2ad961f
related:
    - id: ada4b0c4-758b-46ac-9033-9004613a150d
      type: similar
status: test
description: Detect malicious GPO modifications can be used to implement many other malicious behaviors.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1484.001/T1484.001.md
author: frack113
date: 2022-08-19
tags:
    - attack.privilege-escalation
    - attack.defense-impairment
    - attack.t1484.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_path:
        ScriptBlockText|contains: \SOFTWARE\Policies\Microsoft\Windows\System
    selection_key:
        ScriptBlockText|contains:
            - GroupPolicyRefreshTimeDC
            - GroupPolicyRefreshTimeOffsetDC
            - GroupPolicyRefreshTime
            - GroupPolicyRefreshTimeOffset
            - EnableSmartScreen
            - ShellSmartScreenLevel
    condition: all of selection_*
falsepositives:
    - Legitimate use
level: medium
