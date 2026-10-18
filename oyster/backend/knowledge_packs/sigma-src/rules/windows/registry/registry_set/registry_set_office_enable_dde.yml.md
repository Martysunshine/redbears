<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/registry/registry_set/registry_set_office_enable_dde.yml -->
title: Enable Microsoft Dynamic Data Exchange
id: 63647769-326d-4dde-a419-b925cc0caf42
status: test
description: Enable Dynamic Data Exchange protocol (DDE) in all supported editions of Microsoft Word or Excel.
references:
    - https://msrc.microsoft.com/update-guide/vulnerability/ADV170021
author: frack113
date: 2022-02-26
modified: 2023-08-17
tags:
    - attack.execution
    - attack.t1559.002
logsource:
    category: registry_set
    product: windows
detection:
    selection_word:
        TargetObject|endswith: '\Word\Security\AllowDDE'
        Details:
            - 'DWORD (0x00000001)'
            - 'DWORD (0x00000002)'
    selection_excel:
        TargetObject|endswith:
            - '\Excel\Security\DisableDDEServerLaunch'
            - '\Excel\Security\DisableDDEServerLookup'
        Details: 'DWORD (0x00000000)'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: medium
