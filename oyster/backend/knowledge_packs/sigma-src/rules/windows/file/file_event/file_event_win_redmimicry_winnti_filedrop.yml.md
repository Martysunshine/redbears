<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_redmimicry_winnti_filedrop.yml -->
title: Potential Winnti Dropper Activity
id: 130c9e58-28ac-4f83-8574-0a4cc913b97e
status: test
description: Detects files dropped by Winnti as described in RedMimicry Winnti playbook
references:
    - https://redmimicry.com/posts/redmimicry-winnti/#dropper
author: Alexander Rausch
date: 2020-06-24
modified: 2023-01-05
tags:
    - attack.stealth
    - attack.t1027
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - '\gthread-3.6.dll'
            - '\sigcmm-2.4.dll'
            - '\Windows\Temp\tmp.bat'
    condition: selection
falsepositives:
    - Unknown
level: high
