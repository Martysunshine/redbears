<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_ntds_dit_creation.yml -->
title: NTDS.DIT Created
id: 0b8baa3f-575c-46ee-8715-d6f28cc7d33c
status: test
description: Detects creation of a file named "ntds.dit" (Active Directory Database)
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-05
tags:
    - attack.credential-access
    - attack.t1003.003
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: 'ntds.dit'
    condition: selection
falsepositives:
    - Unknown
level: low
