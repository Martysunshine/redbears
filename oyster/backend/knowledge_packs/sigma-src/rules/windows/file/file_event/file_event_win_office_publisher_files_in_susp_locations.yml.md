<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_office_publisher_files_in_susp_locations.yml -->
title: Publisher Attachment File Dropped In Suspicious Location
id: 3d2a2d59-929c-4b78-8c1a-145dfe9e07b1
status: test
description: Detects creation of files with the ".pub" extension in suspicious or uncommon locations. This could be a sign of attackers abusing Publisher documents
references:
    - https://twitter.com/EmericNasi/status/1623224526220804098
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-02-08
tags:
    - attack.stealth
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains:
            - '\AppData\Local\Temp\'
            - '\Users\Public\'
            - '\Windows\Temp\'
            - 'C:\Temp\'
        TargetFilename|endswith: '.pub'
    condition: selection
falsepositives:
    - Legitimate usage of ".pub" files from those locations
level: medium
