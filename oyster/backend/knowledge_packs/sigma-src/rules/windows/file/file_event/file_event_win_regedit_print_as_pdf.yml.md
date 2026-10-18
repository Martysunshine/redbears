<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_regedit_print_as_pdf.yml -->
title: PDF File Created By RegEdit.EXE
id: 145095eb-e273-443b-83d0-f9b519b7867b
status: test
description: |
    Detects the creation of a file with the ".pdf" extension by the "RegEdit.exe" process.
    This indicates that a user is trying to print/save a registry key as a PDF in order to potentially extract sensitive information and bypass defenses.
references:
    - https://sensepost.com/blog/2024/dumping-lsa-secrets-a-story-about-task-decorrelation/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2024-07-08
tags:
    - attack.stealth
logsource:
    category: file_event
    product: windows
detection:
    selection:
        Image|endswith: '\regedit.exe'
        TargetFilename|endswith: '.pdf'
    condition: selection
falsepositives:
    - Unlikely
level: high
