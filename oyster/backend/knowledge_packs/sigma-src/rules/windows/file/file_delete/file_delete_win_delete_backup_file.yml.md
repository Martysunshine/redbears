<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_delete/file_delete_win_delete_backup_file.yml -->
title: Backup Files Deleted
id: 06125661-3814-4e03-bfa2-1e4411c60ac3
status: test
description: Detects deletion of files with extensions often used for backup files. Adversaries may delete or remove built-in operating system data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md#atomic-test-6---windows---delete-backup-files
author: frack113
date: 2022-01-02
modified: 2023-02-15
tags:
    - attack.impact
    - attack.t1490
logsource:
    product: windows
    category: file_delete
detection:
    selection:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wt.exe'
            - '\rundll32.exe'
            - '\regsvr32.exe'
        TargetFilename|endswith:
            - '.VHD'
            - '.bac'
            - '.bak'
            - '.wbcat'
            - '.bkf'
            - '.set'
            - '.win'
            - '.dsk'
    condition: selection
falsepositives:
    - Legitimate usage
level: medium
