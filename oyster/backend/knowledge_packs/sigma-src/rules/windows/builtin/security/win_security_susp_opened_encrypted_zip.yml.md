<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/security/win_security_susp_opened_encrypted_zip.yml -->
title: Password Protected ZIP File Opened
id: 00ba9da1-b510-4f6b-b258-8d338836180f
status: test
description: Detects the extraction of password protected ZIP archives. See the filename variable for more details on which file has been opened.
references:
    - https://twitter.com/sbousseaden/status/1523383197513379841
author: Florian Roth (Nextron Systems)
date: 2022-05-09
tags:
    - attack.stealth
    - attack.t1027
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5379
        TargetName|contains: 'Microsoft_Windows_Shell_ZipFolder:filename'
    filter:  # avoid overlaps with 54f0434b-726f-48a1-b2aa-067df14516e4
        TargetName|contains: '\Temporary Internet Files\Content.Outlook'
    condition: selection and not filter
falsepositives:
    - Legitimate used of encrypted ZIP files
level: medium
