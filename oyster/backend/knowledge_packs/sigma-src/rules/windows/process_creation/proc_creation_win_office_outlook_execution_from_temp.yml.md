<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_office_outlook_execution_from_temp.yml -->
title: Suspicious Execution From Outlook Temporary Folder
id: a018fdc3-46a3-44e5-9afb-2cd4af1d4b39
status: test
description: Detects a suspicious program execution in Outlook temp folder
author: Florian Roth (Nextron Systems)
references:
    - Internal Research
date: 2019-10-01
modified: 2022-10-09
tags:
    - attack.initial-access
    - attack.t1566.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains: '\Temporary Internet Files\Content.Outlook\'
    condition: selection
falsepositives:
    - Unknown
level: high
