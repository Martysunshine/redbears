<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_susp_exchange_aspx_write.yml -->
title: Suspicious MSExchangeMailboxReplication ASPX Write
id: 7280c9f3-a5af-45d0-916a-bc01cb4151c9
status: test
description: Detects suspicious activity in which the MSExchangeMailboxReplication process writes .asp and .apsx files to disk, which could be a sign of ProxyShell exploitation
references:
    - https://redcanary.com/blog/blackbyte-ransomware/
author: Florian Roth (Nextron Systems)
date: 2022-02-25
tags:
    - attack.initial-access
    - attack.t1190
    - attack.persistence
    - attack.t1505.003
logsource:
    product: windows
    category: file_event
detection:
    selection:
        Image|endswith: '\MSExchangeMailboxReplication.exe'
        TargetFilename|endswith:
            - '.aspx'
            - '.asp'
    condition: selection
falsepositives:
    - Unknown
level: high
