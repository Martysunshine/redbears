<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/application/esent/win_esent_ntdsutil_abuse_susp_location.yml -->
title: Dump Ntds.dit To Suspicious Location
id: 94dc4390-6b7c-4784-8ffc-335334404650
status: test
description: Detects potential abuse of ntdsutil to dump ntds.dit database to a suspicious location
references:
    - https://twitter.com/mgreen27/status/1558223256704122882
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj574207(v=ws.11)
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-14
modified: 2023-10-23
tags:
    - attack.execution
logsource:
    product: windows
    service: application
    # warning: The 'data' field used in the detection section is the container for the event data as a whole. You may have to adapt the rule for your backend accordingly
detection:
    selection_root:
        Provider_Name: 'ESENT'
        EventID: 325 # New Database Created
        Data|contains: 'ntds.dit'
    selection_paths:
        Data|contains:
            # Add more locations that you don't use in your env or that are just suspicious
            - ':\ntds.dit'
            - '\Appdata\'
            - '\Desktop\'
            - '\Downloads\'
            - '\Perflogs\'
            - '\Temp\'
            - '\Users\Public\'
    condition: all of selection_*
falsepositives:
    - Legitimate backup operation/creating shadow copies
level: medium
