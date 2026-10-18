<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/image_load/image_load_rundll32_remote_share_load.yml -->
title: Remote DLL Load Via Rundll32.EXE
id: f40017b3-cb2e-4335-ab5d-3babf679c1de
status: test
description: Detects a remote DLL load event via "rundll32.exe".
references:
    - https://github.com/gabe-k/themebleed
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-09-18
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\rundll32.exe'
        ImageLoaded|startswith: '\\\\'
    condition: selection
falsepositives:
    - Unknown
level: medium
