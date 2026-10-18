<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2022/TA/MERCURY/proc_creation_win_apt_mercury.yml -->
title: MERCURY APT Activity
id: a62298a3-1fe0-422f-9a68-ffbcbc5a123d
status: test
description: Detects suspicious command line patterns seen being used by MERCURY APT
references:
    - https://www.microsoft.com/security/blog/2022/08/25/mercury-leveraging-log4j-2-vulnerabilities-in-unpatched-systems-to-target-israeli-organizations/
author: Florian Roth (Nextron Systems)
date: 2022-08-26
modified: 2023-03-10
tags:
    - attack.execution
    - attack.t1059.001
    - attack.g0069
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '-exec bypass -w 1 -enc'
            - 'UwB0AGEAcgB0AC0ASgBvAGIAIAAtAFMAYwByAGkAcAB0AEIAbABvAGMAawAgAHsAKABzAGEAcABzACAAKAAiAHAA'  # Start-Job -ScriptBlock
    condition: selection
falsepositives:
    - Unknown
level: high
