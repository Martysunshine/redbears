<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_cmd_dosfuscation.yml -->
title: Potential Dosfuscation Activity
id: a77c1610-fc73-4019-8e29-0f51efc04a51
status: test
description: Detects possible payload obfuscation via the commandline
references:
    - https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf
    - https://github.com/danielbohannon/Invoke-DOSfuscation
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: 2022-02-15
modified: 2023-03-06
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '^^'
            - '^|^'
            - ',;,'
            - ';;;;'
            - ';; ;;'
            - '(,(,'
            - '%COMSPEC:~'
            - ' c^m^d'
            - '^c^m^d'
            - ' c^md'
            - ' cm^d'
            - '^cm^d'
            - ' s^et '
            - ' s^e^t '
            - ' se^t '
            # - '%%'
            # - '&&'
            # - '""'
    condition: selection
falsepositives:
    - Unknown
level: medium
