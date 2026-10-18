<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/builtin/cron/lnx_cron_crontab_file_modification.yml -->
title: Modifying Crontab
id: af202fd3-7bff-4212-a25a-fb34606cfcbe
status: test
description: Detects suspicious modification of crontab file.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1053.003/T1053.003.md
author: Pawel Mazur
date: 2022-04-16
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.t1053.003
logsource:
    product: linux
    service: cron
detection:
    keywords:
        - 'REPLACE'
    condition: keywords
falsepositives:
    - Legitimate modification of crontab
level: medium
