<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/builtin/lnx_shellshock.yml -->
title: Shellshock Expression
id: c67e0c98-4d39-46ee-8f6b-437ebf6b950e
status: test
description: Detects shellshock expressions in log files
references:
    - https://owasp.org/www-pdf-archive/Shellshock_-_Tudor_Enache.pdf
author: Florian Roth (Nextron Systems)
date: 2017-03-14
modified: 2022-10-09
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    product: linux
detection:
    keywords:
        - '(){:;};'
        - '() {:;};'
        - '() { :;};'
        - '() { :; };'
    condition: keywords
falsepositives:
    - Unknown
level: high
