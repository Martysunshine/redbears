<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/builtin/lnx_symlink_etc_passwd.yml -->
title: Symlink Etc Passwd
id: c67fc22a-0be5-4b4f-aad5-2b32c4b69523
status: test
description: Detects suspicious command lines that look as if they would create symbolic links to /etc/passwd
references:
    - https://www.qualys.com/2021/05/04/21nails/21nails.txt
author: Florian Roth (Nextron Systems)
date: 2019-04-05
modified: 2021-11-27
tags:
    - attack.t1204.001
    - attack.execution
logsource:
    product: linux
detection:
    keywords:
        - 'ln -s -f /etc/passwd'
        - 'ln -s /etc/passwd'
    condition: keywords
falsepositives:
    - Unknown
level: high
