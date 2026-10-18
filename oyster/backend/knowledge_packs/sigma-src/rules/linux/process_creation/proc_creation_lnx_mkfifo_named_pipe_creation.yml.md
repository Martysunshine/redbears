<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_mkfifo_named_pipe_creation.yml -->
title: Named Pipe Created Via Mkfifo
id: 9d779ce8-5256-4b13-8b6f-b91c602b43f4
status: test
description: Detects the creation of a new named pipe using the "mkfifo" utility
references:
    - https://dev.to/0xbf/use-mkfifo-to-create-named-pipe-linux-tips-5bbk
    - https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-06-16
tags:
    - attack.execution
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/mkfifo'
    condition: selection
falsepositives:
    - Unknown
level: low
