<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_proxy_connection.yml -->
title: Connection Proxy
id: 72f4ab3f-787d-495d-a55d-68c2ff46cf4c
status: test
description: Detects setting proxy configuration
author: Ömer Günal
date: 2020-06-17
modified: 2022-10-05
tags:
    - attack.command-and-control
    - attack.t1090
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'http_proxy='
            - 'https_proxy='
    condition: selection
falsepositives:
    - Legitimate administration activities
level: low
