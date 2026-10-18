<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/network/cisco/aaa/cisco_cli_input_capture.yml -->
title: Cisco Show Commands Input
id: b094d9fb-b1ad-4650-9f1a-fb7be9f1d34b
status: test
description: See what commands are being input into the device by other people, full credentials can be in the history
author: Austin Clark
date: 2019-08-11
modified: 2023-01-04
tags:
    - attack.credential-access
    - attack.t1552.003
logsource:
    product: cisco
    service: aaa
detection:
    keywords:
        - 'show history'
        - 'show history all'
        - 'show logging'
    condition: keywords
falsepositives:
    - Not commonly run by administrators, especially if remote logging is configured
level: medium
