<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/web/product/apache/web_apache_segfault.yml -->
title: Apache Segmentation Fault
id: 1da8ce0b-855d-4004-8860-7d64d42063b1
status: test
description: Detects a segmentation fault error message caused by a crashing apache worker process
references:
    - http://www.securityfocus.com/infocus/1633
author: Florian Roth (Nextron Systems)
date: 2017-02-28
modified: 2021-11-27
tags:
    - attack.impact
    - attack.t1499.004
logsource:
    service: apache
    definition: 'Requirements: Must be able to collect the error.log file'
detection:
    keywords:
        - 'exit signal Segmentation Fault'
    condition: keywords
falsepositives:
    - Unknown
level: high
