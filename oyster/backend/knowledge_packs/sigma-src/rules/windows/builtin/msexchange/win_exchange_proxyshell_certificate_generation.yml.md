<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/msexchange/win_exchange_proxyshell_certificate_generation.yml -->
title: Certificate Request Export to Exchange Webserver
id: b7bc7038-638b-4ffd-880c-292c692209ef
status: test
description: Detects a write of an Exchange CSR to an untypical directory or with aspx name suffix which can be used to place a webshell
references:
    - https://twitter.com/GossiTheDog/status/1429175908905127938
author: Max Altgelt (Nextron Systems)
date: 2021-08-23
modified: 2023-01-23
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    service: msexchange-management
    product: windows
detection:
    keywords_export_command:
        '|all':
            - 'New-ExchangeCertificate'
            - ' -GenerateRequest'
            - ' -BinaryEncoded'
            - ' -RequestFile'
    keywords_export_params:
        - '\\\\localhost\\C$'
        - '\\\\127.0.0.1\\C$'
        - 'C:\\inetpub'
        - '.aspx'
    condition: keywords_export_command and keywords_export_params
falsepositives:
    - Unlikely
level: critical
