<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_wmiexec_default_filename.yml -->
title: Wmiexec Default Output File
id: 8d5aca11-22b3-4f22-b7ba-90e60533e1fb
status: test
description: Detects the creation of the default output filename used by the wmiexec tool
references:
    - https://www.crowdstrike.com/blog/how-to-detect-and-prevent-impackets-wmiexec/
    - https://github.com/fortra/impacket/blob/f4b848fa27654ca95bc0f4c73dbba8b9c2c9f30a/examples/wmiexec.py
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-02
modified: 2023-03-08
tags:
    - attack.lateral-movement
    - attack.execution
    - attack.t1047
logsource:
    category: file_event
    product: windows
detection:
    selection:
        - TargetFilename|re: '\\Windows\\__1\d{9}\.\d{1,7}$' # Admin$
        - TargetFilename|re: 'C:\\__1\d{9}\.\d{1,7}$' # C$
        - TargetFilename|re: 'D:\\__1\d{9}\.\d{1,7}$' # D$
    condition: selection
falsepositives:
    - Unlikely
level: critical
