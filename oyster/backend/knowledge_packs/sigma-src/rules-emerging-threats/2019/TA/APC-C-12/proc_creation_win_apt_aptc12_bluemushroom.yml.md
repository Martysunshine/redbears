<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2019/TA/APC-C-12/proc_creation_win_apt_aptc12_bluemushroom.yml -->
title: Potential APT-C-12 BlueMushroom DLL Load Activity Via Regsvr32
id: bd70d3f8-e60e-4d25-89f0-0b5a9cff20e0
status: test
description: Detects potential BlueMushroom DLL loading activity via regsvr32 from AppData Local
references:
    - https://pbs.twimg.com/media/EF3yLGoWkAEGeLa?format=jpg
author: Florian Roth (Nextron Systems), Tim Shelton, Nasreddine Bencherchali (Nextron Systems)
date: 2019-10-02
modified: 2023-03-29
tags:
    - attack.stealth
    - attack.t1218.010
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'regsvr32'
            - '\AppData\Local\'
            - '.dll'
            - ',DllEntry'
    condition: selection
falsepositives:
    - Unknown
level: medium
