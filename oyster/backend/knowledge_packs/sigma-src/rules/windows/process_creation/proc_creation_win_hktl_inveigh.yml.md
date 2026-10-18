<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_hktl_inveigh.yml -->
title: HackTool - Inveigh Execution
id: b99a1518-1ad5-4f65-bc95-1ffff97a8fd0
status: test
description: Detects the use of Inveigh a cross-platform .NET IPv4/IPv6 machine-in-the-middle tool
references:
    - https://github.com/Kevin-Robertson/Inveigh
    - https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-24
modified: 2023-02-04
tags:
    - attack.credential-access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\Inveigh.exe'
        - OriginalFileName:
              - '\Inveigh.exe'
              - '\Inveigh.dll'
        - Description: 'Inveigh'
        - CommandLine|contains:
              - ' -SpooferIP'
              - ' -ReplyToIPs '
              - ' -ReplyToDomains '
              - ' -ReplyToMACs '
              - ' -SnifferIP'
    condition: selection
falsepositives:
    - Very unlikely
level: critical
