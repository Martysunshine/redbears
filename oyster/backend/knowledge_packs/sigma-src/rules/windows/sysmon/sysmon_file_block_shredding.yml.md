<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/sysmon/sysmon_file_block_shredding.yml -->
title: Sysmon Blocked File Shredding
id: c3e5c1b1-45e9-4632-b242-27939c170239
status: test
description: Triggers on any Sysmon "FileBlockShredding" event, which indicates a violation of the configured shredding policy.
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
author: frack113
date: 2023-07-20
tags:
    - attack.defense-impairment
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 28  # this is fine, we want to match any FileBlockShredding event
    condition: selection
falsepositives:
    - Unlikely
level: high
