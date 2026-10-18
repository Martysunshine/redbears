<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/sysmon/sysmon_file_block_executable.yml -->
title: Sysmon Blocked Executable
id: 23b71bc5-953e-4971-be4c-c896cda73fc2
status: test
description: Triggers on any Sysmon "FileBlockExecutable" event, which indicates a violation of the configured block policy
references:
    - https://medium.com/@olafhartong/sysmon-14-0-fileblockexecutable-13d7ba3dff3e
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-16
modified: 2023-09-16
tags:
    - attack.defense-impairment
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 27  # this is fine, we want to match any FileBlockExecutable event
    condition: selection
falsepositives:
    - Unlikely
level: high
