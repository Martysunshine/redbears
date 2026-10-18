<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_pcre_net_temp_file.yml -->
title: PCRE.NET Package Temp Files
id: 6e90ae7a-7cd3-473f-a035-4ebb72d961da
status: test
description: Detects processes creating temp files related to PCRE.NET package
references:
    - https://twitter.com/rbmaslen/status/1321859647091970051
    - https://twitter.com/tifkin_/status/1321916444557365248
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020-10-29
modified: 2022-10-09
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: \AppData\Local\Temp\ba9ea7344a4a5f591d6e5dc32a13494b\
    condition: selection
falsepositives:
    - Unknown
level: high
