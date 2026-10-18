<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/image_load/image_load_hktl_silenttrinity_stager.yml -->
title: HackTool - SILENTTRINITY Stager DLL Load
id: 75c505b1-711d-4f68-a357-8c3fe37dbf2d
related:
    - id: 03552375-cc2c-4883-bbe4-7958d5a980be # Process Creation
      type: derived
status: test
description: Detects SILENTTRINITY stager dll loading activity
references:
    - https://github.com/byt3bl33d3r/SILENTTRINITY
author: Aleksey Potapov, oscd.community
date: 2019-10-22
modified: 2023-02-17
tags:
    - attack.command-and-control
    - attack.t1071
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Description|contains: 'st2stager'
    condition: selection
falsepositives:
    - Unlikely
level: high
