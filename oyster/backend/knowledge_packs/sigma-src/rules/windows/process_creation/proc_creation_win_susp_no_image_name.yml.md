<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_susp_no_image_name.yml -->
title: Process Launched Without Image Name
id: f208d6d8-d83a-4c2c-960d-877c37da84e5
status: test
description: Detect the use of processes with no name (".exe"), which can be used to evade Image-based detections.
references:
    - https://www.huntress.com/blog/fake-browser-updates-lead-to-boinc-volunteer-computing-software
author: Matt Anderson (Huntress)
date: 2024-07-23
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\.exe'
    condition: selection
falsepositives:
    - Rare legitimate software.
level: medium
