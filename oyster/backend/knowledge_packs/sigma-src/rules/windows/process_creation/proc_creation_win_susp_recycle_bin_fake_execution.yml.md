<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_susp_recycle_bin_fake_execution.yml -->
title: Suspicious Process Execution From Fake Recycle.Bin Folder
id: 5ce0f04e-3efc-42af-839d-5b3a543b76c0
related:
    - id: cd8b36ac-8e4a-4c2f-a402-a29b8fbd5bca
      type: derived
status: test
description: Detects process execution from a fake recycle bin folder, often used to avoid security solution.
references:
    - https://www.mandiant.com/resources/blog/infected-usb-steal-secrets
    - https://unit42.paloaltonetworks.com/cloaked-ursa-phishing/
author: X__Junior (Nextron Systems)
date: 2023-07-12
modified: 2023-12-11
tags:
    - attack.persistence
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains:
            # e.g. C:\$RECYCLER.BIN
            - 'RECYCLERS.BIN\'
            - 'RECYCLER.BIN\'
    condition: selection
falsepositives:
    - Unlikely
level: high
