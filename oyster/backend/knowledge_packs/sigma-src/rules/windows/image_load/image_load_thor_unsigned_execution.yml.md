<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/image_load/image_load_thor_unsigned_execution.yml -->
title: Suspicious Unsigned Thor Scanner Execution
id: ea5c131b-380d-49f9-aeb3-920694da4d4b
status: stable
description: Detects loading and execution of an unsigned thor scanner binary.
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-10-29
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.stealth
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith:
            - '\thor.exe'
            - '\thor64.exe'
        ImageLoaded|endswith:
            - '\thor.exe'
            - '\thor64.exe'
    filter_main:
        Signed: 'true'
        SignatureStatus: 'valid'
        Signature: 'Nextron Systems GmbH'
    condition: selection and not filter_main
falsepositives:
    - Other legitimate binaries named "thor.exe" that aren't published by Nextron Systems
level: high
