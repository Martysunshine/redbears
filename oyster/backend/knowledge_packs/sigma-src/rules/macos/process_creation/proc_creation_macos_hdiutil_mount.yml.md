<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/macos/process_creation/proc_creation_macos_hdiutil_mount.yml -->
title: Disk Image Mounting Via Hdiutil - MacOS
id: bf241472-f014-4f01-a869-96f99330ca8c
status: test
description: Detects the execution of the hdiutil utility in order to mount disk images.
references:
    - https://www.loobins.io/binaries/hdiutil/
    - https://www.sentinelone.com/blog/from-the-front-linesunsigned-macos-orat-malware-gambles-for-the-win/
    - https://ss64.com/mac/hdiutil.html
author: Omar Khaled (@beacon_exe)
date: 2024-08-10
tags:
    - attack.initial-access
    - attack.collection
    - attack.t1566.001
    - attack.t1560.001
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|endswith: /hdiutil
        CommandLine|contains:
            - 'attach '
            - 'mount '
    condition: selection
falsepositives:
    - Legitimate usage of hdiutil by administrators and users.
level: medium
