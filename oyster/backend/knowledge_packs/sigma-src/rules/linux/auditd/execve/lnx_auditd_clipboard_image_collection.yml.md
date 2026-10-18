<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/auditd/execve/lnx_auditd_clipboard_image_collection.yml -->
title: Clipboard Collection of Image Data with Xclip Tool
id: f200dc3f-b219-425d-a17e-c38467364816
status: test
description: |
  Detects attempts to collect image data stored in the clipboard from users with the usage of xclip tool.
  Xclip has to be installed.
  Highly recommended using rule on servers, due to high usage of clipboard utilities on user workstations.
references:
    - https://linux.die.net/man/1/xclip
author: 'Pawel Mazur'
date: 2021-10-01
modified: 2022-10-09
tags:
    - attack.collection
    - attack.t1115
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: EXECVE
        a0: xclip
        a1:
            - '-selection'
            - '-sel'
        a2:
            - clipboard
            - clip
        a3: '-t'
        a4|startswith: 'image/'
        a5: '-o'
    condition: selection
falsepositives:
    - Legitimate usage of xclip tools
level: low
