<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_gpg4win_decryption.yml -->
title: File Decryption Using Gpg4win
id: 037dcd71-33a8-4392-bb01-293c94663e5a
status: test
description: Detects usage of Gpg4win to decrypt files
references:
    - https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
    - https://www.gpg4win.de/documentation.html
    - https://news.sophos.com/en-us/2022/01/19/zloader-installs-remote-access-backdoors-and-delivers-cobalt-strike/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-08-09
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_metadata:
        - Image|endswith:
              - '\gpg.exe'
              - '\gpg2.exe'
        - Description: 'GnuPG’s OpenPGP tool'
    selection_cli:
        CommandLine|contains|all:
            - ' -d '
            - 'passphrase'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
