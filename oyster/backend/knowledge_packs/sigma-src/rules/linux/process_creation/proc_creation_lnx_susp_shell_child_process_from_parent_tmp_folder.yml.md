<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/linux/process_creation/proc_creation_lnx_susp_shell_child_process_from_parent_tmp_folder.yml -->
title: Shell Execution Of Process Located In Tmp Directory
id: 2fade0b6-7423-4835-9d4f-335b39b83867
status: test
description: Detects execution of shells from a parent process located in a temporary (/tmp) directory
references:
    - https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
    - https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
    - https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
    - https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-06-02
tags:
    - attack.execution
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        ParentImage|startswith: '/tmp/'
        Image|endswith:
            - '/bash'
            - '/csh'
            - '/dash'
            - '/fish'
            - '/ksh'
            - '/sh'
            - '/zsh'
    condition: selection
falsepositives:
    - Unknown
level: high
