<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-emerging-threats/2017/TA/Lazarus/proc_creation_win_apt_lazarus_binary_masquerading.yml -->
title: Lazarus System Binary Masquerading
id: 3f7f5b0b-5b16-476c-a85f-ab477f6dd24b
status: test
description: Detects binaries used by the Lazarus group which use system names but are executed and launched from non-default location
references:
    - https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180244/Lazarus_Under_The_Hood_PDF_final.pdf
author: Trent Liffick (@tliffick), Bartlomiej Czyz (@bczyz1)
date: 2020-06-03
modified: 2023-03-10
tags:
    - attack.stealth
    - attack.t1036.005
    - detection.emerging-threats
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\msdtc.exe'
            - '\gpsvc.exe'
    filter:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection and not filter
falsepositives:
    - Unlikely
level: high
