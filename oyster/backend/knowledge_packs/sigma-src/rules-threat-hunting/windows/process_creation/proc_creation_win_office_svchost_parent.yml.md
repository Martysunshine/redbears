<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/windows/process_creation/proc_creation_win_office_svchost_parent.yml -->
title: Suspicious New Instance Of An Office COM Object
id: 9bdaf1e9-fdef-443b-8081-4341b74a7e28
status: test
description: |
    Detects an svchost process spawning an instance of an office application. This happens when the initial word application creates an instance of one of the Office COM objects such as 'Word.Application', 'Excel.Application', etc.
    This can be used by malicious actors to create malicious Office documents with macros on the fly. (See vba2clr project in the references)
references:
    - https://learn.microsoft.com/en-us/previous-versions/office/troubleshoot/office-developer/automate-word-create-file-using-visual-basic
    - https://github.com/med0x2e/vba2clr
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-13
modified: 2023-12-19
tags:
    - attack.execution
    - detection.threat-hunting
    - attack.stealth
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\svchost.exe'
        Image|endswith:
            - '\eqnedt32.exe'
            - '\excel.exe'
            - '\msaccess.exe'
            - '\mspub.exe'
            - '\powerpnt.exe'
            - '\visio.exe'
            - '\winword.exe'
    condition: selection
falsepositives:
    - Legitimate usage of office automation via scripting
level: medium
