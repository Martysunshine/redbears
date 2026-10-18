<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/windows/create_remote_thread/create_remote_thread_win_loadlibrary.yml -->
title: CreateRemoteThread API and LoadLibrary
id: 052ec6f6-1adc-41e6-907a-f1c813478bee
status: test
description: Detects potential use of CreateRemoteThread api and LoadLibrary function to inject DLL into a process
references:
    - https://threathunterplaybook.com/hunts/windows/180719-DLLProcessInjectionCreateRemoteThread/notebook.html
author: Roberto Rodriguez @Cyb3rWard0g
date: 2019-08-11
modified: 2024-01-22
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1055.001
    - detection.threat-hunting
logsource:
    product: windows
    category: create_remote_thread
detection:
    selection:
        StartModule|endswith: '\kernel32.dll'
        StartFunction: 'LoadLibraryA'
    condition: selection
falsepositives:
    - Unknown
level: medium
