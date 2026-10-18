<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_cmd_curl_download_exec_combo.yml -->
title: Curl Download And Execute Combination
id: 21dd6d38-2b18-4453-9404-a0fe4a0cc288
status: test
description: Adversaries can use curl to download payloads remotely and execute them. Curl is included by default in Windows 10 build 17063 and later.
references:
    - https://medium.com/@reegun/curl-exe-is-the-new-rundll32-exe-lolbin-3f79c5f35983 # Dead Link
author: Sreeman, Nasreddine Bencherchali (Nextron Systems)
date: 2020-01-13
modified: 2024-03-05
tags:
    - attack.stealth
    - attack.t1218
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|windash: ' -c '
        CommandLine|contains|all:
            - 'curl '
            - 'http'
            - '-o'
            - '&'
    condition: selection
falsepositives:
    - Unknown
level: high
