<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/system/service_control_manager/win_system_service_terminated_error_generic.yml -->
title: Windows Service Terminated With Error
id: acfa2210-0d71-4eeb-b477-afab494d596c
related:
    - id: d6b5520d-3934-48b4-928c-2aa3f92d6963
      type: similar
status: test
description: Detects Windows services that got terminated for whatever reason
references:
    - https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2022-21894-the-blacklotus-campaign/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-04-14
tags:
    - attack.stealth
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7023 # The X Service service terminated with the following error
    condition: selection
falsepositives:
    - False positives could occur since service termination could happen due to multiple reasons
level: low
