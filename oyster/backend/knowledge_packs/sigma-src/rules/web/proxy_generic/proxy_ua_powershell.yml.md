<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/web/proxy_generic/proxy_ua_powershell.yml -->
title: Windows PowerShell User Agent
id: c8557060-9221-4448-8794-96320e6f3e74
status: test
description: Detects Windows PowerShell Web Access
references:
    - https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest
author: Florian Roth (Nextron Systems)
date: 2017-03-13
modified: 2021-11-27
tags:
    - attack.command-and-control
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
        c-useragent|contains: ' WindowsPowerShell/'
    condition: selection
falsepositives:
    - Administrative scripts that download files from the Internet
    - Administrative scripts that retrieve certain website contents
level: medium
