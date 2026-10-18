<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/pipe_created/pipe_created_hktl_coercedpotato.yml -->
title: HackTool - CoercedPotato Named Pipe Creation
id: 4d0083b3-580b-40da-9bba-626c19fe4033
status: test
description: Detects the pattern of a pipe name as used by the hack tool CoercedPotato
references:
    - https://blog.hackvens.fr/articles/CoercedPotato.html
    - https://github.com/hackvens/CoercedPotato
author: Florian Roth (Nextron Systems)
date: 2023-10-11
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1055
logsource:
    product: windows
    category: pipe_created
    definition: 'Note that you have to configure logging for Named Pipe Events in Sysmon config (Event ID 17 and Event ID 18). The basic configuration is in popular sysmon configuration (https://github.com/SwiftOnSecurity/sysmon-config), but it is worth verifying. You can also use other repo, e.g. https://github.com/Neo23x0/sysmon-config, https://github.com/olafhartong/sysmon-modular. How to test detection? You can check powershell script from this site https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575'
detection:
    selection:
        PipeName|contains: '\coerced\'
    condition: selection
falsepositives:
    - Unknown
level: high
