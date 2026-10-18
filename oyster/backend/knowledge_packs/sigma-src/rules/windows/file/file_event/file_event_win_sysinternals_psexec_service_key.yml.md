<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_sysinternals_psexec_service_key.yml -->
title: PSEXEC Remote Execution File Artefact
id: 304afd73-55a5-4bb9-8c21-0b1fc84ea9e4
status: test
description: Detects creation of the PSEXEC key file. Which is created anytime a PsExec command is executed. It gets written to the file system and will be recorded in the USN Journal on the target system
references:
    - https://aboutdfir.com/the-key-to-identify-psexec/
    - https://twitter.com/davisrichardg/status/1616518800584704028
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-21
modified: 2023-02-23
tags:
    - attack.lateral-movement
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.t1136.002
    - attack.t1543.003
    - attack.t1570
    - attack.s0029
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|startswith: 'C:\Windows\PSEXEC-'
        TargetFilename|endswith: '.key'
    condition: selection
falsepositives:
    - Unlikely
level: high
