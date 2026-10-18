<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/process_creation/proc_creation_win_powershell_get_localgroup_member_recon.yml -->
title: Suspicious Reconnaissance Activity Using Get-LocalGroupMember Cmdlet
id: c8a180d6-47a3-4345-a609-53f9c3d834fc
related:
    - id: cef24b90-dddc-4ae1-a09a-8764872f69fc
      type: similar
status: test
description: Detects suspicious reconnaissance command line activity on Windows systems using the PowerShell Get-LocalGroupMember Cmdlet
references:
    - https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-10
tags:
    - attack.discovery
    - attack.t1087.001
logsource:
    category: process_creation
    product: windows
detection:
    # Covers group and localgroup flags
    selection_cmdlet:
        CommandLine|contains: 'Get-LocalGroupMember '
    selection_group:
        CommandLine|contains:
            # Add more groups for other languages
            - 'domain admins'
            - ' administrator' # Typo without an 'S' so we catch both
            - ' administrateur' # Typo without an 'S' so we catch both
            - 'enterprise admins'
            - 'Exchange Trusted Subsystem'
            - 'Remote Desktop Users'
            - 'Utilisateurs du Bureau à distance' # French for "Remote Desktop Users"
            - 'Usuarios de escritorio remoto' # Spanish for "Remote Desktop Users"
    condition: all of selection_*
falsepositives:
    - Administrative activity
level: medium
