<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_vscode_tunnel_remote_creation_artefacts.yml -->
title: Visual Studio Code Tunnel Remote File Creation
id: 56e05d41-ce99-4ecd-912d-93f019ee0b71
status: test
description: |
    Detects the creation of file by the "node.exe" process in the ".vscode-server" directory. Could be a sign of remote file creation via VsCode tunnel feature
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-10-25
tags:
    - attack.command-and-control
logsource:
    category: file_event
    product: windows
detection:
    selection:
        Image|contains: '\servers\Stable-'
        Image|endswith: '\server\node.exe'
        TargetFilename|contains: '\.vscode-server\data\User\History\'
    condition: selection
falsepositives:
    - Unknown
level: medium
