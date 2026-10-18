<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/builtin/openssh/win_sshd_openssh_server_listening_on_socket.yml -->
title: OpenSSH Server Listening On Socket
id: 3ce8e9a4-bc61-4c9b-8e69-d7e2492a8781
status: test
description: Detects scenarios where an attacker enables the OpenSSH server and server starts to listening on SSH socket.
references:
    - https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/tree/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH
    - https://winaero.com/enable-openssh-server-windows-10/
    - https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse
    - https://virtualizationreview.com/articles/2020/05/21/ssh-server-on-windows-10.aspx
    - https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16
author: mdecrevoisier
date: 2022-10-25
tags:
    - attack.lateral-movement
    - attack.t1021.004
logsource:
    product: windows
    service: openssh
detection:
    selection:
        EventID: 4
        process: sshd
        payload|startswith: 'Server listening on '
    condition: selection
falsepositives:
    - Legitimate administrator activity
level: medium
