<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/windows/file/file_event/file_event_win_iso_file_recent.yml -->
title: ISO or Image Mount Indicator in Recent Files
id: 4358e5a5-7542-4dcb-b9f3-87667371839b
status: test
description: |
    Detects the creation of recent element file that points to an .ISO, .IMG, .VHD or .VHDX file as often used in phishing attacks.
    This can be a false positive on server systems but on workstations users should rarely mount .iso or .img files.
references:
    - https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/
    - https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/malicious-spam-campaign-uses-iso-image-files-to-deliver-lokibot-and-nanocore
    - https://blog.emsisoft.com/en/32373/beware-new-wave-of-malware-spreads-via-iso-file-email-attachments/
    - https://insights.sei.cmu.edu/blog/the-dangers-of-vhd-and-vhdx-files/
author: Florian Roth (Nextron Systems)
date: 2022-02-11
tags:
    - attack.initial-access
    - attack.t1566.001
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - '.iso.lnk'
            - '.img.lnk'
            - '.vhd.lnk'
            - '.vhdx.lnk'
        TargetFilename|contains: '\Microsoft\Windows\Recent\'
    condition: selection
falsepositives:
    - Cases in which a user mounts an image file for legitimate reasons
level: medium
