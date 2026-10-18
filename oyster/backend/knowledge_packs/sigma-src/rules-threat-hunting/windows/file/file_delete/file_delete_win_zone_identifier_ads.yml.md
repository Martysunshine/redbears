<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules-threat-hunting/windows/file/file_delete/file_delete_win_zone_identifier_ads.yml -->
title: ADS Zone.Identifier Deleted
id: 7eac0a16-5832-4e81-865f-0268a6d19e4b
related:
    - id: 3109530e-ab47-4cc6-a953-cac5ebcc93ae
      type: similar
status: test
description: Detects the deletion of the "Zone.Identifier" ADS. Attackers can leverage this in order to bypass security restrictions that make use of the ADS such as Microsoft Office apps.
references:
    - https://securityliterate.com/how-malware-abuses-the-zone-identifier-to-circumvent-detection-and-analysis/
author: frack113
date: 2023-09-04
tags:
    - attack.stealth
    - attack.t1070.004
    - detection.threat-hunting
logsource:
    product: windows
    category: file_delete
detection:
    selection:
        TargetFilename|endswith: ':Zone.Identifier'
    condition: selection
falsepositives:
    - Likely
level: low
