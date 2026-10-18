<!-- source: https://github.com/Azure/Azure-Sentinel/blob/f57d4b0ba1a8e04726d1adec5a370a608878f646/Detections/AzureAppServices/AVScan_Infected_Files_Found.yaml -->
id: 9d0295ee-cb75-4f2c-9952-e5acfbb67036
name: AppServices AV Scan with Infected Files
description: |
  'Identifies if an AV scan finds infected files in Azure App Services.'
severity: Informational
requiredDataConnectors: []
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 1
query: |
  let timeframe = ago(1d);
  AppServiceAntivirusScanAuditLogs
  | where NumberOfInfectedFiles > 0
  | extend timestamp = TimeGenerated
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: AzureID
        columnName: _ResourceId
version: 1.0.3
kind: Scheduled
metadata:
    source:
        kind: Community
    author:
        name: SecurityJedi
    support:
        tier: Community
    categories:
        domains: [ "Security - Others", "Platform" ]