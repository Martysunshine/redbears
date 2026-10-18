<!-- source: https://github.com/SigmaHQ/sigma/blob/4faa9d9d378f726638eb1284e6efd53f1990ee82/rules/application/kubernetes/audit/kubernetes_audit_rolebinding_modification.yml -->
title: Kubernetes Rolebinding Modification
id: 10b97915-ec8d-455f-a815-9a78926585f6
related:
    - id: 0322d9f2-289a-47c2-b5e1-b63c90901a3e
      type: similar
status: test
description: |
    Detects when a Kubernetes Rolebinding is created or modified.
references:
    - https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
    - https://medium.com/@seifeddinerajhi/kubernetes-rbac-privilege-escalation-exploits-and-mitigations-26c07629eeab
author: kelnage
date: 2024-07-11
tags:
    - attack.privilege-escalation
logsource:
    product: kubernetes
    service: audit
detection:
    selection:
        objectRef.apiGroup: 'rbac.authorization.k8s.io'
        objectRef.resource:
            - 'clusterrolebindings'
            - 'rolebindings'
        verb:
            - 'create'
            - 'delete'
            - 'patch'
            - 'replace'
            - 'update'
    condition: selection
falsepositives:
    - Modifying a Kubernetes Rolebinding may need to be done by a system administrator.
    - Automated processes may need to take these actions and may need to be filtered.
level: medium
