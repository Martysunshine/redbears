<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/network/domain/get-domain-controller-name.yml -->
rule:
  meta:
    name: get domain controller name
    namespace: host-interaction/network/domain
    authors:
      - awillia2@cisco.com
    description: Looks for calls to Windows APIs that can be used to determine the name of the domain controller for a Windows domain that a computer is connected to.
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::System Network Configuration Discovery [T1016]
    references:
      - https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netgetdcname
      - https://docs.microsoft.com/en-us/windows/win32/api/dsgetdc/nf-dsgetdc-dsgetdcnamea
      - https://chuongdong.com/reverse%20engineering/2021/05/23/MountLockerRansomware/
    examples:
      - 3808f21e56dede99bc914d90aeabe47a:0x140007144
  features:
    - and:
      - or:
        - api: NetGetDCName
        - api: DsGetDcName
      - optional:
        - api: NetApiBufferFree
