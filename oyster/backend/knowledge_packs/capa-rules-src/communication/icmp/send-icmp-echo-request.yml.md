<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/communication/icmp/send-icmp-echo-request.yml -->
rule:
  meta:
    name: send ICMP echo request
    namespace: communication/icmp
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    mbc:
      - Communication::ICMP Communication::Echo Request [C0014.002]
    references:
      - https://docs.microsoft.com/en-us/windows/win32/api/icmpapi/
    examples:
      - al-khaser_x86.exe_:0x449510
  features:
    - and:
      - or:
        - api: IcmpSendEcho
        - api: IcmpSendEcho2
        - api: IcmpSendEcho2Ex
        - api: Icmp6SendEcho2
      - optional:
        - or:
          - api: IcmpCreateFile
          - api: Icmp6CreateFile
        - api: IcmpCloseHandle
