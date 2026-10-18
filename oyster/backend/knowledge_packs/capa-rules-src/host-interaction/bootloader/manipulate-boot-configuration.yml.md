<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/bootloader/manipulate-boot-configuration.yml -->
rule:
  meta:
    name: manipulate boot configuration
    namespace: host-interaction/bootloader
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    references:
      - https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdedit-command-line-options
    examples:
      - 7FBC17A09CF5320C515FC1C5BA42C8B3:0x40CA00
  features:
    - or:
      - and:
        - string: /bcdedit\.exe/i
        - optional:
          - string: "/deletevalue safeboot"
      - and:
        - string: /boot\.ini/i
        - optional:
          - api: kernel32.GetPrivateProfileStringA
          - api: kernel32.WritePrivateProfileString
          - or:
            - string: /default/i
            - string: /boot loader/i
            - string: /operating systems/i
