<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/persistence/service/persist-via-rc-script.yml -->
rule:
  meta:
    name: persist via rc script
    namespace: persistence/service
    authors:
      - joakim@intezer.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Persistence::Boot or Logon Initialization Scripts::RC Scripts [T1037.004]
    examples:
      - 7351f8a40c5450557b24622417fc478d:0x407D11
  features:
    - and:
      - os: linux
      - match: host-interaction/file-system/write
      - or:
        - substring: "/etc/init.d/"
        - string: /\/etc\/rc[0-9]\.d\//
