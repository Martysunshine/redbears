<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/persistence/persist-via-shell-profile-or-rc-file.yml -->
rule:
  meta:
    name: persist via shell profile or rc file
    namespace: persistence
    authors:
      - joakim@intezer.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Persistence::Event Triggered Execution::Unix Shell Configuration Modification [T1546.004]
    examples:
      - 7351f8a40c5450557b24622417fc478d:0x407D11
  features:
    - and:
      - os: linux
      - match: host-interaction/file-system/write
      - or:
        - substring: "/.bash_profile"
        - substring: "/.bash_login"
        - substring: "/.bashrc"
        - substring: "/.profile"
        - substring: "/etc/profile.d/"
        - string: "/etc/profile"
