<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/environment-variable/get-comspec-environment-variable.yml -->
rule:
  meta:
    name: get COMSPEC environment variable
    namespace: host-interaction/environment-variable
    authors:
      - matthew.williams@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::System Information Discovery [T1082]
    mbc:
      - Operating System::Environment Variable [C0034]
    examples:
      - Practical Malware Analysis Lab 14-02.exe_:0x401880
  features:
    - and:
      - match: query environment variable
      - or:
        - string: "COMSPEC"
        - string: "%COMSPEC%"
