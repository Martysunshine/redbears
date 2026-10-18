<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/persistence/registry/ginadll/persist-via-ginadll-registry-key.yml -->
rule:
  meta:
    name: persist via GinaDLL registry key
    namespace: persistence/registry/ginadll
    authors:
      - michael.hunhoff@fireye.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Persistence::Event Triggered Execution [T1546]
    examples:
      - Practical Malware Analysis Lab 11-01.exe_:0x401000
  features:
    - and:
      - or:
        - match: set registry value
        - number: 0x80000002 = HKEY_LOCAL_MACHINE
      - string: /SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon/i
      - string: /GinaDLL/i
