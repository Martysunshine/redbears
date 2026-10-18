<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/software/get-installed-programs.yml -->
rule:
  meta:
    name: get installed programs
    namespace: host-interaction/software
    authors:
      - moritz.raabe@mandiant.com
      - "@_re_fox"
    scopes:
      static: function
      dynamic: unsupported  # requires characteristic features
    att&ck:
      - Discovery::Software Discovery [T1518]
    examples:
      - 7204e3efc2434012e13ca939db0d0b02:0x00412760
  features:
    - and:
      - match: create or open registry key
      - string: /SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall/i
      - characteristic: loop
      - optional:
        - string: "DisplayName"
