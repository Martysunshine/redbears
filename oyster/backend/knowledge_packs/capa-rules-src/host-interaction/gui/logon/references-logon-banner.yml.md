<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/gui/logon/references-logon-banner.yml -->
rule:
  meta:
    name: references logon banner
    namespace: host-interaction/gui/logon
    authors:
      - "@_re_fox"
    scopes:
      static: basic block
      dynamic: span of calls
    examples:
      - c3341b7dfbb9d43bca8c812e07b4299f:0x4066FC
  features:
    - and:
      - substring: "\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
      - or:
        - substring: "LegalNoticeCaption"
        - substring: "LegalNoticeText"
