<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/password-manager/steal-keepass-passwords-using-keefarce.yml -->
rule:
  meta:
    name: steal KeePass passwords using KeeFarce
    namespace: collection/password-manager
    authors:
      - "@Ana06"
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Credential Access::Credentials from Password Stores::Password Managers [T1555.005]
    references:
      - https://github.com/denandz/KeeFarce
      - https://keepass.info/help/kb/sec_issues.html
    examples:
      - 1e609dffd12a59ea5d5c9b3055939b1f
  features:
    - and:
      - match: inject dll
      - string: /KeePass/i
      - optional:
        - substring: "Bootstrap"
        - substring: "KeeFarce"
