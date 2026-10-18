<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/executable/installer/inno-setup/packaged-as-an-inno-setup-installer.yml -->
rule:
  meta:
    name: packaged as an Inno Setup installer
    namespace: executable/installer/inno-setup
    authors:
      - awillia2@cisco.com
    scopes:
      static: file
      dynamic: file
    references:
      - https://jrsoftware.org/isinfo.php
    examples:
      - 70FD3347786ED7A4A43910E6778EF296
  features:
    - and:
      - string: /^Inno Setup Setup Data \(/
      - string: /^Inno Setup Messages \(/
