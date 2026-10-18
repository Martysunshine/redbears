<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/executable/installer/iexpress/packaged-as-an-iexpress-self-extracting-archive.yml -->
rule:
  meta:
    name: packaged as an IExpress self-extracting archive
    namespace: executable/installer/iexpress
    authors:
      - awillia2@cisco.com
    scopes:
      static: file
      dynamic: file
    references:
      - https://en.wikipedia.org/wiki/IExpress
    examples:
      - ac742739cae0d411dfcb78ae99a7baee:0xA4C0 # wextract_cleanup%d
      - ac742739cae0d411dfcb78ae99a7baee:0xA488 # Software\Microsoft\Windows\CurrentVersion\RunOnce
      - ac742739cae0d411dfcb78ae99a7baee:0x34BA2 # '  <description>IExpress extraction tool</description>'
  features:
    - or:
      - and:
        - string: "wextract_cleanup%d"
        - string: "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
      - string: "  <description>IExpress extraction tool</description>"
