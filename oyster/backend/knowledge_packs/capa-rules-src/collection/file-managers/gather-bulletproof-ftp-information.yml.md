<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/file-managers/gather-bulletproof-ftp-information.yml -->
rule:
  meta:
    name: gather bulletproof-ftp information
    namespace: collection/file-managers
    authors:
      - "@_re_fox"
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Credential Access::Credentials from Password Stores [T1555]
    references:
      - https://bpftp.com/
    examples:
      - 5a2f620f29ca2f44fc22df67b674198f:0x405CCA
  features:
    - or:
      - and:
        - string: ".dat"
        - string: ".bps"
      - and:
        - or:
          - substring: "Software\\BPFTP\\Bullet Proof FTP\\Main"
          - substring: "Software\\BulletProof Software\\BulletProof FTP Client\\Main"
          - substring: "Software\\BulletProof Software\\BulletProof FTP Client\\Options"
          - substring: "Software\\BPFTP\\Bullet Proof FTP\\Options"
          - substring: "Software\\BPFTP"
        - or:
          - string: "LastSessionFile"
          - string: "SitesDir"
