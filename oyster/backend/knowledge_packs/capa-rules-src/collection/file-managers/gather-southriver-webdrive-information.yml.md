<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/file-managers/gather-southriver-webdrive-information.yml -->
rule:
  meta:
    name: gather southriver-webdrive information
    namespace: collection/file-managers
    authors:
      - "@_re_fox"
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Credential Access::Credentials from Password Stores [T1555]
    references:
      - https://southrivertech.com/products/webdriveclient/
    examples:
      - 5a2f620f29ca2f44fc22df67b674198f:0x407F0C
  features:
    - or:
      - substring: "Software\\South River Technologies\\WebDrive\\Connections"
      - and:
        - string: "PassWord"
        - string: "UserName"
        - string: "RootDirectory"
        - string: "Port"
        - string: "ServerType"
