<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/group-policy/discover-group-policy-via-gpresult.yml -->
rule:
  meta:
    name: discover Group Policy via gpresult
    namespace: collection/group-policy
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::Group Policy Discovery [T1615]
    examples:
      - 9e4d06759f278255073f9ac7b31a115a:0x100068B7
  features:
    - and:
      - os: windows
      - or:
        - substring: "gpresult"
        - substring: "GPRESULT"
