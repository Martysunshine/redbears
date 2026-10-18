<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/host-interaction/session/get-current-user-on-linux.yml -->
rule:
  meta:
    name: get current user on Linux
    namespace: host-interaction/session
    authors:
      - joakim@intezer.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::System Owner/User Discovery [T1033]
    examples:
      - 7351f8a40c5450557b24622417fc478d:0x405438
  features:
    - and:
      - or:
        - os: linux
        - os: android
      - or:
        - api: geteuid
        - api: getpwuid
        - api: getlogin
        - api: getlogin_r
        - api: cuserid
