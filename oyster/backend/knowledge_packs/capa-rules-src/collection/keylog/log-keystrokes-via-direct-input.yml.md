<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/keylog/log-keystrokes-via-direct-input.yml -->
rule:
  meta:
    name: log keystrokes via direct input
    namespace: collection/keylog
    authors:
      - zeze-zeze
    scopes:
      static: function
      dynamic: call
    att&ck:
      - Collection::Input Capture::Keylogging [T1056.001]
    examples:
      - 0db010298586f17ee7e46f390d5724be.exe_:0x140001680
  features:
    - or:
      - api: dinput8.DirectInput8Create
      - api: dinput.DirectInputCreateEx
      - api: dinput.DirectInputCreateW
      - api: dinput.DirectInputCreateA
