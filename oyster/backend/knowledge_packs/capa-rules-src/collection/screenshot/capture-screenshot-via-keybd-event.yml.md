<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/screenshot/capture-screenshot-via-keybd-event.yml -->
rule:
  meta:
    name: capture screenshot via keybd event
    namespace: collection/screenshot
    authors:
      - "@_re_fox"
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Collection::Screen Capture [T1113]
    mbc:
      - Collection::Screen Capture [E1113]
    examples:
      - 3f3bbcf8fd90bdcdcdc5494314ed4225:0x402D10
  features:
    - and:
      - or:
        # static
        - basic block:
          - and:
            - number: 0x2C = VK_SNAPSHOT
            - count(api(user32.keybd_event)): 2
            - or:
              - number: 0x3 = KEYEVENTF_KEYUP|KEYEVENTF_EXTENDEDKEY
              - number: 0x2 = KEYEVENTF_KEYUP
        # dynamic
        - call:
          - and:
            - number: 0x2C = VK_SNAPSHOT
            - count(api(user32.keybd_event)): 2
            - or:
              - number: 0x3 = KEYEVENTF_KEYUP|KEYEVENTF_EXTENDEDKEY
              - number: 0x2 = KEYEVENTF_KEYUP
      - match: read clipboard data
      - match: open clipboard
