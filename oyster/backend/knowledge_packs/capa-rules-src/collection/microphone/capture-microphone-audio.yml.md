<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/collection/microphone/capture-microphone-audio.yml -->
rule:
  meta:
    name: capture microphone audio
    namespace: collection/microphone
    authors:
      - "@_re_fox"
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Collection::Audio Capture [T1123]
    examples:
      - a70052c45e907820187c7e6bcdc7ecca:0x405B40
  features:
    - or:
      - and:
        - api: mciSendString
        - string: /^open/i
        - string: /waveaudio/i
        - string: /^record/i
      - api: winmm.waveInOpen
      - api: winmm.waveInAddBuffer
      - api: winmm.waveInStart
