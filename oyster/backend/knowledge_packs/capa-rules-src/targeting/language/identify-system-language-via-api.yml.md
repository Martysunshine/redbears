<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/targeting/language/identify-system-language-via-api.yml -->
rule:
  meta:
    name: identify system language via API
    namespace: targeting/language
    authors:
      - william.ballenthin@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Discovery::System Location Discovery::System Language Discovery [T1614.001]
    examples:
      - 9b7ccaa2ae6a5b96e3110ebcbc4311f6:0x10001F96
  features:
    - and:
      - os: windows
      - or:
        - api: GetUserDefaultUILanguage
        - api: GetSystemDefaultUILanguage
        - api: GetUserDefaultLangID
