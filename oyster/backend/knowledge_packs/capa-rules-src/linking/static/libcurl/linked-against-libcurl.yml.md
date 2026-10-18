<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/linking/static/libcurl/linked-against-libcurl.yml -->
rule:
  meta:
    name: linked against libcurl
    namespace: linking/static/libcurl
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: file
      dynamic: file
    examples:
      - A90E5B3454AA71D9700B2EA54615F44B
  features:
    - or:
      - substring: "CLIENT libcurl"
      - substring: "curl.haxx.se"
