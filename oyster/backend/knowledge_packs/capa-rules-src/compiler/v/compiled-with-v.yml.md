<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/compiler/v/compiled-with-v.yml -->
rule:
  meta:
    name: compiled with V
    namespace: compiler/v
    authors:
      - jakub.jozwiak@mandiant.com
    scopes:
      static: file
      dynamic: file
    references:
      - https://vlang.io
      - https://github.com/vlang/v
    examples:
      - e87076a1182ba40758e1d7258442c1ee23bf71ac77fad9f3babc707dce11c144
  features:
    - or:
      - string: "================ V panic ================"
      - string: "V_RESOURCE_PATH"
      - 5 or more:
        - substring: "v_error:"
        - substring: "v_exit:"
        - substring: "v_free:"
        - substring: "v_malloc:"
        - substring: "v_panic"
        - substring: "v_realloc"
