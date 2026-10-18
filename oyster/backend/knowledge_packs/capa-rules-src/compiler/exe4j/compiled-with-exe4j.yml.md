<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/compiler/exe4j/compiled-with-exe4j.yml -->
rule:
  meta:
    name: compiled with exe4j
    namespace: compiler/exe4j
    authors:
      - johnk3r
    scopes:
      static: file
      dynamic: file
    examples:
      - 6b25f1e754ef486bbb28a66d46bababe:0x404EDE
  features:
    - or:
      - string: "exe4j_log"
      - string: "install4j_log"
      - string: "exe4j_java_home"
      - string: "install4j"
      - string: "exe4j.isinstall4j"
      - string: /com/exe4j/runtime/exe4jcontroller/i
      - string: /com/exe4j/runtime/winlauncher/i
      - string: "EXE4J_LOG"
      - string: "INSTALL4J_LOG"
      - string: "EXE4J_JAVA_HOME"
      - string: "INSTALL4J"
      - string: "EXE4J.ISINSTALL4J"
