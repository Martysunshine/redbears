<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/compiler/zig/compiled-with-zig.yml -->
rule:
  meta:
    name: compiled with Zig
    namespace: compiler/zig
    authors:
      - jakub.jozwiak@mandiant.com
    scopes:
      static: file
      dynamic: file
    references:
      - https://ziglang.org
      - https://github.com/ziglang/zig
    examples:
      - 74e0758e469ab87f38cda7925d696ea41a122364891860e1ae30fc9ff2f68e7d
  features:
    - 2 or more:
      - string: "ZIG_DEBUG_COLOR"
      - string: "Panicked during a panic. Aborting."
      - string: "error.Unexpected NTSTATUS=0x{x}"
      - string: "Unable to dump stack trace: debug info stripped"
      - string: "Unable to dump stack trace: Unable to open debug info: {s}"
      - string: "Unable to dump stack trace: {s}"
      - string: "std.mem.Allocator.alloc"
      - string: "_std.os.getenv"
      - string: "\\\\.\\pipe\\zig-childprocess-{d}-{d}"
