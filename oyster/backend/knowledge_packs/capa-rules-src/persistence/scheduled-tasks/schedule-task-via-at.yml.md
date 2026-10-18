<!-- source: https://github.com/mandiant/capa-rules/blob/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5/persistence/scheduled-tasks/schedule-task-via-at.yml -->
rule:
  meta:
    name: schedule task via at
    namespace: persistence/scheduled-tasks
    authors:
      - joren485
    scopes:
      static: function
      dynamic: call
    att&ck:
      - Persistence::Scheduled Task/Job::At [T1053.002]
    examples:
      - 0ce3bfa972ced61884ae7c1d77c7d4c45e17c7d767e669610cf2ef72b636b464:0x4051AF
  features:
    - and:
      - match: host-interaction/process/create
      - string: /at(|\.exe)/i
      - or:
        - string: "//every:/i"
        - string: "//next:/i"
        - string: "/\\d:\\d/i"
