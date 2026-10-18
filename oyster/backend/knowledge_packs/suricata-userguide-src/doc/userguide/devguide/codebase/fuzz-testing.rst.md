<!-- source: https://github.com/OISF/suricata/blob/9a2b7004716b750f390ee52cf6053c97398d7af3/doc/userguide/devguide/codebase/fuzz-testing.rst -->
Fuzz Testing
============

To enable fuzz targets compilation, add `--enable-fuzztargets` to configure.

.. note:: This changes various parts of Suricata making the `suricata` binary
          unsafe for production use.

The targets can be used with libFuzzer, AFL and other fuzz platforms.


Running the Fuzzers
-------------------

TODO. For now see src/tests/fuzz/README

Reproducing issues
^^^^^^^^^^^^^^^^^^


Extending Coverage
------------------

Adding Fuzz Targets
-------------------


Oss-Fuzz
--------

Suricata is continuously fuzz tested in Oss-Fuzz. See https://github.com/google/oss-fuzz/tree/master/projects/suricata
