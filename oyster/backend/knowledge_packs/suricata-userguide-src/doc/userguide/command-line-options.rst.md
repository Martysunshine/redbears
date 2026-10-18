<!-- source: https://github.com/OISF/suricata/blob/9a2b7004716b750f390ee52cf6053c97398d7af3/doc/userguide/command-line-options.rst -->
Command Line Options
====================

.. toctree::

Suricata's command line options:

.. include:: partials/options.rst

Unit Tests
~~~~~~~~~~

The builtin unittests are only available when Suricata has been configured and built with
``--enable-unittests``.

Running unittests does not require a configuration file. Use -l to supply
an output directory.::

    sudo suricata -u

.. include:: partials/options-unittests.rst
