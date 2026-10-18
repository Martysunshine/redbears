<!-- source: https://github.com/OISF/suricata/blob/9a2b7004716b750f390ee52cf6053c97398d7af3/doc/userguide/lua/libs/config.rst -->
Config Library
##############

The config library provides access to Suricata configuration settings.

To use this library, you must require it::

  local config = require("suricata.config")

Functions
*********

``log_path()``
==============

Returns the configured log directory path.

Example::

  local config = require("suricata.config")

  local log_path, err = config.log_path()
  if log_path == nil then
     print("failed to get log path " .. err)
  end
