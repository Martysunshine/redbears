<!-- source: https://github.com/OWASP/mastg/blob/0e88142b5d7aad8f052b4e75199a8aad9b89d5b5/tools/ios/MASTG-TOOL-0059.md -->
---
title: optool
platform: ios
source: https://github.com/alexzielenski/optool
---

optool is a tool which interfaces with MachO binaries in order to insert/remove load commands, strip code signatures, resign, and remove aslr.

To install it:

```bash
git clone https://github.com/alexzielenski/optool.git
cd optool/
git submodule update --init --recursive
xcodebuild
ln -s <your-path-to-optool>/build/Release/optool /usr/local/bin/optool
```

The last line creates a symbolic link and makes the executable available system-wide. Reload your shell to make the new commands available:

```bash
zsh: # . ~/.zshrc
bash: # . ~/.bashrc
```
