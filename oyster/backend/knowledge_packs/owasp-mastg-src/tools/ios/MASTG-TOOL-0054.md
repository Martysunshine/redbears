<!-- source: https://github.com/OWASP/mastg/blob/0e88142b5d7aad8f052b4e75199a8aad9b89d5b5/tools/ios/MASTG-TOOL-0054.md -->
---
title: ios-deploy
platform: ios
source: https://github.com/ios-control/ios-deploy
---

With ios-deploy you can install and debug iOS apps from the command line, without using Xcode. It can be installed via brew on macOS:

```bash
brew install ios-deploy
```

Alternatively:

```bash
git clone https://github.com/ios-control/ios-deploy.git
cd ios-deploy/
xcodebuild
cd build/Release
./ios-deploy
ln -s <your-path-to-ios-deploy>/build/Release/ios-deploy /usr/local/bin/ios-deploy
```

The last line creates a symbolic link and makes the executable available system-wide. Reload your shell to make the new commands available:

```bash
zsh: # . ~/.zshrc
bash: # . ~/.bashrc
```
