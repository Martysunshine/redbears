<!-- source: https://github.com/LOLBAS-Project/LOLBAS/blob/a2784c79091cb282fefb68f0056a853cfafd7e3c/yml/OtherMSBinaries/AppLauncher.yml -->
---
Name: AppLauncher.exe
Description: User Experience Virtualization tool that launches applications under monitoring to capture and synchronize user settings.
Author: Avihay Eldad
Created: 2025-09-21
Commands:
  - Command: AppLauncher.exe {PATH_ABSOLUTE:.exe}
    Description: Launches an executable via User Experience Virtualization tool.
    Usecase: Executes an executable under a trusted, Microsoft signed binary.
    Category: Execute
    Privileges: User
    MitreID: T1127
    OperatingSystem: Windows
    Tags:
      - Execute: EXE
Full_Path:
  - Path: C:\Program Files\Windows Kits\10\Microsoft User Experience Virtualization\Management\AppLauncher.exe
  - Path: C:\Program Files (x86)\Windows Kits\10\Microsoft User Experience Virtualization\Management\AppLauncher.exe
Resources:
  - Link: https://learn.microsoft.com/en-us/microsoft-desktop-optimization-pack/ue-v/uev-getting-started
Acknowledgement:
  - Person: Avihay Eldad
    Handle: '@AvihayEldad'
