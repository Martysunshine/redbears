<!-- source: https://github.com/LOLBAS-Project/LOLBAS/blob/a2784c79091cb282fefb68f0056a853cfafd7e3c/yml/OtherMSBinaries/Mpiexec.yml -->
---
Name: Mpiexec.exe
Description: Command-line tool for running Message Passing Interface (MPI) applications.
Author: Avihay Eldad
Created: 2025-09-25
Commands:
  - Command: mpiexec.exe {CMD}
    Description: Executes a command via MPI command-line tool.
    Usecase: Executes commands under a trusted, Microsoft signed binary.
    Category: Execute
    Privileges: User
    MitreID: T1127
    OperatingSystem: Windows
    Tags:
      - Execute: CMD
Full_Path:
  - Path: C:\Program Files\Microsoft MPI\Bin\mpiexec.exe
  - Path: C:\Program Files (x86)\Microsoft MPI\Bin\mpiexec.exe
Resources:
  - Link: https://learn.microsoft.com/en-us/powershell/high-performance-computing/mpiexec
Acknowledgement:
  - Person: Avihay Eldad
    Handle: '@AvihayEldad'
