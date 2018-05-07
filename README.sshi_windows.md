# Installing sshi on Windows

ssh-inscribe client can be used on Windows workstation too.

## Installation instructions
1. Download the `sshi-windows-x86_64.exe` from [Releases](https://github.com/aakso/ssh-inscribe/releases)

2. Execute following commands in Powershell. Assuming the downloaded file is in the current directory.
```powershell
New-Item -Path 'C:\Program Files\ssh-inscribe\' -ItemType Directory
Copy-Item sshi-windows-x86_64.exe -Destination 'C:\Program Files\ssh-inscribe\sshi.exe'
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files\ssh-inscribe", [System.EnvironmentVariableTarget]::Machine)
```
3. You might also want to set sshi server url as persistent env variable
```powershell
[Environment]::SetEnvironmentVariable("SSH_INSCRIBE_URL", "https://server.name:8540", [System.EnvironmentVariableTarget]::Machine)
```
3. Relaunch Powershell

## Installing OpenSSH client for Windows

OpenSSH ssh-agent is required for to be able to store the generated
certificate for subsequent use. Enabling ssh-server is not required.

### Windows 10:

Please refer to this article: [Using the OpenSSH Beta in Windows 10 Fall Creators Update and Windows Server 1709](https://blogs.msdn.microsoft.com/powershell/2017/12/15/using-the-openssh-beta-in-windows-10-fall-creators-update-and-windows-server-1709/)

### Previous versions:

1. Download Microsoft's OpenSSH release: [Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH/releases)
2. Unpack the zip
3. Copy the `OpenSSH-Win64` folder to C:\Program Files
4. Add C:\Program Files to the path
5. Execute `install-sshd.ps1`
6. Set service 'ssh-agent' to Automatic and start the service