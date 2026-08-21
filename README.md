
Build in Linux using build_loader.sh 
(exe only)
or

use VS...

Project Included!


**Also included Silent (Production) Loader - contains zero debug, terminal output, no comments plus hide console**


**NEW DLL Version**




   ```bash
 * EvasiveLoader - A C# loader that decrypts and injects shellcode into a suspended process.
 * 
 * This loader performs the following steps:
 * 1. Decrypts an embedded AES-encrypted payload (shellcode).
 * 2. Patches AMSI and ETW to evade detection.
 * 3. Creates a suspended process (default: notepad.exe) with PPID spoofing to explorer.exe.
 * 4. Allocates memory in the target process, writes the shellcode, and changes memory protection to executable.
 * 5. Queues an APC to execute the shellcode in the context of the target process.
```
