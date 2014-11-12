windbglib
=========

Public repository for windbglib, a wrapper around pykd.pyd (for Windbg), used by mona.py


Installation
------------
To get mona.py up and running under WinDBG, please follow these steps:

### Windows 7, 64bit
1. Download pykd.zip from https://github.com/corelan/windbglib/raw/master/pykd/pykd.zip and save it to a temporary location on your computer
2. Check the properties of the file and "Unblock" the file if necessary.
3. Extract the archive. You should get 2 files: pykd.pyd and vcredist_x86.exe
4. Run vcredist_x86.exe with administrator privileges and accept the default values.
5. Copy pykd.pyd to `C:\Program Files (x86)\Windows Kits\8.0\Debuggers\x86\winext`
6. Open a command prompt with administrator privileges and run the following commands:

   ```c:
cd "C:\Program Files (x86)\Common Files\Microsoft Shared\VC"
regsvr32 msdia90.dll
   ```
   (You should get a messagebox indicating that the dll was registered successfully)
7. Download windbglib.py from https://github.com/corelan/windbglib/raw/master/windbglib.py 
8. Save the file under `C:\Program Files (x86)\Windows Kits\8.0\Debuggers\x86`   (“Unblock” the file if necessary)
9. Download mona.py from https://github.com/corelan/mona/raw/master/mona.py  
10. Save the file under `C:\Program Files (x86)\Windows Kits\8.0\Debuggers\x86`   (“Unblock” the file if necessary)
