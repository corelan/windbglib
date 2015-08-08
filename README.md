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

   ```
c:
cd "C:\Program Files (x86)\Common Files\Microsoft Shared\VC"
regsvr32 msdia90.dll
   ```
   (You should get a messagebox indicating that the dll was registered successfully)
7. Download windbglib.py from https://github.com/corelan/windbglib/raw/master/windbglib.py 
8. Save the file under `C:\Program Files (x86)\Windows Kits\8.0\Debuggers\x86`   ("Unblock" the file if necessary)
9. Download mona.py from https://github.com/corelan/mona/raw/master/mona.py  
10. Save the file under `C:\Program Files (x86)\Windows Kits\8.0\Debuggers\x86`   ("Unblock" the file if necessary)


### Windows XP, 32bit
1. Download pykd.zip from https://github.com/corelan/windbglib/raw/master/pykd/pykd.zip and save it to a temporary location on your computer
2. Check the properties of the file and "Unblock" the file if necessary.
3. Extract the archive. You should get 2 files: pykd.pyd and vcredist_x86.exe
4. Run vcredist_x86.exe with administrator privileges and accept the default values.
5. Copy pykd.pyd to `C:\Program Files\Debugging Tools for Windows (x86)\winext`
6. Open a command prompt with administrator privileges and run the following commands:

   ```
c:
cd "C:\Program Files\Common Files\Microsoft Shared\VC"
regsvr32 msdia90.dll
   ```
   (You should get a messagebox indicating that the dll was registered successfully)
7. Download windbglib.py from https://github.com/corelan/windbglib/raw/master/windbglib.py 
8. Save the file under `C:\Program Files\Debugging Tools for Windows (x86)`   ("Unblock" the file if necessary)
9. Download mona.py from https://github.com/corelan/mona/raw/master/mona.py  
10. Save the file under `C:\Program Files\Debugging Tools for Windows (x86)`   ("Unblock" the file if necessary)


Running
--------
Open Windbg and execute the following command: `.load pykd.pyd`

mona commands can the be accessed by running `!py mona`


Notes
-----
1. Make sure your symbol path is set up correctly (if you don't know how to do ths, mona.py will do this for you the first time you run the script)
2. Make sure (at least) the symbols for ntdll.dll are downloaded/available on your system.
   If your machine is connected to the internet, windbg will do this automatically the first time you run mona.py
   When the files are downloaded, you could disconnect the system from the internet if you would like to.