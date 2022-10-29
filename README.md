windbglib
=========

Public repository for windbglib, a wrapper around pykd.pyd (for Windbg), used by mona.py


Installation
------------
To get mona.py up and running under WinDBG, please follow these steps:

### Windows 7 and up, 64bit (WinDBG x86 32 bit)
1. Download pykd.zip from https://github.com/corelan/windbglib/raw/master/pykd/pykd.zip and save it to a temporary location on your computer
2. Check the properties of the file and "Unblock" the file if necessary.
3. Extract the archive. You should get 2 files: pykd.pyd and vcredist_x86.exe
4. Run vcredist_x86.exe with administrator privileges and accept the default values.
5. Copy pykd.pyd to `C:\Program Files (x86)\Windows Kits\8.0\Debuggers\x86\winext` or `C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\winext`
6. Open a command prompt with administrator privileges and run the following commands:

   ```
   c:
   cd "C:\Program Files (x86)\Common Files\Microsoft Shared\VC"
   regsvr32 msdia90.dll
   (You should get a messagebox indicating that the dll was registered successfully)
   ```

7. Download windbglib.py from https://github.com/corelan/windbglib/raw/master/windbglib.py 
8. Save the file under `C:\Program Files (x86)\Windows Kits\8.0\Debuggers\x86` or `C:\Program Files (x86)\Windows Kits\10\Debuggers\x86`   ("Unblock" the file if necessary)
9. Download mona.py from https://github.com/corelan/mona/raw/master/mona.py  
10. Save mona.py under `C:\Program Files (x86)\Windows Kits\8.0\Debuggers\x86` or `C:\Program Files (x86)\Windows Kits\10\Debuggers\x86`   ("Unblock" the file if necessary)


---

### Windows 7 and up, 64bit (WinDBG 64 bit)
#### Install x64 python and pip
Python 2.7
1. Install a recent 64bit version of Python 2.7.x (2.7.14 or higher), verify that it is going to be the default python version.  (Adjust system path if needed) 
2. Install pip:
- Download file get-pip.py from https://bootstrap.pypa.io/pip/2.7/get-pip.py
- Run `python get-pip.py` from an administrator command prompt.
- If needed, add `c:\Python27\Scripts` to the PATH System environment variable. Close the command prompt and open a new administrator command prompt.

Python 3.x
1. Install a recent 64bit version of Python 3.x, verify that it is going to be the default python version.  (Adjust system path if needed) 
2. Install pip:
- Download file get-pip.py from https://bootstrap.pypa.io/get-pip.py
- Run `python get-pip.py`
- If needed, add `c:\Python3\Scripts` to the PATH System environment variable  (check the actual folder name!)

#### Install pykd via pip
1. Open https://pypi.org/project/pykd/0.3.4.15/#files and check the pip command at the top of the page. Take note of the pykd version that is being mentioned (for instance, 0.3.4.15)
2. Run `pip install pykd==0.3.4.15` from an administrator command prompt  (replace 0.3.4.15 with the version that is indicated on the page)

#### Install windbglig and mona

1. Download windbglib.py from https://github.com/corelan/windbglib/raw/master/windbglib.py 
2. Save the file under `C:\Program Files (x86)\Windows Kits\8.0\Debuggers\x64` or `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64`   ("Unblock" the file if necessary)
3. Download mona.py from https://github.com/corelan/mona/raw/master/mona.py  
4. Save mona.py under `C:\Program Files (x86)\Windows Kits\8.0\Debuggers\x64` or `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64`   ("Unblock" the file if necessary)
5. Run windbg.exe from  `C:\Program Files (x86)\Windows Kits\8.0\Debuggers\x64` or `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64`  


---

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
   (You should get a messagebox indicating that the dll was registered successfully)
   ```

7. Download windbglib.py from https://github.com/corelan/windbglib/raw/master/windbglib.py 
8. Save the file under `C:\Program Files\Debugging Tools for Windows (x86)`   ("Unblock" the file if necessary)
9. Download mona.py from https://github.com/corelan/mona/raw/master/mona.py  
10. Save the file under `C:\Program Files\Debugging Tools for Windows (x86)`   ("Unblock" the file if necessary)



Running
--------
Open Windbg and execute the following command: `.load pykd.pyd`

mona commands can the be accessed by running `!py mona`


More info
----------
For more info on using mona.py, consider taking a Corelan Training: https://www.corelan-training.com


Notes
-----
1. Make sure your symbol path is set up correctly (if you don't know how to do ths, mona.py will do this for you the first time you run the script)
2. Make sure (at least) the symbols for ntdll.dll are downloaded/available on your system.
   If your machine is connected to the internet, windbg will do this automatically the first time you run mona.py
   When the files are downloaded, you could disconnect the system from the internet if you would like to.
