"""
Copyright (c) 2011-2020, Peter Van Eeckhoutte - Corelan Consulting bv
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
	* Redistributions of source code must retain the above copyright
	  notice, this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright
	  notice, this list of conditions and the following disclaimer in the
	  documentation and/or other materials provided with the distribution.
	* Neither the name of Corelan nor the
	  names of its contributors may be used to endorse or promote products
	  derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL PETER VAN EECKHOUTTE OR CORELAN GCV BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

$Revision: 145 $
$Id: windbglib.py 145 2020-03-27 16:00:00Z corelanc0d3r $ 
"""

__VERSION__ = '1.0'

#
# Wrapper library around pykd
# (partial immlib logic port)
#
# This library allows you to run mona.py
# under WinDBG, using the pykd extension
#
import pykd
import os
import binascii
import struct
import traceback
import pickle
import ctypes
import array

global MemoryPages
global AsmCache
global OpcodeCache
global InstructionCache
global PageSections
global ModuleCache
global cpebaddress
global PEBModList 

arch = 32
cpebaddress = 0

PageSections = {}
ModuleCache = {}
PEBModList = {}

Registers32BitsOrder = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]
Registers64BitsOrder = ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
						"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"]

if pykd.is64bitSystem():
	arch = 64


# Utility functions

def getOSVersion():
	osversions = {}
	osversions["5.0"] = "2000"
	osversions["5.1"] = "xp"
	osversions["5.2"] = "2003"
	osversions["6.0"] = "vista"
	osversions["6.1"] = "win7"
	osversions["6.2"] = "win8"
	osversions["6.3"] = "win8.1"
	osversions["10.0"] = "win10"
	peb = getPEBInfo()
	majorversion = int(peb.OSMajorVersion)
	minorversion = int(peb.OSMinorVersion)
	thisversion = str(majorversion)+"." + str(minorversion)
	if thisversion in osversions:
		return osversions[thisversion]
	else:
		return "unknown"

def getArchitecture():
	if not pykd.is64bitSystem():
		return 32
	else:
		return 64

def getNtHeaders(modulebase):
	# http://www.nirsoft.net/kernel_struct/vista/IMAGE_DOS_HEADER.html
	# http://www.nirsoft.net/kernel_struct/vista/IMAGE_NT_HEADERS.html
	if getArchitecture() == 64:
		ntheaders = "_IMAGE_NT_HEADERS64"
	else:
		ntheaders = "_IMAGE_NT_HEADERS"

	# modulebase + 0x3c = IMAGE_DOS_HEADER.e_lfanew
	return pykd.module("ntdll").typedVar(ntheaders, modulebase + pykd.ptrDWord(modulebase + 0x3c))

def clearvars():
	global MemoryPages
	global AsmCache
	global OpcodeCache
	global InstructionCache
	global PageSections
	global ModuleCache
	global cpebaddress	
	MemoryPages = None
	AsmCache = None
	OpcodeCache = None
	InstructionCache = None
	InstructionCache = None
	PageSections = None
	ModuleCache = None
	cpebaddress = None
	return

def getPEBInfo():
	try:
		return pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())
	except:
		currversion = getPyKDVersion()
		print("")
		print(" Oops - It seems that PyKD was unable problem to get the PEB object.")
		print(" This usually means that")
		print("  1. msdiaxxx.dll has not been registered correctly    and/or")
		print("  2. symbols are missing for ntdll.dll")
		print("")
		print(" Possible solutions:")
		print(" -------------------")
		print(" 1. Re-register the VC runtime library:")
		print("    * For PyKd v%s:" % currversion)
		if currversion.startswith("0.2"):
			print("      (Re)Install the x86 VC++ Redistributable Package for Visual Studio 2008")
			print("       (https://www.microsoft.com/en-us/download/details.aspx?id=29)")
			print("      Next, run the following command from an administrator prompt:")
			print("        (x86) regsvr32.exe \"%ProgramFiles%\\Common Files\\microsoft shared\\VC\\msdia90.dll\"\n")
			print("        (x64) regsvr32.exe \"%ProgramFiles(x86)%\\Common Files\\microsoft shared\\VC\\msdia90.dll\"\n")
		else:
			print("      Either install Visual Studio 2013, or get a copy of msdia120.dll and register it manually\n")
			print("      You can find a copy of msdia120.dll inside the pykd.zip file inside the github repository")
			print("      (Use at your own risk!).  Place the file in the correct 'VC' folder and run regsvr32 from an administrative prompt:")
			print("        (x86) regsvr32.exe \"%ProgramFiles%\\Common Files\\microsoft shared\\VC\\msdia120.dll\"\n")
			print("        (x64) regsvr32.exe \"%ProgramFiles(x86)%\\Common Files\\microsoft shared\\VC\\msdia120.dll\"\n")

		print(" 2. Force download of the Symbols for ntdll.dll")
		print("    * Connect to the internet, and verify that the symbol path is configured correctly")
		print("      Assuming that the local symbol path is set to c:\\symbols,"  )
		print("      run the following command from within the windbg application folder")
		print("        symchk /r c:\\windows\\system32\\ntdll.dll /s SRV*c:\\symbols*http://msdl.microsoft.com/download/symbols")
		print("")
		print(" Restart windbg and try again")
		exit(1)

def getPEBAddress():
	global cpebaddress
	if cpebaddress ==  0:
		peb = getPEBInfo()
		cpebaddress = peb.getAddress()
	return cpebaddress

def getTEBInfo():
	return pykd.typedVar("_TEB", pykd.getImplicitThread())

def getTEBAddress():
	tebinfo = pykd.dbgCommand("!teb")
	if len(tebinfo) > 0:
		teblines = tebinfo.split("\n")
		tebline = teblines[0]
		tebparts = tebline.split(" ")
		if len(tebparts) > 2:
			return hexStrToInt(tebparts[2])
	# slow
	teb = getTEBInfo()
	return int(teb.Self)

def bin2hex(binbytes):
	"""
	Converts a binary string to a string of space-separated hexadecimal bytes.
	"""
	return ' '.join('%02x' % ord(c) for c in binbytes)

def hexptr2bin(hexptr):
	"""
	Input must be a int
	output : bytes in little endian
	"""
	return struct.pack('<L',hexptr)


def hexStrToInt(inputstr):
	"""
	Converts a string with hex bytes to a numeric value
	Arguments:
	inputstr - A string representing the bytes to convert. Example : 41414141

	Return:
	the numeric value
	"""
	valtoreturn = 0
	try:
		valtoreturn = int(inputstr,16)
	except:
		valtoreturn = 0
	return valtoreturn

def addrToInt(address):
	"""
	Convert a textual address to an integer

	Arguments:
	address - the address

	Return:
	int - the address value
	"""
	
	address = address.replace("\\x","")
	return hexStrToInt(address)

def isAddress(address):
	"""
	Check if a string is an address / consists of hex chars only

	Arguments:
	string - the string to check

	Return:
	Boolean - True if the address string only contains hex bytes
	"""
	address = address.replace("\\x","")
	if len(address) > 16:
		return False

	return set(address.upper()) <= set("ABCDEF1234567890")

def intToHex(address):
	if arch == 32:
		return "0x%08x" % address
	if arch == 64:
		return "0x%016x" % address

def toHexByte(n):
	"""
	Converts a numeric value to a hex byte

	Arguments:
	n - the vale to convert (max 255)

	Return:
	A string, representing the value in hex (1 byte)
	"""
	return "%02X" % n

def hex2bin(pattern):
	"""
	Converts a hex string (\\x??\\x??\\x??\\x??) to real hex bytes

	Arguments:
	pattern - A string representing the bytes to convert 

	Return:
	the bytes
	"""
	pattern = pattern.replace("\\x", "")
	pattern = pattern.replace("\"", "")
	pattern = pattern.replace("\'", "")
	return ''.join([binascii.a2b_hex(i+j) for i,j in zip(pattern[0::2],pattern[1::2])])


def getPyKDVersion():
	currentversion = pykd.version
	currversion = ""
	for versionpart in currentversion:
		if versionpart != " ":
			if versionpart == ",":
				currversion += "."
			else:
				currversion += str(versionpart)
	currversion = currversion.strip(".")
	return currversion

def isPyKDVersionCompatible(currentversion,requiredversion):
	# current version should be at least requiredversion
	if currentversion == requiredversion:
		return True
	else:
		currentparts = currentversion.split(".")
		requiredparts = requiredversion.split(".")
		if len(requiredparts) > len(currentparts):
			delta = len(requiredparts) - len(currentparts)
			cnt = 0
			while cnt < delta:
				currentparts.append("0")
				cnt += 1

		cnt = 0
		while cnt < len(requiredparts):
			if int(currentparts[cnt]) < int(requiredparts[cnt]):
				return False
			if int(currentparts[cnt]) > int(requiredparts[cnt]):
				return True
			cnt += 1
		return True
		
def checkVersion():
	pykdurl = "https://github.com/corelan/windbglib/raw/master/pykd/pykd.zip"
	pykdurl03 = "https://github.com/corelan/windbglib/raw/master/pykd/pykd03.zip"
	pykdversion_needed = "0.2.0.29"
	if arch == 64:
		pykdversion_needed = "0.2.0.29"
	currversion = getPyKDVersion()
	if not isPyKDVersionCompatible(currversion,pykdversion_needed):
		print("*******************************************************************************************")
		print("  You are running the wrong version of PyKD, please update ")
		print("   Installed version : %s " % currversion)
		print("   Required version : %s" % pykdversion_needed)
		print("  You can get an updated PyKD version from one of the following sources:")
		print("   - %s (preferred)" % pykdurl)
		print("     (unzip with 7zip)")
		print("   - http://pykd.codeplex.com (newer versions may not work !)")
		print("*******************************************************************************************")
		import sys
		sys.exit()
		return
	if pykdversion_needed != currversion:
		# version must be higher
		print("*******************************************************************************************")
		print(" You are running a newer version of pykd.pyd")
		print(" mona.py was tested against v%s" % pykdversion_needed)
		print(" and not against v%s" % currversion)
		print(" This version may not work properly.")
		print(" If you are having issues, I recommend to download the correct version from")
		print("   %s" % pykdurl)
		print("   (unzip with 7zip)")
		if currversion.startswith("0.3"):
			print("")
			print(" NOTE: PyKD v%s requires msdia120.dll, which only gets installed via Visual Studio 2013 (yup, I know)" % currversion)
			print(" Alternatively, you can use the copy of msdia120.dll from the pykd.pyd file")
			print("  (%s), but use this file at your own risk" % pykdurl03)
		print("*******************************************************************************************")
	return

def getModulesFromPEB():
	global PEBModList
	peb = getPEBInfo()
	imagenames = []
	# http://www.nirsoft.net/kernel_struct/vista/PEB.html
	# http://www.nirsoft.net/kernel_struct/vista/PEB_LDR_DATA.html
	# http://www.nirsoft.net/kernel_struct/vista/LDR_DATA_TABLE_ENTRY.html
	# The usage of _LDR_DATA_TABLE_ENTRY.SizeOfImage is very confusing and appears to actually contain the module base
	offset = 0x20
	if arch == 64:
		offset = 0x40
	moduleLst = pykd.typedVarList(peb.Ldr.deref().InLoadOrderModuleList, "ntdll!_LDR_DATA_TABLE_ENTRY", "InMemoryOrderLinks.Flink")
	if len(PEBModList) == 0:
		for mod in moduleLst:
			thismod = pykd.loadUnicodeString(mod.BaseDllName).encode("utf8")
			modparts = thismod.split("\\")
			modulename = modparts[len(modparts)-1]
			fullpath = thismod
			exename = modulename

			addtolist = True

			moduleparts = modulename.split(".")
			imagename = ""
			if len(moduleparts) == 1:
				imagename = moduleparts[0]
			cnt = 0
			while cnt < len(moduleparts)-1:
				imagename = imagename + moduleparts[cnt] + "."
				cnt += 1
			imagename = imagename.strip(".")

			# no windbg love for +  -  .
			imagename = imagename.replace("+","_")
			imagename = imagename.replace("-","_")
			imagename = imagename.replace(".","_")

			if imagename in imagenames:
				# duplicate name ?  Append _<baseaddress>
				# mod.getAddress() + offset = _LDR_DATA_TABLE_ENTRY.SizeOfImage
				baseaddy = int(pykd.ptrPtr(mod.getAddress() + offset))
				imagename = imagename+"_%08x" % baseaddy

			# check if module can be loaded
			try:
				modcheck = pykd.module(imagename)
			except:
				# change to image+baseaddress
				# mod.getAddress() + offset = _LDR_DATA_TABLE_ENTRY.SizeOfImage
				baseaddy = int(pykd.ptrPtr(mod.getAddress() + offset))
				imagename = "image%08x" % baseaddy
				try:
					modcheck = pykd.module(imagename)
				except:
					# try with base addy
					try:
						modcheck = pykd.module(baseaddy)
						imagename = modcheck.name()
						#print "Name: %s" % modcheck.name()
						#print "Imagename: %s" % modcheck.image()
					except:
						# try finding it with windbg 'ln'
						cmd2run = "ln 0x%08x" % baseaddy
						output = pykd.dbgCommand(cmd2run)
						if "!__ImageBase" in output:
							outputlines = output.split("\n")
							for l in outputlines:
								if "!__ImageBase" in l:
									lparts = l.split("!__ImageBase")
									leftpart = lparts[0]
									leftparts = leftpart.split(" ")
									imagename = leftparts[len(leftparts)-1]
						try:
							modcheck = pykd.module(imagename)
						except:
							print("")
							print("   *** Error parsing module '%s' ('%s') at 0x%08x ***" % (imagename,modulename,baseaddy))
							print("   *** Please open a github issue ticket at https://github.com/corelan/windbglib ***")
							print("   *** and provide the output of the following 2 windbg commands in the ticket: ***")
							print("         lm")
							print("         !peb")
							print("   *** Thanks")
							print("")
							addtolist = False

			if addtolist:
				imagenames.append(imagename)
				PEBModList[imagename] = [exename, fullpath]
	
	return moduleLst

def getModuleFromAddress(address):

	offset = 0x20
	if arch == 64:
		offset = 0x40

	global ModuleCache
	# try fastest way first
	try:
		thismod = pykd.module(address)
		# if that worked, we could add it to the cache if needed
		modbase = thismod.begin()
		modsize = thismod.size()
		modend = modbase + modsize
		modulename = thismod.image()
		ModuleCache[modulename] = [modbase,modsize]
		if (address >= modbase) and (address <= modend):
			return thismod
	except:
		pass


	# maybe cached	
	for modname in ModuleCache:
		modparts = ModuleCache[modname]
		# 0 : base
		# 1 : size
		modbase = modparts[0]
		modsize = modparts[1]
		modend = modbase + modsize
		if (address >= modbase) and (address <= modend):
			#print "0x%08x belongs to %s" % (address,modname)
			return pykd.module(modname)
	# not cached, find it
	moduleLst = getModulesFromPEB()
	for mod in moduleLst:
		thismod = pykd.loadUnicodeString(mod.BaseDllName).encode("utf8")
		modparts = thismod.split("\\")
		modulename = modparts[len(modparts)-1].lower()
		moduleparts = modulename.split(".")
		modulename = ""
		if len(moduleparts) == 1:
			modulename = moduleparts[0]
		cnt = 0
		while cnt < len(moduleparts)-1:
			modulename = modulename + moduleparts[cnt] + "."
			cnt += 1
		modulename = modulename.strip(".")
		thismod = ""
		imagename = ""

		try:
			moduleLst = getModulesFromPEB()
			for mod in moduleLst:
				thismod = pykd.loadUnicodeString(mod.BaseDllName).encode("utf8")
				modparts = thismod.split("\\")
				thismodname = modparts[len(modparts)-1]
				moduleparts = thismodname.split(".")
				if len(moduleparts) > 1:
					thismodname = ""
					cnt = 0
					while cnt < len(moduleparts)-1:
						thismodname = thismodname + moduleparts[cnt] + "."
						cnt += 1
					thismodname = thismodname.strip(".")					
				if thismodname.lower() == modulename.lower():
					# mod.getAddress() + offset = _LDR_DATA_TABLE_ENTRY.SizeOfImage
					baseaddy = int(pykd.ptrPtr(mod.getAddress() + offset))
					baseaddr = "%08x" % baseaddy
					lmcommand = pykd.dbgCommand("lm")
					lmlines = lmcommand.split("\n")
					foundinlm = False
					for lmline in lmlines:
						linepieces = lmline.split(" ")
						if linepieces[0].upper() == baseaddr.upper():
							cnt = 2
							while cnt < len(linepieces) and not foundinlm:
								if linepieces[cnt].strip(" ") != "":
									imagename = linepieces[cnt]
									foundinlm = True
									break
								cnt += 1
					if not foundinlm:
						imagename = "image%s" % baseaddr.lower()
						break
		except:
			pykd.dprintln(traceback.format_exc())

		try:
			modulename = imagename
			thismod = pykd.module(imagename)
			modbase = thismod.begin()
			modsize = thismod.size()
			modend = modbase + modsize
			ModuleCache[modulename] = [modbase,modsize]
			if (address >= modbase) and (address <= modend):
				return thismod
		except:
			thismod = pykd.module(address)

			modbase = thismod.begin()
			modsize = thismod.size()
			modend = modbase + modsize
			modulename = thismod.image()
			ModuleCache[modulename] = [modbase,modsize]
			if (address >= modbase) and (address <= modend):
				return thismod			

	return None

def getImageBaseOnDisk(fullpath):
	with open(fullpath, "rb") as pe: 
		data = pe.read()
		nt_header_offset = struct.unpack("<I", data[0x3c:0x40])[0]
		optional_header_offset = nt_header_offset + 0x18
		magic = struct.unpack("<H", data[optional_header_offset:optional_header_offset+2])[0]
		if magic == 0x10b:
			#32bit
			imageBase = struct.unpack("<I", data[optional_header_offset+28:optional_header_offset+28+4])[0]
		else:
			# 64bit
			imageBase = struct.unpack("<Q", data[optional_header_offset+24:optional_header_offset+24+8])[0]
	return imageBase



# Classes

class Debugger:

	MemoryPages = {}
	AsmCache = {}
	OpcodeCache = {} 

	def __init__(self):
		self.MemoryPages = {}
		self.AsmCache = {}
		self.allmodules = {}
		self.OpcodeCache = {}
		self.ModCache = {}
		self.fillAsmCache()
		self.knowledgedb = "windbglib.db"

	def setKBDB(self,filename = "windbglib.db"):
		self.knowledgedb = filename
		return

	def getKBDB(self):
		return self.knowledgedb

	def remoteVirtualAlloc(self, size=0x10000,interactive=False):
		PAGE_EXECUTE_READWRITE = 0x40
		VIRTUAL_MEM = ( 0x1000 | 0x2000 )
		vaddr = self.rVirtualAlloc(0,size,VIRTUAL_MEM,PAGE_EXECUTE_READWRITE)
		return vaddr

	def rVirtualAlloc(self, lpAddress, dwSize, flAllocationType, flProtect):
		PROCESS_VM_OPERATION = 0x0008
		kernel32 = ctypes.windll.kernel32
		pid = self.getDebuggedPid()
		hprocess = kernel32.OpenProcess( PROCESS_VM_OPERATION, False, pid )
		vaddr = kernel32.VirtualAllocEx(hprocess, lpAddress, dwSize, flAllocationType, flProtect)
		kernel32.CloseHandle(hprocess)
		return vaddr

	def rVirtualProtect(self, lpAddress, dwSize, flNewProtect, lpflOldProtect = 0):
		PROCESS_VM_OPERATION = 0x0008
		kernel32 = ctypes.windll.kernel32
		pid = self.getDebuggedPid()
		hprocess = kernel32.OpenProcess(PROCESS_VM_OPERATION, False, pid)
		pold_protect = ctypes.addressof(ctypes.c_int32(0))
		returnval = kernel32.VirtualProtectEx(hprocess, lpAddress, dwSize, flNewProtect, pold_protect)
		kernel32.CloseHandle(hprocess)
		return returnval


	def getAddress(self, functionname):
		functionparts = functionname.split(".")
		if len(functionparts) > 1:
			modulename = functionparts[0]
			functionname = functionparts[1]
			funcref = "%s!%s" % (modulename,functionname)			
			cmd2run = "ln %s" % funcref
			output = self.nativeCommand(cmd2run)
			if "Exact matches" in output:
				outputlines = output.split("\n")
				for outputline in outputlines:
					if "(" in outputline.lower():
						lineparts = outputline.split(")")
						address = lineparts[0].replace("(","")
						return hexStrToInt(address)
			else:
				return 0
		else:
			return 0

	def getCurrentTEBAddress(self):
		return getTEBAddress()	

	"""
	AsmCache
	"""

	def fillAsmCache(self):

		self.AsmCache["push eax"] = "\x50"
		self.AsmCache["push ecx"] = "\x51"
		self.AsmCache["push edx"] = "\x52"
		self.AsmCache["push ebx"] = "\x53"
		self.AsmCache["push esp"] = "\x54"
		self.AsmCache["push ebp"] = "\x55"
		self.AsmCache["push esi"] = "\x56"		
		self.AsmCache["push edi"] = "\x57"


		self.AsmCache["pop eax"] = "\x58"
		self.AsmCache["pop ecx"] = "\x59"
		self.AsmCache["pop edx"] = "\x5a"
		self.AsmCache["pop ebx"] = "\x5b"
		self.AsmCache["pop esp"] = "\x5c"
		self.AsmCache["pop ebp"] = "\x5d"
		self.AsmCache["pop esi"] = "\x5e"
		self.AsmCache["pop edi"] = "\x5f"

		self.AsmCache["jmp eax"] = "\xff\xe0"
		self.AsmCache["jmp ecx"] = "\xff\xe1"
		self.AsmCache["jmp edx"] = "\xff\xe2"
		self.AsmCache["jmp ebx"] = "\xff\xe3"
		self.AsmCache["jmp esp"] = "\xff\xe4"
		self.AsmCache["jmp ebp"] = "\xff\xe5"
		self.AsmCache["jmp esi"] = "\xff\xe6"		
		self.AsmCache["jmp edi"] = "\xff\xe7"

		self.AsmCache["call eax"] = "\xff\xd0"
		self.AsmCache["call ecx"] = "\xff\xd1"
		self.AsmCache["call edx"] = "\xff\xd2"
		self.AsmCache["call ebx"] = "\xff\xd3"
		self.AsmCache["call esp"] = "\xff\xd4"
		self.AsmCache["call ebp"] = "\xff\xd5"
		self.AsmCache["call esi"] = "\xff\xd6"		
		self.AsmCache["call edi"] = "\xff\xd7"

		self.AsmCache["jmp [eax]"] = "\xff\x20"
		self.AsmCache["jmp [ecx]"] = "\xff\x21"
		self.AsmCache["jmp [edx]"] = "\xff\x22"
		self.AsmCache["jmp [ebx]"] = "\xff\x23"
		self.AsmCache["jmp [esp]"] = "\xff\x24"
		self.AsmCache["jmp [ebp]"] = "\xff\x25"
		self.AsmCache["jmp [esi]"] = "\xff\x26"
		self.AsmCache["jmp [edi]"] = "\xff\x27"


		self.AsmCache["call [eax]"] = "\xff\x10"
		self.AsmCache["call [ecx]"] = "\xff\x11"
		self.AsmCache["call [edx]"] = "\xff\x12"
		self.AsmCache["call [ebx]"] = "\xff\x13"
		self.AsmCache["call [esp]"] = "\xff\x14"
		self.AsmCache["call [ebp]"] = "\xff\x15"
		self.AsmCache["call [esi]"] = "\xff\x16"
		self.AsmCache["call [edi]"] = "\xff\x17"

		self.AsmCache["xchg eax,esp"] = "\x94"
		self.AsmCache["xchg ecx,esp"] = "\x87\xcc"
		self.AsmCache["xchg edx,esp"] = "\x87\xd4"
		self.AsmCache["xchg ebx,esp"] = "\x87\xdc"
		self.AsmCache["xchg ebp,esp"] = "\x87\xec"
		self.AsmCache["xchg edi,esp"] = "\x87\xfc"
		self.AsmCache["xchg esi,esp"] = "\x87\xf4"
		self.AsmCache["xchg esp,eax"] = "\x94"
		self.AsmCache["xchg esp,ecx"] = "\x87\xcc"
		self.AsmCache["xchg esp,edx"] = "\x87\xd4"
		self.AsmCache["xchg esp,ebx"] = "\x87\xdc"
		self.AsmCache["xchg esp,ebp"] = "\x87\xec"
		self.AsmCache["xchg esp,edi"] = "\x87\xfc"
		self.AsmCache["xchg esp,esi"] = "\x87\xf4"		

		self.AsmCache["pushad"] = "\x60"
		self.AsmCache["popad"] = "\x61"

		try:
   			# Python 2
			xrange
		except NameError:
			# Python 3, xrange is now named range
			xrange = range

		for offset in xrange(4,80,4):
			thisasm = "\x83\xc4" + hex2bin("%02x" % offset)
			self.AsmCache["add esp,%02x" % offset] = thisasm
			self.AsmCache["add esp,%x" % offset] = thisasm

		self.AsmCache["retn"] = "\xc3"
		self.AsmCache["retf"] = "\xdb"
		for offset in xrange(0,80,2):
			thisasm = "\xc2" + hex2bin("%02x" % offset) + "\x00"
			self.AsmCache["retn %02x" % offset] = thisasm
			self.AsmCache["retn %x" % offset] = thisasm
			self.AsmCache["retn 0x%02x" % offset] = thisasm
		return

	"""
	Knowledge
	"""
	def addKnowledge(self, id, object, force_add = 0):
		allk = self.readKnowledgeDB()
		if not id in allk:	
			allk[id] = object
		else:
			if object.__class__.__name__ == "dict":
				for odictkey in object:
					allk[id][odictkey] = object[odictkey] 
		with open(self.knowledgedb,"wb") as fh:
			pickle.dump(allk,fh,-1)
		return

	def getKnowledge(self,id):
		allk = self.readKnowledgeDB()
		if id in allk:
			return allk[id]
		else:
			return None

	def readKnowledgeDB(self):
		allk = {}
		try:
			with open(self.knowledgedb,"rb") as fh:
				allk = pickle.load(fh)
		except:
			pass
		return allk

	def listKnowledge(self):
		allk = self.readKnowledgeDB()
		allid = []
		for thisk in allk:
			allid.append(thisk)
		return allid

	def cleanKnowledge(self):
		try:
			os.remove(self.knowledgedb)
		except:
			try:	
				with open(self.knowledgedb,"wb") as fh:
					pickle.dump({},fh,-1)
			except:
				pass
			pass
		return

	def forgetKnowledge(self,id,entry=""):
		allk = self.readKnowledgeDB()
		if entry == "":
			if id in allk:
				del allk[id]
		else:
			# find the entry
			if id in allk:
				thisidkb = allk[id]
				if entry in thisidkb:
					del thisidkb[entry]
				allk[id] = thisidkb
		with open(self.knowledgedb,"wb") as fh:
			pickle.dump(allk,fh,-1)
		return

	def cleanUp(self):
		self.cleanKnowledge()
		return

	"""
	Placeholders
	"""
	def analysecode(self):
		return

	def isAnalysed(self):
		return True

	"""
	LOGGING
	"""
	def toAsciiOnly(self, message):
		newchar = []
		for thischar in message:
			if ord(thischar) >= 20 and ord(thischar) <= 126:
				newchar.append(thischar)
			else:
				newchar.append(".")
		return "".join(newchar)

	def createLogWindow(self):
		return
	
	def log(self, message, highlight=0, address=None, focus=0):
		if not address == None:
			message = intToHex(address) + " | " + message
		showdml = False
		if highlight == 1:
			showdml = True
			message = "<b>" + message + "</b>"
		pykd.dprintln(self.toAsciiOnly(message), showdml)


	def logLines(self, message, highlight=0,address=None, focus=0):
		allLines = message.split('\n')
		linecnt = 0
		messageprefix = ""
		if not address == None:
			messageprefix = " " * 10
			messageprefix += " | "
		for line in allLines:
			if linecnt == 0:
				self.log(line,highlight,address)
			else:
				self.log(messageprefix+line,highlight)
			linecnt += 1

	def updateLog(self):
		return
		
	def setStatusBar(self, message):
		return
		
	def error(self, message):
		return
		
		
	"""
	Process stuff
	"""
	
	def getDebuggedName(self):
		# http://www.nirsoft.net/kernel_struct/vista/PEB.html
		# http://www.nirsoft.net/kernel_struct/vista/RTL_USER_PROCESS_PARAMETERS.html
		peb = getPEBInfo()
		ProcessParameters = peb.ProcessParameters
		offset = 0x38
		if arch == 64:
			offset = 0x60
		# ProcessParameters + offset = _RTL_USER_PROCESS_PARAMETERS.ImagePathName(_UNICODE_STRING)
		# sImageFile = pykd.loadUnicodeString(ProcessParameters + offset).encode("utf8")
		sImageFile = pykd.loadUnicodeString(int(ProcessParameters) + offset).encode("utf8")
		sImageFilepieces = sImageFile.split("\\")
		return sImageFilepieces[len(sImageFilepieces)-1]
		
	def getDebuggedPid(self):
		# http://www.nirsoft.net/kernel_struct/vista/TEB.html
		# http://www.nirsoft.net/kernel_struct/vista/CLIENT_ID.html
		teb = getTEBAddress()
		offset = 0x20
		if arch == 64:
			offset = 0x40
		# _TEB.ClientId(CLIENT_ID).UniqueProcess(PVOID)
		pid = pykd.ptrDWord(teb+offset)
		return pid

	
	"""
	OS stuff
	"""
	def getOsRelease(self):
		peb = getPEBInfo()
		majorversion = int(peb.OSMajorVersion)
		minorversion = int(peb.OSMinorVersion)
		buildversion = int(peb.OSBuildNumber)
		osversion = str(majorversion)+"."+str(minorversion)+"."+str(buildversion)
		return osversion
	
	def getOsVersion(self):
		return getOSVersion()

	def getPyKDVersionNr(self):
		return getPyKDVersion()
		
	"""
	Registers
	"""
	
	def getRegs(self):
		regs = []
		if arch == 32:
			regs = Registers32BitsOrder
			regs.append("EIP")
		if arch == 64:
			regs = Registers64BitsOrder
			regs.append("RIP")
		reginfo = {}
		for thisreg in regs:
			reginfo[thisreg.upper()] = int(pykd.reg(thisreg.lower()))
		return reginfo
	

	"""
	Commands
	"""
	def nativeCommand(self,cmd2run):
		try:
			output = pykd.dbgCommand(cmd2run)
			return output
		except:
			#dprintln(traceback.format_exc())
			#dprintln(cmd2run)
			return ""

	"""
	SEH
	"""

	def getSehChain(self):
		# http://www.nirsoft.net/kernel_struct/vista/TEB.html
		# http://www.nirsoft.net/kernel_struct/vista/NT_TIB.html
		# http://www.nirsoft.net/kernel_struct/vista/EXCEPTION_REGISTRATION_RECORD.html

		# x64 has no SEH chain
		if arch == 64:
			return []
		sehchain = []
		# get top of chain
		teb = getTEBAddress()
		# _TEB.NtTib(NT_TIB).ExceptionList(PEXCEPTION_REGISTRATION_RECORD)
		nextrecord = pykd.ptrPtr(teb)
		validrecord = True
		while nextrecord != 0xffffffff and pykd.isValid(nextrecord):
			# _EXCEPTION_REGISTRATION_RECORD.Next(PEXCEPTION_REGISTRATION_RECORD)
			nseh = pykd.ptrPtr(nextrecord)
			# _EXCEPTION_REGISTRATION_RECORD.Handler(PEXCEPTION_DISPOSITION)
			seh = pykd.ptrPtr(nextrecord+4)
			sehrecord = [nextrecord,seh]
			sehchain.append(sehrecord)
			nextrecord = nseh
		return sehchain
	
	"""
	Memory
	"""
	def readMemory(self,location,size):
		try:	
			#return hex2bin(''.join(("%02X" % n) for n in loadBytes(location,size)))
			return pykd.loadChars(location,size)
		except:
			return ""

	def readString(self,location):
		if pykd.isValid(location):
			try:
				return pykd.loadCStr(location)
			except pykd.MemoryException:
				return pykd.loadChars(location, 0x100)
			except:
				return ""
		else:
			return ""

	def readWString(self,location):
		if pykd.isValid(location):
			try:
				return pykd.loadWStr(location)
			except pykd.MemoryException:
				return pykd.loadWChars(location, 0x100)
			except:
				return ""
		return


	def readUntil(self,start,end):
		if start > end:
			tmp = start
			start = end
			end = tmp
		size = end-start
		return self.readMemory(start,size)

	def readLong(self,location):
		return pykd.ptrDWord(location)


	def writeMemory(self,location,data):
		A = array.array('B')
		A.fromstring(data)
		pykd.writeBytes(location, A.tolist())
		return

	def writeLong(self,location,dword):
		bytesdword = hexptr2bin(dword)
		self.writeMemory(location,bytesdword)
		return


	def getMemoryPages(self):
		offset = 0
		endaddress = 0x7fffffff
		#pagesize = pageSize()
		if len(self.MemoryPages) == 0:
			while offset < endaddress:
				try:
					startaddress,pagesize = pykd.findMemoryRegion(offset)
					pageobj = wpage(startaddress,pagesize)
					if not startaddress in self.MemoryPages:
						self.MemoryPages[startaddress] = pageobj
					offset += pagesize
				except:
					offset += 0x1000
		return self.MemoryPages

	def getMemoryPageByAddress(self,address):
		if len(self.MemoryPages) == 0:
			# may never get hit
			self.MemoryPages = self.getMemoryPages()
		pagesize = 0
		startaddress = self.getPageContains(address)
		if startaddress in self.MemoryPages:
			return self.MemoryPages[startaddress]
		else:
			page = wpage(startaddress,pagesize)
			return page

	def getMemoryPageByOwner(self,ownerobj):
		return []

	def getPageContains(self,address):
		if len(self.MemoryPages) == 0:
			self.MemoryPages = self.getMemoryPages()
		for pagestart in self.MemoryPages:
			thispage = self.MemoryPages[pagestart]
			pageend = pagestart + thispage.getSize()
			if address >= pagestart and address < pageend:
				return pagestart
		return 0

	def getHeapsAddress(self):
		# http://www.nirsoft.net/kernel_struct/vista/PEB.html
		allheaps = []
		peb = getPEBInfo()
		offset = 0x88
		if arch == 64:
			offset = 0xe8
		# _PEB.NumberOfHeaps(ULONG)
		nrofheaps = int(pykd.ptrDWord(peb+offset))
		# _PEB.ProcessHeaps(VOID**)
		processheaps = int(peb.ProcessHeaps)
		try:
   			# Python 2
			xrange
		except NameError:
			# Python 3, xrange is now named range
			xrange = range

		for i in xrange(nrofheaps):
			# _PEB.ProcessHeaps[i](VOID*)
			nextheap = pykd.ptrPtr(processheaps + (i*(arch/8)))
			if nextheap == 0x00000000:
				break
			if not nextheap in allheaps:
				allheaps.append(nextheap)
		return allheaps


	def getHeap(self,address):
		return wheap(address)

	def getPEBAddress(self):
		return getPEBAddress()

	def getAllThreads(self):
		allthreads = []
		for thisthread in pykd.getProcessThreads():
			allthreads.append(wthread(thisthread))
		return allthreads

	"""
	Modules
	"""
	def getModule(self,modulename):
		wmod = None
		self.origmodname = modulename
		fullpath = ""
		if len(PEBModList) == 0:
			getModulesFromPEB()
		try:
			thismod = None
			if modulename in PEBModList:
				modentry = PEBModList[modulename]
				thismod = pykd.module(modulename)
				fullpath = modentry[1]
			else:
				# find a good one
				for modentry in PEBModList:
					modrecord = PEBModList[modentry]
					# 0 : file
					# 1 : path
					if modulename == modrecord[0]:
						thismod = pykd.module(modentry)
						fullpath = modrecord[1]
						break

			if thismod == None:
				# should never hit, as we have tested if modules can be loaded already
				imagename = self.getImageNameForModule(self.origmodname)
				thismod = pykd.module(str(imagename))

			thisimagename = thismod.image()
			thismodname = thismod.name()
			thismodbase = thismod.begin()
			thismodsize = thismod.size()
			thismodpath = thismod.image()

			try:
				versionstuff = thismod.getVersion()
				thismodversion = ""
				for vstuff in versionstuff:
					thismodversion = thismodversion + str(vstuff) + "."
				thismodversion = thismodversion.strip(".")
			except:
				thismodversion = ""
			ntHeader = getNtHeaders(thismodbase)
			#preferredbase = ntHeader.OptionalHeader.ImageBase
			preferredbase = getImageBaseOnDisk(fullpath)
			entrypoint = ntHeader.OptionalHeader.AddressOfEntryPoint
			codebase = ntHeader.OptionalHeader.BaseOfCode
			if getArchitecture() == 64:
				database = 0
			else:
				database = ntHeader.OptionalHeader.BaseOfData
			sizeofcode = ntHeader.OptionalHeader.SizeOfCode

			wmod = wmodule(thismodname)

			wmod.setBaseAddress(thismodbase)
			wmod.setFixupBase(preferredbase)
			wmod.setPath(thismodpath)
			wmod.setSize(thismodsize)
			wmod.setEntry(entrypoint)
			wmod.setCodeBase(codebase)
			wmod.setCodeSize(sizeofcode)
			wmod.setDatabase(database)
			wmod.setVersion(thismodversion)
		except:
			pykd.dprintln("** Error trying to process module %s" % modulename)
			#dprintln(traceback.format_exc())
			wmod = None
		return wmod
		

	def getAllModules(self):
		if len(self.allmodules) == 0:
			if len(PEBModList) == 0:
				getModulesFromPEB()
			for imagename in PEBModList:
				thismodname = PEBModList[imagename][0]
				wmodobject = self.getModule(imagename)
				self.allmodules[thismodname] = wmodobject
		return self.allmodules


	def getImageNameForModule(self,modulename):
		# http://www.nirsoft.net/kernel_struct/vista/PEB.html
		# http://www.nirsoft.net/kernel_struct/vista/PEB_LDR_DATA.html
		# http://www.nirsoft.net/kernel_struct/vista/LDR_DATA_TABLE_ENTRY.html
		offset = 0x20
		if arch == 64:
			offset = 0x40
		try:
			imagename = ""
			moduleLst = getModulesFromPEB()
			for mod in moduleLst:
				thismod = pykd.loadUnicodeString(mod.BaseDllName).encode("utf8")
				modparts = thismod.split("\\")
				thismodname = modparts[len(modparts)-1]
				moduleparts = thismodname.split(".")
				if thismodname.lower() == modulename.lower():
					# mod.getAddress() + offset = _LDR_DATA_TABLE_ENTRY.SizeOfImage
					baseaddy = int(pykd.ptrPtr(mod.getAddress() + offset))
					baseaddr = "%08x" % baseaddy
					lmcommand = self.nativeCommand("lm")
					lmlines = lmcommand.split("\n")
					foundinlm = False
					for lmline in lmlines:
						linepieces = lmline.split(" ")
						if linepieces[0].upper() == baseaddr.upper():
							cnt = 2
							while cnt < len(linepieces) and not foundinlm:
								if linepieces[cnt].strip(" ") != "":
									imagename = linepieces[cnt]
									foundinlm = True
								cnt += 1
					if not foundinlm:
						imagename = "image%s" % baseaddr.lower()
					return imagename
		except:
			pykd.dprintln(traceback.format_exc())
		return None

	"""
	Assembly & Disassembly related routes
	"""

	def disasm(self,address):
		return self.getOpcode(address)

	def disasmSizeOnly(self,address):
		return self.getOpcode(address)

	def disasmForward(self,address,depth=0):
		# go to correct location
		cmd2run = "u 0x%08x L%d" % (address,depth+1)
		try:
			disasmlist = pykd.dbgCommand(cmd2run)
			disasmLinesTmp = disasmlist.split("\n")
			disasmLines = []
			for line in disasmLinesTmp:
				if line.replace(" ","") != "":
					disasmLines.append(line)
			lineindex = len(disasmLines)-1
			if lineindex > -1:
				asmline = disasmLines[lineindex]
				pointer = asmline[0:8]
				if pointer > address:
					return self.getOpcode(hexStrToInt(pointer))
				else:
					return self.getOpcode(address)
			else:
				return self.getOpcode(address)
		except:
			# probably invalid instruction, so fake by returning itself
			# caller should check if address is different than what was provided
			return self.getOpcode(address)


	def disasmForwardAddressOnly(self,address,depth):
		# go to correct location
		return self.disasmForward(address,depth).getAddress()

	def disasmBackward(self,address,depth):
		while True:
			cmd2run = "ub 0x%08x L%d" % (address,depth)
			try:
				disasmlist = pykd.dbgCommand(cmd2run)
				disasmLinesTmp = disasmlist.split("\n")
				disasmLines = []
				for line in disasmLinesTmp:
					if line.replace(" ","") != "":
						disasmLines.append(line)
				lineindex = len(disasmLines)-depth
				if lineindex > -1:
					asmline = disasmLines[lineindex]
					pointer = asmline[0:8]
					return self.getOpcode(hexStrToInt(pointer))
				else:
					return self.getOpcode(address)
			except:
				# probably invalid instruction, so fake by returning itself
				# caller should check if address is different than what was provided
				if depth == 1:
					return self.getOpcode(address)
			depth -= 1

	def assemble(self,instructions):
		allbytes = ""
		address = pykd.reg("eip")
		if not pykd.isValid(address):
			# assemble somewhere else - let's say at the ntdll entrypoint
			thismod = pykd.module("ntdll")
			thismodbase = thismod.begin()
			ntHeader = getNtHeaders(thismodbase)
			entrypoint = ntHeader.OptionalHeader.AddressOfEntryPoint
			address = thismodbase + entrypoint
		allinstructions = instructions.lower().split("\n")
		origbytes = pykd.loadChars(address,20)
		cached = True
		for thisinstruction in allinstructions:	
			thisinstruction = thisinstruction.strip(" ").lstrip(" ")
			if thisinstruction.startswith("ret") and not thisinstruction.startswith("retf"):
				thisinstruction = thisinstruction.replace("retn","ret").replace("ret","retn")

			if not thisinstruction in self.AsmCache:
				objdisasm = pykd.disasm(address)
				try:
					objdisasm.asm(thisinstruction)
				except:
					return ""
				opc = opcode(address)	
				thesebytes = opc.getBytes()
				allbytes += thesebytes
				self.AsmCache[thisinstruction] = thesebytes
				cached = False
			else:
			# return from cache
				allbytes += self.AsmCache[thisinstruction]
		if not cached:
			putback = "eb 0x%08x " % address
			restorebytes = [''.join(bin2hex(origbyte)) for origbyte in origbytes] 
			putback += ' '.join(restorebytes)
			pykd.dbgCommand(putback)
		return allbytes

	def getOpcode(self,address):
		if address in self.OpcodeCache:
			return self.OpcodeCache[address]
		else:
			opcodeobj = opcode(address)
			self.OpcodeCache[address] = opcodeobj
			return opcodeobj

	"""
	strings
	"""

	def readString(self,address):
		return pykd.loadCStr(address)

	"""
	Breakpoints
	"""
	def setBreakpoint(self,address):
		try:
			cmd2run = "bp 0x%08x" % address
			self.nativeCommand(cmd2run)
		except:
			return False
		return True

	def deleteBreakpoint(self,address):
		getallbps = "bl"
		allbps = self.nativeCommand(getallbps)
		bplines = allbps.split("\n")
		for line in bplines:
			fieldcnt = 0
			if line.replace(" ","") != "":
				lineparts = line.split(" ")
				id = ""
				type = ""
				bpaddress = ""
				for part in lineparts:
					if part != "":
						fieldcnt += 1
					if fieldcnt == 1:
						id = part
					if fieldcnt == 2:
						type = part
					if fieldcnt == 3:
						bpaddress = part
						break
				if hexStrToInt(bpaddress) == address and id != "":
					rmbp = "bc %s" % id
					self.nativeCommand(rmbp)

	def setMemBreakpoint(self,address,memType):
		validtype = False
		bpcommand = ""
		if memType.upper() == "S":
			bpcommand = "ba e 1 0x%08x" % address
			validtype = True
		if memType.upper() == "R":
			bpcommand = "ba r 4 0x%08x" % address
			validtype = True
		if memType.upper() == "W":
			bpcommand = "ba w 4 0x%08x" % address
			validtype = True
		if validtype:
			output = ""
			try:
				output = pykd.dbgCommand(bpcommand)
			except:
				if memType.upper() == "S":
					bpcommand = "bp 0x%08x" % address
					output = pykd.dbgCommand(bpcommand)
				else:
					self.log("** Unable to set memory breakpoint. Check alignment,")
					self.log("   and try to run the following command to get more information:")
					self.log("   %s" % bpcommand)

	"""
	Table
	"""

	def createTable(self,title,columns):
		return wtable(title,columns)

	"""
	Symbols
	"""

	def resolveSymbol(self,symbolname):
		resolvecmd = "u %s L1" % symbolname
		try:
			output=self.nativeCommand(resolvecmd)
			outputlines = output.split("\n")
			for line in outputlines:
				lineparts = line.split(" ")
				if len(lineparts) > 1:
					symfound = True
					symaddy = lineparts[0]
					break
			if symfound:
				return symaddy
			else:
				return ""
		except:
			return ""

# other classes

class wtable:

	def __init__(self,title,columns):
		self.title = title
		self.columns = columns
		self.values = []
	
	def add(self,tableindex,values):
		self.values.append(values)
		return None


class wmodule:

	def __init__(self,modname):
		self.key = modname
		self.modname = modname
		self.modpath = None
		self.modbase = None
		self.modsize = None
		self.modend  = None
		self.entrypoint = None
		self.preferredbase = None
		self.codebase = None
		self.sizeofcode = None
		self.database = None
		self.modversion = None

	# setters
	def setBaseAddress(self,value):
		self.modbase = value

	def setFixupBase(self,value):
		self.preferredbase = value

	def setPath(self,value):
		self.modpath = value

	def setSize(self,value):
		self.modsize = value

	def setVersion(self,value):
		self.modversion = value

	def setEntry(self,value):
		self.entrypoint = value

	def setCodeBase(self,value):
		self.codebase = value

	def setCodeSize(self,value):
		self.sizeofcode = value

	def setDatabase(self,value):
		self.database = value

	# getters
	def __str__(self):
		return self.modname

	def key(self):
		return self.modname

	def getName(self):
		return self.modname
	
	def getBaseAddress(self):
		return self.modbase
	
	def getFixupbase(self):
		return self.preferredbase

	def getPath(self):
		return self.modpath
	
	def getSize(self):
		return self.modsize

	def getIssystemdll(self):
		modisos = False
		if "WINDOWS" in self.modpath.upper():
			modisos = True
		else:
			modisos = False
		# exceptions
		if self.modname.lower()=="ntdll":
			modisos = True
		self.issystemdll = modisos
		return self.issystemdll
	
	def getVersion(self):
		return self.modversion
	
	def getEntry(self):
		return self.entrypoint
	
	def getCodebase(self):
		return self.codebase
		
	def getCodesize(self):
		return self.sizeofcode

	def getDatabase(self):
		return self.database

	def getSymbols(self):
		# enumerate IAT and EAT and put into a symbol object
		ntHeader = getNtHeaders(self.modbase)
		pSize = 4
		if arch == 64:
			pSize = 8
		iatlist = self.getIATList(ntHeader,pSize)
		symbollist = {}
		for iatEntry in iatlist:
			iatEntryAddress = iatEntry
			iatEntryName = iatlist[iatEntry]
			sym = wsymbol("Import", iatEntryAddress, iatEntryName)
			symbollist[iatEntryAddress] = sym 

		eatlist = self.getEATList(ntHeader,pSize)
		for eatEntry in eatlist:
			eatEntryName = eatEntry
			eatEntryAddress = eatlist[eatEntry]
			sym = wsymbol("Export", eatEntryAddress, eatEntryName)
			symbollist[eatEntryAddress] = sym
		return symbollist

	def getIATList(self,ntHeader, pSize):
		# If Import Address Table Directory (DataDirectory[12]) is set this will work.
		# The fallback case of Import Directory (DataDirectory[1]) will produce garbage.
		iatlist = {}
		iatdir = ntHeader.OptionalHeader.DataDirectory[12]
		if iatdir.Size == 0:
			iatdir = ntHeader.OptionalHeader.DataDirectory[1]
		if iatdir.Size > 0:
			iatAddr = self.modbase + iatdir.VirtualAddress
			for i in range(0, iatdir.Size / pSize):
				iatEntry = pykd.ptrPtr(iatAddr + i*pSize)
				if iatEntry != None and iatEntry != 0:
					symbolName = pykd.findSymbol(iatEntry)
					if "!" in symbolName:
						iatlist[iatAddr + i*pSize] = symbolName
		return iatlist
					
	def getEATList(self,ntHeader, pSize):
		# http://www.pinvoke.net/default.aspx/Structures.IMAGE_EXPORT_DIRECTORY
		eatlist = {}
		if ntHeader.OptionalHeader.DataDirectory[0].Size > 0:
			eatAddr = self.modbase + ntHeader.OptionalHeader.DataDirectory[0].VirtualAddress
			# eatAddr + 0x18 = IMAGE_EXPORT_DIRECTORY.NumberOfNames(DWORD)
			nr_of_names = pykd.ptrDWord(eatAddr + 0x18)
			# eatAddr + 0x20 = IMAGE_EXPORT_DIRECTORY.AddressOfNames(DWORD)
			rva_of_names = self.modbase + pykd.ptrDWord(eatAddr + 0x20)
			# eatAddr + 0x1c = IMAGE_EXPORT_DIRECTORY.AddressOfFunctions(DWORD)
			address_of_functions = self.modbase + pykd.ptrDWord(eatAddr + 0x1c)
			for i in range (0, nr_of_names):
				# IMAGE_EXPORT_DIRECTORY.AddressOfNames[i](DWORD)
				eatName = pykd.loadCStr(self.modbase + pykd.ptrDWord(rva_of_names + 4 * i))
				# IMAGE_EXPORT_DIRECTORY.AddressOfFunctions[i](DWORD)
				eatAddress = self.modbase + pykd.ptrDWord(address_of_functions + 4*i)
				eatlist[eatName] = eatAddress
		return eatlist

	def getSectionAddress(self,sectionname):
		ntHeader = getNtHeaders(self.modbase)
		nrsections = int(ntHeader.FileHeader.NumberOfSections)
		sectionsize = 40
		sizeOptionalHeader = int(ntHeader.FileHeader.SizeOfOptionalHeader)
		try:
   			# Python 2
			xrange
		except NameError:
			# Python 3, xrange is now named range
			xrange = range

		for sectioncnt in xrange(nrsections):
			# IMAGE_SECTION_HEADER[i]
			sectionstart = (ntHeader.OptionalHeader.getAddress() + sizeOptionalHeader) + (sectioncnt*sectionsize)
			thissection = pykd.loadChars(sectionstart, 8).rstrip('\0')
			if thissection == sectionname:
				# IMAGE_SECTION_HEADER.SizeOfRawData(DWORD)
				thissectionsize = pykd.ptrDWord(sectionstart + 0x8 + 0x8)
				# IMAGE_SECTION_HEADER.VirtualAddress(DWORD)
				thissectionrva = pykd.ptrDWord(sectionstart + 0x4 + 0x8)
				thissectionstart = self.modbase + thissectionrva
				return thissectionstart
		return 0


class wsymbol():

	def __init__(self,type,address,name):
		self.type = type
		self.address = address
		self.name = name

	def getType(self):
		return self.type

	def getAddress(self):
		return self.address

	def getName(self):
		return self.name


class wpage():
	def __init__(self,begin,size):
		self.begin = begin
		self.size = size
		self.end = self.begin+self.size
		self.protect = None

	def getSize(self):
		return self.size

	def getMemory(self):
		if self.getAccess() > 0x1:
			try:
				data =  pykd.loadChars(self.begin,self.size)
				return data
			except:
				return None
		else:
			return None


	def getMemoryOld(self):
		if self.getAccess() > 0x1:
			try:
				nrofdwords = self.size / 4
				delta = self.size - (nrofdwords * 4)
				dwords = pykd.loadDWords(self.begin,nrofdwords)
				curpos = self.begin + (nrofdwords * 4)
				remainingbytes = pykd.loadBytes(curpos,delta)
				allbytes = []
				for dword in dwords:
					dwordhex = "%08x" % dword
					allbytes.append(dwordhex[6:8] + dwordhex[4:6] + dwordhex[2:4] + dwordhex[0:2])
				dwords = None
				for byte in remainingbytes:
					allbytes.append("%02x" % bytes)
				data = hex2bin(''.join(allbytes))
				#return hex2bin(''.join(("%02X" % n) for n in loadBytes(self.begin,self.size)))
				return data
			except:
				return None
		else:
			return None

	def getAccess(self,human=False):
		humanaccess = {
		0x01 : "PAGE_NOACCESS",
		0x02 : "PAGE_READONLY",
		0x04 : "PAGE_READWRITE",
		0x08 : "PAGE_WRITECOPY",
		0x10 : "PAGE_EXECUTE",
		0x20 : "PAGE_EXECUTE_READ",
		0x40 : "PAGE_EXECUTE_READWRITE",
		0x80 : "PAGE_EXECUTE_WRITECOPY"
		}

		modifiers = {
		0x100 : "PAGE_GUARD",
		0x200 : "PAGE_NOCACHE",
		0x400 : "PAGE_WRITECOMBINE"
		}

		modifaccess = {}
		for access in humanaccess:
			newaccess = access
			newacl = humanaccess[access]
			for modif in modifiers:
				newaccess += modif
				newacl = newacl + " " + modifiers[modif]
				modifaccess[newaccess] = newacl

		for modif in modifaccess:
			humanaccess[modif] = modifaccess[modif]

		if self.protect == None:
			try:
				self.protect = pykd.getVaProtect(self.begin)
			except:
				self.protect = 0x1
		if self.protect == 0x0:
			self.protect = 0x1
		if not human:
			return self.protect
		else:
			if self.protect in humanaccess:
				return humanaccess[self.protect]
			else:
				return ""

	def getBegin(self):
		return self.begin

	def getBaseAddress(self):
		return self.begin

	def getSection(self):
		global PageSections
		if self.begin in PageSections:
			return PageSections[self.begin]
		else:
			sectiontoreturn = ""
			imagename = getModuleFromAddress(self.begin)
			if not imagename == None:
				thismod = pykd.module(imagename)
				thismodbase = thismod.begin()
				thismodend = thismod.end()
				if self.begin >= thismodbase and self.begin <= thismodend:
					# find sections and their addresses
					ntHeader = getNtHeaders(thismodbase)
					nrsections = int(ntHeader.FileHeader.NumberOfSections)
					sectionsize = 40
					sizeOptionalHeader = int(ntHeader.FileHeader.SizeOfOptionalHeader)
					try:
						# Python 2
						xrange
					except NameError:
						# Python 3, xrange is now named range
						xrange = range

					for sectioncnt in xrange(nrsections):
						sectionstart = (ntHeader.OptionalHeader.getAddress() + sizeOptionalHeader) + (sectioncnt*sectionsize)
						thissection = pykd.loadChars(sectionstart, 8).rstrip('\0')
						# IMAGE_SECTION_HEADER.SizeOfRawData(DWORD)
						thissectionsize = pykd.ptrDWord(sectionstart + 0x8 + 0x8)
						# IMAGE_SECTION_HEADER.VirtualAddress(DWORD)
						thissectionrva = pykd.ptrDWord(sectionstart + 0x4 + 0x8)
						thissectionstart = thismodbase + thissectionrva
						thissectionend = thissectionstart + thissectionsize
						if (thissectionstart <= self.begin) and (self.begin <= thissectionend):
							sectiontoreturn = thissection
							break
						else:
							PageSections[self.begin]=thissection
					PageSections[self.begin]=sectiontoreturn
					return sectiontoreturn
				PageSections[self.begin]=sectiontoreturn
				return sectiontoreturn
			else:
				return ""


class LogBpHook():
	def __init__(self):
		return


class Function:
	def __init__(self,obj,address):
		self.function_allmodules = {}
		self.address = address
		self.obj = obj

	def getName(self):
		modname = "unknown"
		funcname = "unknown"
		# get module this address belongs to
		self.function_allmodules = self.obj.getAllModules()
		for objmod in self.function_allmodules:
			thismod = self.function_allmodules[objmod]
			startaddress = thismod.getBaseAddress()
			size = thismod.getSize()
			endaddress = startaddress + size
			if self.address >= startaddress and self.address <= endaddress:
				modname = thismod.getName().lower()
				syms = thismod.getSymbols()
				for sym in syms:
					if syms[sym].getType().startswith("Export"):
						eatsym = syms[sym]
						if eatsym.getAddress() == self.address:
							funcname = eatsym.getName()
							break
		thename = "%s.%s" % (modname,funcname)
		return thename

	def hasAddress(self):
		return False

class opcode:

	opsize = 0
	dump = ""

	def __init__(self,address):
		self.address = address
		self.dumpdata = ""
		self.dump = ""
		self.instruction = ""
		self.getDisasm()

	def getBytes(self):
		self.opsize = len(self.dumpdata) / 2
		return hex2bin(self.dumpdata)

	def isJmp(self):
		if self.instruction.upper().startswith("JMP"):
			return True
		return False

	def isCall(self):
		if self.instruction.upper().startswith("CALL"):
			return True
		return False

	def isPush(self):
		if self.instruction.upper().startswith("PUSH"):
			return True
		return False

	def isPop(self):
		if self.instruction.upper().startswith("POP"):
			return True
		return False

	def isRet(self):
		if self.instruction.upper().startswith("RET"):
			return True
		return False

	def isRep(self):
		if self.instruction.upper().startswith("REP"):
			return True
		return False		

	def getDisasm(self):
		if self.instruction == "":
			disasmdata = ""

			disasmlines = pykd.dbgCommand("u 0x%08x L 1" % self.address)
			for thisline in disasmlines.split("\n"):
				if thisline.lower().startswith("%08x" % self.address):
					disasmdata = thisline
					break
			if disasmdata != "":
				# 0 -> 7 : address
				# 8 : space
				# 9 -> 24 : bytes
				# 25 -> end : instruction
				if len(disasmdata) > 25:
					self.instruction = disasmdata[25:len(disasmdata)]
					self.dumpdata = disasmdata[9:24].replace(" ","")
					self.opsize = len(self.dumpdata) / 2
				addressstring = disasmdata[0:8]
				self.address = addrToInt(addressstring)
				self.instruction = self.instruction.replace("   "," ").replace("  "," ")
				# sanitize instruction to make output immlib compatible. Ugly. A bit.
				instructionpieces = self.instruction.split(" ")
				self.instruction = ""
				extrainfo = ""
				for instructionpiece in instructionpieces:
					if ("{" not in instructionpiece and "s:" not in instructionpiece) or ("fs:[" in instructionpiece):
							self.instruction += instructionpiece
							self.instruction += " "
					else:
						extrainfo = instructionpiece.upper()
						break
				self.instruction = self.instruction.strip(" ").upper()
				self.instruction = self.instruction.replace("   "," ").replace("  "," ")
				if "SS:" in extrainfo:
					self.instruction = self.instruction.replace("PTR [","PTR SS:[")
				if "DS:" in extrainfo:
					self.instruction = self.instruction.replace("PTR [","PTR DS:[")
				self.instruction = self.instruction.replace("RET","RETN")	
				self.instruction = self.instruction.replace(",[",",DWORD PTR DS:[")
				if ",OFFSET" in self.instruction:
					# find the value between ()
					instrparts=self.instruction.split("(")
					if len(instrparts) > 1:
						instrparts2 = instrparts[1].split(")")
						offsetval = instrparts2[0].replace(" ","").strip("H")
						if offsetval != "":
							pos = self.instruction.find(",OFFSET")
							self.instruction = self.instruction[0:pos] + "," + offsetval
				if "," in self.instruction and self.instruction.endswith("H"):
					instructionparts = self.instruction.split(",")
					cnt = 0
					self.instruction = ""
					while cnt < len(instructionparts)-1:
						self.instruction = instructionparts[cnt] + ","
						cnt += 1
					self.instruction = self.instruction+ instructionparts[len(instructionparts)-1].strip("H")
		self.dump = self.instruction
		return self.instruction

	def getDump(self):
		if self.dumpdata == "":
			self.getDisasm()
		return self.dumpdata

	def getAddress(self):
		return self.address



class wthread:
	def __init__(self,address):
		self.address = address

	def getTEB(self):
		# return address of the TEB
		return self.address

	def getId(self):
		# http://www.nirsoft.net/kernel_struct/vista/TEB.html
		# http://www.nirsoft.net/kernel_struct/vista/CLIENT_ID.html
		teb = self.getTEB()
		offset = 0x24
		if arch == 64:
			offset = 0x48
		# _TEB.ClientId(CLIENT_ID).UniqueThread(PVOID)
		tid = pykd.ptrDWord(teb+offset)
		return tid

class wheap:
	def __init__(self,address):
		self.address = address

	def getChunks(self,address):
		return {}


class LogBpHook:
	def __init__(self):
		return

