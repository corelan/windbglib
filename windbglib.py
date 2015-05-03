"""
Copyright (c) 2011-2015, Peter Van Eeckhoutte - Corelan GCV
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

$Revision: 138 $
$Id: windbglib.py 138 2015-05-03 09:59:58Z corelanc0d3r $ 
"""

__VERSION__ = '1.0'

#
# Wrapper library around pykd
# (partial immlib logic port)
#
# This library allows you to run mona.py
# under WinDBG, using the pykd extension
#
from pykd import *
import os
import binascii
import struct
import traceback
import pickle
import ctypes
from ctypes import *

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
Registers64BitsOrder = ["RAX", "RCX", "EDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"]

if is64bitSystem():
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
	peb = getPEBInfo()
	majorversion = int(peb.OSMajorVersion)
	minorversion = int(peb.OSMinorVersion)
	thisversion = str(majorversion)+"." + str(minorversion)
	if thisversion in osversions:
		return osversions[thisversion]
	else:
		return "unknown"

def getArchitecture():
	if not is64bitSystem():
		return 32
	else:
		return 64

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
	return typedVar( "ntdll!_PEB", getCurrentProcess())

def getPEBAddress():
	global cpebaddress
	if cpebaddress ==  0:
		peb = getPEBInfo()
		cpebaddress = peb.getAddress()
	return cpebaddress

def getTEBInfo():
	return typedVar("_TEB",getImplicitThread())

def getTEBAddress():
	tebinfo = dbgCommand("!teb")
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
	currentversion = version
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
	pykdversion_needed = "0.2.0.29"
	if arch == 64:
		pykdversion_needed = "0.2.0.29"
	currversion = getPyKDVersion()
	if not isPyKDVersionCompatible(currversion,pykdversion_needed):
		print "*******************************************************************************************"
		print "  You are running the wrong version of PyKD, please update "
		print "   Installed version : %s " % currversion
		print "   Required version : %s" % pykdversion_needed
		print "  You can get an updated PyKD version from one of the following sources:"
		print "   - %s (preferred)" % pykdurl
		print "     (unzip with 7zip)"
		print "   - http://pykd.codeplex.com (newer versions may not work !)"
		print "*******************************************************************************************"
		import sys
		sys.exit()
		return
	if pykdversion_needed != currversion:
		# version must be higher
		print "*******************************************************************************************"
		print " You are running a newer version of pykd.pyd"
		print " mona.py was tested against v%s" % pykdversion_needed
		print " and not against v%s" % currversion
		print " This version may not work properly."
		print " If you are having issues, I recommend to download the correct version from"
		print "   - %s (preferred)" % pykdurl
		print "     (unzip with 7zip)"
		print "*******************************************************************************************"		
	return

def getModulesFromPEB():
	global PEBModList
	peb = getPEBInfo()
	imagenames = []
	moduleLst = typedVarList( peb.Ldr.deref().InLoadOrderModuleList, "ntdll!_LDR_DATA_TABLE_ENTRY", "InMemoryOrderLinks.Flink")
	if len(PEBModList) == 0:
		for mod in moduleLst:
			thismod = loadUnicodeString(mod.BaseDllName).encode("utf8")
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
				baseaddy = int(ptrDWord(mod.getAddress() + 0x20))
				imagename = imagename+"_%08x" % baseaddy

			# check if module can be loaded
			try:
				modcheck = module(imagename)
			except:
				# change to image+baseaddress
				baseaddy = int(ptrDWord(mod.getAddress() + 0x20))
				imagename = "image%08x" % baseaddy
				try:
					modcheck = module(imagename)
				except:
					print ""
					print "   *** Error parsing %s (%s) ***" % (imagename,modulename)
					print "   *** Please open a github issue ticket at https://github.com/corelan/windbglib ***"
					print "   *** and provide the output of 'lm' in the ticket ***"
					print ""
					addtolist = False

			if addtolist:
				imagenames.append(imagename)
				PEBModList[imagename] = [exename, fullpath]
	
	return moduleLst

def getModuleFromAddress(address):
	global ModuleCache
	for modname in ModuleCache:
		modparts = ModuleCache[modname]
		# 0 : base
		# 1 : size
		modbase = modparts[0]
		modsize = modparts[1]
		modend = modbase + modsize
		if (address >= modbase) and (address <= modend):
			return module(modname)
	# not cached, find it
	moduleLst = getModulesFromPEB()
	for mod in moduleLst:
		thismod = loadUnicodeString(mod.BaseDllName).encode("utf8")
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
				thismod = loadUnicodeString(mod.BaseDllName).encode("utf8")
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
					baseaddy = int(ptrDWord(mod.getAddress() + 0x20))
					baseaddr = "%08x" % baseaddy
					lmcommand = dbgCommand("lm")
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
			dprintln(traceback.format_exc())
		modulename = imagename
		thismod = module(imagename)
		modbase = thismod.begin()
		modsize = thismod.size()
		modend = modbase + modsize
		ModuleCache[modulename] = [modbase,modsize]
		if (address >= modbase) and (address <= modend):
			return thismod
	return None


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
		PROCESS_ALL_ACCESS = ( 0x000F0000 | 0x00100000 | 0xFFF )
		kernel32 = windll.kernel32
		pid = getCurrentProcessId()
		hprocess = kernel32.OpenProcess( PROCESS_ALL_ACCESS, False, pid )
		vaddr = kernel32.VirtualAllocEx(hprocess, lpAddress, dwSize, flAllocationType, flProtect)
		return vaddr

	def rVirtualProtect(self, lpAddress, dwSize, flNewProtect, lpflOldProtect = 0):
		origbytes = ""
		mustrestore = False
		if lpflOldProtect == 0:
			# set it to lpAddress and restore lpAddress later on
			mustrestore = True
			lpflOldProtect = lpAddress
			origbytes = self.readMemory(lpAddress,4)
		if lpflOldProtect > 0:
			PROCESS_ALL_ACCESS = ( 0x000F0000 | 0x00100000 | 0xFFF )
			kernel32 = windll.kernel32
			pid = getCurrentProcessId()
			hprocess = kernel32.OpenProcess( PROCESS_ALL_ACCESS, False, pid )
			returnval = kernel32.VirtualProtectEx(hprocess, lpAddress, dwSize, flNewProtect, lpflOldProtect)
			if mustrestore:
				self.writeMemory(lpAddress,origbytes)
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
		dprintln(self.toAsciiOnly(message), showdml)


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
		peb = getPEBInfo()
		ProcessParameters = peb.ProcessParameters
		ImageFile = ProcessParameters + 0x3c
		pImageFile = ptrDWord(ImageFile)
		sImageFile = loadWStr(pImageFile).encode("utf8")
		sImageFilepieces = sImageFile.split("\\")
		return sImageFilepieces[len(sImageFilepieces)-1]
		
	def getDebuggedPid(self):
		teb = getTEBAddress()
		offset = 0x20
		if arch == 64:
			offset = 0x40
		pid = ptrDWord(teb+offset)
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
			reginfo[thisreg.upper()] = int(reg(thisreg))
		return reginfo
	

	"""
	Commands
	"""
	def nativeCommand(self,cmd2run):
		try:
			output = dbgCommand(cmd2run)
			return output
		except:
			#dprintln(traceback.format_exc())
			#dprintln(cmd2run)
			return ""

	"""
	SEH
	"""

	def getSehChain(self):
		sehchain = []
		# get top of chain
		teb = getTEBAddress()
		nextrecord = ptrDWord(teb)
		validrecord = True
		while nextrecord != 0xffffffff and isValid(nextrecord):
			nseh = ptrDWord(nextrecord)
			seh = ptrDWord(nextrecord+4)
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
			return loadChars(location,size)
		except:
			return ""

	def readString(self,location):
		if isValid(location):
			try:
				return loadCStr(location)
			except MemoryException:
				return loadChars(location,0x100)
			except:
				return ""
		else:
			return ""

	def readWString(self,location):
		if isValid(location):
			try:
				return loadWStr(location)
			except MemoryException:
				return loadWChars(location,0x100)
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
		return ptrDWord(location)


	def writeMemory(self,location,data):
		putback = "eb 0x%08x" % location
		thisbyte = ""
		for origbyte in data:
			thisbyte = bin2hex(origbyte)
			putback += " %s" % thisbyte
		self.nativeCommand(putback)
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
					startaddress,pagesize = findMemoryRegion(offset)
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
		allheaps = []
		peb = getPEBInfo()
		nrofheaps = int(ptrDWord(peb+0x88))
		processheaps = int(peb.ProcessHeaps)
		for i in xrange(nrofheaps):
			nextheap = ptrDWord(processheaps + (i*4))
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
		for thisthread in getProcessThreads():
			allthreads.append(wthread(thisthread))
		return allthreads

	"""
	Modules
	"""
	def getModule(self,modulename):
		wmod = None
		self.origmodname = modulename
		if len(PEBModList) == 0:
			getModulesFromPEB()
		try:
			thismod = None
			if modulename in PEBModList:
				modentry = PEBModList[modulename]
				thismod = module(modulename)
			
			else:
				# find a good one
				for modentry in PEBModList:
					modrecord = PEBModList[modentry]
					# 0 : file
					# 1 : path
					if modulename == modrecord[0]:
						thismod = module(modentry)
						break

			if thismod == None:
				# should never hit, as we have tested if modules can be loaded already
				imagename = self.getImageNameForModule(self.origmodname)
				thismod = module(str(imagename))

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
			ntHeader = module("ntdll").typedVar("_IMAGE_NT_HEADERS", thismodbase + ptrDWord(thismodbase + 0x3c))
			preferredbase = ntHeader.OptionalHeader.ImageBase
			entrypoint = ntHeader.OptionalHeader.AddressOfEntryPoint
			codebase = ntHeader.OptionalHeader.BaseOfCode
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
			dprintln("** Error trying to process module %s" % modulename)
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
		try:
			imagename = ""
			moduleLst = getModulesFromPEB()
			for mod in moduleLst:
				thismod = loadUnicodeString(mod.BaseDllName).encode("utf8")
				modparts = thismod.split("\\")
				thismodname = modparts[len(modparts)-1]
				moduleparts = thismodname.split(".")
				if thismodname.lower() == modulename.lower():
					baseaddy = int(ptrDWord(mod.getAddress() + 0x20))
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
			dprintln(traceback.format_exc())
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
			disasmlist = dbgCommand(cmd2run)
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
				disasmlist = dbgCommand(cmd2run)
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
		address = reg("eip")
		if not isValid(address):
			# assemble somewhere else - let's say at the ntdll entrypoint
			thismod = module("ntdll")
			thismodbase = thismod.begin()
			ntHeader = module("ntdll").typedVar("_IMAGE_NT_HEADERS", thismodbase + ptrDWord(thismodbase + 0x3c))
			entrypoint = ntHeader.OptionalHeader.AddressOfEntryPoint
			address = thismodbase + entrypoint
		allinstructions = instructions.lower().split("\n")
		origbytes = loadChars(address,20)
		cached = True
		for thisinstruction in allinstructions:	
			thisinstruction = thisinstruction.strip(" ").lstrip(" ")
			if thisinstruction.startswith("ret") and not thisinstruction.startswith("retf"):
				thisinstruction = thisinstruction.replace("retn","ret").replace("ret","retn")

			if not thisinstruction in self.AsmCache:
				objdisasm = disasm(address)
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
			dbgCommand(putback)			
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
		return loadCStr(address)

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
				output = dbgCommand(bpcommand)
			except:
				if memType.upper() == "S":
					bpcommand = "bp 0x%08x" % address
					output = dbgCommand(bpcommand)
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
		ntHeader = module("ntdll").typedVar("_IMAGE_NT_HEADERS", self.modbase + ptrDWord(self.modbase + 0x3c))
		pSize = 4
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
		iatlist = {}
		iatdir = ntHeader.OptionalHeader.DataDirectory[12]
		if iatdir.Size == 0:
			iatdir = ntHeader.OptionalHeader.DataDirectory[1]
		if iatdir.Size > 0:
			iatAddr = self.modbase + iatdir.VirtualAddress
			for i in range(0, iatdir.Size / pSize):
				iatEntry = ptrDWord(iatAddr + i*pSize)
				if iatEntry != None and iatEntry != 0:
					symbolName = findSymbol(iatEntry)
					if "!" in symbolName:
						iatlist[iatAddr + i*pSize] = symbolName
		return iatlist
					
	def getEATList(self,ntHeader, pSize):
		eatlist = {}
		if ntHeader.OptionalHeader.DataDirectory[0].Size > 0:
			eatAddr = self.modbase + ntHeader.OptionalHeader.DataDirectory[0].VirtualAddress
			nr_of_names = ptrDWord(eatAddr + 0x18)
			rva_of_names = self.modbase + ptrDWord(eatAddr + 0x20)
			address_of_functions = self.modbase + ptrDWord(eatAddr + 0x1c)
			for i in range (0, nr_of_names):
				eatName = loadCStr(self.modbase + ptrDWord(rva_of_names + 4 * i))
				eatAddress = self.modbase + ptrDWord(address_of_functions + 4*i)
				eatlist[eatName] = eatAddress
		return eatlist

	def getSectionAddress(self,sectionname):
		ntHeader = module("ntdll").typedVar("_IMAGE_NT_HEADERS", self.modbase + ptrDWord(self.modbase + 0x3c))
		nrsections = int(ntHeader.FileHeader.NumberOfSections)
		sectionsize = 40
		sizeOptionalHeader = int(ntHeader.FileHeader.SizeOfOptionalHeader)
		for sectioncnt in xrange(nrsections):
			sectionstart = (ntHeader.OptionalHeader.getAddress() + sizeOptionalHeader) + (sectioncnt*sectionsize)
			thissection = loadCStr(sectionstart)
			if thissection == sectionname:
				thissectionsize = ptrDWord(sectionstart + 0x8 + 0x8)
				thissectionrva = ptrDWord(sectionstart + 0x4 + 0x8)
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
				data =  loadChars(self.begin,self.size)
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
				dwords = loadDWords(self.begin,nrofdwords)
				curpos = self.begin + (nrofdwords * 4)
				remainingbytes = loadBytes(curpos,delta)
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
				self.protect = getVaProtect(self.begin)
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
				thismod = module(imagename)
				thismodbase = thismod.begin()
				thismodend = thismod.end()
				if self.begin >= thismodbase and self.begin <= thismodend:
					# find sections and their addresses
					ntHeader = module("ntdll").typedVar("_IMAGE_NT_HEADERS", thismodbase + ptrDWord(thismodbase + 0x3c))
					nrsections = int(ntHeader.FileHeader.NumberOfSections)
					sectionsize = 40
					sizeOptionalHeader = int(ntHeader.FileHeader.SizeOfOptionalHeader)
					for sectioncnt in xrange(nrsections):
						sectionstart = (ntHeader.OptionalHeader.getAddress() + sizeOptionalHeader) + (sectioncnt*sectionsize)
						thissection = loadCStr(sectionstart)
						thissectionsize = ptrDWord(sectionstart + 0x8 + 0x8)
						thissectionrva = ptrDWord(sectionstart + 0x4 + 0x8)
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

			disasmlines = dbgCommand("u 0x%08x L 1" % self.address)
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
		teb = self.getTEB()
		offset = 0x24
		if arch == 64:
			offset = 0x48
		tid = ptrDWord(teb+offset)
		return tid

class wheap:
	def __init__(self,address):
		self.address = address

	def getChunks(self,address):
		return {}


class LogBpHook:
	def __init__(self):
		return

