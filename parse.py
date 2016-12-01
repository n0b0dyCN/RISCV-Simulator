#!/usr/bin/python
## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-12 - ROPgadget tool
##
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
##

from capstone   import *
from ctypes     import *
from struct     import *
from elfheader	import *
import sys

debugger = 0


""" This class parses the ELF """
class ELF:
	def __init__(self, binary):
		self.__binary    = bytearray(binary)
		self.__ElfHeader = None
		self.__shdr_l    = []
		self.__phdr_l    = []

		self.__setHeaderElf()
		self.__setShdr()
		self.__setPhdr()

	""" Parse ELF header """
	def __setHeaderElf(self):
		e_ident = self.__binary[:15]

		ei_class = e_ident[ELFFlags.EI_CLASS]
		ei_data  = e_ident[ELFFlags.EI_DATA]

		if ei_class != ELFFlags.ELFCLASS32 and ei_class != ELFFlags.ELFCLASS64:
			print("[Error] ELF.__setHeaderElf() - Bad Arch size")
			return None

		if ei_data != ELFFlags.ELFDATA2LSB and ei_data != ELFFlags.ELFDATA2MSB:
			print("[Error] ELF.__setHeaderElf() - Bad architecture endian")
			return None

		if ei_class == ELFFlags.ELFCLASS32:
			if   ei_data == ELFFlags.ELFDATA2LSB: self.__ElfHeader = Elf32_Ehdr_LSB.from_buffer_copy(self.__binary)
			elif ei_data == ELFFlags.ELFDATA2MSB: self.__ElfHeader = Elf32_Ehdr_MSB.from_buffer_copy(self.__binary)
		elif ei_class == ELFFlags.ELFCLASS64:
			if   ei_data == ELFFlags.ELFDATA2LSB: self.__ElfHeader = Elf64_Ehdr_LSB.from_buffer_copy(self.__binary)
			elif ei_data == ELFFlags.ELFDATA2MSB: self.__ElfHeader = Elf64_Ehdr_MSB.from_buffer_copy(self.__binary)

		self.getArch() # Check if architecture is supported

	""" Parse Section header """
	def __setShdr(self):
		shdr_num = self.__ElfHeader.e_shnum
		base = self.__binary[self.__ElfHeader.e_shoff:]
		shdr_l = []

		e_ident = self.__binary[:15]
		ei_data = e_ident[ELFFlags.EI_DATA]

		for i in range(shdr_num):

			if self.getArchMode() == CS_MODE_32:
				if   ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf32_Shdr_LSB.from_buffer_copy(base)
				elif ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf32_Shdr_MSB.from_buffer_copy(base)
			elif self.getArchMode() == CS_MODE_64:
				if   ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf64_Shdr_LSB.from_buffer_copy(base)
				elif ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf64_Shdr_MSB.from_buffer_copy(base)

			self.__shdr_l.append(shdr)
			base = base[self.__ElfHeader.e_shentsize:]

		# setup name from the strings table
		if self.__ElfHeader.e_shstrndx != 0:
			string_table = str(self.__binary[(self.__shdr_l[self.__ElfHeader.e_shstrndx].sh_offset):])
			for i in range(shdr_num):
				self.__shdr_l[i].str_name = string_table[self.__shdr_l[i].sh_name:].split('\0')[0]

	""" Parse Program header """
	def __setPhdr(self):
		pdhr_num = self.__ElfHeader.e_phnum
		base = self.__binary[self.__ElfHeader.e_phoff:]
		phdr_l = []

		e_ident = self.__binary[:15]
		ei_data = e_ident[ELFFlags.EI_DATA]

		for i in range(pdhr_num):
			if self.getArchMode() == CS_MODE_32:
				if   ei_data == ELFFlags.ELFDATA2LSB: phdr = Elf32_Phdr_LSB.from_buffer_copy(base)
				elif ei_data == ELFFlags.ELFDATA2MSB: phdr = Elf32_Phdr_MSB.from_buffer_copy(base)
			elif self.getArchMode() == CS_MODE_64:
				if   ei_data == ELFFlags.ELFDATA2LSB: phdr = Elf64_Phdr_LSB.from_buffer_copy(base)
				elif ei_data == ELFFlags.ELFDATA2MSB: phdr = Elf64_Phdr_MSB.from_buffer_copy(base)

			self.__phdr_l.append(phdr)
			base = base[self.__ElfHeader.e_phentsize:]

	def getEntryPoint(self):
		return self.__ElfHeader.e_entry

	# .text segment
	def getExecSections(self):
		ret = []
		for segment in self.__phdr_l:
			if (segment.p_flags & 0x1) or 1:
				ret +=  [{
							"offset"  : segment.p_offset,
							"filesz"  : segment.p_filesz,
							"memsz" : segment.p_memsz,
							"vaddr"   : int(segment.p_vaddr),
							"opcodes" : bytes(self.__binary[segment.p_offset:segment.p_offset+segment.p_memsz])
						}]
		return ret

	# other segments
	def getDataSections(self):
		ret = []
		for section in self.__shdr_l:
			if (not (section.sh_flags & 0x4) and (section.sh_flags & 0x2)):
				ret +=  [{
							"name"    : section.str_name,
							"offset"  : section.sh_offset,
							"size"    : section.sh_size,
							"vaddr"   : int(section.sh_addr),
							"opcodes" : str(self.__binary[section.sh_offset:section.sh_offset+section.sh_size])
						}]
		return ret


	# all segments
	def getAllSections(self):
		ret = []
		for section in self.__shdr_l:
			#if section.str_name.find("debug") != -1:
			#	continue
			ret +=  [{
						"name"    : section.str_name,
						"offset"  : section.sh_offset,
						"size"    : section.sh_size,
						"vaddr"   : section.sh_addr,
						"opcodes" : str(self.__binary[section.sh_offset:section.sh_offset+section.sh_size])
					}]
		return ret

	def getArch(self):
		if self.__ElfHeader.e_machine == ELFFlags.EM_386 or self.__ElfHeader.e_machine == ELFFlags.EM_X86_64:
			return CS_ARCH_X86
		elif self.__ElfHeader.e_machine == ELFFlags.EM_ARM:
			return CS_ARCH_ARM
		elif self.__ElfHeader.e_machine == ELFFlags.EM_ARM64:
			return CS_ARCH_ARM64
		elif self.__ElfHeader.e_machine == ELFFlags.EM_MIPS:
			return CS_ARCH_MIPS
		elif self.__ElfHeader.e_machine == ELFFlags.EM_PowerPC:
			return CS_ARCH_PPC
		elif self.__ElfHeader.e_machine == ELFFlags.EM_SPARCv8p:
			return CS_ARCH_SPARC
		else:
			print ("[Error] ELF.getArch() - Architecture not supported: 0x%02x" % self.__ElfHeader.e_machine)
			return None

	def getArchMode(self):
		if self.__ElfHeader.e_ident[ELFFlags.EI_CLASS] == ELFFlags.ELFCLASS32:
			return CS_MODE_32
		elif self.__ElfHeader.e_ident[ELFFlags.EI_CLASS] == ELFFlags.ELFCLASS64:
			return CS_MODE_64
		else:
			print("[Error] ELF.getArchMode() - Bad Arch size")
			return None

	def getFormat(self):
		return "ELF"

	def printExecSections(self):
		execSection = self.getExecSections()
		print "========================================"
		print "Exec Sections"
		print "offset\tfilesz\tmemsz\tvaddr\t"
		for each in execSection:
			#print type(each["vaddr"])
			print "%x\t%x\t%x\t%x" % (each["offset"], each["filesz"], each["memsz"], each["vaddr"])
		print "========================================"

	def printSections(self):
		dataSection = self.getAllSections()
		print "========================================"
		print "Sections"
		print "name\toffset\tsize\tvaddr"
		for each in dataSection:
			#print type(each["vaddr"])
			print "%s\t%x\t%x\t%x" % (each["name"].strip('elf'), each["offset"], each["size"], each["vaddr"])
		print "========================================"


class MEM:

	"""
	Memory is 32bit align
	use long type to get 32bit or 64bit data
	"""
	def __init__(self, elf):
		self.memSpace = self.getMemSpace(elf)

	def getMemSpace(self, elf):
		print "----------MEM SPACE----------"
		memMap = [ [each["name"], each["vaddr"], each["opcodes"], each["size"], each["vaddr"]+each["size"]] for each in elf.getAllSections()]
		maxend = 0
		for each in memMap:
			maxend = max(each[4], maxend)
		heap = '\x00'*16*1024
		memMap.append(["heap", maxend , heap, len(heap), maxend+len(heap)])
		stack = '\x00'*8*1024
		memMap.append(["stack", 0x10000000 , stack, len(stack), 0x10000000+len(stack)])
		for each in memMap:
			print "%s\t0x%x\t0x%x\t0x%x" % (each[0], each[3], each[1], each[4])
		print "----------END   MEM----------"
		return memMap

	def printMem(self, addr, l):
		addr = addr - (addr % 4)
		l = l/4+1
		for i in range(l):
			tmp = addr + i*4
			raw = self.load32(tmp)
			print "[0x%.08x] %.08x" % (tmp, raw)

	#load bytes from memory
	def load(self, addr, length):
#		print "--------------------"
		sec_start = 0
		sec_end = 0
		sec_name = ""
		sec_buf = "NOT FOUND"
		found = 0
		sec_len = 0
		data_len = 0
		global debugger

		# check data length
		if (length == 64):
			data_len = length/8
		elif (length == 32) or (length == 16) or (length == 8):
			data_len = length/8
		else:
			print "Cannot load data with length=%d" % (length)
			return -1

		# check align
# 		if not self.checkaddr(addr, data_len):
			#return '\x00\x00\x00\x00'
#			return -2

		addr = long(addr)
#		print "addr = 0x%x" % (addr)
		for sections in self.memSpace:
			sec_start = sections[1]
			sec_end = sections[4]
#			print "[0x%x, 0x%x]" % (sec_start, sec_end)
			if (addr >= sec_start):
#				print "Judge 1"
				if (addr+(data_len)<=sec_end):
#					print "Judge 2"
					sec_name = sections[0]
#					print sec_name
					sec_buf = sections[2]
#					print hex(len(sec_buf))
					found = 1
#					print "Found"
					break;

		if (found == 0):
			print "Cannot fetch data at [0x%x] with length %d" % (addr, length)
			return -3

		strb = long(addr) - long(sec_start)
		stre = long(addr) - long(sec_start) + (data_len)
		raw_data = sec_buf[strb : stre]

#		if (data_len == 64):
#			ret = unpack("<Q", raw_data)[0]
#		elif (data_len == 32):
#			ret = unpack("<I", raw_data)[0]
		ret = raw_data
		return ret

	# store bytes to memory
	def store(self, addr, val, length):
		# check decode
		#return

		sec_start = 0
		sec_buf = None
		sec_len = 0
		data_len = 0

		# check data length
		if (length == 64):
#			val = val & 0xffffffffffffffff
			data_len = length/8
		elif (length == 32) or (length == 16) or (length == 8):
#			val = val & 0xffffffff
			data_len = length/8
		else:
			print "Cannot store data with length=%d" % length
			return "ERROR"

		# check align
#		if not self.checkaddr(addr, data_len):
#			print "Bad align"
#			return "ERROR"

		for sections in self.memSpace:
			if (addr >= sections[1]):
				sec_start = sections[1]
				sec_buf = sections[2]
				sec_len = sections[3]
				if (addr - sec_start + data_len <= sec_len):
#					if (data_len == 64):
#						raw_data = pack("<Q", val)
#					elif (data_len == 32):
#						raw_data = pack("<I", val)
					raw_data = val
					#print "Store data:" + raw_data
					#print "[=] before: 0x%x" % len(sections[2])
					#print "[=] data_len: 0x%x" % data_len
					#print "[=] len(raw): 0x%x" % len(raw_data)
					sections[2] = sec_buf[0:addr-sec_start] + raw_data + sec_buf[addr-sec_start+len(raw_data): ]
					#print "[=] after : 0x%x" % len(sections[2])
					return data_len

		return "ERROR"

	def storeraw(self, addr, raw):
		sec_start = 0
		sec_buf = None
		sec_len = 0
		data_len = len(raw)
		for sections in self.memSpace:
			if (addr >= sections[1]):
				sec_start = sections[1]
				sec_buf = sections[2]
				sec_len = sections[3]
				if (addr - sec_start + data_len <= sec_len):
					raw_data = raw
					sections[2] = sec_buf[0:addr-sec_start] + raw_data + sec_buf[addr-sec_start+len(raw_data): ]
					return data_len

	def loadraw(self, addr, data_len):
		sec_start = 0
		sec_buf = None
		sec_len = 0
		for sections in self.memSpace:
			if (addr >= sections[1]):
				sec_start = sections[1]
				sec_buf = sections[2]
				sec_len = sections[3]
				if (addr - sec_start + data_len <= sec_len):
					raw = sec_buf[addr-sec_start : addr - sec_start + data_len]
					return raw

	def checkaddr(self, addr, align):
		if (align == 32):
			if (addr & 0x3):
				print "Address align = %d bytes, addr = 0x%.08x" % (align, addr)
				return False
			return True
		elif (align == 64):
			if (addr & 0x7):
				print "Address align = %d bytes, addr = 0x%.08x" % (align, addr)
				return False
			return True
		else:
			print "Bad align: %d" % (align)
			return False

	def store08(self, addr, val):
		val = val & 0xff
		val = pack("<I", val)[0]
#		offs = addr % 4
#		addr = (addr>>2)<<2
#		oristr = self.load(addr, 32)
#		resstr = oristr[0:offs] + val + oristr[offs+len(val): ]
		ret = self.store(addr, val, 8)
		check = self.load64(addr)
#		if debugger == 1:
##			print "[debugmem] Store08: %s" % val
##			print "[debugmem] Addr : %.016x" % addr
##			print "[debugmem] len  : %d" % len(val)
##			print "[debugmem] check: %.016x" % check
		return ret

	def store16(self, addr, val):
		val = val & 0xffff
		val = pack("<I", val)[0:2]
#		offs = addr % 4
#		addr = (addr>>2)<<2
#		oristr = self.load(addr, 32)
#		resstr = oristr[0:offs] + val + oristr[offs+len(val): ]
		ret = self.store(addr, val, 16)
		check = self.load64(addr)
#		if debugger:
#			print "[debugmem] Store16: %s" % val
#			print "[debugmem] Addr : %.016x" % addr
#			print "[debugmem] len  : %d" % len(val)
#			print "[debugmem] check: %.016x" % check
		return ret

	def store32(self, addr, val):
		val = val & 0xffffffff
		val = pack("<I", val)
		ret = self.store(addr, val, 32)
		check = self.load64(addr)
#		if debugger:
#			print "[debugmem] Store32: %s" % val
#			print "[debugmem] Addr : %.016x" % addr
#			print "[debugmem] len  : %d" % len(val)
#			print "[debugmem] check: %.016x" % check
		return ret

	def store64(self, addr, val):
		val = val & 0xffffffffffffffff
		val = pack("<Q", val)
		ret = self.store(addr, val, 64)
		check = self.load64(addr)
#		if debugger:
#			print "[debugmem] Store64: %s" % val
#			print "[debugmem] Addr : %.016x" % addr
#			print "[debugmem] len  : %d" % len(val)
#			print "[debugmem] check: %.016x" % check
		return ret

	def store32F(self, addr, val):
		val = pack("<f", val)
		ret = self.store(addr, val, 32)
		check = self.load64(addr)
#		if debugger:
#			print "[debugmem] Store32F: %s" % val
#			print "[debugmem] Addr : %.016x" % addr
#			print "[debugmem] len  : %d" % len(val)
#			print "[debugmem] check: %.016x" % check
		return ret

	def store64F(self, addr, val):
		val = pack("<d", val)
		ret = self.store(addr, val, 64)
		check = self.load64(addr)
		return ret


	def load08(self, addr):
#		return 0
#		offs = addr % 4
#		addr = (addr>>2)<<2
#		check = self.load(addr, 64)
##		print "[debug] check: %.016x" % unpack("<Q", check)[0]
		ret = self.load(addr, 8)
		result = ret + '\x00\x00\x00'
#		print "[addr ] 0x%.08x" % addr
##		print "[debug] result :" +  str(result)
##		print "[debug] ret : %s" % (ret)
##		print "[debug] ret len = %d" % len(ret)
##		print "[debug] result len = %d" % len(result)
		ret = unpack("<I", result)[0]
		ret = (ret) & 0xff
		return ret

	def load16(self, addr):
#		return 0
#		offs = addr % 4
#		addr = (addr>>2)<<2
		#check = self.load(addr, 64)
		##print "[debug] check: %.016x" % unpack("<Q", check)[0]
		result = self.load(addr, 16) + '\x00\x00'
		ret = unpack("<I", result)[0]
#		print "[debugmem] addr  : 0x%.08x" % addr
#		print "[debugmem] load16: 0x%.08x" % ret
		ret = (ret) & 0xffff
		return ret

	def load32(self, addr):
#		if addr>0x205ec or addr < 0x10000:
#			return 0
#		check = self.load(addr, 64)
##		print "[debug] check: %.016x" % unpack("<Q", check)[0]
		result = self.load(addr, 32)
##		print "[debug] result : %s" % (result)
##		print "[debug] result len: %d" % len(result)
		ret =  unpack("<I", result)[0]
		return ret

	def load64(self, addr):
#		return 0
#		check = self.load(addr, 64)
##		print "[debug] check: %.016x" % unpack("<Q", check)[0]
		result = self.load(addr, 64)
#		if debugger:
#			print "[debugmem] " + str(result)
#			print "[debugmem] result len: %d" % len(result)
		ret =  unpack("<Q", result)[0]
		return ret

	def load32F(self, addr):
#		return 0
		result = self.load(addr, 32)
		ret = unpack("<f", result)[0]
		return ret

	def load64F(self, addr):
		result = self.load(addr, 64)
		ret = unpack("<d", result)[0]
		return ret

class Extender:
	def format64(self, x):
		return int(x % 0x10000000000000000)

	def format32(self, x):
		return int(x % 0x100000000)

	def signExtend(self, val, length):
		sign = (val >> (length-1)) & 0x1
		if (sign == 0):
			mask = ~((~0)<<length)
			ret = val & mask
		elif (sign == 1):
			mask = ((~0)<<length)
			ret = val | mask

		ret = self.format64(ret)
		return ret

	def zeroExtend(self, val, length):
		mask = ~((~0)<<length)
		ret = val & mask
		ret = self.format64(ret)
		return ret

	#def s2u64(self, val):
	#	return val % 0x10000000000000000


class RegFile:

	"""
	kown the usage of register, see page 85
	"""
	def __init__(self, elf):

		self.x = [int(0)]*32
		self.f = [float(0)]*32
		self.pc = elf.getEntryPoint()
		# initialize the stack pointer
		self.x[2] = 0x10001f00
		self.xname = [  "zero", "  ra", "  sp", "  gp",
						"  tp", "  t0", "  t1", "  t2",
						"  s0", "  s1", "  a0", "  a1",
						"  a2", "  a3", "  a4", "  a5",
						"  a6", "  a7", "  s2", "  s3",
						"  s4", "  s5", "  s6", "  s7",
						"  s8", "  s9", " s10", " s11",
						"  t3", "  t4", "  t5", "  t6"]

	def printRegx(self):
		#return
		print "--------------------Regx--------------------"
		print "pc = 0x%.08x" % self.pc
		for i in range(8):
			print "%s : 0x%.08x\t %s : 0x%.08x\t %s : 0x%.08x\t %s : 0x%.08x" % (self.xname[4*i], self.x[4*i], self.xname[4*i+1], self.x[4*i+1], self.xname[4*i+2], self.x[4*i+2], self.xname[4*i+3], self.x[4*i+3])
		print "--------------------------------------------"

	def printRegf(self):
		pass


	def setReg(self, t, no, val):
		if (t == "x"):
			return self.setx(no, val)
		elif (t == "f"):
			return self.setf(no, val)
		elif (t == "pc"):
			return self.setpc(val)
		else:
			print "[-] no such type register."
			return "ERROR"

	def getReg(self, t, no):
		if (t == "x"):
			return self.getx(no)
		elif (t == "f"):
			return self.getf(no)
		elif (t == "pc"):
			return self.getpc()
		else:
			print "no such type register."
			return "ERROR"

	def setx(self, no, val):
		if (no < 0) or (no > 31):
			print "register no error."
			return "ERROR"
		if (no == 0):
			self.x[0] = int(0)
			return 0
		else:
			val = int(val % 0x10000000000000000)
			self.x[no] = val
			return val

	def setf(self, no, val):
		if (no < 0) or (no > 31):
			print "register no error."
			return "ERROR"
		else:
			val = float(val)
			self.f[no] = val
			return val

	def setpc(self, val):
		val = int(val % 0x10000000000000000)
		self.pc = val

	def getx(self, no):
		if (no < 0) or (no > 31):
			print "register no error."
			return "ERROR"
		elif (no == 0):
			return 0
		else:
			return self.x[no]

	def getf(self, no):
		if (no < 0) or (no > 31):
			print "register no error."
			return "ERROR"
		else:
			return self.f[no]

	def getpc(self):
		#print "pc = 0x%x" % self.pc
		return self.pc

class ALU_UNIT:
	"""
	self.action indicates which operation is taking
	"""
	def __init__(self):
		self.action = 0
		self.extender = Extender()

	def absf(self, x):
		if x >= 0:
			return x
		return -x

	def format64(self, x):
		return int(x & 0xffffffffffffffff)

	def format32(self, x):
		return int(x & 0xffffffff)

	def d2f(self, val):
		val = pack("<f", val)
		val = unpack("<f", val)[0]
		return val

	def f2d(self, val):
		val = pack("<d", val)
		val = unpack("<d", val)[0]
		return val

	def MUL64(self, x, y):
		ret = x*y
		ret = ret & 0xffffffffffffffff
		return ret

	def MULH64(self, x, y):
		x = self.u2s64(x)
		y = self.u2s64(y)
		ret = ((x * y) & 0xffffffffffffffff0000000000000000) >> 64
		return ret

	def MULHU64(self, x, y):
		x = self.s2u64(x)
		y = self.s2u64(y)
		ret = ((x * y) & 0xffffffffffffffff0000000000000000) >> 64
		return ret


	def DIV64(self, x, y):
		x = self.u2s64(x)
		y = self.u2s64(y)
		ret = x // y
		return ret

	def DIVU64(self, x, y):
		x = self.s2u64(x)
		y = self.s2u64(y)
		ret = x // y
		return ret

	def REMU64(self, x, y):
		x = self.s2u64(x)
		y = self.s2u64(y)
		ret = x % y
		return ret

	def MULW32(self, x, y):
		x = self.u2s32(x)
		y = self.u2s32(y)
		ret = self.extender.signExtend((x * y) & 0xffffffff, 32)
		return ret

	def DIVW32(self, x, y):
		x = self.u2s32(x)
		y = self.u2s32(y)
		ret = self.extender.signExtend(x // y, 32)
		return ret

	def DIVUW32(self, x, y):
		x = self.s2u32(x)
		y = self.s2u32(y)
		ret = self.extender.signExtend(x // y, 32)
		return ret

	def REMW32(self, x, y):
		x = self.u2s32(x)
		y = self.u2s32(y)
		ret = self.extender.signExtend(x % y, 32)
		return ret

	def MUL32F(self, x, y):
		ret = x * y
		ret = self.d2f(ret)
		return ret


	def MUL64F(self, x, y):
		ret = x * y
		return ret


	def DIV32F(self, x, y):
		ret = x / y
		ret = self.d2f(ret)
		return ret


	def DIV64F(self, x, y):
		ret = x / y
		return ret

	def ADD64F(self, x, y):
		ret = x + y
		return ret

	def SUB64F(self, x, y):
		ret = x - y
		return ret

	def i32toF(self, val):
		ret = float(val)
		return ret

	def u32toF(self, val):
		ret = float(val)
		return ret

	def i64toF(self, val):
		ret = float(val)
		return ret

	def f2i32(self, val):
		val = int(val)
		ret = self.extender.format32(val)
		return ret

	def f2i64(self, val):
		val = int(val)
		ret = self.extender.format64(val)
		return ret

	def ADD64(self, x, y):
		self.action = 0x1
		ret = x+y
		#print "ret = %.08x" % ret
		ret = self.format64(ret)
		#print "ret = %.08x" % ret
		return ret;

	def ADD32(self, x, y):
		self.action = 0x1
		ret = x+y
		ret = self.format32(ret)
		ret = self.extender.signExtend(ret, 32)
		return ret;

	def SUB64(self, x, y):
		self.action = 0x2
		ret = x-y
		ret = self.format64(ret)
		return ret

	def SUB32(self, x, y):
		self.action = 0x2
		ret = x-y
		ret = self.format32(ret)
		ret = self.extender.signExtend(ret, 32)
		return ret

	def XOR64(self, x, y):
		self.action = 0x3
		ret = x^y
		ret = self.format64(ret)
		return ret

	def XOR32(self, x, y):
		self.action = 0x3
		ret = x^y
		ret = self.format32(ret)
		ret = self.extender.signExtend(ret, 32)
		return ret

	def OR64(self, x, y):
		self.action = 0x4
		ret = x|y
		ret = self.format64(ret)
		return ret

	def OR32(self, x, y):
		self.action = 0x4
		ret = x|y
		ret = self.format32(ret)
		ret = self.extender.signExtend(ret, 32)
		return ret

	def AND64(self, x, y):
		self.action = 0x5
		ret = x&y
		ret = self.format64(ret)
		return ret

	def AND32(self, x, y):
		self.action = 0x5
		ret = x&y
		ret = self.format32(ret)
		ret = self.extender.signExtend(ret, 32)
		return ret

	def SRL(self, x, shamt):
		ret = (x>>shamt) if (x>=0) else (x + 0x10000000000000000)>>shamt
		ret = self.format64(ret)
		return ret

	def SRA(self, x, shamt):
		ret = x>>shamt
		ret = self.format64(ret)
		return ret

	def SLL(self, x, shamt):
		ret = x<<shamt
		ret = self.format64(ret)
		return ret

	def s2u64(self, val):
		return val % 0x10000000000000000

	def u2s64(self, val):
		if val<0:
			return val
		if not (val>>63):
			return val
		return val - 0x10000000000000000

	def s2u32(self, val):
		return val % 0x100000000

	def u2s32(self, val):
		if val<0:
			return val
		if not (val>>31):
			return val
		return val - 0x100000000

	# if (signed)a < (signed)b, return true
	def LTH32(self, a, b):
		return a < b
		#return self.u2s32(a) < self.u2s32(b)

	def LTH64(self, a, b):
		return a < b
		#return self.u2s64(a) < self.u2s64(b)

	# if (signed)a <= (signed)b return true
	def LEQ32(self, a, b):
		return a <= b
		#return self.u2s32(a) <= self.u2s32(b)

	def LEQ64(self, a, b):
		return a <= b
		#return self.u2s64(a) <= self.u2s64(b)

	def EQU(self, a, b):
		return self.format64(a) == self.format64(b)

class Decoder:

	def __init__(self):
		self.cmd = 0
		self.opcode = 0 	# 0-6
		self.rd = 0 		# 7-11
		self.func3 = 0 		# 12-14
		self.rs1 = 0 		# 15-19
		self.rs2 = 0 		# 20-24
		self.rs3 = 0
		self.func7 = 0 		# 25-31
		self.shamt = 0 		# 20-24
		self.shamt_6 = 0 	# 20-25
		self.func_6 = 0 	# 26-31
		self.imm_I = 0
		self.imm_S = 0
		self.imm_SB = 0
		self.imm_U = 0
		self.imm_UJ = 0
		self.branch = 0		# determine whether pc need to be added 4
		self.ALU = ALU_UNIT()
		self.extender = Extender()
		self.so = CDLL('./cfunctions.so')

	def printParse(self):
		print "cmd    = 0x%.08x" % self.cmd
		print "opcode = 0x%.02x" % self.opcode
		print "func3  = 0x%.01x" % self.func3
		print "func7  = 0x%.02x" % self.func7
		print "func6  = 0x%.02x" % self.func6
		print "rs1 = %d, rs2 = %d, rd = %d" % (self.rs1, self.rs2, self.rd)
		print "shamt = %d, shamt6 = %d" % (self.shamt, self.shamt_6)
		print "imm_I  = 0x%.05x" % self.imm_I
		print "imm_S  = 0x%.05x" % self.imm_S
		print "imm_SB = 0x%.05x" % self.imm_SB
		print "imm_U  = 0x%.05x" % self.imm_U
		print "imm_UJ = 0x%.05x" % self.imm_UJ

	def getimm_20(self, cmd):		# index 0-19
		imm_20 = (cmd & 0x80000000) >> 12
		imm_10_1 = (cmd & 0x7fe00000) >> 21
		imm_11 = (cmd & 0x00100000) >> 10
		imm_19_12 = (cmd & 0xff000) >> 1
		self.imm_20 = imm_20 + imm_10_1 + imm_11 + imm_19_12

	def getimm_branch(self, cmd):
		imm_12 = (cmd & 0x80000000) >> 20
		imm10_5 = (cmd & 0x7e000000) >> 21
		imm11 = (cmd & 0x80) << 3
		imm4_1 = (cmd & 0xf00) >> 8
		self.imm_branch12_1 = imm_12 + imm10_5 + imm11 + imm4_1

	def getopcode(self, cmd):
		self.opcode = cmd & 0x7f

	def getrd(self, cmd):
		self.rd = (cmd & 0xf80)>>7

	def getimm4_0(self, cmd):
		self.imm4_0 = (cmd & 0xf80)>>7

	def getfunc3(self, cmd):
		self.func3 = (cmd & 0x7000)>>12

	def getrs1(self, cmd):
		self.rs1 = (cmd & 0xf8000)>>15

	def getrs2(self, cmd):
		self.rs2 = (cmd & 0x1f00000)>>20

	def getrs3(self, cmd):
		self.rs3 = (cmd >> 27) & 0x1f

	def getshamt(self, cmd):
		self.shamt = (cmd & 0x1f00000)>>20

	def getshamt_6(self, cmd):
		self.shamt_6 = (cmd & 0x3f00000)>>20

	def getfunc7(self, cmd):
		self.func7 = (cmd & 0xfe000000)>>25

	def getfunc_6(self, cmd):
		self.func_6 = (cmd & 0xfc000000)>>26

	def getimm11_5(self, cmd):
		self.imm11_5 = (cmd & 0xfe000000)>>25

	def getimm11_0(self, cmd):
		self.imm11_0 = (cmd & 0xfff00000)>>20

	def getimm31_12(self, cmd):
		self.imm31_12 = (cmd & 0xfffff000)>>12

	def parse(self, cmd):
		self.cmd = cmd
		self.getopcode(cmd)
		self.getfunc3(cmd)
		self.getfunc7(cmd)
		self.getfunc_6(cmd)
		self.getrd(cmd)
		self.getrs1(cmd)
		self.getrs2(cmd)
		self.getrs3(cmd)
		self.getshamt(cmd)
		self.getshamt_6(cmd)
		self.getImm_I(cmd)
		self.getImm_S(cmd)
		self.getImm_SB(cmd)
		self.getImm_U(cmd)
		self.getImm_UJ(cmd)

	def getImm_I(self, cmd):
		self.imm_I = (cmd>>20)

	def getImm_S(self, cmd):
		imm4_0 = (cmd>>7)&0x1f
		imm11_5 = (cmd>>25)&0x7f
		self.imm_S = (imm11_5<<5) | imm4_0

	def getImm_SB(self, cmd):
		imm11 = (cmd>>7)&0x1
		imm4_1 = (cmd>>8)&0xf
		imm10_5 = (cmd>>25)&0x3f
		imm12 = (cmd>>31)&0x1
		self.imm_SB = ((imm4_1<<1) | (imm10_5<<5) | (imm11<<11) | (imm12<<12))

	def getImm_U(self, cmd):
		self.imm_U = (cmd>>12)<<12

	def getImm_UJ(self, cmd):
		imm20 = cmd>>31
		imm10_1 = (cmd>>21)&0x3ff
		imm11 = (cmd>>20)&0x0000001
		imm19_12 = (cmd>>12) & 0x0000ff
		self.imm_UJ = (imm10_1<<1) | (imm11<<11) | (imm19_12<<12) | (imm20<<20)

	def syscall(self, no, argv, reg, mem):
		if (no == 93):
			# SYS_exit
			#print "SYS_exit"
			raw_input("exit>")
			sys.exit(argv[0])
		if (no == 64):
			#return
			#print "SYS_write"
			# SYS_write
			fd = argv[0]
			buf = argv[1]
			length = argv[2]
			#print "++++++++++SYS_write++++++++++"
			#print "no = %d" % no
			#print "argv"
			#print "buf: %.016x" % buf
			#print "len: %d" % length
			
			if (length > 100):
				print "[Error] SYS_write error"
				sys.exit(-1)
			#if (fd == 1):
			#	fd = sys.stdout
			"""
			output = ''
			for i in range(length):
				c = mem.load08(buf+i)
				try:
					output += chr(c)
				except:
					break
			
			print("[Debug]" + output)
			"""
			
			raw = mem.loadraw(buf, length)
			new_buf = create_string_buffer(raw)
			#new_buf.from_buffer_copy()

			#mem.printMem(buf, length)
			#print "----"
			#mem.printMem(new_buf, length)
			ret_val = self.so.SYS_write(fd, new_buf, length)
			#print "++++++++END SYS_write++++++++"

			#print "[write]>>" + output
			#raw_input()
			#ret_val = len(output)
			reg.setReg("x", 10, ret_val)
		if (no == 63):
			#print "SYS_read"
			#return
			# SYS_read
			fd = argv[0]
			tar_addr = argv[1]
			length = argv[2]

			#print "++++++++++SYS_read++++++++++"
			#print "no = %d" % no
			#print "argv"
			#print argv
			buf = create_string_buffer(length)
			ret_val = self.so.SYS_read(fd, buf, length)
			read_str = buf.raw
			#if (read_str == '\n'):
			#	read_str = '\x00'
			#for i in range(len(read_str)):
			#	mem.store08(tar_addr+i, ord(read_str[i]))
			
		#mem.printMem(tar_addr, 8)
			mem.storeraw(argv[1], read_str)
			
			# mem.store08(tar_addr+len(read_str), 0)
			#raw_input('1>')
			#raw_input('2>')
		#mem.printMem(tar_addr, 8)
			#print "return [%d]" % ret_val
		#mem.printMem(0x10001f00 - 0x50, 64)
			#print "++++++++END SYS_read++++++++"
			#raw_input('3>')
			#raw_input('4>')
			reg.setReg("x", 10, ret_val)
			pass
		if (no == 80):
			reg.setReg("x", 10, 0)
			return
			#print "----------------"
			#print "SYS_fstat(%d, %.08x)" % (argv[0], argv[1])
			# SYS_fstat
			buf = create_string_buffer(144)
			self.so.SYS_fstat(argv[0], buf)
			raw = buf.raw
			mem.storeraw(argv[1], raw)
			#tar_addr = argv[1]
			#for i in range(len(raw)):
			#	mem.store08(tar_addr+i, raw[i])

			#for i in range(144/4):
			#	print "%.02x %.02x %.02x %.02x" % (ord(raw[4*i]), ord(raw[4*i+1]), ord(raw[4*i+2]), ord(raw[4*i+3]))

			#print "----------------"
			#mem.printMem(reg.getReg("x", 2)-0x10, 144)
			#print "----------------"

			pass
		if (no == 214):
			#print "SYS_brk"
			# SYS_brk
			pass
		if (no == 169):
			#print "SYS_gettimeofday"
			# SYS_gettimeofday
		#print "++++++++++SYS_gettimeofday++++++++++"
			buf = create_string_buffer(16)
			ret_val = self.so.SYS_gettimeofday(buf)
			raw = buf.raw
		#mem.printMem(argv[0], 16)
			mem.storeraw(argv[0], raw)
		#mem.printMem(argv[0], 16)
			reg.setReg("x", 10, ret_val)
		#print "++++++++++END_thissyscall+++++++++++++++"


	def do(self, cmd, reg, mem):
		self.branch = 0
		self.parse(cmd)

		if cmd==0x73: # ECALL
			syscall_no = reg.getReg("x", 17)
			#if syscall_no == 64:
			#	print "[Debug]length = %d" % (reg.getReg("x", 12))
			#	print "[Debug]a3 = %d" % (reg.getReg("x", 13))
			syscall_argv = [reg.getReg("x", 10), reg.getReg("x", 11), reg.getReg("x", 12), reg.getReg("x", 13)]
			self.syscall(syscall_no, syscall_argv, reg, mem)
			return "ECALL"

		# JAL JALR
		if self.opcode == 0x67 and self.func3 == 0: # RV32I JALR
			pc = reg.getReg("pc", 0)
			imm = self.extender.signExtend(self.imm_I, 12)
			src1 = reg.getReg("x", self.rs1)
			tar_addr = (self.ALU.ADD64(imm, src1)>>1)<<1
			reg.setReg("x", self.rd, pc + 4)
			reg.setReg("pc", 0, tar_addr)
			self.branch = 1
			return "JALR 0x%x(x%d)" % (self.imm_I, self.rs1)

		elif self.opcode == 0x6f: # RV32I JAL
			pc = reg.getReg("pc", 0)
			reg.setReg("x", self.rd, pc + 4)
			imm = self.extender.signExtend(self.imm_UJ, 21)
			tar_addr = self.ALU.ADD64(pc, imm)
			reg.setReg("pc", 0, tar_addr)
			self.branch = 1
			return "JAL 0x%x" % tar_addr

		# BEQ BNE BLT BGE BLTU BGEU
		if self.opcode == 0x63 and self.func3 == 0: # RV32I BEQ
			val1 = self.ALU.s2u64(reg.getReg("x", self.rs1))
			val2 = self.ALU.s2u64(reg.getReg("x", self.rs2))
			if self.ALU.EQU(val1, val2):
				pc = reg.getReg("pc", 0)
				pc = pc + (self.extender.signExtend(self.imm_SB, 13))
				reg.setReg("pc", 0, pc)
				self.branch = 1
			return "BEQ x%d, x%d" % (self.rs1, self.rs2)

		elif self.opcode == 0x63 and self.func3 == 1: # RV32I BNE
			val1 = self.ALU.s2u64(reg.getReg("x", self.rs1))
			val2 = self.ALU.s2u64(reg.getReg("x", self.rs2))
			if not self.ALU.EQU(val1, val2):
				pc = reg.getReg("pc", 0)
				pc = pc + (self.extender.signExtend(self.imm_SB, 13))
				reg.setReg("pc", 0, pc)
				self.branch = 1
			return "BNE x%d, x%d" % (self.rs1, self.rs2)

		elif self.opcode == 0x63 and self.func3 == 4: # RV32I BLT
			val1 = self.ALU.u2s64(reg.getReg("x", self.rs1))
			val2 = self.ALU.u2s64(reg.getReg("x", self.rs2))
			if self.ALU.LTH64(val1, val2):
				pc = reg.getReg("pc", 0)
				pc = pc + (self.extender.signExtend(self.imm_SB, 13))
				reg.setReg("pc", 0, pc)
				self.branch = 1
			return "BLT x%d, x%d" % (self.rs1, self.rs2)

		elif self.opcode == 0x63 and self.func3 == 5: # RV32I BGE
			val1 = self.ALU.u2s64(reg.getReg("x", self.rs1))
			val2 = self.ALU.u2s64(reg.getReg("x", self.rs2))
			if self.ALU.LEQ64(val2, val1):
				pc = reg.getReg("pc", 0)
				pc = pc + (self.extender.signExtend(self.imm_SB, 13))
				reg.setReg("pc", 0, pc)
				self.branch = 1
			return "BGE x%d, x%d" % (self.rs1, self.rs2)

		elif self.opcode == 0x63 and self.func3 == 6: # RV32I BLTU
			val1 = self.ALU.s2u64(reg.getReg("x", self.rs1))
			val2 = self.ALU.s2u64(reg.getReg("x", self.rs2))
			if self.ALU.LTH64(val1, val2):
				pc = reg.getReg("pc", 0)
				pc = pc + (self.extender.signExtend(self.imm_SB, 13))
				reg.setReg("pc", 0, pc)
				self.branch = 1
			return "BLTU x%d, x%d" % (self.rs1, self.rs2)

		elif self.opcode == 0x63 and self.func3 == 7: # RV32I BGEU
			val1 = self.ALU.s2u64(reg.getReg("x", self.rs1))
			val2 = self.ALU.s2u64(reg.getReg("x", self.rs2))
			if self.ALU.LEQ64(val2, val1):
				pc = reg.getReg("pc", 0)
				pc = pc + (self.extender.signExtend(self.imm_SB, 13))
				reg.setReg("pc", 0, pc)
				self.branch = 1
			return "BGEU x%d, x%d" % (self.rs1, self.rs2)




		# SLT SLTI SLTU SLTIU
		if self.opcode == 0x33 and self.func3 == 2 and self.func7 == 0: # RV32I SLT
			val1 = self.ALU.u2s64(reg.getReg("x", self.rs1))
			val2 = self.ALU.u2s64(reg.getReg("x", self.rs2))
			if self.ALU.LTH64(val1, val2):
				reg.setReg("x", self.rd, 1)
			else:
				reg.setReg("x", self.rd, 0)
			return "SLT x%d, x%d, x%d" % (self.rd, self.rs1, self.rs2)

		elif self.opcode == 0x33 and self.func3 == 3 and self.func7 == 0: # RV32I SLTU
			val1 = self.ALU.s2u64(reg.getReg("x", self.rs1))
			val2 = self.ALU.s2u64(reg.getReg("x", self.rs2))
			if self.ALU.LTH64(val1, val2):
				reg.setReg("x", self.rd, 1)
			else:
				reg.setReg("x", self.rd, 0)
			return "SLTU x%d, x%d, x%d" % (self.rd, self.rs1, self.rs2)

		elif self.opcode == 0x13 and self.func3 == 2: # RV32I SLTI SvsS
			val1 = self.ALU.u2s64(reg.getReg("x", self.rs1))
			val2 = self.extender.signExtend(self.imm_I, 12)
			if self.ALU.LTH64(val1, val2):
				reg.setReg("x", self.rd, 1)
			else:
				reg.setReg("x", self.rd, 0)
			return "SLTI x%d, x%d, 0x%x" % (self.rd, self.rs1, val2)

		elif self.opcode == 0x13 and self.func3 == 3: # RV32I SLTIU UvsU but sign_extend imm
			val1 = self.ALU.s2u64(reg.getReg("x", self.rs1))
			val2 = self.extender.signExtend(self.imm_I, 12)
			if self.ALU.LTH64(val1, val2):
				reg.setReg("x", self.rd, 1)
			else:
				reg.setReg("x", self.rd, 0)
			return "SLTIU x%d, x%d, 0x%x" % (self.rd, self.rs1, val2)




		# XOR XORI OR ORI AND ANDI
		if self.opcode == 0x33 and self.func3 == 0x4 and self.func7 == 0: # RV32I XOR
			src1 = reg.getReg("x", self.rs1)
			src2 = reg.getReg("x", self.rs2)
			val = self.ALU.XOR64(src1, src2)
			reg.setReg("x", self.rd, val)
			return "XOR x%d, x%d, x%d" % (self.rd, self.rs1, self.rs2)

		elif self.opcode == 0x33 and self.func3 == 0x6 and self.func7 == 0: # RV32I OR
			src1 = reg.getReg("x", self.rs1)
			src2 = reg.getReg("x", self.rs2)
			val = self.ALU.OR64(src1, src2)
			reg.setReg("x", self.rd, val)
			return "OR x%d, x%d, x%d" % (self.rd, self.rs1, self.rs2)

		elif self.opcode == 0x33 and self.func3 == 0x7 and self.func7 == 0: # RV32I AND
			src1 = reg.getReg("x", self.rs1)
			src2 = reg.getReg("x", self.rs2)
			val = self.ALU.AND64(src1, src2)
			reg.setReg("x", self.rd, val)
			return "AND x%d, x%d, x%d" % (self.rd, self.rs1, self.rs2)

		elif self.opcode == 0x13 and self.func3 == 0x4: # RV32I XORI
			src1 = reg.getReg("x", self.rs1)
			#print "[Imm_I]: " + bin(self.imm_I)
			src2 = self.extender.signExtend(self.imm_I, 12)
			#print "[src2]: " + bin(src2)
			val = self.ALU.XOR64(src1, src2)
			reg.setReg("x", self.rd, val)
			return "XORI x%d, x%d, 0x%x" % (self.rd, self.rs1, src2)

		elif self.opcode == 0x13 and self.func3 == 0x6: # RV32I ORI
			src1 = reg.getReg("x", self.rs1)
			src2 = self.extender.signExtend(self.imm_I, 12)
			val = self.ALU.OR64(src1, src2)
			reg.setReg("x", self.rd, val)
			return "ORI x%d, x%d, 0x%x" % (self.rd, self.rs1, val)

		elif self.opcode == 0x13 and self.func3 == 0x7: # RV32I ANDI
			src1 = reg.getReg("x", self.rs1)
			src2 = self.extender.signExtend(self.imm_I, 12)
			val = self.ALU.AND64(src1, src2)
			reg.setReg("x", self.rd, val)
			#print "Imm_I = " + bin(self.imm_I)
			#print "src_2 = " + bin(src2)
			return "ANDI x%d, x%d, 0x%x" % (self.rd, self.rs1, src2)

		# SLL SLLI SRL SRLI SRA SRAI....
		# RV32I base instructions
		"""
		if self.opcode == 0x13 and self.func3 == 1 and self.func7 == 0: # RV32I SLLI
			val = reg.getReg("x", self.rs1)
			val = self.ALU.SLL(val, self.shamt)
			val = self.ALU.format32(val)
			reg.setReg("x", self.rd, val)
			return "SLLI x%d, x%d, %d" % (self.rd, self.rs1, self.shamt)

		elif self.opcode == 0x13 and self.func3 == 5 and self.func7 == 0: # RV32I SRLI
			val = reg.getReg("x", self.rs1)
			val = self.ALU.SRL(val, self.shamt)
			val = self.ALU.format32(val)
			reg.setReg("x", self.rd, val)
			return "SRLI x%d, x%d, %d" % (self.rd, self.rs1, self.shamt)

		elif self.opcode == 0x13 and self.func3 == 5 and self.func7 == 0x20: # RV32I SRAI
			val = reg.getReg("x", self.rs1)
			val = self.ALU.SRA(val, self.shamt)
			val = self.ALU.format32(val)
			reg.setReg("x", self.rd, val)
			return "SRAI x%d, x%d, %d" % (self.rd, self.rs1, self.shamt)
		"""
		# low 6 bits of rs2 will be used as shamt in 64bit system
		if self.opcode == 0x33 and self.func3 == 1 and self.func7 == 0: # RV32I SLL
			tmp_shamt = reg.getReg("x", self.rs2) & 0x3f
			val = reg.getReg("x", self.rs1)
			val = self.ALU.SLL(val, tmp_shamt)
			val = self.ALU.format32(val)
			reg.setReg("x", self.rd, val)
			return "SLL x%d, x%d, x%d" % (self.rd, self.rs1, self.rs2)

		elif self.opcode == 0x33 and self.func3 == 5 and self.func7 == 0: # RV32I SRL
			tmp_shamt = reg.getReg("x", self.rs2) & 0x3f
			val = reg.getReg("x", self.rs1)
			val = self.ALU.SRL(val, tmp_shamt)
			val = self.ALU.format32(val)
			reg.setReg("x", self.rd, val)
			return "SRL x%d, x%d, x%d" % (self.rd, self.rs1, self.rs2)

		elif self.opcode == 0x33 and self.func3 == 5 and self.func7 == 0x20: # RV32I SRA
			tmp_shamt = reg.getReg("x", self.rs2) & 0x3f
			val = reg.getReg("x", self.rs1)
			val = self.ALU.SRA(val, tmp_shamt)
			val = self.ALU.format32(val)
			reg.setReg("x", self.rd, val)
			return "SRA x%d, x%d, x%d" % (self.rd, self.rs1, self.rs2)


		# RV64I instructions

		elif self.opcode == 0x13 and self.func3 == 1 and self.func_6 == 0: ## RV64I SLLI
			val = reg.getReg("x", self.rs1)
			val = self.ALU.SLL(val, self.shamt_6)
			val = self.ALU.format64(val)
			reg.setReg("x", self.rd, val)
			return "SLLI x%d, x%d, %d" % (self.rd, self.rs1, self.shamt_6)

		elif self.opcode == 0x13 and self.func3 == 5 and self.func_6 == 0: ## RV64I SRLI
			val = reg.getReg("x", self.rs1)
			val = self.ALU.SRL(val, self.shamt_6)
			val = self.ALU.format64(val)
			reg.setReg("x", self.rd, val)
			return "SRLI x%d, x%d, %d" % (self.rd, self.rs1, self.shamt_6)

		elif self.opcode == 0x13 and self.func3 == 5 and self.func_6 == 0x10: ## RV64I SRAI
			val = reg.getReg("x", self.rs1)
			val = self.ALU.SRA(val, self.shamt_6)
			val = self.ALU.format64(val)
			reg.setReg("x", self.rd, val)
			return "SRAI x%d, x%d, %d" % (self.rd, self.rs1, self.shamt_6)

		if self.opcode == 0x1b and self.func3 == 1 and self.func7 == 0: ## RV64I SLLIW
			val = reg.getReg("x", self.rs1)
			val = self.ALU.SLL(val, self.shamt)
			val = self.ALU.format32(val)
			reg.setReg("x", self.rd, val)
			return "SLLIW x%d, x%d, %d" % (self.rd, self.rs1, self.shamt)

		elif self.opcode == 0x1b and self.func3 == 5 and self.func7 == 0: ## RV64I SRLIW
			val = reg.getReg("x", self.rs1)
			val = self.ALU.SRL(val, self.shamt)
			val = self.ALU.format32(val)
			reg.setReg("x", self.rd, val)
			return "SRLIW x%d, x%d, %d" % (self.rd, self.rs1, self.shamt)

		elif self.opcode == 0x1b and self.func3 == 5 and self.func7 == 0x20: ## RV64I SRAIW
			val = reg.getReg("x", self.rs1)
			val = self.ALU.SRA(val, self.shamt)
			val = self.ALU.format32(val)
			reg.setReg("x", self.rd, val)
			return "SRAIW x%d, x%d, %d" % (self.rd, self.rs1, self.shamt)

		# low 5 bits of rs2 will be used as shamt
		if self.opcode == 0x3b and self.func3 == 1 and self.func7 == 0: ## RV64I SLLW
			tmp_shamt = reg.getReg("x", self.rs2) & 0x1f
			val = reg.getReg("x", self.rs1)
			val = self.ALU.SLL(val, tmp_shamt)
			val = self.ALU.format32(val)
			reg.setReg("x", self.rd, val)
			return "SLLW x%d, x%d, x%d" % (self.rd, self.rs1, self.rs2)

		elif self.opcode == 0x3b and self.func3 == 5 and self.func7 == 0: ## RV64I SRLW
			tmp_shamt = reg.getReg("x", self.rs2) & 0x1f
			val = reg.getReg("x", self.rs1)
			val = self.ALU.SRL(val, tmp_shamt)
			val = self.ALU.format32(val)
			reg.setReg("x", self.rd, val)
			return "SRLW x%d, x%d, x%d" % (self.rd, self.rs1, self.rs2)

		elif self.opcode == 0x3b and self.func3 == 5 and self.func7 == 0x20: ## RV64I SRAW
			tmp_shamt = reg.getReg("x", self.rs2) & 0x1f
			val = reg.getReg("x", self.rs1)
			val = self.ALU.SRA(val, tmp_shamt)
			val = self.ALU.format32(val)
			reg.setReg("x", self.rd, val)
			return "SRAW x%d, x%d, x%d" % (self.rd, self.rs1, self.rs2)



		# ADD ADDI SUB LUI AUIPC
		if self.opcode == 0x33 and self.func7 == 0 and self.func3 == 0: # RV32I ADD
			add1 = reg.getReg("x", self.rs1)
			add2 = reg.getReg("x", self.rs2)
			val = self.ALU.ADD64(add1, add2)
			reg.setReg("x", self.rd, val)
			return "ADD x%d, x%d, x%d" % (self.rd, self.rs1, self.rs2)

		elif self.opcode == 0x33 and self.func7 == 0x20 and self.func3 == 0: # RV32I SUB
			src1 = reg.getReg("x", self.rs1)
			src2 = reg.getReg("x", self.rs2)
			val = self.ALU.SUB64(src1, src2)
			reg.setReg("x", self.rd, val)
			return "SUB x%d, x%d, x%d" % (self.rd, self.rs1, self.rs2)

		elif self.opcode == 0x13 and self.func3 == 0: # RV32I ADDI
			src1 = self.extender.signExtend(self.imm_I, 12)
			src2 = reg.getReg("x", self.rs1)
			val = self.ALU.ADD64(src1, src2)
			reg.setReg("x", self.rd, val)
			return "ADDI x%d, x%d, 0x%x" % (self.rd, self.rs1, src1)

		elif self.opcode == 0x37: # RV32I LUI
			val = self.imm_U
			val = self.extender.signExtend(self.imm_U, 32)
			reg.setReg("x", self.rd, val)
			return "LUI x%d, 0x%x" % (self.rd, val)

		elif self.opcode == 0x17: # RV32I AUIPC
			src1 = self.imm_U
#			print "src1 = 0x%x" % src1
#			print "rd = x%d" % self.rd
			src1 = self.extender.signExtend(self.imm_U, 32)
			val = self.ALU.ADD64(src1, reg.getReg("pc", 0))
#			print "val = 0x%x" % val
			reg.setReg("x", self.rd, val)
#			print "----------------------------------"
			return "AUIPC x%d, 0x%x" % (self.rd, src1)

		elif self.opcode == 0x1b and self.func3 == 0: # RV64I ADDIW
			src1 = self.extender.signExtend(self.imm_I, 12)
			src2 = reg.getReg("x", self.rs1)
			val = self.ALU.ADD32(src1, src2)
			val = self.extender.signExtend(val, 32)
			reg.setReg("x", self.rd, val)
			return "ADDIW x%d, x%d, 0x%x" % (self.rd, self.rs1, src1)

		elif self.opcode == 0x3b and self.func7 == 0 and self.func3 == 0: # RV64I ADDW
			src1 = reg.getReg("x", self.rs1)
			src2 = reg.getReg("x", self.rs2)
			val = self.ALU.ADD32(src1, src2)
			reg.setReg("x", self.rd, val)
			return "ADDW x%d, x%d, x%d" % (self.rd, self.rs1, self.rs2)

		elif self.opcode == 0x3b and self.func7 == 0x20 and self.func3 == 0: # RV64I SUBW
			src1 = reg.getReg("x", self.rs1)
			src2 = reg.getReg("x", self.rs2)
			val = self.ALU.SUB32(src1, src2)
			reg.setReg("x", self.rd, val)
			return "SUBW x%d, x%d, x%d" % (self.rd, self.rs1, self.rs2)

		# LB LH LW LBU LHU LWU LD
		src1 = reg.getReg("x", self.rs1)
		src2 = self.extender.signExtend(self.imm_I, 12)
		addr = self.ALU.ADD64(src1, src2)

		if self.opcode == 0x3 and self.func3 == 0:	# RV32I LB
			val = mem.load08(addr)
			val = val & 0xff
			val = self.extender.signExtend(val, 8)
			reg.setReg("x", self.rd, val)
			return "LB x%d, 0x%x(x%d)" % (self.rd, self.imm_I, self.rs1)

		elif self.opcode == 0x3 and self.func3 == 1: # RV32I LH
#			print "[debug] RH: 0x%.08x" % addr
			val = mem.load16(addr)
			val = val & 0xffff
#			print "val = %x" % val
			val = self.extender.signExtend(val, 16)
			reg.setReg("x", self.rd, val)
			return "LH x%d, 0x%x(x%d)" % (self.rd, self.imm_I, self.rs1)

		elif self.opcode == 0x3 and self.func3 == 2: # RV32I LW
			val = mem.load32(addr)
			#print "[LW] addr = %.08x" % addr
			#print "[LW] val = %.08x" % val
			val = self.extender.signExtend(val, 32)
			#print "[LW] extended val = %.08x" % val
			reg.setReg("x", self.rd, val)
			return "LW x%d, 0x%x(x%d)" % (self.rd, self.imm_I, self.rs1)

		elif self.opcode == 0x3 and self.func3 == 4: # RV32I LBU
			val = mem.load08(addr)
			val = val & 0xff
			val = self.extender.zeroExtend(val, 8)
			reg.setReg("x", self.rd, val)
			return "LBU x%d, 0x%x(x%d)" % (self.rd, self.imm_I, self.rs1)

		elif self.opcode == 0x3 and self.func3 == 5: # RV32I LHU
			val = mem.load16(addr)
			val = val & 0xffff
			val = self.extender.zeroExtend(val, 16)
			reg.setReg("x", self.rd, val)
			return "LHU x%d, 0x%x(x%d)" % (self.rd, self.imm_I, self.rs1)

		elif self.opcode == 0x3 and self.func3 == 6: # RV64I LWU
			val = mem.load32(addr)
			val = self.extender.zeroExtend(val, 32)
			reg.setReg("x", self.rd, val)
			return "LWU x%d, 0x%x(x%d)" % (self.rd, self.imm_I, self.rs1)

		elif self.opcode == 0x3 and self.func3 == 3: # RV64I LD
			#print "src1 = 0x%.016x" % src1
			#print "src2 = 0x%.016x" % src2
			#reg.printRegx()
			val = mem.load64(addr)
			reg.setReg("x", self.rd, val)
			return "LD x%d, 0x%x(x%d)" % (self.rd, self.imm_I, self.rs1)


		# SB SH SW SD
		src1 = self.extender.signExtend(self.imm_S, 12)
		src2 = reg.getReg("x", self.rs1)
		addr = self.ALU.ADD64(src1, src2)
		val = reg.getReg("x", self.rs2)

		if self.opcode == 0x23 and self.func3 == 0: # RV32I SB
			val = val & 0xff
			self.extender.signExtend(val, 8)
			mem.store08(addr, val)
			return "SB x%d, 0x%x(x%d)" % (self.rs2, self.imm_S, self.rs1)

		elif self.opcode == 0x23 and self.func3 == 1: # RV32I SH
			val = val & 0xffff
			self.extender.signExtend(val, 16)
			mem.store16(addr, val)
			return "SH x%d, 0x%x(x%d)" % (self.rs2, self.imm_S, self.rs1)

		elif self.opcode == 0x23 and self.func3 == 2: # RV32I SW
			val = val & 0xffffffff
			self.extender.signExtend(val, 32)
			mem.store32(addr, val)
			return "SW x%d, 0x%x(x%d)" % (self.rs2, self.imm_S, self.rs1)

		elif self.opcode == 0x23 and self.func3 == 3: # RV64I SD
			mem.store64(addr, val)
#			reg.printRegx()
#			print "src1 = 0x%.016x" % src1
#			print "src2 = 0x%.016x" % src2
#			raw_input(">")
			return "SD x%d, 0x%x(x%d)" % (self.rs2, self.imm_S, self.rs1)


		# MUL
		if self.opcode == 0x33 and self.func7 == 1:
			val1 = reg.getReg("x", self.rs1)
			val2 = reg.getReg("x", self.rs2)
			if self.func3 == 0:				# RV64M MUL
				val = self.ALU.MUL64(val1, val2)
				reg.setReg("x", self.rd, val)
				return "MUL x%d x%d x%d" % (self.rd, self.rs1, self.rs2)

			elif self.func3 == 1:	# RV64M MULH
				val = self.ALU.MULH64(val1, val2)
				reg.setReg("x", self.rd, val)
				return "MULH x%d x%d x%d" % (self.rd, self.rs1, self.rs2)

			#elif self.func3 == 2:	# RV64M MULHSU
			#	val =

			elif self.func3 == 3:	# RV64M MULHU
				val = self.ALU.MULHU64(val1, val2)
				reg.setReg("x", self.rd, val)
				return "MULHU x%d x%d x%d" % (self.rd, self.rs1, self.rs2)

			elif self.func3 == 4:	# RV64M DIV
				# rs1 / rs2
				val = self.ALU.DIV64(val1, val2)
				reg.setReg("x", self.rd, val)
				return "DIV dst:x%d  x%d / x%d" % (self.rd, self.rs1, self.rs2)

			elif self.func3 == 5:	# RV64M DIVU
				val = self.ALU.DIVU64(val1, val2)
				reg.setReg("x", self.rd, val)
				return "DIVU dst:x%d  x%d / x%d" % (self.rd, self.rs1, self.rs2)


#			elif self.func3 == 6:	# RV64M REM
#				val = val1 % val2
#				reg.setReg("x", self.rd, val)
#				return "REM dst:x%d  x%d %% x%d" % (self.rd, self.rs1, self.rs2)

			elif self.func3 == 7:	# RV64M REMU
				val = self.ALU.REMU64(val1, val2)
				reg.setReg("x", self.rd, val)
				return "REMU dst:x%d  x%d %% x%d" % (self.rd, self.rs1, self.rs2)


		if self.opcode == 0x3b and self.func7 == 1:
			val1 = reg.getReg("x", self.rs1) & 0xffffffff
			val2 = reg.getReg("x", self.rs2) & 0xffffffff

			if self.func3 == 0:		# MULW
				val = self.ALU.MULW32(val1, val2)
				reg.setReg("x", self.rd, val)
				return "MULW x%d x%d x%d" % (self.rd, self.rs1, self.rs2)

			elif self.func3 == 4:	# DIVW
				val = self.ALU.DIVW32(val1, val2)
				reg.setReg("x", self.rd, val)
				return "DIVW dst:x%d  x%d / x%d" % (self.rd, self.rs1, self.rs2)

			elif self.func3 == 5:	# DIVUW
				val = self.ALU.DIVUW32(val1, val2)
				reg.setReg("x", self.rd, val)
				return "DIVUW dst:x%d  x%d / x%d" % (self.rd, self.rs1, self.rs2)

			elif self.func3 == 6:	# REMW
				val = self.ALU.REMW32(val1, val2)
				reg.setReg("x", self.rd, val)
				return "REMW dst:x%d  x%d %% x%d" % (self.rd, self.rs1, self.rs2)

			elif self.func3 == 7:	# REMUW
				val1 = self.ALU.s2u32(val1)
				val2 = self.ALU.s2u32(val2)
				val = self.extender.signExtend(val1 % val2)
				reg.setReg("x", self.rd, val)
				return "REMUW dst:x%d  x%d %% x%d" % (self.rd, self.rs1, self.rs2)


		# Float Double		here func3 == rm
		if self.opcode == 0x53 and self.func7 == 8:	# FMUL.S
			val1 = reg.getReg("f", self.rs1)
			val2 = reg.getReg("f", self.rs2)
			val = self.ALU.MUL32F(val1, val2)
			reg.setReg("f", self.rd, val)
			return "FMUL.S dst:f%d, f%d * f%d" % (self.rd, self.rs1, self.rs2)

		elif self.opcode == 0x53 and self.func7 == 12:	# FDIV.S
			val1 = reg.getReg("f", self.rs1)
			val2 = reg.getReg("f", self.rs2)
			val = self.ALU.DIV32F(val1, val2)
			reg.setReg("f", self.rd, val)
			return "FDIV.S dst:f%d, f%d / f%d" % (self.rd, self.rs1, self.rs2)

		elif self.opcode == 0x07 and self.func3 == 2:	# FLW
			offset = self.extender.signExtend(self.imm_I, 12)
			addr_base = reg.getReg("x", self.rs1)
			addr = self.ALU.ADD64(addr_base, offset)
			val = mem.load32F(addr)
			reg.setReg("f", self.rd, val)
			return "FLW32 f%d, 0x%x(x%d)" % (self.rd, self.imm_I, self.rs1)

		elif self.opcode == 0x27 and self.func3 == 2:	# FSW
			src1 = self.extender.signExtend(self.imm_S, 12)
			src2 = reg.getReg("x", self.rs1)
			addr = self.ALU.ADD64(src1, src2)
			val = reg.getReg("f", self.rs2)
			mem.store32F(addr, val)
			return "FSW32 f%d, 0x%x(x%d)" % (self.rs2, self.imm_S, self.rs1)


		# here rs2 doesn't mean rs2
		elif self.opcode == 0x53 and self.rs2 == 0 and self.func7 == 0x68:	# FCVT.S.W
			val1 = reg.getReg("x", self.rs1)
			val = self.ALU.i32toF(val1)
			reg.setReg("f", self.rd, val)
			return "FCVT.S.W x%d, f%d" % (self.rs1, self.rd)

		elif self.opcode == 0x53 and self.rs2 == 2 and self.func7 == 0x68:	# FCVT.S.L
			val1 = reg.getReg("x", self.rs1)
			val = self.ALU.i64toF(val1)
			reg.setReg("f", self.rd, val)
			return "FCVT.S.L x%d, f%d" % (self.rs1, self.rd)

		# start F64
		elif self.opcode == 0x7 and self.func3 == 3:	# FLD
			offset = self.extender.signExtend(self.imm_I, 12)
			addr_base = reg.getReg("x", self.rs1)
			addr = self.ALU.ADD64(addr_base, offset)
			val = mem.load64F(addr)
			reg.setReg("f", self.rd, val)
			return "FLD64 f%d, 0x%x(x%d)" % (self.rd, self.imm_I, self.rs1)

		elif self.opcode == 0x27 and self.func3 == 3:	# FSD
			src1 = self.extender.signExtend(self.imm_S, 12)
			src2 = reg.getReg("x", self.rs1)
			addr = self.ALU.ADD64(src1, src2)
			val = reg.getReg("f", self.rs2)
			mem.store64F(addr, val)
			return "FSD64 f%d, 0x%x(x%d)" % (self.rs2, self.imm_S, self.rs1)


		elif self.opcode == 0x53 and self.func7 == 1:	# FADD.D
			val1 = reg.getReg("f", self.rs1)
			val2 = reg.getReg("f", self.rs2)
			val = self.ALU.ADD64F(val1, val2)
			reg.setReg("f", self.rd, val)
			return "FADD.D dst:f%d, f%d + f%d" % (self.rd, self.rs1, self.rs2)

		elif self.opcode == 0x53 and self.func7 == 5:	# FSUB.D
			val1 = reg.getReg("f", self.rs1)
			val2 = reg.getReg("f", self.rs2)
			val = self.ALU.SUB64F(val1, val2)
			reg.setReg("f", self.rd, val)
			return "FSUB.D dst:f%d, f%d - f%d" % (self.rd, self.rs1, self.rs2)

		elif self.opcode == 0x53 and self.func7 == 9:	# FMUL.D
			val1 = reg.getReg("f", self.rs1)
			val2 = reg.getReg("f", self.rs2)
			val = self.ALU.MUL64F(val1, val2)
			reg.setReg("f", self.rd, val)
			return "FMUL.D dst:f%d, f%d * f%d" % (self.rd, self.rs1, self.rs2)

		elif self.opcode == 0x53 and self.func7 == 0xd:	# FDIV.D
			val1 = reg.getReg("f", self.rs1)
			val2 = reg.getReg("f", self.rs2)
			val = self.ALU.DIV64F(val1, val2)
			reg.setReg("f", self.rd, val)
			return "FDIV.D dst:f%d, f%d / f%d" % (self.rd, self.rs1, self.rs2)

		# here rs2 doesn't mean rs2
		elif self.opcode == 0x53 and self.rs2 == 1 and self.func7 == 0x20:	# FCVT.S.D
			val1 = reg.getReg("f", self.rs1)
			val = self.ALU.d2f(val1)
			reg.setReg("f", self.rd, val)
			return "FCVT.S.D dst:f%d, src:f%d" % (self.rd, self.rs1)

		elif self.opcode == 0x53 and self.rs2 == 0 and self.func7 == 0x21:	# FCVT.D.S
			val1 = reg.getReg("f", self.rs1)
			val = self.ALU.f2d(val1)
			reg.setReg("f", self.rd, val)
			return "FCVT.D.S dst:f%d, src:f%d" % (self.rd, self.rs1)

		elif self.opcode == 0x53 and self.rs2 == 0 and self.func7 == 0x69:	# FCVT.D.W
			val1 = reg.getReg("x", self.rs1) & 0xffffffff
			val1 = self.ALU.u2s32(val1)
			val = self.ALU.i32toF(val1)
			reg.setReg("f", self.rd, val)
			return "FCVT.D.W dst:f%d, src:x%d" % (self.rd, self.rs1)

		elif self.opcode == 0x53 and self.rs2 == 1 and self.func7 == 0x69:	# FCVT.D.WU
			val1 = reg.getReg("x", self.rs1)
			val1 = self.ALU.s2u32(val1)
			val = self.ALU.u32toF(val1)
			reg.setReg("f", self.rd, val)
			return "FCVT.D.WU dst:f%d, src:x%d" % (self.rd, self.rs1)

		elif self.opcode == 0x53 and self.rs2 == 0 and self.func7 == 0x61:	# FCVT.W.D
			val1 = reg.getReg("f", self.rs1)
			val = self.ALU.f2i32(val1)
			reg.setReg("x", self.rd, val)
			return "FCVT.W.D dst:x%d, src:f%d" % (self.rd, self.rs1)

		elif self.opcode == 0x53 and self.rs2 == 1 and self.func7 == 0x61:	# FCVT.WU.D
			val1 = reg.getReg("f", self.rs1)
			if val < 0:
				val = 0
			elif val >= 2147483647:
				val = 2147483647
			else:
				val = self.ALU.f2i32(val1)
				val = self.ALU.s2u32(val)
			reg.setReg("x", self.rd, val)
			return "FCVT.WU.D dst:x%d, src:f%d" % (self.rd, self.rs1)


		elif self.opcode == 0x53 and self.func3 == 0 and self.rs2 == 0 and self.func7 == 0x71:	# FMV.X.D
			val1 = reg.getReg("f", self.rs1)
			val1 = pack("<d", val1)
			val = unpack("<Q", val1)[0]
			reg.setReg("x", self.rd, val)
			return "FMV.X.D f%d --> x%d" % (self.rs1, self.rd)

		elif self.opcode == 0x53 and self.func3 == 0 and self.rs2 == 0 and self.func7 == 0x79:	# FMV.D.X
			val1 = reg.getReg("x", self.rs1)
			val1 = pack("<Q", val1)
			val = unpack("<d", val1)[0]
			reg.setReg("f", self.rd, val)
			return "FMV.D.X x%d --> f%d" % (self.rs1, self.rd)

		elif self.opcode == 0x43 and (self.func7 & 0x3) == 1:	# FMADD.D
			val1 = reg.getReg("f", self.rs1)
			val2 = reg.getReg("f", self.rs2)
			val3 = reg.getReg("f", self.rs3)
			val = self.ALU.MUL64F(val1, val2)
			val = self.ALU.ADD64F(val3, val)
			reg.setReg("f", self.rd, val)
			return "FMADD.D dst:f%d, f%d * f%d + f%d" % (self.rd, self.rs1, self.rs2, self.rs3)

		elif self.opcode == 0x47 and (self.func7 & 0x3) == 1:	# FMSUB.D
			val1 = reg.getReg("f", self.rs1)
			val2 = reg.getReg("f", self.rs2)
			val3 = reg.getReg("f", self.rs3)
			val = self.ALU.MUL64F(val1, val2)
			val = self.ALU.SUB64F(val, val3)
			reg.setReg("f", self.rd, val)
			return "FMSUB.D dst:f%d, f%d * f%d - f%d" % (self.rd, self.rs1, self.rs2, self.rs3)

		elif self.opcode == 0x4f and (self.func7 & 0x3) == 1:	# FNMADD.D
			val1 = reg.getReg("f", self.rs1)
			val2 = reg.getReg("f", self.rs2)
			val3 = reg.getReg("f", self.rs3)
			val = self.ALU.MUL64F(val1, val2)
			val = self.ALU.ADD64F(val3, val)
			val = -val
			reg.setReg("f", self.rd, val)
			return "FNMADD.D dst:f%d, f%d * f%d + f%d" % (self.rd, self.rs1, self.rs2, self.rs3)

		elif self.opcode == 0x4b and (self.func7 & 0x3) == 1:	# FMSUB.D
			val1 = reg.getReg("f", self.rs1)
			val2 = reg.getReg("f", self.rs2)
			val3 = reg.getReg("f", self.rs3)
			val = self.ALU.MUL64F(val1, val2)
			val = self.ALU.SUB64F(val, val3)
			val = -val
			reg.setReg("f", self.rd, val)
			return "FNMSUB.D dst:f%d, f%d * f%d - f%d" % (self.rd, self.rs1, self.rs2, self.rs3)


		elif self.opcode == 0x53 and self.func7 == 0x51 and self.func3 == 0:	# FLE.D
			val1 = reg.getReg("f", self.rs1)
			val2 = reg.getReg("f", self.rs2)
			if(val1 <= val2):
				ret = 1
			else:
				ret = 0
			ret.setReg("x", self.rd, ret)
			return "FLE f%d < f%d --> x%d" % (self.rs1, self.rs2, self.rd)

		elif self.opcode == 0x53 and self.func7 == 0x51 and self.func3 == 1:	# FLT.D
			val1 = reg.getReg("f", self.rs1)
			val2 = reg.getReg("f", self.rs2)
			if(val1 < val2):
				ret = 1
			else:
				ret = 0
			reg.setReg("x", self.rd, ret)
			return "FLT f%d < f%d --> x%d" % (self.rs1, self.rs2, self.rd)

		elif self.opcode == 0x53 and self.func7 == 0x51 and self.func3 == 2:	# FEQ.D
			val1 = reg.getReg("f", self.rs1)
			val2 = reg.getReg("f", self.rs2)
			if(val1 == val2):
				ret = 1
			else:
				ret = 0
			reg.setReg("x", self.rd, ret)
			return "FEQ f%d == f%d --> x%d" % (self.rs1, self.rs2, self.rd)


		elif self.opcode == 0x53 and self.func7 == 0x11 and self.func3 == 0:	# FSGNJ.D
			val1 = reg.getReg("f", self.rs1)
			val2 = reg.getReg("f", self.rs2)
			if val2 >= 0:
				val = self.ALU.absf(val1)
			else:
				val = -self.ALU.absf(val1)
			reg.setReg("f", self.rd, val)
			return "FSGNJ.D value:f%d sign:f%d  dst:f%d" % (self.rs1, self.rs2, self.rd)

		elif self.opcode == 0x53 and self.func7 == 0x11 and self.func3 == 1:	# FSGNJN.D
			val1 = reg.getReg("f", self.rs1)
			val2 = reg.getReg("f", self.rs2)
			if val2 >= 0:
				val = -self.ALU.absf(val1)
			else:
				val = self.ALU.absf(val1)
			reg.setReg("f", self.rd, val)
			return "FSGNJN.D value:f%d sign:f%d  dst:f%d" % (self.rs1, self.rs2, self.rd)

		elif self.opcode == 0x53 and self.func7 == 0x11 and self.func3 == 2:	# FSGNJX.D
			val1 = reg.getReg("f", self.rs1)
			val2 = reg.getReg("f", self.rs2)
			if val1 >= 0:
				s1 = 0
			else:
				s1 = 1
			if val2 >= 0:
				s2 = 0
			else:
				s2 = 1

			if (s1 ^ s2) == 1:
				val = -self.ALU.absf(val1)
			else:
				val = self.ALU.absf(val1)
			reg.setReg("f", self.rd, val)
			return "FSGNJ.D value:f%d sign:f%d(half of the sign)  dst:f%d" % (self.rs1, self.rs2, self.rd)





	def work(self, cmd, reg, mem):
		result = self.do(cmd, reg, mem)
		if self.branch == 0:
			#print "add pc"
			pc = reg.getpc()
			reg.setpc(pc+4)
		return result


