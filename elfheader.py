#from capstone   import *
from ctypes     import *
from struct     import *


class ELFFlags:
	ELFCLASS32  = 0x01
	ELFCLASS64  = 0x02
	EI_CLASS    = 0x04
	EI_DATA     = 0x05
	ELFDATA2LSB = 0x01
	ELFDATA2MSB = 0x02
	EM_386      = 0x03
	EM_X86_64   = 0x3e
	EM_ARM      = 0x28
	EM_MIPS     = 0x08
	EM_SPARCv8p = 0x12
	EM_PowerPC  = 0x14
	EM_ARM64    = 0xb7

class Elf32_Ehdr_LSB(LittleEndianStructure):
	_fields_ =  [
					("e_ident",         c_ubyte * 16),
					("e_type",          c_ushort),
					("e_machine",       c_ushort),
					("e_version",       c_uint),
					("e_entry",         c_uint),
					("e_phoff",         c_uint),
					("e_shoff",         c_uint),
					("e_flags",         c_uint),
					("e_ehsize",        c_ushort),
					("e_phentsize",     c_ushort),
					("e_phnum",         c_ushort),
					("e_shentsize",     c_ushort),
					("e_shnum",         c_ushort),
					("e_shstrndx",      c_ushort)
				]

class Elf64_Ehdr_LSB(LittleEndianStructure):
	_fields_ =  [
					("e_ident",         c_ubyte * 16),
					("e_type",          c_ushort),
					("e_machine",       c_ushort),
					("e_version",       c_uint),
					("e_entry",         c_ulonglong),
					("e_phoff",         c_ulonglong),
					("e_shoff",         c_ulonglong),
					("e_flags",         c_uint),
					("e_ehsize",        c_ushort),
					("e_phentsize",     c_ushort),
					("e_phnum",         c_ushort),
					("e_shentsize",     c_ushort),
					("e_shnum",         c_ushort),
					("e_shstrndx",      c_ushort)
				]

class Elf32_Phdr_LSB(LittleEndianStructure):
	_fields_ =  [
					("p_type",          c_uint),
					("p_offset",        c_uint),
					("p_vaddr",         c_uint),
					("p_paddr",         c_uint),
					("p_filesz",        c_uint),
					("p_memsz",         c_uint),
					("p_flags",         c_uint),
					("p_align",         c_uint)
				]

class Elf64_Phdr_LSB(LittleEndianStructure):
	_fields_ =  [
					("p_type",          c_uint),
					("p_flags",         c_uint),
					("p_offset",        c_ulonglong),
					("p_vaddr",         c_ulonglong),
					("p_paddr",         c_ulonglong),
					("p_filesz",        c_ulonglong),
					("p_memsz",         c_ulonglong),
					("p_align",         c_ulonglong)
				]

class Elf32_Shdr_LSB(LittleEndianStructure):
	_fields_ =  [
					("sh_name",         c_uint),
					("sh_type",         c_uint),
					("sh_flags",        c_uint),
					("sh_addr",         c_uint),
					("sh_offset",       c_uint),
					("sh_size",         c_uint),
					("sh_link",         c_uint),
					("sh_info",         c_uint),
					("sh_addralign",    c_uint),
					("sh_entsize",      c_uint)
				]

class Elf64_Shdr_LSB(LittleEndianStructure):
	_fields_ =  [
					("sh_name",         c_uint),
					("sh_type",         c_uint),
					("sh_flags",        c_ulonglong),
					("sh_addr",         c_ulonglong),
					("sh_offset",       c_ulonglong),
					("sh_size",         c_ulonglong),
					("sh_link",         c_uint),
					("sh_info",         c_uint),
					("sh_addralign",    c_ulonglong),
					("sh_entsize",      c_ulonglong)
				]

class Elf32_Ehdr_MSB(BigEndianStructure):
	_fields_ =  [
					("e_ident",         c_ubyte * 16),
					("e_type",          c_ushort),
					("e_machine",       c_ushort),
					("e_version",       c_uint),
					("e_entry",         c_uint),
					("e_phoff",         c_uint),
					("e_shoff",         c_uint),
					("e_flags",         c_uint),
					("e_ehsize",        c_ushort),
					("e_phentsize",     c_ushort),
					("e_phnum",         c_ushort),
					("e_shentsize",     c_ushort),
					("e_shnum",         c_ushort),
					("e_shstrndx",      c_ushort)
				]

class Elf64_Ehdr_MSB(BigEndianStructure):
	_fields_ =  [
					("e_ident",         c_ubyte * 16),
					("e_type",          c_ushort),
					("e_machine",       c_ushort),
					("e_version",       c_uint),
					("e_entry",         c_ulonglong),
					("e_phoff",         c_ulonglong),
					("e_shoff",         c_ulonglong),
					("e_flags",         c_uint),
					("e_ehsize",        c_ushort),
					("e_phentsize",     c_ushort),
					("e_phnum",         c_ushort),
					("e_shentsize",     c_ushort),
					("e_shnum",         c_ushort),
					("e_shstrndx",      c_ushort)
				]

class Elf32_Phdr_MSB(BigEndianStructure):
	_fields_ =  [
					("p_type",          c_uint),
					("p_offset",        c_uint),
					("p_vaddr",         c_uint),
					("p_paddr",         c_uint),
					("p_filesz",        c_uint),
					("p_memsz",         c_uint),
					("p_flags",         c_uint),
					("p_align",         c_uint)
				]

class Elf64_Phdr_MSB(BigEndianStructure):
	_fields_ =  [
					("p_type",          c_uint),
					("p_flags",         c_uint),
					("p_offset",        c_ulonglong),
					("p_vaddr",         c_ulonglong),
					("p_paddr",         c_ulonglong),
					("p_filesz",        c_ulonglong),
					("p_memsz",         c_ulonglong),
					("p_align",         c_ulonglong)
				]

class Elf32_Shdr_MSB(BigEndianStructure):
	_fields_ =  [
					("sh_name",         c_uint),
					("sh_type",         c_uint),
					("sh_flags",        c_uint),
					("sh_addr",         c_uint),
					("sh_offset",       c_uint),
					("sh_size",         c_uint),
					("sh_link",         c_uint),
					("sh_info",         c_uint),
					("sh_addralign",    c_uint),
					("sh_entsize",      c_uint)
				]

class Elf64_Shdr_MSB(BigEndianStructure):
	_fields_ =  [
					("sh_name",         c_uint),
					("sh_type",         c_uint),
					("sh_flags",        c_ulonglong),
					("sh_addr",         c_ulonglong),
					("sh_offset",       c_ulonglong),
					("sh_size",         c_ulonglong),
					("sh_link",         c_uint),
					("sh_info",         c_uint),
					("sh_addralign",    c_ulonglong),
					("sh_entsize",      c_ulonglong)
				]
