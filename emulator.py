#!/usr/bin/python

from parse import *
from struct import *
import sys

fuck = 0

def writeline(f, s):
	f.write(s+'\n')

def handle(reg):
	cmd = raw_input(">")
	if (cmd == "n"):
		return
	elif (cmd == "pf"):
		reg.printRegf()
		return
	else :
		reg.printRegx()
		return
	return

def sections(elf):
	elf.printSections()
	raw_input(">")

def find_undefined_cmd(binary):
	elf = ELF(binary)
	mem = MEM(elf)
	sections(elf)
	reg = RegFile(elf)
	decoder = Decoder()
	f = open("dry2reg_undefined", "w")
	pc = reg.getpc()
	while (pc <= 0x205ec):
		print "[ pc ] 0x%.08x" % pc
		#raw_input(">")
		cmd = mem.load32(pc)
		if (cmd == -1):
			break;
		result = decoder.work(cmd, reg, mem)
		print "[cmd ] 0x%.08x" % cmd
		print result
		if (result == None):
			writeline(f, "%.08x" % cmd)
		pc += 4
	f.close()

def checkmem(mem, addr):
	global fuck
	if (fuck == 0):
		x = mem.load64(addr)
		print "[memtest] %.016x" % x
		if (x == 1):
			fuck = 1
			print "START FUCKING"
	elif (fuck == 1):
		x = mem.load64(addr)
		print "[memtest] %.016x" % x
		if (x != 1):
			print "WHAT THE FUCK!!!!!!!!!!!!!!!!!!"

def run(binary):
	"""
	find_undefined_cmd(binary)
	"""
	cnt = 0
	elf = ELF(binary)
	mem = MEM(elf)
	sections(elf)
	reg = RegFile(elf)
	decoder = Decoder()
	bp = []
	#raw_input("Enter anything to start>")
	while True	:
		#print "====================START===================="
		pc = reg.getpc()
		tmppc = pc
		#print "[pc] 0x%.08x" % pc
		cmd = mem.load32(pc)
		if (cmd == -1):
			break;
		result = decoder.work(cmd, reg, mem)
		#print "[%d] %.08x\t\t"%(cnt, tmppc) + result
		cnt += 1
		if (pc in bp):
			cmdl = raw_input("bp>")
			if (cmdl == "ni"):
				bp.append(pc+4)
		#print "==================== END ===================="
	"""
	elf.printSections()
	"""


if __name__ == '__main__':
	with open(sys.argv[1], "rb") as f:
		binary = f.read()
		f.close()
		run(binary)
