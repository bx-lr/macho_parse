import sys
import os
import struct
import binascii
'''
constants
'''
FATMAGIC = 0xcafebabe
MACHMAGIC = 0xfeedface
MACHMAGIC_LE = 0xcefaedfe
DEFAULTSIZE = 0x04

#taken from mach-o/loader.h
LC_REQ_DYLD = 0x80000000

# Constants for the cmd field of all load commands, the type #
LC_SEGMENT =0x1	# segment of this file to be mapped
LC_SYMTAB = 0x2 # link-edit stab symbol table info 
LC_SYMSEG = 0x3 # link-edit gdb symbol table info (obsolete) 
LC_THREAD = 0x4 # thread 
LC_UNIXTHREAD = 0x5 # unix thread (includes a stack) 
LC_LOADFVMLIB = 0x6 # load a specified fixed VM shared library 
LC_IDFVMLIB = 0x7 # fixed VM shared library identification 
LC_IDENT = 0x8 # object identification info (obsolete) 
LC_FVMFILE = 0x9 # fixed VM file inclusion (internal use) 
LC_PREPAGE = 0xa # prepage command (internal use) 
LC_DYSYMTAB = 0xb # dynamic link-edit symbol table info 
LC_LOAD_DYLIB = 0xc # load a dynamically linked shared library 
LC_ID_DYLIB = 0xd # dynamically linked shared lib ident 
LC_LOAD_DYLINKER = 0xe # load a dynamic linker 
LC_ID_DYLINKER = 0xf # dynamic linker identification 
LC_PREBOUND_DYLIB = 0x10 # modules prebound for a dynamically 

			# linked shared library 
LC_ROUTINES = 0x11 # image routines 
LC_SUB_FRAMEWORK = 0x12 # sub framework 
LC_SUB_UMBRELLA = 0x13 # sub umbrella 
LC_SUB_CLIENT = 0x14 # sub client 
LC_SUB_LIBRARY = 0x15 # sub library 
LC_TWOLEVEL_HINTS = 0x16 # two-level namespace lookup hints 
LC_PREBIND_CKSUM = 0x17 # prebind checksum 

'''
load a dynamically linked shared library that is allowed to be missing
(all symbols are weak imported).
'''
LC_LOAD_WEAK_DYLIB = (0x18 | LC_REQ_DYLD)
LC_SEGMENT_64 = 0x19 # 64-bit segment of this file to be mapped 
LC_ROUTINES_64 = 0x1a # 64-bit image routines 
LC_UUID = 0x1b # the uuid 
LC_RPATH = (0x1c | LC_REQ_DYLD) # runpath additions 
LC_CODE_SIGNATURE = 0x1d # local of code signature 
LC_SEGMENT_SPLIT_INFO = 0x1e # local of info to split segments 
LC_REEXPORT_DYLIB = (0x1f | LC_REQ_DYLD) # load and re-export dylib 
LC_LAZY_LOAD_DYLIB = 0x20 # delay load of dylib until first use 
LC_ENCRYPTION_INFO = 0x21 # encrypted segment information 
LC_DYLD_INFO = 0x22	# compressed dyld information 
LC_DYLD_INFO_ONLY = (0x22|LC_REQ_DYLD)	#compressed dyld information only 

LC_UNKNOWN = 0x25
LC_UNKNOWN_2 = 0x26 
LC_UNKNOWN_3 = 0x29

API_CALLS = []
FRAMEWORKS = []
DEBUG = False

class FAT_HEADER:
	struct_size = 2 * DEFAULTSIZE

	def __init__(self, tmp, foffset):
		self.magic = tmp[0]
		self.nfat_arch = tmp[1]
		self.foffset = foffset

	def pprint(self):
		print "struct fat_header @ %08x" % self.foffset
		print "{"
		print "uint32_t magic = %08x" % int(self.magic, 16)
		print "uint32_t nfat_arch = %08x" % self.nfat_arch
		print "};\n"


class FAT_ARCH:
	struct_size = 5 * DEFAULTSIZE	

	def __init__(self, tmp, foffset):
		self.cputype = tmp[0]
		self.cpusubtype = tmp[1]
		self.offset = tmp[2]
		self.size = tmp[3]
		self.align = tmp[4]
		self.foffset = foffset

	def pprint(self):
		print "struct fat_arch @ %08x" % self.foffset
		print "{"
		print "cpu_type_t cputype = %08x" % self.cputype
		print "cpu_subtype_t cpusubtype = %08x" % self.cpusubtype
		print "uint32_t offset = %08x" % self.offset
		print "uint32_t size = %08x" % self.size
		print "uint32_t align = %08x" % self.align
		print "};\n"


class MACH_HEADER:
	struct_size = 7 * DEFAULTSIZE

	def __init__(self, tmp, foffset):
		self.magic = tmp[0]
		self.cputype = tmp[1]
		self.cpusubtype = tmp[2]
		self.filetype = tmp[3]
		self.ncmds = tmp[4]
		self.sizeofcmds = tmp[5]
		self.flags = tmp[6]
		self.foffset = foffset

	def pprint(self):
		print "struct mach_header @ %08x" % self.foffset
		print "{"
		print "uint32_t magic = %08x" % self.magic
		print "cpu_type_t cputype = %08x" % self.cputype
		print "cpu_subtype_t cpusubtype = %08x" % self.cpusubtype
		print "uint32_t filetype = %08x" % self.filetype
		print "uint32_t ncmds = %08x" % self.ncmds
		print "uint32_t sizeofcmds = %08x" % self.sizeofcmds
		print "uint32_t flags = %08x"% self.flags
		print "};\n"


class LOAD_COMMAND:
	struct_size = 2 * DEFAULTSIZE

	def __init__(self, tmp, foffset):
		self.cmd = tmp[0]
		self.cmdsize = tmp[1]
		self.foffset = foffset

	def pprint(self):
		print "struct load_command @ %08x" % self.foffset
		print "{"
		print "uint32_t cmd = %08x" % self.cmd
		print "uint32_t cmdsize = %08x" % self.cmdsize
		print "};\n"

class SEGMENT_COMMAND:
	struct_size = 14 * DEFAULTSIZE

	def __init__(self, tmp, foffset, data):
		self.cmd = tmp[0]
		self.cmdsize = tmp[1]
		self.segname = tmp[2]
		self.vmaddr = tmp[3]
		self.vmsize = tmp[4]
		self.fileoff = tmp[5]
		self.filesize = tmp[6]
		self.maxprot = tmp[7]
		self.initprot = tmp[8]
		self.nsects = tmp[9]
		self.flags = tmp[10]
		self.foffset = foffset
		self.data = data[self.vmaddr : self.vmsize]


	def pprint(self):
		print "struct segment_command @ %08x" % self.foffset
		print "{"
		print "uint32_t cmd = %08x" % self.cmd
		print "uint32_t cmdsize = %08x" % self.cmdsize
		print "char segname[16] = %s" % self.segname
		print "uint32_t vmaddr = %08x" % self.vmaddr
		print "uint32_t vmsize = %08x" % self.vmsize
		print "uint32_t fileoff = %08x" % self.fileoff
		print "uint32_t filesize = %08x" % self.filesize
		print "vm_prot_t maxprot = %08x" % self.maxprot
		print "vm_prot_t initprot = %08x" % self.initprot
		print "uint32_t nsects = %08x" % self.nsects
		print "uint32_t flags = %08x" % self.flags
		print "};\n"

class SECTION:
	struct_size = 17 * DEFAULTSIZE

	def __init__(self, tmp, foffset, data):
		self.sectname = tmp[0]
		self.segname = tmp[1]
		self.addr = tmp[2]
		self.size = tmp[3]
		self.offset = tmp[4]
		self.align = tmp[5]
		self.reloff = tmp[6]
		self.nreloc = tmp[7]
		self.flags = tmp[8]
		self.reserved1 = tmp[9]
		self.reserved2 = tmp[10]
		self.foffset=foffset
		self.section_data = data[self.addr: self.addr + self.size]

	def pprint(self):
		print "struct section @ %08x" % self.foffset
		print "{"
		print "char sectname[16] = %s" % self.sectname
		print "char segname[16] = %s" % self.segname
		print "uint32_t addr = %08x" % self.addr
		print "uint32_t size = %08x" % self.size
		print "uint32_t offset = %08x" % self.offset
		print "uint32_t align = %08x" % self.align
		print "uint32_t reloff = %08x" % self.reloff
		print "uint32_t nreloc = %08x" % self.nreloc
		print "uint32_t flags = %08x" % self.flags
		print "uint32_t reserved1 = %08x" % self.reserved1
		print "uint32_t reserved2 = %08x" % self.reserved2
		print "};\n"

class SYMTAB_COMMAND:
	struct_size = 6 * DEFAULTSIZE

	def __init__(self, tmp, foffset, data, hmacho):
		self.cmd = tmp[0]
		self.cmdsize = tmp[1]
		self.symoff = tmp[2]
		self.nsyms = tmp[3]
		self.stroff = tmp[4]
		self.strsize = tmp[5]
		self.foffset = foffset
		self.str_table = data[self.stroff + hmacho.foffset : self.stroff + hmacho.foffset + self.strsize]


	def pprint(self):
		print "struct symtab_command @ %08x" % self.foffset
		print "{"
		print "uint_32 cmd = %08x" % self.cmd
		print "uint_32 cmdsize = %08x" % self.cmdsize
		print "uint_32 symoff = %08x" % self.symoff
		print "uint_32 nsyms = %08x" % self.nsyms
		print "uint_32 stroff = %08x" % self.stroff
		print "uint_32 strsize = %08x" % self.strsize
		print "};\n"

class N_LIST:
	struct_size = 3 * DEFAULTSIZE

	def __init__(self, tmp, foffset, data):
		self.n_un = tmp[0]
		self.n_type = tmp[1]
		self.n_sect = tmp[2]
		self.n_desc = tmp[3]
		self.n_value = tmp[4]
		self.foffset = foffset
		self.data = data
		self.sym = ""


	def pprint(self):
		print "struct nlist @ %08x" % self.foffset
		print "{"
		print "uint_32 n_un = %08x -> '%s'" % (self.n_un, self.sym)
		print "uint8 n_type = %02x" % self.n_type
		print "uint8 n_sect = %02x" % self.n_sect
		print "int16_t n_desc = %04x" % self.n_desc
		print "uint_32 n_value = %08x" % self.n_value
		print "};\n"


class DYSYMTAB_COMMAND:
	struct_size = 20 * DEFAULTSIZE

	def __init__(self, tmp, foffset, data):
		self.cmd = tmp[0]
		self.cmdsize = tmp[1]
		self.ilocalsym = tmp[2]
		self.nlocalsym = tmp[3]
		self.iextdefsym = tmp[4]
		self.nextdefsym = tmp[5]
		self.iundefsym = tmp[6]
		self.nundefsym = tmp[7]
		self.tocoff = tmp[8]
		self.ntoc = tmp[9]
		self.modtaboff = tmp[10]
		self.nmodtab = tmp[11]
		self.extrefsymoff = tmp[12]
		self.nextrefsyms = tmp[13]
		self.indirectsymoff = tmp[14]
		self.nindirectsyms = tmp[15]
		self.extreloff = tmp[16]
		self.nextrel = tmp[17]
		self.locreloff = tmp[18]
		self.nlocrel = tmp[19]
		self.foffset = foffset

	def pprint(self):
		print "struct dysymtab_command @ %08x" % self.foffset
		print "{"
		print "uint32_t cmd = %08x" % self.cmd
		print "uint32_t cmdsize = %08x" % self.cmdsize
		print "uint32_t ilocalsym = %08x" % self.ilocalsym
		print "uint32_t nlocalsym = %08x" % self.nlocalsym
		print "uint32_t iextdefsym = %08x" % self.iextdefsym
		print "uint32_t nextdefsym = %08x" % self.nextdefsym
		print "uint32_t iundefsym = %08x" % self.iundefsym
		print "uint32_t nundefsym = %08x" % self.nundefsym
		print "uint32_t tocoff = %08x" % self.tocoff
		print "uint32_t ntoc = %08x" % self.ntoc
		print "uint32_t modtaboff = %08x" % self.modtaboff
		print "uint32_t nmodtab = %08x" % self.nmodtab
		print "uint32_t extrefsymoff = %08x" % self.extrefsymoff
		print "uint32_t nextrefsyms = %08x" % self.nextrefsyms
		print "uint32_t indirectsymoff = %08x" % self.indirectsymoff
		print "uint32_t nindirectsyms = %08x" % self.nindirectsyms
		print "uint32_t extreloff = %08x" % self.extreloff
		print "uint32_t nextrel = %08x" % self.nextrel
		print "uint32_t locreloff = %08x" % self.locreloff
		print "uint32_t nlocrel = %08x" % self.nlocrel
		print "};\n"


class DYLINKER_COMMAND:
	struct_size = 7 * DEFAULTSIZE

	def __init__(self, tmp, foffset):
		self.cmd = tmp[0]
		self.cmdsize = tmp[1]
		self.lc = tmp[2]
		self.name = tmp[3]
		self.foffset = foffset

	def pprint(self):
		print "struct dylinker_command @ %08x" % self.foffset
		print "{"
		print "uint32_t cmd = %08x" % self.cmd
		print "uint32_t cmdsize = %08x" % self.cmdsize
		print "union lc_str name = %08x %s" % (self.lc, self.name)
		print "};\n"

class UUID_COMMAND:
	struct_size = 6 * DEFAULTSIZE

	def __init__(self, tmp, foffset):
		self.cmd = tmp[0]
		self.cmdsize = tmp[1]
		self.uuid = tmp[2]
		self.foffset = foffset

	def pprint(self):
		print "struct uuid_command @ %08x" % self.foffset
		print "{"
		print "uint32_t cmd = %08x" % self.cmd
		print "uint32_t cmdsize = %08x" % self.cmdsize
		print "uint8_t uuid[16] %s" % binascii.hexlify(self.uuid)
		print "};\n"

class THREAD_COMMAND:
	struct_size = 21 * DEFAULTSIZE

	def __init__(self, tmp, foffset):
		self.cmd = tmp[0]
		self.cmdsize = tmp[1]
		self.flavor = tmp[2]
		self.count = tmp[3]
		self.cpu_thread_state = tmp[4]
		self.foffset = foffset

	def pprint(self):
		print "struct thread_command @ %08x" % self.foffset
		print "{"
		print "uint32_t cmd = %08x" % self.cmd
		print "uint32_t cmdsize = %08x" % self.cmdsize
		print "uint32_t flavor = %08x" % self.flavor
		print "uint32_t count = %08x" % self.count
		print "struct cpu_thread_state = %s" % binascii.hexlify(self.cpu_thread_state)
		print "};\n"

class ENCRYPTION_INFO_COMMAND:
	struct_size = 5 * DEFAULTSIZE

	def __init__(self, tmp, foffset, data):
		self.cmd = tmp[0]
		self.cmdsize = tmp[1]
		self.cryptoff = tmp[2]
		self.cryptsize = tmp[3]
		self.cryptid = tmp[4]
		self.foffset = foffset
		self.data = data[self.cryptoff : self.cryptoff + self.cryptsize]

	def pprint(self):
		print "struct encryption_info_command @ %08x" % self.foffset
		print "{"
		print "uint32_t cmd = %08x" % self.cmd
		print "uint32_t cmdsize = %08x" % self.cmdsize
		print "uint32_t cryptoff = %08x" % self.cryptoff
		print "uint32_t cryptsize = %08x" % self.cryptsize
		print "uint32_t cryptid = %08x" % self.cryptid
		print "};\n"

class DYLIB_COMMAND:
	def __init__(self, tmp, foffset):
		self.cmd = tmp[0]
		self.cmdsize = tmp[1]
		self.unk1 = tmp[2]
		self.unk2 = tmp[3]
		self.unk3 = tmp[4]
		self.unk4 = tmp[5]
		self.name = tmp[6]
		self.struct_size = self.cmdsize
		self.foffset = foffset

	def pprint(self):
		print "struct dylib_command @ %08x" % self.foffset
		print "{"
		print "uint32_t cmd = %08x" % self.cmd
		print "uint32_t cmdsize = %08x" % self.cmdsize
		print "uint32_t unk1 = %08x" % self.unk1
		print "uint32_t unk2 = %08x" % self.unk2
		print "uint32_t unk3 = %08x" % self.unk3
		print "uint32_t unk4 = %08x" % self.unk4
		print "char[%d] name %s" % (len(self.name),self.name)
		print "};\n"


class LINKEDIT_DATA_COMMAND:
	struct_size = 4 * DEFAULTSIZE

	def __init__(self, tmp, foffset, data):
		self.cmd = tmp[0]
		self.cmdsize = tmp[1]
		self.dataoff = tmp[2]
		self.datasize = tmp[3]
		self.foffset = foffset
		self.data = data[self.dataoff : self.dataoff + self.datasize]

	def pprint(self):
		print "struct linkedit_data_command @ %08x" % self.foffset
		print "{"
		print "uint32_t cmd = %08x" % self.cmd
		print "uint32_t cmdsize = %08x" % self.cmdsize
		print "uint32_t dataoff = %08x" % self.dataoff
		print "uint32_t datasize = %08x" % self.datasize
		print "};\n"

class LC_DYLD_INFO_COMMAND:
	struct_size = 12 * DEFAULTSIZE

	def __init__(self, tmp, foffset, data):
		self.cmd = tmp[0]
		self.cmdsize = tmp[1]
		self.rebase_off = tmp[2]
		self.rebase_size = tmp[3]
		self.bind_off = tmp[4]
		self.bind_size = tmp[5]
		self.weak_bind_off = tmp[6]
		self.weak_bind_size = tmp[7]
		self.lazy_bind_off = tmp[8]
		self.lazy_bind_size = tmp[9]
		self.export_off = tmp[10]
		self.export_size = tmp[11]
		self.foffset = foffset

	def pprint(self):
		print "struct dyld_info_command  @ %08x" % self.foffset
		print "{"
		print "uint32_t cmd = %08x" % self.cmd
		print "uint32_t cmdsize = %08x" % self.cmdsize
		print "uint32_t rebase_off = %08x" % self.rebase_off
		print "uint32_t rebase_size = %08x" % self.rebase_size
		print "uint32_t bind_off = %08x" % self.bind_off
		print "uint32_t bind_size = %08x" % self.bind_size
		print "uint32_t weak_bind_off = %08x" % self.weak_bind_off
		print "uint32_t weak_bind_size = %08x" % self.weak_bind_size
		print "uint32_t lazy_bind_off = %08x" % self.lazy_bind_off
		print "uint32_t lazy_bind_size = %08x" % self.lazy_bind_size
		print "uint32_t export_off = %08x" % self.export_off
		print "uint32_t export_size = %08x" % self.export_size
		print "};\n"

class UNKNOWN_COMMAND:
	struct_size = 4 * DEFAULTSIZE

	def __init__(self, tmp, foffset):
		self.cmd = tmp[0]
		self.cmdsize = tmp[1]
		self.unk1 = tmp[2]
		self.unk2 = tmp[3]
		self.foffset = foffset

	def pprint(self):
		print "struct unknown_command @ %08x" % self.foffset
		print "{"
		print "uint32_t cmd = %08x" % self.cmd
		print "uint32_t cmdsize = %08x" % self.cmdsize
		print "uint32_t unk1 = %08x" % self.unk1
		print "uint32_t unk2 = %08x" % self.unk2
		print "};\n"


def parse_section(seg, data, offset):
	section_list = []
	offset += seg.struct_size
	for i in range(0, seg.nsects):
		tmp = struct.unpack("<16s16s9I", data[offset : offset + SECTION.struct_size])
		section_list.append(SECTION(tmp, offset, data))
		offset += SECTION.struct_size

	return section_list


def parse_segment(load_command, data, offset, hmacho):
	global API_CALLS
	global FRAMEWORKS
	if load_command.cmd == LC_SEGMENT:
		tmp = struct.unpack("<2I16s8I" , data[offset : offset + SEGMENT_COMMAND.struct_size])
		seg = SEGMENT_COMMAND(tmp, offset, data)
		if DEBUG:
			seg.pprint()
		if seg.nsects != 0x00000000:
			section_list = parse_section(seg, data, offset)
			if DEBUG:
				for section in section_list:
					section.pprint()

	elif load_command.cmd == LC_SYMTAB:
		tmp = struct.unpack("<6I", data[offset : offset + SYMTAB_COMMAND.struct_size])
		seg = SYMTAB_COMMAND(tmp, offset, data, hmacho)
		if DEBUG:
			seg.pprint()
		element_offset = seg.symoff + hmacho.foffset
#		print seg.str_table
		for i in range(0, seg.nsyms):
			tmp = struct.unpack("<IBBHI", data[element_offset : element_offset + N_LIST.struct_size])
			element = N_LIST(tmp, element_offset, data)
			if element.n_un < len(seg.str_table) and element.n_un != 0x00000000:
				#this is REALLY slow maybe do a while char != \x00 append char 
				sym = seg.str_table[element.n_un:element.n_un + seg.str_table[element.n_un:].index('\x00')]
				element.sym = sym
				if element.n_type == 0x01 and element.n_sect == 0x00:
					API_CALLS.append(sym)
				if DEBUG:
					element.pprint()
			element_offset += N_LIST.struct_size

	elif load_command.cmd == LC_DYSYMTAB:
		tmp = struct.unpack("<20I", data[offset : offset + DYSYMTAB_COMMAND.struct_size])
		seg = DYSYMTAB_COMMAND(tmp, offset, data)
		if DEBUG:
			seg.pprint()

	elif load_command.cmd == LC_LOAD_DYLINKER:
		tmp = struct.unpack("<3I16s", data[offset : offset + DYLINKER_COMMAND.struct_size])
		seg = DYLINKER_COMMAND(tmp, offset)
		if DEBUG:
			seg.pprint()

	elif load_command.cmd == LC_UUID:
		tmp = struct.unpack("<2I16s", data[offset : offset + UUID_COMMAND.struct_size])
		seg = UUID_COMMAND(tmp, offset)
		if DEBUG:
			seg.pprint()

	elif load_command.cmd == LC_UNIXTHREAD:
		tmp = struct.unpack("<4I68s", data[offset : offset + THREAD_COMMAND.struct_size])
		seg = THREAD_COMMAND(tmp, offset)
		if DEBUG:
			seg.pprint()

	elif load_command.cmd == LC_ENCRYPTION_INFO:
		tmp = struct.unpack("<5I", data[offset : offset + ENCRYPTION_INFO_COMMAND.struct_size])
		seg = ENCRYPTION_INFO_COMMAND(tmp, offset, data)
		if DEBUG:
			seg.pprint()

	elif load_command.cmd == LC_LOAD_WEAK_DYLIB:
		tmp = struct.unpack("<6I%ds" % (load_command.cmdsize - (6 * DEFAULTSIZE)), data[offset : offset + load_command.cmdsize])
		seg = DYLIB_COMMAND(tmp, offset)
		if DEBUG:
			seg.pprint()
		FRAMEWORKS.append(seg.name)

	elif load_command.cmd == LC_LOAD_DYLIB:
		tmp = struct.unpack("<6I%ds" % (load_command.cmdsize - (6 * DEFAULTSIZE)), data[offset : offset + load_command.cmdsize])
		seg = DYLIB_COMMAND(tmp, offset)
		if DEBUG:
			seg.pprint()
		FRAMEWORKS.append(seg.name)

	elif load_command.cmd == LC_CODE_SIGNATURE:
		tmp = struct.unpack("<4I", data[offset : offset + LINKEDIT_DATA_COMMAND.struct_size])
		seg = LINKEDIT_DATA_COMMAND(tmp, offset, data)
		if DEBUG:
			seg.pprint()

	elif load_command.cmd == LC_DYLD_INFO or load_command.cmd == LC_DYLD_INFO_ONLY:
		tmp = struct.unpack("<12I", data[offset : offset + LC_DYLD_INFO_COMMAND.struct_size])
		seg = LC_DYLD_INFO_COMMAND(tmp, offset, data)
		if DEBUG:
			seg.pprint()

	elif load_command.cmd == LC_UNKNOWN:
		tmp = struct.unpack("<4I", data[offset : offset + UNKNOWN_COMMAND.struct_size])
		seg = UNKNOWN_COMMAND(tmp, offset)
		if DEBUG:
			seg.pprint()

	elif load_command.cmd == LC_UNKNOWN_2:
		tmp = struct.unpack("<4I", data[offset : offset + UNKNOWN_COMMAND.struct_size])
		seg = UNKNOWN_COMMAND(tmp, offset)
		if DEBUG:
			seg.pprint()

	elif load_command.cmd == LC_UNKNOWN_3:
		tmp = struct.unpack("<4I", data[offset : offset + UNKNOWN_COMMAND.struct_size])
		seg = UNKNOWN_COMMAND(tmp, offset)
		if DEBUG:
			seg.pprint()


	else:
		print "LOAD COMMAND NOT SUPPORTED: %08x" % load_command.cmd


def parse_macho(fat_arch, data):
	if DEBUG:
		fat_arch.pprint()

	tmp = struct.unpack("<%dI" % (MACH_HEADER.struct_size / DEFAULTSIZE),  data[fat_arch.offset: fat_arch.offset + MACH_HEADER.struct_size])
	hmacho = MACH_HEADER(tmp, fat_arch.offset)
	if hmacho.magic != MACHMAGIC:
		return
	if DEBUG:
		hmacho.pprint()

	offset = fat_arch.offset + hmacho.struct_size
	for i in range(0, hmacho.ncmds):
		tmp = struct.unpack("<%dI" % (DEFAULTSIZE / 2), data[offset : offset + (DEFAULTSIZE * 2)])
		load_command = LOAD_COMMAND(tmp, offset)
		parse_segment(load_command, data, offset, hmacho)
		offset += load_command.cmdsize


def get_data(file_name, calls=True, frameworks=True):
	global API_CALLS
	global FRAMEWORKS
	API_CALLS = []
	FRAMEWORKS = []
	fd = open(file_name, "rb")
	data = fd.read()
	fd.close()
	coffset = 0
	magic = binascii.hexlify(data[coffset : coffset + DEFAULTSIZE])

	if int(magic, 16) == FATMAGIC:
		coffset += DEFAULTSIZE
		nfat_arch = int(binascii.hexlify(data[coffset : coffset + DEFAULTSIZE]), 16)
		coffset += DEFAULTSIZE

		fat_header = FAT_HEADER([magic, nfat_arch], 0)
		if DEBUG:
			fat_header.pprint()


		fat_arch_list = []
		for i in range(0, nfat_arch):
			tmp = struct.unpack(">%dI" % (FAT_ARCH.struct_size / DEFAULTSIZE), data[coffset : coffset + FAT_ARCH.struct_size])
			fat_arch = FAT_ARCH(tmp, coffset)
			fat_arch_list.append(fat_arch)
			coffset += fat_arch.struct_size
		
		for fat_arch in fat_arch_list:
			parse_macho(fat_arch, data)

		ret = {'API_CALLS': [], 'FRAMEWORKS': []}
		if calls:
			ret['API_CALLS'] = list(set(API_CALLS))
		if frameworks:
			ret['FRAMEWORKS'] = list(set(FRAMEWORKS))
		return ret

	elif int(magic, 16) == MACHMAGIC_LE:
		tmp = [0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000]
		fat_arch = FAT_ARCH(tmp, coffset)
		parse_macho(fat_arch, data)

		ret = {'API_CALLS': [], 'FRAMEWORKS': []}
		if calls:
			ret['API_CALLS'] = list(set(API_CALLS))
		if frameworks:
			ret['FRAMEWORKS'] = list(set(FRAMEWORKS))
		return ret

	else:
		print "FATMAGIC and MACHMAGIC do not match!!"
		sys.exit()


def usage():
		print "%s file" % sys.argv[0]
		sys.exit()


def main():
	data = get_data(sys.argv[1])
	for k,v in data.iteritems():
		print k, len(v)
		for i in v:
			print "\t", i
		print ""

if __name__ == '__main__':
	if len(sys.argv) < 2:
		usage()

	if not os.path.exists(sys.argv[1]):
		usage()

	main()