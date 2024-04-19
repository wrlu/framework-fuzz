import angr
import struct
import os
import pdb
import sys


current_patch_py_path = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(current_patch_py_path,"..","utils"))
from custom_logger import logger



main_options = {'main_opts' : { 'custom_base_addr' : 0x0 } }


def patch_elf(patch_target_offset,real_trace_pc_guard_offset,elf_file_path):
	
	if patch_target_offset!=0 and real_trace_pc_guard_offset!=0:

		# determine if jump back or forward?
		if real_trace_pc_guard_offset < patch_target_offset:
			# jump back
			# the bytecode of 'B XXXX' in aarch64 is 0x17000000  + XXXXXX
			# the formula to calc the offset 'XXXXXX' is 0x1000000 + 1 - (address to patch +4 - target address)/4
			b_ins_offset = int(0x1000000 + 1 - (patch_target_offset + 4 - real_trace_pc_guard_offset)/4)
			ins = 0x17000000 + b_ins_offset
			logger.info("Patch target to jump back")

		else:
			# jump forward
			# the bytecode of 'B XXXX' in aarch64 is 0x14000000  + XXXXXX
			b_ins_offset = int((real_trace_pc_guard_offset - patch_target_offset)/4)
			ins = 0x14000000 + b_ins_offset
			logger.info("Patch target to jump forward")
		
		ins_byte_code = struct.pack("<i",int(ins))
		
		with open(elf_file_path,"rb") as f:
			content = f.read()
			original_bytes = content[patch_target_offset:patch_target_offset+4]

		new_content = content[:patch_target_offset] + ins_byte_code + content[patch_target_offset+4:]

		with open(elf_file_path,"wb") as f:
			f.write(new_content)

		logger.info("Patched done")
	else:
		logger.warning("Do not find patch_target_offset or real_trace_pc_guard_offset, wont patch")


def extract_instruction_bytecode(elf_file_path):

	logger.info("Loading {} with angr".format(os.path.basename(elf_file_path)))

	p = angr.Project(elf_file_path, load_options={'auto_load_libs': False, 'main_opts':main_options})
	cfg = p.analyses.CFGFast()

	# get .plt section
	plt_section = None
	sections = p.loader.main_object.sections
	for section in sections:
		if section.name ==".plt":
			logger.info("Found plt section")
			plt_section = section
			break


	patch_target_offset = 0x0
	real_trace_pc_guard_offset =0x0
	# enumerate all the functions and find __sanitizer_cov_trace_pc_guard,
	# There should be two __sanitizer_cov_trace_pc_guard in ideal, the target should be in .plt
	for func in p.kb.functions.values():
		if func.name == "__sanitizer_cov_trace_pc_guard":
			logger.info("{}:{}".format(func.name,hex(func.offset)))

			# is this function in .plt section ? 
			if plt_section.offset <= func.offset <= plt_section.offset+plt_section.memsize:
				patch_target_offset = func.offset
			else:
				real_trace_pc_guard_offset = func.offset

	logger.info("Found patch target: {} and real_trace_pc_guard_offset: {}".format(hex(patch_target_offset), hex(real_trace_pc_guard_offset)))
	return patch_target_offset, real_trace_pc_guard_offset


if __name__ == "__main__":
	patch_target_offset, real_trace_pc_guard_offset =  extract_instruction_bytecode(sys.argv[1])
	patch_elf(patch_target_offset, real_trace_pc_guard_offset,sys.argv[1])