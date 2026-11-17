import os
import sys
import random
import lief
import pefile
import time
sys.path.append("modifier")

from overlay_append import *
from perturb_pe_header import *
from modify_dos_header import *
from extend_dos_header import *
from dropper import *
from entry_point_extend import *
from code_randomization import *
from jmp_back_to_other_address import *
from add_section import *
from change_entrypoint import *
from entry_point_extend import *
from nop_insertion import *
from packing import *
from section_append import *
from filling_slack import *
from contents_shifting import *
from import_function_injection import *
from section_rename import *
from rich_header import *
from pert_optional_header import *
from coff_header import *
from data_directory import *
from instruction_change import *
from resource_change import *
from section_increase import *
from semantic_nop import *
from makeover import *

class Modifier:
    def __init__(self, sample_path, opath):
        self.sample_path = sample_path
        if "/" in sample_path:
            self.sample = sample_path[sample_path.rindex("/")+1:]
            self.root_sample = sample_path.replace(self.sample,"")
        else:
            self.sample = sample_path
            self.root_sample = "./"

        self.data = open(sample_path, "rb").read()
        self.opath = opath

    def build_lief_name(self, fparsed, pertname):
        pe = pefile.PE(self.sample_path)
        # fparsed = lief.parse(fbytes)
        builder = lief.PE.Builder(fparsed)
        builder.build()
        new_fname = "{}/{}|{}.exe".format(self.opath, self.sample[:-4], pertname)
        builder.write(new_fname)

        pe2 = pefile.PE(new_fname)

        if pe.OPTIONAL_HEADER.SizeOfHeaders != pe2.OPTIONAL_HEADER.SizeOfHeaders:
            pe2.OPTIONAL_HEADER.SizeOfHeaders = pe.OPTIONAL_HEADER.SizeOfHeaders

        pe2.write(new_fname)

    def overlay_append(self):
        append_data = os.urandom(0x1000)
        new_data = overlay_append_dummy(self.data, append_data)
        open("{}/{}|overlay_append.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def section_rename(self):
        length = random.randrange(1,10)
        section_name ="."+''.join(random.sample([chr(i) for i in range(97,123)], length))
        checksum = os.urandom(0x4) # b"\x01\x02\x03\x04"
        new_data = perturb_pe_header(self.data, section_name, checksum)
        open("{}/{}|section_rename.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def fill_slack_space(self):
        new_data = fill_slack(self.data)
        open("{}/{}|perturb_header.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def modify_dos_header(self):
        new_data = modify_dos_header(self.data)
        open("{}/{}|modify_dos_header.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def extend_dos_stub(self):
        code = os.urandom(0xA00)
        new_data = extend_dos_stub(self.data, code)
        open("{}/{}|extend_dos_stub.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

#     def content_shifting(self):
#         new_data = gap_sections(self.data)
#         new_data = extend_and_shift_sections(new_data)
#         open("{}/{}|content_shifting.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)
        
    def content_shifting(self):
        new_data = gap_sections(self.data)
        new_data = extend_and_shift_sections(new_data)

        output_path = "{}/{}|content_shifting.exe".format(self.opath, self.sample[:-4])
        with open(output_path, "wb") as f:
            f.write(new_data)

        return output_path


    def inject_import_func(self): 
        # Does not work
        arbitrary_code = b"\xcc" * 0x100
        value = [
            {"funcname" : b"GetProcAddress", "nativecode" : b"\xcc" * 0x100},
            {"funcname" : b"GetCurrentThreadId", "nativecode" : b"\x90" * 0x100},
        ]
        new_data = iat_injection(self.data, value)
        open("{}/{}|inject_import_func.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def section_add(self):
        _data = bytearray(self.data)
        length = random.randrange(1,10)
        section_name ="."+''.join(random.sample([chr(i) for i in range(97,123)], length))
        content = os.urandom(0x100)
        new_data = add_section(_data, section_name, content, PERM.READ | PERM.WRITE | PERM.EXEC)
        open("{}/{}|section_add.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def section_append(self):
        new_data = section_append_unused(self.data)
        new_data = section_append_gap(new_data)
        open("{}/{}|section_append.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def packing(self):
        output_exe_path = "{}/{}|packing.exe".format(self.opath, self.sample[:-4])
        pack_with_upx(self.sample_path, output_exe_path)

    
    def code_randomization(self):
        _data = bytearray(self.data)
        new_data = code_randomization(_data)
        open("{}/{}|code_randomization.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def change_entrypoint(self):
        # Does not work
        _data = bytearray(self.data)
        new_data = change_entry_point(_data, 0xdeadbeef)
        open("{}/{}|change_entrypoint.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def dropper(self):
        # Does not work
        '''
        _data = bytearray(self.data)
        drop_binary = bytearray(open("test/hello_world.exe", "rb").read())
        new_data = dropper(_data, drop_binary, b"C:\\tmp\\test.exe")
        open("{}/{}_dropper.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)
        '''
        pass
    
    def extend_entrypoint(self):
        # Does not work
        _data = bytearray(self.data)
        new_data = entry_point_extend(_data, '.tls', 0x1234, 0xdeadbeef)
        open("{}/{}|extend_entrypoint.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)

    def nop_insertion(self):
        _data = bytearray(self.data)
        new_data = nop_insertion(_data, 2)
        open("{}/{}|nop_insertion.exe".format(self.opath, self.sample[:-4]), "wb").write(new_data)


    def jmp_overlay_back(self):
        fparsed = lief.parse(self.data)
        _data = bytearray(self.data)

        pe_header_offset = int.from_bytes(_data[0x3C:0x40], byteorder="little")
        num_sections = int.from_bytes(_data[pe_header_offset + 6 : pe_header_offset + 8], byteorder="little")

        print(f" [DEBUG] Number of sections read by LIEF: {len(fparsed.sections)}")
        print(f" [DEBUG] Number of sections read directly from the PE header: {num_sections}")

        if len(fparsed.sections) != num_sections:
            print(f" [ERROR] LIEF differs from the number read from the PE header (lief={len(fparsed.sections)}, PE haeder={num_sections})")

        if num_sections > 100:
            raise ValueError(f" Abnormal PE section count: {num_sections}! Risk of file corruption (aborting)")

        file_end_offset = len(_data.rstrip(b'\x00'))  
        baseof_code = fparsed.optional_header.baseof_code
        overlay_addr = (file_end_offset + 0x10) & ~0xF
        code_base = fparsed.optional_header.imagebase + baseof_code

        new_data = jmp_back_to_other_address(_data, code_base, overlay_addr)

        rebuilt = lief.parse(bytes(new_data))
        if rebuilt is None:
            raise ValueError("lief parse failed after jmp_overlay_back")

        builder = lief.PE.Builder(rebuilt)
        builder.build()
        builder.build_imports(False)

        output_path = f"{self.opath}/{self.sample[:-4]}|jmp_overlay_back.exe"
        builder.write(output_path)

        return output_path

    
    def section_rename(self):
        fparsed = section_rename(self.data)
        self.build_lief_name(fparsed,"section_rename")
    
    def rich_header(self):
        fparsed = pert_rich_header(self.data)
        self.build_lief_name(fparsed,"rich_header")
        

    def optional_header(self):
        fparsed = pert_optional_header(self.data)
        self.build_lief_name(fparsed,"optional_header")

    def coff_header(self):
        fparsed = pert_coff_header(self.data)
        self.build_lief_name(fparsed,"coff_header")

    def data_directory(self):
        fparsed = pert_data_directory(self.data)
        self.build_lief_name(fparsed,"data_directory")

    def instruction_change(self):
        args = (self.sample, self.root_sample, self.opath)
        output_path = instruction_change(args)  # instruction_change 함수가 반환해야 함
        if output_path is None:
            print(f"[Modifier] instruction_change returned None for: {self.sample}")
            return None
        return output_path

    def resource_change(self):
        args = (self.sample, self.root_sample, self.opath)
        output_path = resource_change(args)
        #output_path = output_path.replace('resource_change','RC')
        return output_path

    def section_increase(self):
        args = (self.sample, self.root_sample, self.opath)
        section_increase(args)
        
    def semantic_nop(self):
        args = (self.sample, self.root_sample, self.opath)
        semantic_nop(args)
        
    def makeover(self):
        args = (self.sample, self.root_sample, self.opath)
        makeover(args)

