import lief
from iced_x86 import *
from pe_library import *
from typing import Union, Dict, Sequence 
from types import ModuleType
import binascii
from keystone import *
import pandas as pd
import shutil
from common_function import *
import multiprocessing
import capstone
from functools import lru_cache

def increase_section_size_with_nop(file_path, output_file, increase_size, nop_count):
    """
    Args:
        file_path (str): original PE file path
        output_file (str): modigied PE file path
        increase_size (int): Number of bytes to increase section size
        nop_count (int): Number of NOP bytes to add at the end of the section
    """
    try:
        # PE fiel load
        pe = lief.parse(file_path)
        if not pe or not hasattr(pe, 'optional_header'):
            print(f"[ERROR] The file '{file_path}' is not a valid PE file or does not have an optional header.")
            return False

        # get FileAlignment, SectionAlignment
        file_alignment = pe.optional_header.file_alignment
        section_alignment = pe.optional_header.section_alignment

        print(f"[INFO] FileAlignment: {file_alignment}, SectionAlignment: {section_alignment}")

        # modified each section size and section header
        previous_end_of_file = 0
        for section in pe.sections:
            print(f"[INFO] Processing section: {section.name}")

            # increasing file size (SizeOfRawData) and aligning
            raw_size = section.size + increase_size
            new_raw_size = (raw_size + file_alignment - 1) // file_alignment * file_alignment
            section.size = new_raw_size
            print(f"  [INFO] New SizeOfRawData: {new_raw_size} (aligned from {raw_size})")

            # incerasing memory size (VirtualSize) and aligning
            virtual_size = section.virtual_size + increase_size
            new_virtual_size = (virtual_size + section_alignment - 1) // section_alignment * section_alignment
            section.virtual_size = new_virtual_size
            print(f"  [INFO] New VirtualSize: {new_virtual_size} (aligned from {virtual_size})")

            # updating section data offset (PointerToRawData)
            if previous_end_of_file == 0:
                previous_end_of_file = section.offset + new_raw_size
            else:
                section.offset = previous_end_of_file
                previous_end_of_file += new_raw_size
            print(f"  [INFO] Updated PointerToRawData: {section.offset}")

            # Add NOP (0x90) at the end of the section + Apply padding
            section_data = list(section.content)  
            section_data.extend([0x90] * nop_count)
            padding_size = section.size - len(section_data) 
            if padding_size > 0:
                section_data.extend([0x00] * padding_size) 
            section.content = section_data 

            print(f"  [INFO] Added {nop_count} NOP (0x90) and {padding_size} bytes padding to section: {section.name}")

        # updating SizeOfImage
        last_section = list(pe.sections)[-1]
        new_size_of_image = last_section.virtual_address + last_section.virtual_size
        pe.optional_header.sizeof_image = new_size_of_image
        print(f"[INFO] Updated SizeOfImage: {new_size_of_image}")

        # saving modified file (using PE Builder)
        builder = lief.PE.Builder(pe)
        builder.build()
        builder.write(output_file)
        print(f"[SUCCESS] Modified file saved to: {output_file}")

        return True

    except Exception as e:
        print(f"[ERROR] {e}")
        return False
    
def section_increase(args):
    sample, root, save_dir = args
    increase_size = 1
    nop_count  = 5
    input_filepath = os.path.join(root, sample)
    output_filename = sample.replace('.exe', '|section_increase.exe')
    output_filepath = os.path.join(save_dir, output_filename)


    try:
        increase_section_size_with_nop(input_filepath, output_filepath, increase_size, nop_count)

    except pefile.PEFormatError:
        pass
    
def list_files_by_size(directory):
    # Return a list of files in the directory sorted by size
    files_with_sizes = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.isfile(file_path):
                files_with_sizes.append((file, os.path.getsize(file_path), root))
    # Sort files by size (smallest to largest)
    files_with_sizes.sort(key=lambda x: x[1])
    return [file[0] for file in files_with_sizes]  # Return only file names

def create_directory(dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)

def main():
    sample = "putty.exe"
    root = "./"
    save_dir = "./temp/"
    
    increase_size=1
    nop_count=0
    
    process_sample((sample, root, save_dir))