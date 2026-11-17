from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from add_section import * 
from iced_x86 import *
from overlay_append import *
from pwn import *
import lief

def btoi(data: bytes) -> int:
    return int.from_bytes(data, byteorder="little")

def itob4(data: int) -> bytes:
    return data.to_bytes(4, byteorder="little")

def itob2(data: int) -> bytes:
    return data.to_bytes(2, byteorder="little")

def get_overlay_address(data: bytearray) -> int:
    pe_header_offset = btoi(data[0x3C:0x40])
    if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header offset")

    size_of_optional_header = btoi(data[pe_header_offset + 0x14 : pe_header_offset + 0x16])
    section_header_start_offset = pe_header_offset + 0x18 + size_of_optional_header
    total_number_of_sections = btoi(data[pe_header_offset + 0x6 : pe_header_offset + 0x8])

    print(f" get_overlay_address [DEBUG]: {total_number_of_sections}")

    highest_PointerToRawData = 0 
    highest_SizeOfRawData = 0

    for i in range(total_number_of_sections):
        cur_section_header = section_header_start_offset + i * 0x28  # 섹션 헤더 크기
        cur_SizeOfRawData = btoi(data[cur_section_header + 0x10 : cur_section_header + 0x14])
        cur_PointerToRawData = btoi(data[cur_section_header + 0x14 : cur_section_header + 0x18])

        if cur_SizeOfRawData + cur_PointerToRawData > len(data):
            print(f" get_overlay_address [WARNING] (ignored)")
            continue
        
        if cur_SizeOfRawData + cur_PointerToRawData > highest_PointerToRawData + highest_SizeOfRawData:
            highest_PointerToRawData = cur_PointerToRawData
            highest_SizeOfRawData = cur_SizeOfRawData
    
    if len(data) > highest_PointerToRawData + highest_SizeOfRawData:
        overlay_address = highest_PointerToRawData + highest_SizeOfRawData
        print(f" get_overlay_address [DEBUG] caluated Overlay address: {hex(overlay_address)}")
        return overlay_address

    return None

def search_section_header_by_name(data: bytes, section_name: bytes) -> int:
    pe_header_offset = btoi(data[0x3C:0x40])
    if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header offset")

    size_of_optional_header = btoi(data[pe_header_offset + 0x14 : pe_header_offset + 0x16])
    section_header_start_offset = pe_header_offset + 0x18 + size_of_optional_header
    total_number_of_sections = btoi(data[pe_header_offset + 0x6 : pe_header_offset + 0x8])

    section_header_size = 0x28
    for i in range(total_number_of_sections):
        cur_section_header = section_header_start_offset + i * section_header_size
        cur_section_name = bytes(data[cur_section_header : cur_section_header + 0x8])

        if cur_section_name.replace(b'\x00', b'') == section_name:
            return cur_section_header
    
    return 0

def make_assemble_jmp(jmp_target, origin=0):
    rel_offset = jmp_target - origin
    if not -2**31 <= rel_offset < 2**31:
        raise ValueError(f"JMP offset out of range: {rel_offset}")
    return b"\x68" + itob4(jmp_target) + b"\xc3"

def make_assemble_call(call_target):
    asm_bytes = b"\x57" + b"\x68" + itob4(call_target) + b"\x5f" + b'\xff\xd7' + b'\x5f'
    return asm_bytes

def manually_add_section(data: bytearray, section_name: str):
    pe_header_offset = btoi(data[0x3C:0x40])
    section_table_offset = pe_header_offset + 0xf8
    num_sections = btoi(data[pe_header_offset + 6: pe_header_offset + 8])

    new_section_offset = section_table_offset + num_sections * 0x28
    if new_section_offset + 0x28 > len(data):
        raise ValueError("[-] Not enough space to add new sections.")

    # writing new section header
    data[new_section_offset : new_section_offset + 8] = section_name.encode().ljust(8, b"\x00")  # 섹션 이름

    # Section preferences (default size 0x1000)
    data[new_section_offset + 0x8 : new_section_offset + 0x10] = itob4(0x1000)  # VirtualSize
    data[new_section_offset + 0x10 : new_section_offset + 0x14] = itob4(0x1000)  # SizeOfRawData
    data[new_section_offset + 0x14 : new_section_offset + 0x18] = itob4(len(data))  # PointerToRawData (파일 끝에 추가)
    data[new_section_offset + 0x24 : new_section_offset + 0x28] = itob4(0x60000020)  # Characteristics (RWX 권한)

    # Increase the number of sections in the PE header
    data[pe_header_offset + 6 : pe_header_offset + 8] = itob2(num_sections + 1)
    print(f"✅ [DEBUG] Added .ccc section! Number of new sections: {num_sections + 1}")

    return data

def fix_reloc_section(data: bytearray):
    pe_header_offset = btoi(data[0x3C:0x40])
    num_sections = btoi(data[pe_header_offset + 6: pe_header_offset + 8])
    section_table_offset = pe_header_offset + 0xf8

    for i in range(num_sections):
        section_offset = section_table_offset + (i * 0x28)
        section_name = data[section_offset : section_offset + 8].rstrip(b"\x00").decode(errors="ignore")

        if section_name == ".reloc":
            size_of_raw_data = btoi(data[section_offset + 0x10 : section_offset + 0x14])
            pointer_to_raw_data = btoi(data[section_offset + 0x14 : section_offset + 0x18])

            # Force adjustment if .reloc section size is abnormally large
            if size_of_raw_data > 0x10000:  # 64KB 이상이면 비정상
                print(f" .reloc section size abnormal ({size_of_raw_data:#x}) → Adjust to 0x1000")
                data[section_offset + 0x10 : section_offset + 0x14] = itob4(0x1000)

    return data

def fix_pe_data_directory(data: bytearray):
    pe_header_offset = btoi(data[0x3C:0x40])
    optional_header_offset = pe_header_offset + 0x18

    # Import Table, Reloc Table 위치 확인
    import_rva = btoi(data[optional_header_offset + 0x80 : optional_header_offset + 0x84])
    reloc_rva = btoi(data[optional_header_offset + 0xa0 : optional_header_offset + 0xa4])

    if import_rva == 0 or reloc_rva == 0:
        print("Import Table or Reloc Table RVA set to 0 → Need to be modified")

        # Moving the Import Table to the .data section
        data[optional_header_offset + 0x80 : optional_header_offset + 0x84] = itob4(0x400000 + 0x2000)
        data[optional_header_offset + 0xa0 : optional_header_offset + 0xa4] = itob4(0x400000 + 0x3000)

    return data


def jmp_back_to_other_address(data: bytes, hook_target_VA: int, overlay_address: int) -> bytes:
    data = bytearray(data)

    pe_header_offset = btoi(data[0x3C:0x40])
    
    if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header offset")

    # check the number of PE sections
    section_header_start_offset = pe_header_offset + 0xf8
    total_number_of_sections = btoi(data[pe_header_offset + 0x6 : pe_header_offset + 0x8])
    lief_parsed = lief.parse(bytes(data))
    
    if lief_parsed is None:
        raise ValueError("[-] Failed to parse PE file with LIEF (possibly corrupted or packed).")

    lief_section_count = len(lief_parsed.sections)

    print(f" jmp_back_to_other_address [DEBUG] Number of sections read from the PE header.: {total_number_of_sections}")
    print(f" jmp_back_to_other_address [DEBUG] Number of sections read by LIEF: {lief_section_count}")

    if abs(total_number_of_sections - lief_section_count) > 2:
        print(" jmp_back_to_other_address [WARNING] Large discrepancy between the section count read by LIEF and the PE header → using the PE header value")
        total_number_of_sections = lief_section_count

    print(f" jmp_back_to_other_address [DEBUG] Final number of PE sections: {total_number_of_sections}")

    hook_section_header = search_section_header_by_name(data, b".ccc")

    if hook_section_header == 0:
        print("[+] No .ccc section → add a new one")
        if total_number_of_sections >= 50:
            raise ValueError("Too many sections → abort adding the .ccc section")

        try:
            data = add_section(data, ".ccc", b"\x00" * 0x1000, PERM.READ | PERM.EXEC)
            lief_parsed_after = lief.parse(bytes(data))
            if lief_parsed_after:
                print(f" jmp_back_to_other_address [DEBUG] PE section list after adding the section: {[sec.name for sec in lief_parsed_after.sections]}")
        except Exception as e:
            print(f" lief.add_section() fail: {str(e)}")

        hook_section_header = search_section_header_by_name(data, b".ccc")
        if hook_section_header == 0:
            # By-construction profile: do NOT hand-roll section/header repair.
            # manually_add_section + fix_pe_data_directory can rewrite import/reloc
            # RVAs to hardcoded guesses and corrupt the binary. If LIEF could not
            # add the section cleanly, skip this sample instead.
            raise ValueError("[-] LIEF failed to add .ccc; skipping (by-construction profile)")
        
        print(f"[DEBUG] Number of PE sections after adding .ccc: {total_number_of_sections + 1}")
    else:
        print("[+] Found an existing .ccc section → not adding a new one")

    return data


if __name__ == '__main__':
    data = bytearray(open("test/putty.exe", "rb").read())
    data = overlay_append_dummy(data, itob4(0x40105c))
    overlay_addr = 0x115120

    print(f"target overlay = {hex(overlay_addr)}")
    new_data = jmp_back_to_other_address(data, 0x401000, overlay_addr)
    open("test/putty_new.exe", "wb").write(new_data)