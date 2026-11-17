import bisect
import pefile
import capstone
from capstone import x86


def _exec_sections(pe):
    CH = pefile.SECTION_CHARACTERISTICS
    for s in pe.sections:
        c = s.Characteristics
        if (c & CH['IMAGE_SCN_MEM_EXECUTE']) or (c & CH['IMAGE_SCN_CNT_CODE']):
            yield s


def _add_reloc_targets(pe, pe_data, refs, lo, hi):
    if not hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
        return
    for block in pe.DIRECTORY_ENTRY_BASERELOC:
        for e in block.entries:
            # 3 = IMAGE_REL_BASED_HIGHLOW (4 bytes), 10 = IMAGE_REL_BASED_DIR64 (8)
            if e.type == 3:
                size = 4
            elif e.type == 10:
                size = 8
            else:
                continue
            try:
                off = pe.get_offset_from_rva(e.rva)
            except Exception:
                continue
            val = int.from_bytes(pe_data[off:off + size], 'little')
            if lo <= val < hi:
                refs.add(val)


def _add_code_refs(pe, pe_data, refs, lo, hi):
    is64 = (pe.FILE_HEADER.Machine == 0x8664)
    mask = (1 << 64) - 1 if is64 else (1 << 32) - 1
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if is64 else capstone.CS_MODE_32)
    md.detail = True

    image_base = pe.OPTIONAL_HEADER.ImageBase
    for s in _exec_sections(pe):
        start = s.PointerToRawData
        code = pe_data[start:start + s.SizeOfRawData]
        if not code:
            continue
        base_va = image_base + s.VirtualAddress
        try:
            for insn in md.disasm(code, base_va):
                try:
                    ops = insn.operands
                except Exception:
                    continue
                for op in ops:
                    if op.type == x86.X86_OP_IMM:
                        v = op.imm & mask
                        if lo <= v < hi:
                            refs.add(v)
                    elif op.type == x86.X86_OP_MEM:
                        if op.mem.base == x86.X86_REG_RIP:
                            tgt = insn.address + insn.size + op.mem.disp
                            if lo <= tgt < hi:
                                refs.add(tgt)
                        elif op.mem.base == 0 and op.mem.index == 0:
                            v = op.mem.disp & mask
                            if lo <= v < hi:
                                refs.add(v)
        except capstone.CsError:
            pass


def collect_referenced_vas(pe, pe_data):
    """Return a sorted list of virtual addresses that code references."""
    lo = pe.OPTIONAL_HEADER.ImageBase
    hi = lo + pe.OPTIONAL_HEADER.SizeOfImage
    refs = set()
    try:
        _add_reloc_targets(pe, pe_data, refs, lo, hi)
    except Exception:
        pass
    try:
        _add_code_refs(pe, pe_data, refs, lo, hi)
    except Exception:
        pass
    return sorted(refs)


def any_ref_in_range(sorted_refs, va0, va1):
    """True if any referenced VA lies in the half-open interval [va0, va1)."""
    if not sorted_refs or va1 <= va0:
        return False
    i = bisect.bisect_left(sorted_refs, va0)
    return i < len(sorted_refs) and sorted_refs[i] < va1
