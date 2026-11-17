import lief
import random

def pert_optional_header(fbytes):
    random.seed(None)
    fparsed = lief.parse(fbytes)
    
    temp1 = [fparsed.optional_header.sizeof_uninitialized_data,
    fparsed.optional_header.sizeof_initialized_data,
    fparsed.optional_header.baseof_code,
    fparsed.optional_header.checksum, 
    fparsed.optional_header.sizeof_heap_reserve,
    fparsed.optional_header.sizeof_stack_commit,
    fparsed.optional_header.win32_version_value,

    fparsed.optional_header.major_linker_version,
    fparsed.optional_header.major_image_version,
    fparsed.optional_header.major_operating_system_version,
    fparsed.optional_header.major_subsystem_version,
    fparsed.optional_header.minor_image_version,
    fparsed.optional_header.minor_linker_version,
    fparsed.optional_header.minor_operating_system_version,
    fparsed.optional_header.minor_subsystem_version]
     
    idx = random.randrange(len(temp1))
    if idx < 6:
        temp1[idx] = random.randrange(0,2**32)
    else:
        temp1[idx] = random.randrange(0,2**8)
    
    safe_types = ('DEBUG', 'CERTIFICATE', 'ARCHITECTURE', 'GLOBAL_PTR')
    inert_dirs = [d for d in fparsed.data_directories
                  if any(s in str(d.type).upper() for s in safe_types)]
    if inert_dirs:
        target = random.choice(inert_dirs)
        target.rva = random.randrange(0, 2**32)
        target.size = random.randrange(0, 2**32)

    return fparsed
