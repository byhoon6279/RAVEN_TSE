import pefile
from iced_x86 import *
from pe_library import *
from iced_x86 import *
from typing import Union, Dict, Sequence 
from types import ModuleType
import binascii
from keystone import *
import pandas as pd
import shutil
from identify import identify
import pickle
from functools import lru_cache
from common_function import *
import multiprocessing
from xref import collect_referenced_vas, any_ref_in_range

MUTATE_OVERLAY = False

old_rawPointer = 0
modified_section_data = {}

def modify_overlay_worker(queue, data, function_list):
    try:
        result = modify_data_sections("overlay", data, function_list)
        queue.put(result)
    except Exception as e:
        print("Worker Exception:", e)
        queue.put(None)
        
import signal

class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException()

def safe_modify_overlay_with_timeout(overlay_data, function_list, timeout_sec=300):
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout_sec)
    try:
        result = modify_data_sections("overlay", overlay_data, function_list)
        signal.alarm(0) 
        return result
    except TimeoutException:
        print(f"[!] Overlay processing timed out after {timeout_sec} seconds. Skipping modification.")
        return overlay_data
    except Exception as e:
        print(f"[!] Overlay processing failed: {e}")
        return overlay_data


@lru_cache(maxsize=None)
def get_imported_functions(pe):
    imported_functions = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            for imp in entry.imports:
                if imp.name:
                    function_name = imp.name.decode('utf-8')
                    offset = imp.address - pe.OPTIONAL_HEADER.ImageBase
                    imported_functions.append(function_name)
    return imported_functions

@lru_cache(maxsize=None)
def get_exported_functions(pe):
    exported_functions = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                function_name = exp.name.decode('utf-8')
                offset = exp.address - pe.OPTIONAL_HEADER.ImageBase

                exported_functions.append(function_name)
    return exported_functions

@lru_cache(maxsize=None)
def is_printable(b):
    return 32 <= b < 127

def is_utf16le_string(data, start):
    """ Checking UTF-16 LE String"""
    length = len(data)
    for i in range(start, length, 2):
        if i + 1 >= length or data[i+1] != 0x00:
            return False
        if data[i] == 0x00 and data[i+1] == 0x00:  # End of string
            break
    return True

def decode_utf16le_string(data, start):
    """UTF-16 LE 문자열을 디코딩"""
    end = start
    utf16le_str = []
    while end < len(data) and data[end] != 0x00:
        utf16le_str.append(chr(data[end]))
        end += 2  # 2바이트씩 증가
    return ''.join(utf16le_str), end + 2  # Null string



def modify_data_sections(section_name = None, data = None , function_list = None, section_base_va = None, sorted_refs = None):
    modified_data = bytearray(data)
    i = 0
    letters_set = (string.ascii_lowercase + string.digits) * 5

    with open('./api.pickle', "rb") as fw:
        api_list = pickle.load(fw)
        
    while i < len(modified_data):
        try:
            if is_printable(modified_data[i]):
                start = i
                # Check UTF-16 LE String
                if is_utf16le_string(modified_data, start):
                    utf16_text, end = decode_utf16le_string(modified_data, start)

                    if section_base_va is not None and any_ref_in_range(
                            sorted_refs, section_base_va + start, section_base_va + end):
                        i = end
                        continue

                    if  (
                            (re.findall(r'(%[-+0# ]*\d*(?:\.\d+)?[diuoxXfFeEgGaAcCsSpnYZPRTUVWzZ])', utf16_text)) 
                            or 
                            (
                                re.findall(r'\b[a-zA-Z0-9][a-zA-Z0-9\s\.,;:!?\'"()\[\]{}<>-]{5,}\b', utf16_text)  
                                and not re.findall(r'[-+#/\?^@\"※~ㆍ』;*%\{\}\<\>‘|\[\]`\'…》\”\“\’·$=_:&]', utf16_text)
                            ) 
                            or 
                            (
                                '\\' in utf16_text 
                                and len(utf16_text) > 5 
                                and not re.findall(r'[-+,#/\?^@\"※~ㆍ!』;*%\{\}\<\>‘|\(\)\[\]`\'…》\”\“\’·$=_:.&]', utf16_text) 
                                and not re.findall(r'[0-9]+', utf16_text)
                            )
                            or 
                            (
                                re.findall(r'(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}', utf16_text) 
                                and not re.findall(r'<[^>]+>', utf16_text) 
                                and not re.findall(r'=', utf16_text)
                            )
                            or
                            (
                                re.findall(r'^(?=.*[a-zA-Z])(?=.*[()._])[a-zA-Z()._]+$',utf16_text)
                                #re.findall(r'^[a-zA-Z()._]+$',utf16_text) and len(utf16_text) >= 5
                            )
                        ):
                        
                        if not re.findall(r'(?i)^[a-z\s]+$', utf16_text):                      
                            if len(modified_data[start:end]) <= len(letters_set):
                                random_list = random.sample(letters_set, int(len(modified_data[start:end])/2))

                            else:
                                random_list = random.choices(letters_set, k=int(len(modified_data[start:end])/2))

                            modified_text = ''.join(random_list)
                            modified_utf16_data = bytearray(modified_text.encode('utf-16le'))                            
                            
                        elif ' ' in utf16_text and len(re.findall(r' ', utf16_text)) >= 3:                            
                            utf16_space_chacker = utf16_text.split()
                            space_cnt = 0
                            
                            for chunk in utf16_space_chacker:
                                if chunk[0].isupper():
                                    space_cnt+=1
                            
                            if space_cnt == len(utf16_space_chacker) or int(len(utf16_space_chacker)/2) <= space_cnt:
                                
                                if utf16_text.isupper():
                                    #new_text = text + '.dll'
                                    modified_text = utf16_text.lower().encode('utf-16le')
                                else:
                                    #new_text = text + '.dll'
                                    modified_text = utf16_text.upper().encode('utf-16le')

                                modiied_utf16_data = bytearray(modified_text+b'\x00\x00')
                                
                            else:
                                modified_utf16_data = modified_data[start:end]
                        else:                            
                            if (utf16_text[0].isupper() and utf16_text[1:].islower()) or (utf16_text.islower()):
                                modified_text = utf16_text.upper().encode('utf-16le')
                                modified_text= bytearray(modified_text+b'\x00\x00')
                                
                            else: 
                                modified_text = modified_data[start:end]
                                
                            modified_utf16_data = modified_text

                    else:
                        # Using original data 
                        
                        if len(utf16_text) > 5 and '\\x' not in utf16_text.encode('ascii', 'ignore').decode('utf-8') and '-' not in utf16_text:
                            
                            if utf16_text in api_list:

                                modified_text = modified_data[start:end]
                                modified_text = bytes(modified_text)
                                modified_data[start:end] = modified_text
                                i=end
                                continue
                                
                            if len(modified_data[start:end]) <= len(letters_set):
                                random_list = random.sample(letters_set, int(len(modified_data[start:end])/2))

                            else:
                                random_list = random.choices(letters_set, k=int(len(modified_data[start:end])/2))

                            modified_text = ''.join(random_list)
                            modified_utf16_data = bytearray(modified_text.encode('utf-16le'))
                            
                        else:
                            modified_utf16_data = modified_data[start:end]
                                      
                    modified_data[start:end] = modified_utf16_data
                    i = end
                    continue
                
                
                while i < len(modified_data) and is_printable(modified_data[i]):
                    i += 1
                    
                end = i

                # Code-reference guard (see UTF-16 path above).
                if section_base_va is not None and any_ref_in_range(
                        sorted_refs, section_base_va + start, section_base_va + end):
                    i = end
                    continue

                text = modified_data[start:end].decode('ascii', errors='ignore')
                txt_type = identify.tags_from_filename(text.strip())

                if ('.dll' in text.lower() and 'binary' in txt_type) or ('.dll' in text.lower()):
                    new_text=''
                    ori_text = text
                    text = text.split('.')#[0]
                    
                    if len(text) == 2 :
                        if len(text[-1].lower().replace('dll',''))==0:
                            new_text = text[0] + '.dll'
                        
                        else:
                            for idx,content in enumerate(text):
                                if idx==0:
                                    new_text+=content
                                if 'dll' in content.lower():
                                    new_text= new_text +'.'+content                           
                                            
                    if text[0].isupper():
                        modified_text = new_text.lower().encode('ascii')
                    else:
                        modified_text = new_text.upper().encode('ascii')
                        
                    modified_data[start:end] = modified_text
                    i = end
                    continue
                    
                                    
                elif (
                        # 'image', 'plain-text', 'audio', 'html' string in txt_type case
                        'image' in txt_type or 'plain-text' in txt_type or 'audio' in txt_type or 'html' in txt_type 

                        # Or if a format string (%d, %f, etc.) is included, or if it contains 5 or more alphanumeric characters and a specific symbol
                        or (
                            re.findall(r'(%[-+0# ]*\d*(?:\.\d+)?[diuoxXfFeEgGaAcCsSpnYZPRTUVWzZ])', text)
                            or 
                            (  # If alphanumeric characters and certain symbols are more than 5 characters
                                re.findall(r'\b[a-zA-Z0-9][a-zA-Z0-9\s\.,;:!?\'"()\[\]{}<>-]{5,}\b', text) 
                                and not re.findall(r'[-+#/\?^@\"※~ㆍ』;*%\{\}\<\>‘|\[\]`\'…》\”\“\’·$=:&]', text) 
                            )
                        )

                        #if it contains a (\), is longer than 5 characters long, and does not contain specific special characters and numbers
                        or (
                            '\\' in text 
                            and len(text) > 5 
                            and not re.findall(r'[-+,#/\?^@\"※~ㆍ!』;*%\{\}\<\>‘|\(\)\[\]`\'…》\”\“\’·$=_:.&]', text) 
                            and not re.findall(r'[0-9]+', text)
                        )

                        # or text containing domain patterns
                        or (
                            re.findall(r'(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}', text)  # domain pattern (ex: example.com)
                            and not re.findall(r'<[^>]+>', text)  # checking no HTML tags
                            and not re.findall(r'=', text)  # checking no equal sign
                        )
                    ):
        
                    format_specifier = ''      
                    spel_upper_check = 0
                
                    if text in api_list:
                        modified_text = modified_data[start:end]
                        modified_text = bytes(modified_text)
                        modified_data[start:end] = modified_text
                        i = end
                        continue
                        
                    if  (
                            '\\' in text 
                            and len(text) > 5 
                            and not re.findall(r'[-+,#/\?^@\"※~ㆍ!』;*%\{\}\<\>‘|\(\)\[\]`\'…》\”\“\’·$=_:.&]', text)
                            and not re.findall(r'[0-9]+', text)
                        )  or (
                            re.findall(r'(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}', text)  # domain pattern (ex: example.com)
                            and not re.findall(r'<[^>]+>', text)  # checking no HTEML tags
                            and not re.findall(r'=', text)  # checking no equal sign
                        ):
                            if len(text) <= len(letters_set):
                                random_list = random.sample(letters_set, len(text))
                            else:
                                random_list = random.choices(letters_set, k=len(text))

                            modified_text = ''.join(random_list)
                            modified_text = bytes(modified_text, 'utf-8')
                            modified_data[start:end] = modified_text
                            i = end
                            continue

                    if len(text)>5 and re.findall(r'(%[-+0# ]*\d*(?:\.\d+)?[diuoxXfFeEgGaAcCsSpnYZPRTUVWzZ%])',text):
                        format_specifier = re.findall(r'(%[-+0# ]*\d*(?:\.\d+)?[diuoxXfFeEgGaAcCsSpnYZPRTUVWzZ%])',text)
                        split_texts = re.split(r'(%[-+0# ]*\d*(?:\.\d+)?[diuoxXfFeEgGaAcCsSpnYZPRTUVWzZ%])',text)

                        modified_text = ''
                        for idx, split_text in enumerate(split_texts):
                            if '%' not in split_text:
                                if len(split_text) <= len(letters_set):
                                    random_list = random.sample(letters_set, len(split_text))
                                else:
                                    random_list = random.choices(letters_set, k=len(split_text))
                                    
                                if idx==0:    
                                    modified_text = ''.join(random_list)
                                else:
                                    modified_text += ''.join(random_list)

                            else:
                                modified_text += split_text
                        modified_text = bytes(modified_text, 'utf-8')
                        modified_data[start:end] = modified_text
                        i = end
                        continue
                        
                    else:
                        if 'overlay'in section_name and len(text)>5 and re.findall(r'(?i)^[a-z0-9]+$',text):
                            if len(text) <= len(letters_set):
                                random_list = random.sample(letters_set, len(text))
                            else:
                                random_list = random.choices(letters_set, k=len(text))

                            modified_text = ''.join(random_list)
                            modified_text = bytes(modified_text, 'utf-8')

                            modified_data[start:end] = modified_text
                            i = end
                            continue
                        
                        
                        spel_upper_check = sum(1 for char in text if char.isupper())
                        if (len(text)>=10 and '0x' not in text and ' ' in text) or (re.fullmatch(r'^[A-Z].*[a-z]$', text) and '%' not in text and ' ' in text) or (len(text)>=5 and '%' not in text and not re.findall(r'[-+,#/\?^@\"※~ㆍ!』;*%\{\}\<\>‘|\(\)\[\]`\'…》\”\“\’·$=_:.&]', text) and '0x' not in text and spel_upper_check<=1):
                            
                            if len(text) <= len(letters_set):
                                random_list = random.sample(letters_set, len(text))
                            else:
                                random_list = random.choices(letters_set, k=len(text))

                            modified_text = ''.join(random_list)
                            modified_text = bytes(modified_text, 'utf-8')
                            modified_data[start:end] = modified_text
                            i = end
                            continue
                        
                        if ('.reloc' not in section_name and (len(text)>=5 and '%' not in text and not re.findall(r'[-+,#/\?^@\"※~ㆍ!』;*%\{\}\<\>‘|\(\)\[\]`\'…》\”\“\’·$=_:.&]', text) and '0x' not in text)):
                            if int(len(text))>=spel_upper_check:
                                modified_text = text.lower().encode('ascii')
                                
                            else:
                                modified_text = text.upper().encode('ascii')
                                
                            modified_data[start:end] = modified_text
                            i = end
                            continue
                               
                        modified_text = modified_data[start:end]
                        modified_text = bytes(modified_text)
                        modified_data[start:end] = modified_text
                        i = end
                        continue      
                        
                else:
                    modified_text = modified_data[start:end]
                    modified_text = bytes(modified_text)
                    modified_data[start:end] = modified_text
                    i = end
                    continue
            else:
                i += 1

        except Exception as e:
            i += 1 
            continue

    return bytes(modified_data)



@lru_cache(maxsize=None)
def change_resource_case(file_path, output_path):
    print(file_path)
    pe = pefile.PE(file_path)
    pe_data = open(file_path, "rb").read()

    image_base = pe.OPTIONAL_HEADER.ImageBase
    sorted_refs = collect_referenced_vas(pe, pe_data)
    
    import_function = get_imported_functions(pe)
    export_function = get_exported_functions(pe)

    modified_data = bytearray()

    function_list = import_function + export_function

    try:
        for section_idx, section in enumerate(pe.sections):
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00').lower()

            if section_idx == 0:
                modified_data += pe.header
        
            if ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']) or \
                (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'])) and \
               not ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']) and \
                    (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) and \
                    not (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'])) and\
                not section_name.startswith(('upx', '.upx')):

                section_start = section.PointerToRawData
                section_end = section_start + section.SizeOfRawData

                section_data = pe_data[section_start:section_end]
                modified_rdata = modify_data_sections(section.Name.decode('utf-8', errors='ignore').strip('\x00'), section_data, function_list, image_base + section.VirtualAddress, sorted_refs)
                
                modified_data += modified_rdata

            else:
                section_start = section.PointerToRawData
                section_end = section_start + section.SizeOfRawData

                section_data = pe_data[section_start:section_end]
                modified_data += section_data

        # checking overlay region
        last_section = list(pe.sections)[-1]
        last_section_end = last_section.PointerToRawData + last_section.SizeOfRawData
        if len(pe_data) > last_section_end:
            overlay_data = pe_data[last_section_end:]
            if MUTATE_OVERLAY:
                modified_overlay_data = safe_modify_overlay_with_timeout(overlay_data, function_list)
            else:
                modified_overlay_data = overlay_data
            modified_data += modified_overlay_data

    except Exception as e:
        print(f"Error in processing PE file: {str(e)}")

    output_file = os.path.join(output_path, os.path.basename(file_path)).replace('.exe', '|resource_change.exe')
    with open(output_file, "wb") as f:
        f.write(modified_data)

    pe.close()
       
def resource_change(args):
    sample, root, save_dir = args
    file_path = os.path.join(root, sample)
    output_filename = sample.replace('.exe', '|resource_change.exe')
    
    try:
        change_resource_case(file_path, save_dir)
        print(f"Resource case changed for {sample}\n")
        
    except pefile.PEFormatError:
        pass     
    
    return output_filename

def main():
    sample = "putty.exe"
    root = "./"
    save_dir = "./temp/"

    process_sample((sample, root, save_dir))
 
