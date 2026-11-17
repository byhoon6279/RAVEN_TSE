import os

def semantic_nop(args):
    sample, root, save_dir = args
    input_filepath = os.path.join(root, sample)

    os.system(f'python ./modifier/MalGuise/src/utils/pe_patcher/get_call_addr.py -f "{input_filepath}"')
    os.system(f'python ./modifier/MalGuise/src/utils/pe_patcher/patcher_custom.py -f "{input_filepath}"')

    os.system(f'rm -rf "{input_filepath}.i64"')
    os.system(f'rm -rf "{input_filepath}.txt"')

    output_filename = sample.replace('.exe', '_semantic_nop.exe')
    output_filepath = os.path.join(save_dir, output_filename)

    os.system(f'mv "{input_filepath.replace(".exe", "_semantic_nop.exe")}" "{output_filepath}"')

    print(f"semantic_nop complete: {output_filepath}")
