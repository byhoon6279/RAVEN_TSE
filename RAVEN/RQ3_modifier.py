import os
import shutil
import itertools
import argparse
from modifier import Modifier
import multiprocessing

pert_abbr = {
    "resource_change": "RC",
    "instruction_change": "IC",
    "jmp_overlay_back": "JOB",
    "content_shifting": "CS"
}


perts = list(pert_abbr.keys())
from itertools import combinations
all_combinations = {
    i: list(combinations(perts, i))
    for i in range(2, 5)
}

def retry_with_permutation(file_path, pert_list, rel_path, tmp_dir, log_file_path, max_attempts=10):
    permutations = list(itertools.permutations(pert_list))
    attempts = 0

    for perm in permutations:
        if attempts >= max_attempts:
            log_message(f" [ABORT] : {max_attempts}", log_file_path)
            break

        log_message(f"\n [RETRY] new order ({attempts+1}/{max_attempts}): {' + '.join(pert_abbr[p] for p in perm)}", log_file_path)
        try:
            prev_file = file_path
            applied_keys = []

            for pert in perm:
                applied_keys.append(pert_abbr[pert])
                short_name = f"{os.path.basename(file_path).split('|')[0]}|{'_'.join(applied_keys)}.exe"
                tmp_save_dir = os.path.join(tmp_dir, rel_path)
                os.makedirs(tmp_save_dir, exist_ok=True)
                tmp_save_path = os.path.join(tmp_save_dir, short_name)

                mod = Modifier(prev_file, tmp_save_dir)
                result_file = eval(f"mod.{pert}()")
                if not os.path.exists(result_file):
                    raise FileNotFoundError(f"{result_file} not found after applying {pert}")

                if result_file != tmp_save_path:
                    os.rename(result_file, tmp_save_path)
                    log_message(f" [renameing] {result_file} → {tmp_save_path}", log_file_path)

                prev_file = tmp_save_path

            log_message(f" [SUCCESS] : {' + '.join(pert_abbr[p] for p in perm)}", log_file_path)
            return prev_file 

        except Exception as e:
            log_message(f" [FAILURE] : {' + '.join(pert_abbr[p] for p in perm)} /: {str(e)}", log_file_path)
            attempts += 1

    log_message(f"💥 [FAILURE] Failed in all order", log_file_path)
    return None


def log_message(message, log_file_path):
    print(message)
    with open(log_file_path, "a", encoding="utf-8") as log_file:
        log_file.write(message + "\n")

def get_base_file_if_exists(base_save_dir, pert_chain, file_stub, rel_path, num):
    if rel_path == ".":
        rel_path = ""


    base_name = os.path.splitext(file_stub.split('|')[0])[0] 

    for i in range(len(pert_chain) - 1, 0, -1):
        partial_key = '+'.join([pert_abbr[p] for p in pert_chain[:i]])
        sub_dir = os.path.join(base_save_dir, f"{i}_perts", partial_key, rel_path)

        if i == 1:
            filename = f"{base_name}|{pert_abbr[pert_chain[0]]}.exe"
        else:
            filename = f"{base_name}|{'_'.join([pert_abbr[p] for p in pert_chain[:i]])}.exe"

        candidate_path = os.path.join(sub_dir, filename)
        print(f"[DEBUG] Discovery path candidates:: {candidate_path}")

        if os.path.exists(candidate_path):
            return candidate_path
    return None

def process_directory(directory, num, pert_list, comb_key, input_dir, base_save_dir, tmp_base_root, log_file_path, dry_run=False):
    pid = os.getpid()
    tmp_base_dir = os.path.join(tmp_base_root, f"tmp_{pid}")
    save_dir = os.path.join(base_save_dir, f"{num}_perts", comb_key)
    tmp_dir = os.path.join(tmp_base_dir, f"{num}_perts", comb_key)
    os.makedirs(tmp_dir, exist_ok=True)

    for root, _, files in os.walk(directory):
        for file in files:
            try:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(root, start=directory)
                if rel_path == ".":
                    rel_path = os.path.basename(directory)
                file_stub = os.path.basename(file)

                modified_file_keys = [pert_abbr[p] for p in pert_list]
                base_part = file_stub.split('|')[0].split('.')[0]

                final_save_dir = os.path.join(save_dir, rel_path)
                os.makedirs(final_save_dir, exist_ok=True)
                final_save_file = os.path.join(final_save_dir, f"{base_part}|{'_'.join(modified_file_keys)}.exe")

                log_message("\n" + "-" * 80, log_file_path)
                log_message(f"[num={num}] Variant target file: {full_path}", log_file_path)
                log_message(f"Selected variant combination: {' + '.join(modified_file_keys)}", log_file_path)

                if os.path.exists(final_save_file):
                    log_message(f" [SKIP ALL] Final result already exists → {final_save_file}", log_file_path)
                    continue

                prev_file = get_base_file_if_exists(base_save_dir, pert_list, file_stub, rel_path, num)
                start_index = 0
                if prev_file is None:
                    prev_file = full_path
                else:
                    log_message(f" [Reuse Existing Variations] Use previous results as inputs: {prev_file}", log_file_path)
                    applied = prev_file.split('|')[1].replace('.exe', '').split('_')
                    start_index = len(applied)

                applied_keys = [pert_abbr[p] for p in pert_list[:start_index]]
                for pert in pert_list[start_index:]:
                    file_name, file_ext = os.path.splitext(os.path.basename(prev_file))
                    base_part = file_name.split('|')[0]
                    applied_keys.append(pert_abbr[pert])

                    short_file_name = f"{base_part}|{'_'.join(applied_keys)}.exe"

                    tmp_save_dir = os.path.join(tmp_dir, rel_path)
                    os.makedirs(tmp_save_dir, exist_ok=True)

                    tmp_save_file = os.path.join(tmp_save_dir, f"{base_part}|{pert}{file_ext}")
                    short_tmp_save_file = os.path.join(tmp_save_dir, short_file_name)

                    log_message(f"   Current variant stage: {pert} ({pert_abbr[pert]})", log_file_path)
                    log_message(f"     └ input: {prev_file}", log_file_path)
                    log_message(f"     └ Temporary storage path: {tmp_save_file}", log_file_path)
                    log_message(f"     └ Final file name: {short_file_name}", log_file_path)

                    if not dry_run:
                        mod = Modifier(prev_file, tmp_save_dir)
                        result_file = eval(f"mod.{pert}()")
                        
                        if not os.path.isabs(result_file):
                            result_file = os.path.join(tmp_save_dir, result_file)
                        print("result_file : ", result_file)

                        if not os.path.exists(result_file):
                            log_message(f" [Error] Result failed: {result_file}", log_file_path)
                            continue

                        short_tmp_save_file = os.path.join(tmp_save_dir, short_file_name)
                        if result_file != short_tmp_save_file:
                            os.rename(result_file, short_tmp_save_file)
                            log_message(f" [Renameing] {result_file} → {short_tmp_save_file}", log_file_path)

                        log_message(f" [Complete] {pert} → {short_tmp_save_file}", log_file_path)
                        prev_file = short_tmp_save_file
                    else:
                        prev_file = short_tmp_save_file
                        log_message(f" [DRY-RUN] : {pert}", log_file_path)

                if not dry_run:
                    shutil.move(prev_file, final_save_file)
                    log_message(f" [Move] File move → {final_save_file}", log_file_path)
                else:
                    log_message(f" [DRY-RUN] Final file storage path: {final_save_file}", log_file_path)

            except Exception as e:
                log_message(f" [EXCEPTION] {file} : {str(e)}", log_file_path)
                
                if not dry_run:
                    retry_result = retry_with_permutation(
                        file_path=full_path,
                        pert_list=pert_list,
                        rel_path=rel_path,
                        tmp_dir=tmp_dir,
                        log_file_path=log_file_path,
                        max_attempts=5
                    )
                    if retry_result and os.path.exists(retry_result):
                        shutil.move(retry_result, final_save_file)
                        log_message(f" [Finish] → {final_save_file}", log_file_path)

                continue



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Batch perturbation script")
    parser.add_argument("-i", "--input", required=True, help="Input base directory")
    parser.add_argument("-o", "--output", help="Output directory (default: same as input)")
    parser.add_argument("-l", "--log", default="debug_output.txt", help="Log file path")
    parser.add_argument("--cleanup", action="store_true", default=True, help="Delete temporary directory after execution")
    parser.add_argument("-j", "--jobs", type=int, default=None, help="Number of parallel jobs (default: half of CPU cores)")
    parser.add_argument("--dry-run", action="store_true", help="Perform dry-run without actual file modifications")
    args = parser.parse_args()

    input_dir = args.input
    base_save_dir = args.output if args.output else input_dir
    os.makedirs(base_save_dir, exist_ok=True)
    tmp_base_root = os.path.join(os.path.dirname(os.path.abspath(input_dir)), "tmp", "perturbation_tmp")
    log_file_path = args.log
    cleanup_tmp = args.cleanup

    if os.path.exists(log_file_path):
        os.remove(log_file_path)

    if os.path.exists(tmp_base_root):
        shutil.rmtree(tmp_base_root)

    sub_dirs = [os.path.join(input_dir, d) for d in os.listdir(input_dir) if os.path.isdir(os.path.join(input_dir, d))]
    cpu_half = 1
    #cpu_half = max(1, int(multiprocessing.cpu_count()) - 12)
    num_workers = args.jobs if args.jobs else min(len(sub_dirs), cpu_half)

    for num in range(2, 5):
        for pert_list in all_combinations[num]:
            comb_key = '+'.join([pert_abbr[p] for p in pert_list])

            log_message(f"\n [START] Execute start: {comb_key}", log_file_path)

            with multiprocessing.Pool(num_workers) as pool:
                pool.starmap(
                    process_directory,
                    [
                        (
                            d,
                            num,
                            list(pert_list),
                            comb_key,
                            input_dir,
                            base_save_dir,
                            tmp_base_root,
                            log_file_path,
                            args.dry_run
                        )
                        for d in sub_dirs
                    ]
                )

            log_message(f"\n [DONE] : {comb_key}", log_file_path)

            if cleanup_tmp and os.path.exists(tmp_base_root):
                shutil.rmtree(tmp_base_root)
                log_message(f"\n [CLEANUP] : {tmp_base_root}\n", log_file_path)


    log_message("\n [ALL PERTURBATION COMBINATIONS DONE]", log_file_path)


    
#python RQ3_modifier.py -i ~/Dike_lable/label_test/ -o ~/Dike_lable/ -o ~/Dike_lable/RQ3

#python RQ3_modifier.py -i ~/Dike_label/label_test -o ~/Dike_label/RQ3 --dry-run