import os
from datetime import datetime
import hashlib
import stat
import json
import pwd
import grp
import time
import logging

# folder to monitor
monitored_folder = 'sensitive-data'

# logging config
logging.basicConfig(
    filename='fim_system.log',
    filemode='a',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def get_file_hash(file_path):
    hash_obj = hashlib.sha256()
    try:
        with open(file_path, 'rb') as arquivo:
            while True:
                dados = arquivo.read(4096)
                if not dados:
                    break
                hash_obj.update(dados)

        return hash_obj.hexdigest()

    except PermissionError:
        print(f"Erro: Permissão negada - {file_path}")
        return None
    except Exception as e:
        print(f"Erro inesperado ao processar {file_path}: {e}")
        return None

def get_file_permissions(file_path):
    file_info = os.stat(file_path)
    permissions = stat.filemode(file_info.st_mode)
    return permissions

def get_file_owner_group(file_path):
    stat_info = os.stat(file_path)
    uid = stat_info.st_uid
    gid = stat_info.st_gid

    owner = pwd.getpwuid(uid).pw_name
    group = grp.getgrgid(gid).gr_name

    return owner, group

def get_file_info(file_path):
    file_name = os.path.basename(file_path)
    last_time_accessed = time.ctime(os.path.getatime(file_path))
    last_time_modified = time.ctime(os.path.getmtime(file_path))
    creation_time = time.ctime(os.path.getctime(file_path))
    file_hash = get_file_hash(file_path)
    file_permissions = get_file_permissions(file_path)
    owner, group = get_file_owner_group(file_path)


    file_info = {
        "file_name": file_name,
        "hash": file_hash,
        "permissions": file_permissions,
        "creation_time": creation_time,
        "last_time_accessed": last_time_accessed,
        "last_time_modified": last_time_modified,
        "owner": owner,
        "group": group
    }

    return file_info

def create_baseline_file():
    baseline_info = {
        "metadata": {
            "creation_time": datetime.now().ctime(),
            "monitored_folder": monitored_folder,
            "baseline_version": 1.0,
            "algorithm": "sha256",
            "OS": "Linux"
        },
        "files": {

        }
    }

    with open('baseline.json', 'w') as baseline_file:
        json.dump(baseline_info, baseline_file, indent=4)

def send_file_to_baseline(file_obj):
    with open('baseline.json', 'r') as baseline_file:
        original_data = json.load(baseline_file)

    if file_obj['file_name'] in original_data['files']:
        print(f'File already in baseline: {file_obj["file_name"]}')
        return False

    original_data['files'][file_obj['file_name']] = file_obj

    with open('baseline.json', 'w') as baseline_file:
        json.dump(original_data, baseline_file, indent=4)

    print(f'CREATE - {file_obj["file_name"]} | file added to baseline')
    return True

def check_hash(file_obj):
    with open('baseline.json', 'r') as baseline_file:
        original_data = json.load(baseline_file)

    try:
        baseline_file_hash = original_data['files'][file_obj['file_name']]['hash']
        current_file_hash = file_obj['hash']

        if baseline_file_hash != current_file_hash:
            return False # modified
        else:
            return True # intact
    except KeyError:
        return None # probably had its name changed

def generate_hash_alert(file_name):
    print(f'ALERT - {file_name} | file content modified (hashes dont match)')
    logging.critical(f'"{file_name}" | file content modified (hashes dont match)')

def check_name(file_obj):
    with open('baseline.json', 'r') as baseline_file:
        original_data = json.load(baseline_file)

    if file_obj['file_name'] in original_data['files']:
        return True  # file name unchanged

    for file_name, file_info in original_data['files'].items():
        hash_in_baseline = file_info['hash']
        file_hash = file_obj['hash']

        if hash_in_baseline == file_hash:
            return False  # ALERT file name changed

    return None  # file does not exist in baseline

def generate_file_name_alert(file_name):
    print(f'ALERT - {file_name} | file name modified (file name does not exist on baseline, but hash exist)')
    logging.critical(f'"{file_name}" | file name modified (file name does not exist on baseline, but hash exist)')

def check_permissions(file_obj):
    with open('baseline.json', 'r') as baseline_file:
        original_data = json.load(baseline_file)

    try:
        baseline_file_permissions = original_data['files'][file_obj['file_name']]['permissions']
        current_file_permissions = file_obj['permissions']
        if baseline_file_permissions == current_file_permissions:
            return True # INTACT - is the same permissions
        else:
            return False #CHANGED - is not the same permissions

    except KeyError:
        return None # probably had its name changed

def generate_file_permissions_alert(file_name):
    print(f'ALERT - {file_name} | file permissions modified (file permissions dont matches)')
    logging.critical(f'"{file_name}" | file permissions modified (file permissions dont matches)')

def check_owner_group(file_obj):
    with open('baseline.json', 'r') as baseline_file:
        original_data = json.load(baseline_file)

    try:
        response = ''
        baseline_file_owner = original_data['files'][file_obj['file_name']]['owner']
        baseline_file_group = original_data['files'][file_obj['file_name']]['group']

        current_file_owner = file_obj['owner']
        current_file_group = file_obj['group']

        if baseline_file_owner == current_file_owner and baseline_file_group == current_file_group:
            return False
        if baseline_file_owner != current_file_owner:
            response += 'Owner '
        if baseline_file_group != current_file_group:
            response += 'Group '

        return response

    except KeyError:
        return None # probably had its name changed

def generate_file_owner_group_alert(file_name, response):
    print(f'ALERT - {file_name} | file {response}Changed')
    logging.critical(f'"{file_name}" | file {response}Changed')

def check_new_file(file_obj):
    with open('baseline.json', 'r') as baseline_file:
        original_data = json.load(baseline_file)

    for file_name_in_baseline in original_data['files']:
        if file_obj['file_name'] == file_name_in_baseline:
            return False  # file exists in baseline

    return True  # file is new

def generate_new_file_alert(file_name):
    print(f'ALERT - {file_name} | new file created')
    logging.critical(f'"{file_name}" | new file created')

def check_deleted_file(monitored_folder):
    with open('baseline.json', 'r') as baseline_file:
        original_data = json.load(baseline_file)

    current_files = set(os.listdir(monitored_folder))
    deleted_files = []

    for file_name_in_baseline in original_data['files']:
        if file_name_in_baseline not in current_files:
            deleted_files.append(file_name_in_baseline)

    return deleted_files

def generate_deleted_file_alert(file_list):
    for file in file_list:
        print(f'ALERT - {file} | file deleted')
        logging.critical(f'"{file}" | file deleted')

def update_baseline_file():
    with open('baseline.json', 'r') as baseline_file:
        original_data = json.load(baseline_file)

    current_baseline_version = original_data['metadata']['baseline_version']
    new_baseline_version = current_baseline_version + 1
    original_data['metadata']['baseline_version'] = new_baseline_version

    with open('baseline.json', 'w') as baseline_file:
        json.dump(original_data, baseline_file, indent=4)

    return current_baseline_version, new_baseline_version

def generate_baseline_file_updated_warn(current_baseline_version, new_baseline_version):
    print(f'INFO - baseline.json version uptaded {current_baseline_version} -> {new_baseline_version}')
    logging.INFO(f'baseline.json version uptaded {current_baseline_version} -> {new_baseline_version}')



# creating baseline file, if not exists
if not os.path.exists('baseline.json'):
    create_baseline_file()


# Monitoring and Alerting
for file in os.listdir(monitored_folder):
    # check if file name has changed
    is_same_name = check_name(get_file_info(f'{monitored_folder}/{file}'))
    if not is_same_name and is_same_name != None:
        generate_file_name_alert(file)
    else:
        # check if some file was created
        exist_a_new_file = check_new_file(get_file_info(f'{monitored_folder}/{file}'))
        if exist_a_new_file:
            generate_new_file_alert(file)

            # send file metadata to baseline file
            send_file_to_baseline(get_file_info(f'{monitored_folder}/{file}'))
            current_baseline_version, new_baseline_version = update_baseline_file()
            if current_baseline_version and new_baseline_version:
                generate_baseline_file_updated_warn(current_baseline_version, new_baseline_version)

    # check if file permissions has changed
    # must run with root, to read any permissions without problems
    is_same_permissions = check_permissions(get_file_info(f'{monitored_folder}/{file}'))
    if not is_same_permissions and is_same_permissions != None:
        generate_file_permissions_alert(file)


    # check if file content has changed
    is_same_hash = check_hash(get_file_info(f'{monitored_folder}/{file}'))
    if not is_same_hash and is_same_hash != None:
        generate_hash_alert(file)


    # check if file owner or group has changed
    is_same_owner_and_group = check_owner_group(get_file_info(f'{monitored_folder}/{file}'))
    if is_same_owner_and_group and is_same_owner_and_group != None:
        generate_file_owner_group_alert(file, is_same_owner_and_group)


# check if some file was deleted
deleted_files = check_deleted_file(monitored_folder)
if deleted_files:
    generate_deleted_file_alert(deleted_files)











