import os
from datetime import datetime
import hashlib
import stat
import json
import pwd
import grp
import time


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

def get_file_info(file_path):
    stat_info = os.stat(file_path)
    uid = stat_info.st_uid
    gid = stat_info.st_gid

    file_name = os.path.basename(file_path)
    last_time_accessed = time.ctime(os.path.getatime(file_path))
    last_time_modified = time.ctime(os.path.getmtime(file_path))
    creation_time = time.ctime(os.path.getctime(file_path))
    file_hash = get_file_hash(file_path)
    file_permissions = get_file_permissions(file_path)
    owner = pwd.getpwuid(uid).pw_name
    group = grp.getgrgid(gid).gr_name


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
            "algorithm": "sha256"
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

    print(f'File added to baseline: {file_obj["file_name"]}')
    return True

def check_hash(file_obj):
    with open('baseline.json', 'r') as baseline_file:
        original_data = json.load(baseline_file)

    baseline_file_hash = original_data['files'][file_obj['file_name']]['hash']
    current_file_hash = file_obj['hash']

    if baseline_file_hash != current_file_hash:
        return False # modified
    else:
        return True # intact

def generate_hash_alert(file_name):
    print(f'ALERT - file: {file_name} modified (hashes dont match)')

def check_name(file_obj):
    with open('baseline.json', 'r') as baseline_file:
        original_data = json.load(baseline_file)

    """
    TODO (2 dias já nesse projeto, achei q ia ser facil)
    nessa parte eu tenho que comparar os nomes dos arquivos para ver se mudou o nome
    porem ao mudar o nome do arquivo, o hash continua o msm,
    logo tem que fazer isso:
    1- verificar se o file_obj['file_name'] existe na baseline
        se existir, OTIMO -> quer dizer que nada foi alterado
        se nao existir -> verificar a hash do file_obj['hash'] com todas as hashes da baseline
            se existir uma hash na baseline que de match com file_obj['hash'] -> ALERT arquivo X teve o nome mudado
            se nao existir nenhuma hash que de match -> arquivo nao existe
    """



monitored_folder = 'sensitive-data/'
file_path = f'{monitored_folder}test.txt'


# creating baseline file, if not exists
if not os.path.exists('baseline.json'):
    create_baseline_file()

# send file metadata to baseline file
#send_file_to_baseline(get_file_info(file_path))

# checks if the current hash matches the baseline hash, name (comparando hash e nome), permissions, owner and group
# hash file_test.txt: 55f8718109829bf506b09d8af615b9f107a266e19f7a311039d1035f180b22d4
# hash test.txt:      55f8718109829bf506b09d8af615b9f107a266e19f7a311039d1035f180b22d4

# Monitoring and Alerting
for file in os.listdir('sensitive-data'):
    is_same_hash = check_hash(get_file_info(f'sensitive-data/{file}'))

    if not is_same_hash:
        generate_hash_alert(file)








