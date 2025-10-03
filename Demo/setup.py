import sqlite3
import uuid
import argparse
import pathlib

import Backend.utils as utils

DEMO_PSK = None
NODE_PRIMARY = None
NODE_MGMT_TOKEN = None


def create_tables() -> None:
    conn = sqlite3.connect(utils.DEMO_DB_PATH)
    cursor = conn.cursor()

    # Cleanup in case something wonky is happening....
    cursor.execute('DROP TABLE IF EXISTS mgmt_auth;')
    cursor.execute('DROP TABLE IF EXISTS cp_auth;')
    cursor.execute('DROP TABLE IF EXISTS dp_auth;')
    cursor.execute('DROP TABLE IF EXISTS documents;')
    cursor.execute('DROP TABLE IF EXISTS flags;')

    # Management API
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mgmt_auth (
            token TEXT PRIMARY KEY,
            expiration TEXT NOT NULL
        );
    ''')

    # Control Plane
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cp_auth (
            token TEXT PRIMARY KEY,
            expiration TEXT NOT NULL
        );
    ''')

    # Data plane
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dp_auth (
            token TEXT PRIMARY KEY,
            expiration TEXT NOT NULL
        );
    ''')

    # Pre-defined documents for mock data
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS documents (
            doc_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            filename TEXT NOT NULL,
            extension TEXT NOT NULL,
            shared INTEGER NOT NULL CHECK (shared IN (0, 1))
        );
    ''')

    # Store the CTF flag
    cursor.execute('CREATE TABLE IF NOT EXISTS flags (flag_id TEXT PRIMARY KEY, valid INTEGER NOT NULL CHECK (valid IN (0, 1)));')

    conn.commit()
    conn.close()


def prep_node() -> None:
    conn = sqlite3.connect(utils.DEMO_DB_PATH)
    cursor = conn.cursor()

    global NODE_PRIMARY
    global DEMO_PSK
    global NODE_MGMT_TOKEN


    ########## References for the documents ##########

    if NODE_PRIMARY: # primary (entrypoint) node
        doc_id = str(uuid.uuid4())
        cursor.execute(f'INSERT INTO documents VALUES ("{doc_id}", "Blind SSRF Vulnerabilities", "Portswigger", "BlindSSRFPortswigger.pdf", "pdf", "1")')

        doc_id = str(uuid.uuid4())
        cursor.execute(f'INSERT INTO documents VALUES ("{doc_id}", "SSRF Overview", "OWASP", "ServerSideRequestForgeryOWASPFoundation.pdf", "pdf", "0");')

        doc_id = str(uuid.uuid4())
        cursor.execute(f'INSERT INTO documents VALUES ("{doc_id}", "SSRF Prevention Cheat Sheet", "OWASP", "SSRFCheatSheetOWASP.pdf", "pdf", "1");')

        doc_id = str(uuid.uuid4())
        cursor.execute(f'INSERT INTO documents VALUES ("{doc_id}", "SSRF Protection Redirect Bypass", "Leviathan Security Group", "SSRFProtectionRedirectBypasses.pdf", "pdf", "0");')


    else: # non-primary (target) node
        doc_id = str(uuid.uuid4())
        cursor.execute(f'INSERT INTO documents VALUES ("{doc_id}", "Steal EC2 Metadata Credentials via SSRF", "HackingTheCloud", "SSRFStealIMDSData.pdf", "pdf", "1");')

        doc_id = str(uuid.uuid4())
        cursor.execute(f'INSERT INTO documents VALUES ("{doc_id}", "A New Era of SSRF", "Orange Tsai", "URLParserSSRF.pdf", "pdf", "1");')

        doc_id = str(uuid.uuid4())
        with open(f'{utils.DEMO_FILE_DIR}/secret_file.txt', 'w') as file:
            ctf_flag = 'CTF{'+str(uuid.uuid4())+'}\n\n'
            file.write(ctf_flag)
        cursor.execute(f'INSERT INTO documents VALUES ("{doc_id}", "CTF Challenge", "@Vexance", "secret_file.txt", "txt", "0");')


    ########## Set auth tokens to the mgmt APIs ##########

    # no expiration necessary for the mgmt API
    cursor.execute(f'INSERT INTO mgmt_auth VALUES ("{NODE_MGMT_TOKEN}", "None");')


    ########## Set pre-shared key type thing for the two distributed nodes to determine  ##########
    with open(utils.DEMO_PSK_PATH, 'w') as file:
        file.write(f'{DEMO_PSK}')


    print('Completed demo database and config setup')
    
    conn.commit()
    conn.close()


def do_setup(psk: str | None):

    global NODE_MGMT_TOKEN
    global NODE_PRIMARY
    global DEMO_PSK
    
    NODE_PRIMARY = (psk == None)
    DEMO_PSK = str(uuid.uuid4()) if NODE_PRIMARY else psk

    NODE_MGMT_TOKEN = str(uuid.uuid4())

    try:
        pathlib.Path(utils.DEMO_FILE_DIR).mkdir(parents=True, exist_ok=True)
        pathlib.Path(utils.DEMO_DB_PATH).touch(exist_ok=True)
        pathlib.Path(utils.DEMO_PARTNER_URL_PATH).touch(exist_ok=True)
        pathlib.Path(utils.DEMO_SELF_URL_PATH).touch(exist_ok=True)
        pathlib.Path(utils.DEMO_PSK_PATH).touch(exist_ok=True)

        print('Prepped demo temp directories and files')

    except Exception as err:
        print('Error creating demo temp directories / files')
        exit()

    if NODE_PRIMARY:
        print(f'  > Entrypoint node management API token: {NODE_MGMT_TOKEN}')
        print(f'  > Partner node pre-shared key (--psk): {DEMO_PSK}')


    create_tables()
    prep_node()


if __name__ == '__main__':
    parser = argparse.ArgumentParser('demo_setup.py', 'Setup for demo')
    parser.add_argument('--psk', type=str, required=False, default=None, help='Set the PSK for the secondary node launched')
    args = parser.parse_args()

    do_setup(args.psk)

