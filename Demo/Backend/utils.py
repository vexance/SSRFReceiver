import sqlite3
from re import match as regex_match
from uuid import uuid4
import datetime


DEMO_DB_PATH = '/tmp/demo/demo.db'
DEMO_PSK_PATH = '/tmp/demo/psk.txt'
DEMO_PARTNER_URL_PATH = '/tmp/demo/partner.txt'
DEMO_SELF_URL_PATH = '/tmp/demo/self.txt'
DEMO_TMP_DIR = '/tmp/demo'
DEMO_FILE_DIR = '/tmp/demo/docs/'
UUID_REGEX = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$'
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def query(query: str) -> list:
    conn = sqlite3.connect(DEMO_DB_PATH)
    cursor = conn.cursor()

    row = cursor.execute(query) # for our demo we won't (shouldn't :) ) ever really select more than one
    results = row.fetchall()

    conn.close()

    return results


def execute(sql: str) -> None:
    conn = sqlite3.connect(DEMO_DB_PATH)
    cursor = conn.cursor()

    cursor.execute(sql) # for our demo we won't (shouldn't :) ) ever really select more than one
    
    conn.commit()
    conn.close()


# Verify token hasn't expired; remove if necessary
def authenticate(table: str, token: str) -> bool:
    # No authorization levels; all-or-nothing
    if token == None: return False        

    # As always, input validation first :/
    token = token.strip()
    if not regex_match(UUID_REGEX, token): return False
    if table not in ['mgmt_auth', 'cp_auth', 'dp_auth']: return False
    
    ret = query(f'SELECT expiration FROM {table} WHERE token = "{token}";')

    # No matching auth token
    if len(ret) < 1: return False
    
    # first column of first row
    expiration = ret[0][0] 

    # Token that isn't expiring
    if expiration == "None" or expiration == None: return True

    # Check if we're beyond expiration; remove the row if so
    exp_datetime = datetime.datetime.strptime(expiration, TIME_FORMAT)
    if datetime.datetime.now() > exp_datetime: 
        invalidate_auth_token(table, token)
        return False

    # Otherwise we should be okay
    else: return True
    

# Create an auth token in the table
def generate_auth_token(table: str) -> str:

    if table not in ['mgmt_auth', 'cp_auth', 'dp_auth']: return False

    token = str(uuid4())

    exp = datetime.datetime.now() + datetime.timedelta(seconds=30)
    exp_str = exp.strftime(TIME_FORMAT)

    execute(f'INSERT INTO {table} VALUES ("{token}", "{exp_str}")')

    return token


# Remove an auth token from the table
def invalidate_auth_token(table: str, token: str) -> None:

    # Input validation
    if not regex_match(UUID_REGEX, token): return False
    if table not in ['mgmt_auth', 'cp_auth', 'dp_auth']: return False

    execute(f'DELETE FROM {table} where token = "{token}";')

    return None


# Set demo PSK
def set_demo_psk(psk: str) -> str:

    with open(DEMO_PSK_PATH, 'w') as file:
        file.write(f'{psk}\n')

    return psk


# Retrieve the PSK
def get_demo_psk() -> str:
    psk = None
    with open(DEMO_PSK_PATH, 'r') as file:
        lines = [line for line in file.readlines()]
        psk = ''.join(lines).strip()

    return psk


# Set partner URL
def set_demo_partner_host(host: str) -> str:

    with open(DEMO_PARTNER_URL_PATH, 'w') as file:
        file.write(f'{host}\n')
        
    return host


# Retrieve the partner URL
def get_demo_partner_host() -> str:
    host = None
    with open(DEMO_PARTNER_URL_PATH, 'r') as file:
        lines = [line for line in file.readlines()]
        host = ''.join(lines).strip()

    return host

# Set partner URL
def set_self_host(host: str) -> str:

    with open(DEMO_SELF_URL_PATH, 'w') as file:
        file.write(f'{host}\n')
        
    return host


# Retrieve the partner URL
def get_self_host() -> str:
    host = None
    with open(DEMO_SELF_URL_PATH, 'r') as file:
        lines = [line for line in file.readlines()]
        host = ''.join(lines).strip()

    return host
