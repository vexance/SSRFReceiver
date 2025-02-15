import bottle
from re import match as regex_match
import requests
from hashlib import sha256, sha384
import utils
import datetime
import asyncio
import threading

AUTH_TABLE = 'cp_auth'
MGMT_AUTH_TABLE = 'mgmt_auth'
control_plane = bottle.Bottle()


# Setup background thread for async request handling
background_event_loop = asyncio.new_event_loop()

def start_loop():
    asyncio.set_event_loop(background_event_loop)
    background_event_loop.run_forever()

threading.Thread(target=start_loop, daemon=True).start()

async def async_do_request(method: str, url: str, headers: str, req_body: str):
    # Wait 2 seconds to simulate something more realistic
    await asyncio.sleep(2)
    
    try:
        ret = requests.request(method=method, url=url, headers=headers, json=req_body, allow_redirects=True)

        with open(f'{utils.DEMO_TMP_DIR}/asyncreq_debug.txt', 'w') as file:

            file.write(f'Request headers: {ret.request.headers}\n\n')
            file.write(f'Request body: {ret.request.body}\n\n')


            file.write(f'Response status: {ret.status_code}\n\n')
            file.write(f'Response Headers: {ret.headers}\n\n')
            file.write(f'Response Body: {ret.content}\n\n')

    except Exception as err:
        pass # ¯\_(ツ)_/¯
        

    return None


@control_plane.route('/negotiate', method='POST')
def negotiate_token() -> dict:
    if bottle.request.get_header('Content-Type') != 'application/json':
        bottle.response.status = 415  # Unsupported Media Type
        return {"error": 'Content-Type must be application/json'}

    # Negotiate will use the PSK to determine validity
    request_psk_hash = bottle.request.get_header('Authorization')
    stored_psk = utils.get_demo_psk()
    stored_psk_hash = sha256(stored_psk.encode('utf-8')).hexdigest()

    if request_psk_hash != stored_psk_hash:
        bottle.response.status = 403
        return {'error': 'Authentication failed'}
    

    token = utils.generate_auth_token(AUTH_TABLE)

    return {'token': token}



@control_plane.route('/documents/public', method='POST')
def list_public_docs() -> dict:
    authN = utils.authenticate(AUTH_TABLE, bottle.request.get_header('Authorization'))
    if authN == False:
        bottle.response.status = 403
        return {'error': 'Authentication failed'}
    
    ret = utils.query('SELECT doc_id FROM documents WHERE shared = "1";')

    content = [{'DocumentId': row[0]} for row in ret]
    return {'Documents': content, 'QueryFinish': str(datetime.datetime.now())}



@control_plane.route('/documents/public/<id>', method='POST')
def get_public_doc(doc_id: str) -> dict:
    authN = utils.authenticate(AUTH_TABLE, bottle.request.get_header('Authorization'))
    if authN == False:
        bottle.response.status = 403
        return {'error': 'Authentication failed'}
    
    # Document id input validation 
    if not regex_match(utils.UUID_REGEX, doc_id):
        bottle.response.status = 400
        return {'error': 'Invalid document identifier'}
    
    ret = utils.query(f'SELECT * FROM documents WHERE doc_id = "{doc_id}" AND shared = "1";')

    # Suppose there _could_ be more than one, but we don't really care enough to handle that :.|
    if len(ret) < 1:
        bottle.response.status = 404
        return {'error': 'Document not found'}


    content = []
    for row in ret:
        obj = {
            'DocumentId': row[0],
            'Title': row[1],
            'Author': row[2],
            'FileType': row[4], # skip filepath & shared
            'Shared': (row[5] == 1 or row[5] == "1"),
        }
        content.append(obj)
    
    if len(content) != 1:
        bottle.response.status = 400
        return {'error': 'Something went wrong...'}

    return {'DocumentMetadata': content[0], 'QueryFinish': str(datetime.datetime.now())}



# Intent is to have user perform a redirect
@control_plane.route('/documents', method='GET')
def list_all_docs() -> dict:
    auth_token = bottle.request.get_header('Authorization').strip()
    authN = utils.authenticate(AUTH_TABLE, auth_token)
    if authN == True:
        bottle.response.status = 403
        return {'error': 'You are not authorized to perform this action. Privileged control plane token is required.'}
    else:
        dhash = sha256(sha384(str(auth_token).encode('utf-8')).hexdigest().encode('utf-8')).hexdigest()
        psk = utils.get_demo_psk()
        dhash_psk = sha256(sha384(psk.encode('utf-8')).hexdigest().encode('utf-8')).hexdigest()
        
        if dhash != dhash_psk:
            bottle.response.status = 403
            return {'error': 'Authentication failed.'}
    
    ret = utils.query('SELECT doc_id FROM documents')

    content = [{'DocumentId': row[0]} for row in ret]
    return {'Documents': content}



# Intent is to have the user perform a redirect
@control_plane.route('/documents/<doc_id>', method='GET')
def get_doc(doc_id: str) -> dict:
    auth_token = bottle.request.get_header('Authorization').strip()
    authN = utils.authenticate(AUTH_TABLE, auth_token)
    if authN == True:
        bottle.response.status = 403
        return {'error': 'You are not authorized to perform this action. Privileged control plane token is required.'}
    else:
        dhash = sha256(sha384(str(auth_token).encode('utf-8')).hexdigest().encode('utf-8')).hexdigest()
        psk = utils.get_demo_psk()
        dhash_psk = sha256(sha384(psk.encode('utf-8')).hexdigest().encode('utf-8')).hexdigest()
        
        if dhash != dhash_psk:
            bottle.response.status = 403
            return {'error': 'Authentication failed.'}
    
    # Document id input validation 
    if not regex_match(utils.UUID_REGEX, doc_id):
        bottle.response.status = 400
        return {'error': 'Invalid document identifier'}
    
    ret = utils.query(f'SELECT * FROM documents WHERE doc_id = "{doc_id}"')

    # Suppose there _could_ be more than one, but we don't really care enough to handle that :.|
    if len(ret) < 1:
        bottle.response.status = 404
        return {'error': 'Document not found'}


    content = []
    for row in ret:
        obj = {
            'DocumentId': row[0],
            'Title': row[1],
            'Author': row[2],
            'FileType': row[4], # skip filepath & shared
            'Shared': (row[5] == 1 or row[5] == "1"),
            'DownloadReference': sha256(sha256(str(row[0]).encode('utf-8')).hexdigest().encode('utf-8')).hexdigest()
        }
        content.append(obj)
    
    if len(content) != 1:
        bottle.response.status = 400
        return {'error': 'Something went wrong...'}

    return content[0]


# Receive inbound request, issues callbak to /syn/ack
@control_plane.route('/synchronize', method='POST')
def syn() -> dict:
    auth_token = bottle.request.get_header('Authorization').strip()
    authN = utils.authenticate(AUTH_TABLE, auth_token)
    if authN == True:
        bottle.response.status = 403
        return {'error': 'You are not authorized to perform this action. Privileged control plane token is required.'}
    else:
        psk = utils.get_demo_psk()
        dhash_psk = sha256(sha384(psk.encode('utf-8')).hexdigest().encode('utf-8')).hexdigest()
        
        if auth_token != dhash_psk:
            print(f'inbound token: {auth_token}')
            print(f'expected hash: {dhash_psk}')
            bottle.response.status = 403
            return {'error': 'Authentication failed.'}
    
    if bottle.request.get_header('Content-Type') != 'application/json':
        bottle.response.status = 415  # Unsupported Media Type
        return {"error": 'Content-Type must be application/json'}
    
    body = bottle.request.json
    syn_id = body.get('SynchronizationId', None)
    callback_address = body.get('CallbackAddress', None)

    if syn_id == None or callback_address == None:
        bottle.response.status = 400
        return {'error': 'Invalid request format'}

    # sync id input validation 
    if not regex_match(utils.UUID_REGEX, syn_id):
        bottle.response.status = 400
        return {'error': 'Invalid synchronization identifier'}
    
    # START ASYNC JOB TO ISSUE ACK REQUEST
    try:
        req_body = {'AcknowledgementMessage': f'Acknowledging synchronization request {syn_id}'}
        req_headers = {'Content-Type': 'application/json', 'Authorization': sha256(auth_token.encode('utf-8')).hexdigest()}
        callback = f'{callback_address}/ctrl/synchronize/{syn_id}/acknowledgement'
        method = 'POST'

        asyncio.run_coroutine_threadsafe(async_do_request(method=method, url=callback, headers=req_headers, req_body=req_body), background_event_loop)

    except Exception as err:
        bottle.response.status = 500
        return {'error': 'An internal error occured.'}

    bottle.response.status = 202



@control_plane.route('/synchronize/<syn_id>/acknowledgement', method='POST')
def syn_ack(syn_id: str) -> dict:
    auth_token = bottle.request.get_header('Authorization').strip()
    authN = utils.authenticate(AUTH_TABLE, auth_token)
    if authN == True:
        bottle.response.status = 403
        return {'error': 'You are not authorized to perform this action. Privileged control plane token is required.'}
    else:
        psk = utils.get_demo_psk()
        dhash_psk = sha256(sha384(psk.encode('utf-8')).hexdigest().encode('utf-8')).hexdigest()
        thash_psk = sha256(dhash_psk.encode('utf-8')).hexdigest()
        
        if auth_token != thash_psk:
            print(f'inbound token: {auth_token}')
            print(f'expected hash: {dhash_psk}')
            print(f'thash val: {thash_psk}')
            bottle.response.status = 403
            return {'error': 'Authentication failed.'}

    if not regex_match(utils.UUID_REGEX, syn_id):
        bottle.response.status = 400
        return {'error': 'Invalid synchronization id. Expected UUID'}
    
    return f'Synchronization {syn_id} Complete'



@control_plane.route('/healthcheck', method='GET')
def healthcheck():
    return 'healthy'


@control_plane.route('/', method='GET')
@control_plane.route('/', method='POST')
@control_plane.route('/<url:re:.+>', method='GET')
@control_plane.route('/<url:re:.+>', method='POST')
def default_route(url: str = None) -> dict:
    authN = utils.authenticate(AUTH_TABLE, bottle.request.get_header('Authorization'))
    if authN == False:
        bottle.response.status = 403
        return {'error': 'Authentication failed'}

    bottle.response.status = 404
    return {'error': 'Requested action not found'}



@control_plane.route('/', method='TRACE')
@control_plane.route('/', method='PUT')
@control_plane.route('/', method='DELETE')
@control_plane.route('/', method='HEAD')
@control_plane.route('/', method='PATCH')
@control_plane.route('/', method='CONNECT')
@control_plane.route('/<url:re:.+>', method='TRACE')
@control_plane.route('/<url:re:.+>', method='PUT')
@control_plane.route('/<url:re:.+>', method='DELETE')
@control_plane.route('/<url:re:.+>', method='HEAD')
@control_plane.route('/<url:re:.+>', method='PATCH')
@control_plane.route('/<url:re:.+>', method='CONNECT')
def method_not_supported(url: str = None):
    bottle.response.status = 405
    return None



control_plane.run(host='0.0.0.0', port=8080)