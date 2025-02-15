import bottle
from re import match as regex_match
from hashlib import sha256, sha384
import json
import requests
import utils
import datetime
import asyncio
import threading

AUTH_TABLE = 'mgmt_auth'
mgmt_api = bottle.Bottle()


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


# ListDocuments
@mgmt_api.route('/documents', method='GET')
def list_documents() -> str:
    authN = utils.authenticate(AUTH_TABLE, bottle.request.headers['Authorization'])
    if authN == False:
        bottle.response.status = 403
        return {'error': 'Authentication failed'}
    

    ret = utils.query('SELECT doc_id FROM documents;')

    content = [{'DocumentId': row[0]} for row in ret]
    return {'Documents': content}


# GetDocument
@mgmt_api.route('/documents/<doc_id>', method='GET')
def get_document(doc_id: str):
    authN = utils.authenticate(AUTH_TABLE, bottle.request.headers['Authorization'])
    if authN == False:
        bottle.response.status = 403
        return {'error': 'Authentication failed'}

    # Document id input validation 
    if not regex_match(utils.UUID_REGEX, doc_id):
        bottle.response.status = 400
        return {'error': 'Invalid document identifier'}
    
    ret = utils.query(f'SELECT * FROM documents WHERE doc_id = "{doc_id}";')

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


# ShareDocument
@mgmt_api.route('/documents/<doc_id>/share', method='GET')
def enable_document_sharing(doc_id: str) -> dict:
    authN = utils.authenticate(AUTH_TABLE, bottle.request.headers['Authorization'])
    if authN == False:
        bottle.response.status = 403
        return {'error': 'Authentication failed'}

    # Document id input validation 
    if not regex_match(utils.UUID_REGEX, doc_id):
        bottle.response.status = 400
        return {'error': 'Invalid document identifier'}
    
    ret = utils.query(f'SELECT "1" FROM documents WHERE doc_id = "{doc_id}"')

    # Suppose there _could_ be more than one, but we don't really care enough to handle that :.|
    if len(ret) < 1:
        bottle.response.status = 404
        return {'error': 'Document not found'}


    # Set shared to 1
    try:
        utils.execute(f'UPDATE documents SET shared = "1" WHERE doc_id = "{doc_id}";')
    except Exception as err:
        bottle.response.status = 400
        return {'error': "Unable to share the target document."}

    bottle.response.status = 202
    return None


# UnshareDocument
@mgmt_api.route('/documents/<doc_id>/unshare', method='GET')
def disable_document_sharing(doc_id: str) -> dict: 
    authN = utils.authenticate(AUTH_TABLE, bottle.request.headers['Authorization'])
    if authN == False:
        bottle.response.status = 403
        return {'error': 'Authentication failed'}

    # Document id input validation 
    if not regex_match(utils.UUID_REGEX, doc_id):
        bottle.response.status = 400
        return {'error': 'Invalid document identifier'}
    
    ret = utils.query(f'SELECT "1" FROM documents WHERE doc_id = "{doc_id}"')

    # Suppose there _could_ be more than one, but we don't really care enough to handle that :.|
    if len(ret) < 1:
        bottle.response.status = 404
        return {'error': 'Document not found'}
    

    # Set shared to 0
    try:
        utils.execute(f'UPDATE documents SET shared = "0" WHERE doc_id = "{doc_id}";')
    except Exception as err:
        bottle.response.status = 400
        return {'error': "Unable to unshare the target document."}

    bottle.response.status = 202
    return None


# ListPartnerDocuments
@mgmt_api.route('/partners/documents', method='POST')
def list_partner_documents() -> dict:
    authN = utils.authenticate(AUTH_TABLE, bottle.request.headers['Authorization'])
    if authN == False:
        bottle.response.status = 403
        return {'error': 'Authentication failed'}
    
    if bottle.request.get_header('Content-Type') != 'application/json':
        bottle.response.status = 415  # Unsupported Media Type
        return {"error": 'Content-Type must be application/json'}
    
    # Negotiate a temporary control plane auth token
    try:
        ret = requests.post(f'{utils.get_demo_partner_host()}/ctrl/negotiate',
                            headers={'Content-Type': 'application/json','Authorization': sha256(utils.get_demo_psk().encode('utf-8')).hexdigest()})
        if ret.status_code != 200: raise Exception
        token = json.loads(ret.content).get('token', None)

        if token == None: raise Exception

    except Exception as err:
        bottle.response.status = 400
        return {'error': 'Something went wrong...'}


    body = bottle.request.json
    partner_url = body.get('PartnerUrl', None)

    # Fluff request body to make it realistic(ish)
    json_body = {'ParticipantId': utils.get_demo_psk(), 'QueryStart': str(datetime.datetime.now())}
    
    try:
        ret = requests.post(f'{partner_url}/ctrl/documents/public', allow_redirects=True,
                            headers={'Content-Type': 'application/json', 'Authorization': token}, json=json_body)
        
        if ret.status_code != 200: raise Exception
        content = ret.content
        #if content == None: raise Exception
    
    except Exception as err:
        print(f'ListPartnerDocuments Request Error: {err}')
        bottle.response.status = 500 # mark a different response code / message here from negotiation failure
        return {'error': 'Internal error encountered'}
    
    bottle.response.add_header('Content-Type', 'application/json')
    return ret.content


# InitiatePartnerSynchronization
@mgmt_api.route('/partners/synchronize', method='POST')
def partner_sync() -> dict:
    authN = utils.authenticate(AUTH_TABLE, bottle.request.headers['Authorization'])
    if authN == False:
        bottle.response.status = 403
        return {'error': 'Authentication failed'}
    
    if bottle.request.get_header('Content-Type') != 'application/json':
        bottle.response.status = 415  # Unsupported Media Type
        return {"error": 'Content-Type must be application/json'}


    body = bottle.request.json
    partner_url = body.get('PartnerUrl', None)
    msg = body.get('SynchronizationMessage', None)
    syn_id = body.get('SynchronizationId', None)

    if partner_url == None or msg == None or syn_id == None:
        bottle.response.status = 400
        return {'error': 'Invalid request format.'}
    

    if not regex_match(utils.UUID_REGEX, syn_id):
        bottle.response.status = 400
        return {'error': 'Invalid synchronization id, expected UUID format.'}

    token = sha256(sha384(utils.get_demo_psk().encode('utf-8')).hexdigest().encode('utf-8')).hexdigest()
    
    req_headers = {'Content-Type': 'application/json', 'Authorization': token}
    req_body = body={'CallbackAddress': f'{utils.get_self_host()}', 'SynchronizationId': syn_id, 'Message': msg, 'ParticipantId': utils.get_demo_psk(), 'QueryStart': str(datetime.datetime.now())}
    # THIS NEEDS TO BE ASYNC
    try:
        asyncio.run_coroutine_threadsafe(async_do_request(method='POST', url=f'{partner_url}/ctrl/synchronize', headers=req_headers, req_body=req_body), background_event_loop)
    except Exception as err:
        print(f'Synchronize Request Error: {err}')
        bottle.response.status = 500 # mark a different response code / message here from negotiation failure
        return {'error': 'Internal error encountered'}
    # END ASYNC BLOCK
    

    return {'msg': f'Initiated synchronization with Id: {syn_id}'}


# Unauthenticated to reset demo lab stuff
@mgmt_api.route('/init', method='POST')
@mgmt_api.route('/init', method='GET')
def init_demo() -> dict:
    if bottle.request.method == "POST" and bottle.request.get_header('Content-Type') != 'application/json':
        bottle.response.status = 415  # Unsupported Media Type
        return {"error": "Content-Type must be application/json"}

    body = bottle.request.json

    if body != None:
        psk = body.get('psk', None)
        partner = body.get('partner', None)
        self_ref = body.get('self', None)
    else:
        psk = None
        partner = None
        self_ref = None

    if psk != None:
        psk = utils.set_demo_psk(psk)
    else: psk = utils.get_demo_psk()
    
    if partner != None:
        partner = utils.set_demo_partner_host(partner)
    else: partner = utils.get_demo_partner_host()

    if self_ref != None:
        self_ref = utils.set_self_host(self_ref)
    else: self_ref = utils.get_self_host()

    return {
        'msg': 'This action is used to update/confirm demo settings and is not part of the CTF. Output from this action should contain the same PSK on both the primary and partner systems, with each partner parameter as the opposite partner hostname',
        'psk': psk,
        'partner': partner,
        'self': self_ref
    }
    

@mgmt_api.route('/healthcheck', method='GET')
def healthcheck():
    return 'healthy'



@mgmt_api.route('/', method='GET')
@mgmt_api.route('/', method='POST')
@mgmt_api.route('/<url:re:.+>', method='GET')
@mgmt_api.route('/<url:re:.+>', method='POST')
def default_route(url: str = None) -> dict:

    authN = utils.authenticate(AUTH_TABLE, bottle.request.get_header('Authorization'))
    if authN == False:
        bottle.response.status = 403
        return {'error': 'Authentication failed'}

    bottle.response.status = 404
    return {'error': 'Requested action not found'}



@mgmt_api.route('/', method='TRACE')
@mgmt_api.route('/', method='PUT')
@mgmt_api.route('/', method='DELETE')
@mgmt_api.route('/', method='HEAD')
@mgmt_api.route('/', method='PATCH')
@mgmt_api.route('/', method='CONNECT')
@mgmt_api.route('/<url:re:.+>', method='TRACE')
@mgmt_api.route('/<url:re:.+>', method='PUT')
@mgmt_api.route('/<url:re:.+>', method='DELETE')
@mgmt_api.route('/<url:re:.+>', method='HEAD')
@mgmt_api.route('/<url:re:.+>', method='PATCH')
@mgmt_api.route('/<url:re:.+>', method='CONNECT')
def method_not_supported(url: str = None):
    bottle.response.status = 405
    return None



mgmt_api.run(host='0.0.0.0', port=8000)
