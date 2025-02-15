import bottle
import utils
from hashlib import sha256, sha384
from re import match as regex_match

data_plane = bottle.Bottle()


# Not bother with authN / authZ since we're just going to run it locally for this demo
@data_plane.route('/download/<doc_ref>', method='GET')
def download_doc(doc_ref: str):

    ret = utils.query(f'SELECT doc_id, filename FROM documents')

    # Suppose there _could_ be more than one, but we don't really care enough to handle that :.|
    if len(ret) < 1:
        bottle.response.status = 404
        return {'error': 'Document not found'}

    name = None
    for row in ret:
        doc_id_dhash = sha256(sha256(str(row[0]).encode('utf-8')).hexdigest().encode('utf-8')).hexdigest()
        if doc_ref == doc_id_dhash:
            name = row[1]

    if name == None:
        bottle.response.status = 404
        return {'error': 'Document reference not found'}

    return bottle.static_file(filename=name, root=utils.DEMO_FILE_DIR, download=True)



@data_plane.route('/submit/<submit_hash>', method='GET')
def submit_ctf(submit_hash: str):
    psk = utils.get_demo_psk()
    dhash_psk = sha256(sha384(psk.encode('utf-8')).hexdigest().encode('utf-8')).hexdigest()
    thash_psk = sha256(dhash_psk.encode('utf-8')).hexdigest()

    if submit_hash != thash_psk:
        bottle.response.status = 403
        return {'succes': False, 'msg': 'Incorrect submission'}

    else:
        return {'success': True, 'msg': 'CTF Complete!'}


@data_plane.route('/healthcheck', method='GET')
def healthcheck():
    return 'healthy'



@data_plane.route('/', method='GET')
@data_plane.route('/', method='POST')
@data_plane.route('/<url:re:.+>', method='GET')
@data_plane.route('/<url:re:.+>', method='POST')
def default_route(url: str = None) -> dict:
    bottle.response.status = 404
    return {'error': 'Requested action not found'}


@data_plane.route('/', method='TRACE')
@data_plane.route('/', method='PUT')
@data_plane.route('/', method='DELETE')
@data_plane.route('/', method='HEAD')
@data_plane.route('/', method='PATCH')
@data_plane.route('/', method='CONNECT')
@data_plane.route('/<url:re:.+>', method='TRACE')
@data_plane.route('/<url:re:.+>', method='PUT')
@data_plane.route('/<url:re:.+>', method='DELETE')
@data_plane.route('/<url:re:.+>', method='HEAD')
@data_plane.route('/<url:re:.+>', method='PATCH')
@data_plane.route('/<url:re:.+>', method='CONNECT')
def method_not_supported(url: str = None):
    bottle.response.status = 405
    return None




data_plane.run(host='127.0.0.1', port='8888')

