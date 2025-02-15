from bottle import Bottle, request, run, response
from datetime import datetime
import logging
import json
import requests
import urllib3
import argparse
from re import match as regex_match


#############################################
#               Setup Configs               #
#############################################

# Default logging format
def log_request(msg: str) -> None:
    source = str(request.environ.get('REMOTE_ADDR'))
    

    if (regex_match('^10[.].*$', source) or regex_match('^172[.](1[6-9]|2[0-9]|3[0-2])[.].*$', source) or (regex_match('^192[.]168[.].*$', source))):
        logger.debug('Request received from internal address, attempting to interpret X-Forwarded-For header')
        forwarded_for = dict(request.headers).get('X-Forwarded-For', None)
        if forwarded_for != None:
            source = f'{source} ({forwarded_for})'

    entry = f'{source} - {request.method} {request.path}'
    logger.info(entry)
    logger.info(msg)
    
    return None

# Global config vars
CATCH_ALL_STATUS = 200
CATCH_ALL_MESSAGE = 'CatchAll'
INTERCEPT_PROXIES = {}
logger = None


#############################################
#               Routed Paths                #
#############################################

serve = Bottle()


# Healthcheck for load balancer
@serve.route('/healthcheck', method='GET')
def healthcheck():

    log_request('Received healthcheck query')
    return 'healthy'


# Logs request headers and body
@serve.route('/log-all/<path:re:.*>', method='POST')
@serve.route('/log-all/<path:re:.*>', method='GET')
@serve.route('/log-all', method='POST')
@serve.route('/log-all', method='GET')
def log_all(path: str = None):
    
    log_request(f'Logging request header & body details')

    body = request.body.read().decode('utf-8')
    headers = dict(request.headers)
    
    logger.info(f'Request Headers: {dict(request.headers)}')
    logger.info(f'Request Body: {body}')

    return "success"


# Echo the authorization header back in the response
@serve.route('/echo-auth', method='POST')
@serve.route('/echo-auth', method='GET')
def echo_auth():

    log_request('Echoing authorization header')
    auth = dict(request.headers).get('Authorization')

    return auth


# Echo the request headers back in the response
@serve.route('/echo-headers', method='POST')
@serve.route('/echo-headers', method='GET')
def echo_headers():

    log_request('Echoing authorization header')
    headers = dict(request.headers)

    return json.dumps(headers)


# Echo the request body back in the response
@serve.route('/echo-body', method='POST')
@serve.route('/echo-body', method='GET')
def echo_body():

    log_request('Echoing request body')
    body = request.body.read().decode('utf-8')

    return body


# Relay an intercepted request to the target 
@serve.route('/intercept/<destination:re:.*>', method='POST')
@serve.route('/intercept/<destination:re:.*>', method='GET')
def intercept(destination: str):
    
    log_request(f'Intercepted request to {destination}')

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    headers = dict(request.headers)
    target_host = destination.split('/')[2]

    # Trim out request URI authentication and service port if exists
    at_idx = target_host.find('@')
    colon_idx = target_host.find(':')
    start = at_idx if (at_idx != -1) else 0
    end = colon_idx if (colon_idx != -1) else len(target_host)

    headers['Host'] = target_host[start:end]
    body = json.loads(request.body.read().decode('utf-8'))
    method = request.method

    logger.info(f'Relaying to {target_host}')
    try:
        res = requests.request(method, destination, headers=headers, json=body, proxies=INTERCEPT_PROXIES, verify=False)
        response.status = res.status_code

    except Exception as err:
        logger.warning(f'Exception thrown during interception relay: {err}')
        return 'failure'
    
    logger.debug(f'Relayed response headers: {res.headers}')
    logger.debug(f'Relayed response body: {res.text}')

    return res.text


# Return a response with the designated status code, setting Location header to trailing path
@serve.route('/response/<status:int>/<path:re:.*>', method='POST')
@serve.route('/response/<status:int>/<path:re:.*>', method='GET')
@serve.route('/response/<status:int>', method='POST')
@serve.route('/response/<status:int>', method='GET')
def response_status(status: int, path: str = None):
    msg = f'Received proxy request for status {status}'
    if path != None: msg = f'{msg} to {path}'
    log_request(msg)

    try:
        response.status = status
        if path != None:
            response.set_header('Location', path)
    except Exception as err:
        logger.warning(f'{err}')

    return f'Status {status} to {path}'


@serve.route('/<path:re:.*>', method='GET')
@serve.route('/<path:re:.*>', method='POST')
@serve.route('/<path:re:.*>', method='PUT')
@serve.route('/<path:re:.*>', method='DELETE')
@serve.route('/<path:re:.*>', method='HEAD')
@serve.route('/<path:re:.*>', method='PATCH')
@serve.route('/', method='GET')
@serve.route('/', method='POST')
@serve.route('/', method='PUT')
@serve.route('/', method='DELETE')
@serve.route('/', method='HEAD')
@serve.route('/', method='PATCH')
def catch_all(path: str = None):

    log_request('Received request to CatchAll endpoint')

    response.status = CATCH_ALL_STATUS
    return CATCH_ALL_MESSAGE


# Run the server
if __name__ == "__main__":
    parser = argparse.ArgumentParser('SSRFReceiver', 'python3 SSRFReceiver.py [--listen-port LISTEN_PORT] [--no-intercept-proxy] [--intercept-port [INTERCEPT_PORT]')
    parser.add_argument('--listen-port', type=int, required=False, default=8080, help='Port to listen on [default: 8080]')
    parser.add_argument('--intercept-port', type=int, required=False, default=8090, help='Interception relay bound port [default: 8090]')
    parser.add_argument('--no-intercept-proxy', required=False, action='store_true', help='Disable intercept HTTP proxy when relaying requests')
    parser.add_argument('--catchall-msg', type=str, required=False, default='CatchAll', help='Response message to catchall endpoint')
    parser.add_argument('--catchall-status', type=int, required=False, default=200, help='Response status code to catchall endpoint')
    parser.add_argument('--log-level', type=str, required=False, default='INFO', choices=('DEBUG','INFO','WARNING','ERROR','CRITICAL'), help='Log level (use DEBUG to log intercepted response details)')
    args = parser.parse_args()

    INTERCEPT_PROXIES['http'] = f'http://127.0.0.1:{args.intercept_port}'
    INTERCEPT_PROXIES['https'] = f'http://127.0.0.1:{args.intercept_port}'

    if args.no_intercept_proxy == True:
        INTERCEPT_PROXIES = None

    CATCH_ALL_MESSAGE = args.catchall_msg
    CATCH_ALL_STATUS = args.catchall_status


    # Setup logger 
    logging.basicConfig(
        filename=f'{datetime.now().strftime("%Y-%m-%d")}-SSRFReceiver.log',          # Log file name
        level=args.log_level,          # Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format='%(asctime)s - %(levelname)s - %(message)s',  # Log message format
        datefmt='%Y-%m-%d %H:%M:%S'  # Date format for timestamps
    )
    logger = logging.getLogger(__name__)
    
    logger.info(f'Using CatchAll status {CATCH_ALL_STATUS} with message \'{CATCH_ALL_MESSAGE}\'')
    logger.info(f'Using port {args.intercept_port} for relaying requests to interception endpoint')
    logger.info(f'Starting SSRFReceiver on 0.0.0.0:{args.listen_port} with {args.log_level} logging')

    print(f'Using CatchAll status {CATCH_ALL_STATUS} with message \'{CATCH_ALL_MESSAGE}\'')
    print(f'Using port {args.intercept_port} for relaying requests to interception endpoint')
    print(f'Starting SSRFReceiver on 0.0.0.0:{args.listen_port} with {args.log_level} logging\n\n')

    run(serve, host='0.0.0.0', port=args.listen_port)

