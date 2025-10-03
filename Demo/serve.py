import argparse
import yaml

from bottle import Bottle, response, redirect, static_file

from Backend import control_plane, data_plane, mgmt_service
from setup import do_setup



app = Bottle()

# Mount mgmt service and ctrl / data planes
app.mount('/mgmt', mgmt_service.mgmt_api)
app.mount('/ctrl', control_plane.control_plane)
app.mount('/data', data_plane.data_plane)


# OpenAPI Specification
@app.route('/swagger/openapi.json', method='GET')
def openapi_json():
    response.content_type = 'application/json'
    try:
        with open('./openapi.yaml', 'r') as f:
            spec_dict = yaml.safe_load(f)
            
    except Exception as err:
        response.status = 500
        return {'status': 'error', 'error': f'Unable to load OpenAPI specification: {err}'}
    
    return spec_dict


# Swagger docs
@app.route('/swagger/<filename>', method='GET')
def swagger_docs(filename):
    return static_file(filename=filename, root='./Swagger')

@app.route('<path:re:.+>', method='GET')
def swagger_redirect(path):
    return redirect('/swagger/index.html')


if __name__ == '__main__':
    parser = argparse.ArgumentParser('serve.py', 'Demo api server')
    parser.add_argument('--host', type=str, required=False, default='0.0.0.0', help='Interface for API server to listen on')
    parser.add_argument('--port', type=int, required=False, default=8000, help='API server listen port')
    parser.add_argument('--psk', type=str, required=False, default=None, help='Set the PSK for the secondary node launched')
    args = parser.parse_args()

    do_setup(args.psk)
    app.run(host=args.host, port=args.port)

