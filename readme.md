SSRF Receiver
=============

A pretty lightweight SSRF listener / proxy that is helpful for testing semi-blind and blind SSRF interactions.

```bash
user@linux: python3 SSRFReceiver.py
Using CatchAll status 200 with message 'CatchAll'
Using port 8090 for relaying requests to interception endpoint
Starting SSRFReceiver on 0.0.0.0:8080 with INFO logging


Bottle v0.13.2 server starting up (using WSGIRefServer())...
Listening on http://0.0.0.0:8080/
Hit Ctrl-C to quit.


```

## Receiver Endpoints

* `/healthcheck`: Health endpoint for loadbalancers / middlewares to check status
* `/log-all` or `/log-all/<path>`: Logs request headers and body for incoming requests
* `/echo-auth`: Echo the request authorization header content back in the response
* `/echo-headers`: Echo all request headers back in the response
* `/echo-body`: Echo the request body data back in the response
* `/intercept/<destination>`: Relays the incoming request to the specified destination (e.g., `http://example.com/some/path`) through a local proxy (defaults to port 8090). Very useful for sending blind SSRF connections back through Burp Suite assuming the local proxy is bound to the Burp listener.
    * This can be easily setup with ssh (`ssh user@host -R 127.0.0.1:8090:127.0.0.1:8080`)
* `/response/<status>` or `/response/<status>/<path>`: Designates the status code for the inbound request's HTTP response. If a path follows the stats, this value will be set as the `Location` header of the response. This is useful particularly for identifying which 3XX series response codes a HTTP client will accept for redirections (e.g., redirecting a `POST` request to a `GET`).
* All other paths will be handled by a catch-all endpoint, which responds with a designated status code & message (defaults to status 200 and 'CatchAll')


## Demo Capture-The-Flag (CTF)

Included in the `Demo` folder is a docker CTF deployment you can use to practice some examples as to how to leverage some of the features supported. Refer to the Demo's readme page for setup instructions and API overview.

* **Management API:** Intended interface for users to interact with the demo service.
* **Control Plane API:** Intended for node-to-node communications. Not intended for users to be able to interact with these directly. You will need to break this expectation in order to complete the challenge.
* **Data Plane API:** Serves data to users or to the other node directly. Your goal is to extract data from the secondary node's data plane through the submit action (primary node).
