"""
XSA Python buildpack app example
Author: Andrew Lunde
"""
from flask import Flask
from flask import request
from flask import Response

from flask import send_from_directory
#   
import os
#import pyhdb
# Downloading pyhdb-0.3.3.tar.gz
import json
import datetime
#import Crypto.PublicKey.RSA as RSA
#import jws.utils
#import python_jwt as jwt
#https://help.sap.com/viewer/4505d0bdaf4948449b7f7379d24d0f0d/2.0.03/en-US/8732609bd5314b51a17d6a3cc09110c3.html#loio8732609bd5314b51a17d6a3cc09110c3__section_atx_2vt_vt
from sap import xssec
from cfenv import AppEnv
#
#from sap.cf_logging import flask_logging
#
#https://help.sap.com/viewer/0eec0d68141541d1b07893a39944924e/2.0.03/en-US/d12c86af7cb442d1b9f8520e2aba7758.html
from hdbcli import dbapi


app = Flask(__name__)
env = AppEnv()

# Get port from environment variable or choose 9099 as local default
# If you are testing locally (i.e. not with xs or cf deployments,
# Be sure to pull all the python modules locally 
#   with pip using XS_PYTHON unzipped to /tmp
# mkdir -p local
# pip install -t local -r requirements.txt -f /tmp
port = int(os.getenv("PORT", 9099))
hana = env.get_service(label='hana')

def attach(port, host):
    try:
        import pydevd
        pydevd.stoptrace() #I.e.: disconnect if already connected
        # pydevd.DebugInfoHolder.DEBUG_RECORD_SOCKET_READS = True
        # pydevd.DebugInfoHolder.DEBUG_TRACE_BREAKPOINTS = 3
        # pydevd.DebugInfoHolder.DEBUG_TRACE_LEVEL = 3
        pydevd.settrace(
            port=port,
            host=host,
            stdoutToServer=True,
            stderrToServer=True,
            overwrite_prev_trace=True,
            suspend=False,
            trace_only_current_thread=False,
            patch_multiprocessing=False,
        )
    except:
        import traceback;traceback.print_exc() 
        
        
# This module's Flask webserver will respond to these three routes (URL paths)
# If there is no path then just return Hello World and this module's instance number
# Requests passed through the app-router will never hit this route.
@app.route('/')
def hello_world():
    output = '<strong>Hello World! I am instance ' + str(os.getenv("CF_INSTANCE_INDEX", 0)) + '</strong> Try these links.</br>\n'
    output += '<a href="/env">/env</a><br />\n'
    output += '<a href="/python/test">/python/test</a><br />\n'
    output += '<a href="/python/db_only">/python/db_only</a><br />\n'
    output += '<a href="/auth_python/db_valid">/auth_python/db_valid</a><br />\n'
    return output
    
# Satisfy browser requests for favicon.ico so that don't return 404
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/env')
def dump_env():
    output = '\n Key Environment variables... \n'
    output += 'PYTHONHOME: ' + str(os.getenv("PYTHONHOME", 0)) + '\n'
    output += 'PYTHONPATH: ' + str(os.getenv("PYTHONPATH", 0)) + '\n'
    output += 'VCAP_SERVICES: ' + str(os.getenv("VCAP_SERVICES", 0)) + '\n'
    output += 'host: ' + hana.credentials['host'] + '\n'
    output += 'port: ' + hana.credentials['port'] + '\n'
    output += 'user: ' + hana.credentials['user'] + '\n'
    output += 'pass: ' + hana.credentials['password'] + '\n'
    output += '\n'
    return output

# Coming through the app-router
@app.route('/python/links')
def python_links():
    output = '<strong>Hello World! I am instance ' + str(os.getenv("CF_INSTANCE_INDEX", 0)) + '</strong> Try these links.</br>\n'
    output += '<a href="/python/test">/python/test</a><br />\n'
    output += '<a href="/python/db_only">/python/db_only</a><br />\n'
    output += '<a href="/auth_python/db_valid">/auth_python/db_valid</a><br />\n'
    return output

# If there is a request for a python/test, return Testing message and module's instance number
@app.route('/python/test')
def unauth_test():
    return 'Python UnAuthorized Test, Yo! <br />\nI am instance ' + str(os.getenv("CF_INSTANCE_INDEX", 0))

@app.route('/python/post', methods=['POST'])
def unauth_post():
    output = 'Python Post to DB (Dangerous!). \n'
    output += '\n'
    output += 'Receiving module should check that it came from our approuter and verify or abort if otherwise.\n'
    output += '\n'

    content = request.json

    output += content

    return Response(output, mimetype='application/json' , status=201,)

@app.route('/python/set_env')
def set_pyenv():
    output = '\n Set Environment variable... \n'
    if request.args.get('PATHS_FROM_ECLIPSE_TO_PYTHON'):
        output += request.args.get('PATHS_FROM_ECLIPSE_TO_PYTHON')
        os.environ["PATHS_FROM_ECLIPSE_TO_PYTHON"] = request.args.get('PATHS_FROM_ECLIPSE_TO_PYTHON')
        output += '\n'
        output += 'Eclipse paths set for debugging.\n'
        output += '\n'
    output += '\n'
    return Response(output, mimetype='text/plain' , status=200,)

@app.route('/python/env')
def dump_pyenv():
    output = '\n Key Environment variables... \n'
    output += 'PYTHONHOME: ' + str(os.getenv("PYTHONHOME", 0)) + '\n'
    output += 'PYTHONPATH: ' + str(os.getenv("PYTHONPATH", 0)) + '\n'
    output += 'PATHS_FROM_ECLIPSE_TO_PYTHON: ' + str(os.getenv("PATHS_FROM_ECLIPSE_TO_PYTHON", 0)) + '\n'
    jsonok = json.loads(os.environ.get('PATHS_FROM_ECLIPSE_TO_PYTHON', '[]'))
    if jsonok:
        output += "JSON is OK" + '\n'
        tuples = [tuple(x) for x in jsonok]
    else:
        output += "JSON is NOT OK" + '\n'
    output += 'VCAP_SERVICES: ' + str(os.getenv("VCAP_SERVICES", 0)) + '\n'
    output += 'host: ' + hana.credentials['host'] + '\n'
    output += 'port: ' + hana.credentials['port'] + '\n'
    output += 'user: ' + hana.credentials['user'] + '\n'
    output += 'pass: ' + hana.credentials['password'] + '\n'
    output += '\n'
    return output

@app.route('/python/attach')
def do_attach():
    output = '\n Attaching to debugger... \n'
    attach(5678,"localhost")
    output += '\n Set some breakpoints...\n'
    return output

# If there is a request for a python/test2, return Testing message and then check JWT and connect to the data service and retrieve some data
@app.route('/python/db_only')
def unauth_db_only():
    output = 'Python UnAuthorized DB Only. \n'
    #Enable to trigger debugging
    os.environ["PATHS_FROM_ECLIPSE_TO_PYTHON"] = "[['/Users/i830671/git/mta_python_dev_env/python','/home/vcap/app']]"
    output += '\n'
    output += 'Receiving module should check that it came from our approuter and verify or abort if otherwise.\n'
    output += '\n'
    svcs_json = str(os.getenv("VCAP_SERVICES", 0))
    svcs = json.loads(svcs_json)

    schema = hana.credentials['schema']
    host = hana.credentials['host']
    port = hana.credentials['port']
    user = hana.credentials['user']
    password = hana.credentials['password']

    # The certificate will available for HANA service instances that require an encrypted connection
    # Note: This was tested to work with python hdbcli-2.3.112 tar.gz package not hdbcli-2.3.14 provided in XS_PYTHON00_0-70003433.ZIP  
    if 'certificate' in hana.credentials:
        haascert = hana.credentials['certificate']
    
    output += 'schema: ' + schema + '\n'
    output += 'host: ' + host + '\n'
    output += 'port: ' + port + '\n'
    output += 'user: ' + user + '\n'
    output += 'pass: ' + password + '\n'

#    # Connect to the python HANA DB driver using the connection info
# User for HANA as a Service instances
    if 'certificate' in hana.credentials:
        connection = dbapi.connect(
            address=host,
            port=int(port),
            user=user,
            password=password,
            currentSchema=schema,
            encrypt="true",
            sslValidateCertificate="true",
            sslCryptoProvider="openssl",
            sslTrustStore=haascert
        )
    else:
        connection = dbapi.connect(
            address=host,
            port=int(port),
            user=user,
            password=password,
            currentSchema=schema
        )
 

#    # Prep a cursor for SQL execution
    cursor = connection.cursor()

#    # Form an SQL statement to retrieve some data
    cursor.execute('SELECT "tempId", "tempVal", "ts", "created" FROM "data::sensors.temp"')

#    # Execute the SQL and capture the result set
    sensor_vals = cursor.fetchall()
#
#    # Loop through the result set and output
    for sensor_val in sensor_vals:
        output += 'sensor_val: ' + str(sensor_val[1]) + ' at: ' + str(sensor_val[2]) + '\n'
#
#    # Close the DB connection
    connection.close()
#
    # Return the results
    return output

# If there is a request for a python/test2, return Testing message and then check JWT and connect to the data service and retrieve some data
@app.route('/auth_python/db_valid')
def auth_db_valid():
    output = 'Python Authorized DB Validated Request. \n'
    output += '\n'
    output += 'Receiving module should check that it came from our approuter and verify or abort if otherwise.\n'
    output += '\n'
    svcs_json = str(os.getenv("VCAP_SERVICES", 0))
    svcs = json.loads(svcs_json)

    # Verify the JWT before proceeding. or refuse to process the request.
    # https://jwt.io/ JWT Debugger Tool and libs for all languages
    # https://github.com/jpadilla/pyjwt/
    # https://github.com/davedoesdev/python-jwt

    # From the vcap_services environment variable pull out these things for later.
#    vkey = svcs["xsuaa"][0]["credentials"]["verificationkey"]
#    secret = svcs["xsuaa"][0]["credentials"]["clientsecret"]
#
#    #output += 'vkey: ' + vkey + '\n'
#    #output += 'secret: ' + secret + '\n'
#
#    #jwt.decode(encoded, verify=False)
#    req_host = request.headers.get('Host')
#    req_auth = request.headers.get('Authorization')
#
#    #output += 'req_host: ' + req_host + '\n'
#    #output += 'req_auth: ' + req_auth + '\n'
#
#    #import jwt
#    #output += 'req_auth = ' + req_auth + '\n'
#
#    #Check to see if the request has an authorization header and if it starts with "Bearer "
#    if req_auth:
#        if req_auth.startswith("Bearer "):
#            output += 'JWT Authorization is of type Bearer! \n'
#        else:
#            output += 'JWT Authorization is not of type Bearer! \n'
#    else:
#        output += 'Authorization header is missing! \n'
#
#    output += '\n'
#
#    #If it looks like the right type of authoriztion header, grab it's contents.
#    if req_auth:
#        jwtoken = req_auth[7:]
#
#        # The PKEY in the env has the \n stripped out and the importKey expects them!
#        pub_pem = "-----BEGIN PUBLIC KEY-----\n" + vkey[26:-24] + "\n-----END PUBLIC KEY-----\n"
#        #output += 'pub_pem = ' + pub_pem + '\n'
#
#	# Manipulate the pem key so that we can verify it.
#        pub_key = RSA.importKey(pub_pem)
#        (header, claim, sig) = jwtoken.split('.')
#        header = jws.utils.from_base64(header)
#        claim = jws.utils.from_base64(claim)
#        if jws.verify(header, claim, sig, pub_key, is_json=True):
#            output += 'JWT is Verified! \n'
#        else:
#            output += 'JWT FAILED Verification! \n'
#
#    else:
#    else:
#        output += 'Normally we would only do work if JWT is verified.\n'
#
#    output += '\n'

    uaa_service = env.get_service(label='xsuaa').credentials
    access_token = request.headers.get('authorization')[7:]

    security_context = xssec.create_security_context(access_token, uaa_service)
    isAuthorized = security_context.check_scope('openid')
    if not isAuthorized:
        abort(403)

    output += 'get_logon_name: ' + security_context.get_logon_name() + '\n'
#    output += 'get_given_name: ' + security_context.get_given_name() + '\n'
#    output += 'get_family_name: ' + security_context.get_family_name() + '\n'
    output += 'get_email: ' + security_context.get_email() + '\n'
#    output += 'get_subdomain: ' + security_context.get_subdomain() + '\n'
#    output += 'get_clientid: ' + security_context.get_clientid() + '\n'
    output += 'get_identity_zone: ' + security_context.get_identity_zone() + '\n'
#    output += 'get_grant_type: ' + security_context.get_grant_type() + '\n'
    
#
#    # This module should only proced with any further execution if the JWT has been verified.
#    # In this example we blindly continue, but this is not the best practice.
#
#    # Grab information from the vcap_services about the database connection
#    schema = svcs["hana"][0]["credentials"]["schema"]
#    user = svcs["hana"][0]["credentials"]["user"]
#    password = svcs["hana"][0]["credentials"]["password"]
#    conn_str = svcs["hana"][0]["credentials"]["url"]
#    host = svcs["hana"][0]["credentials"]["host"]
#    port = svcs["hana"][0]["credentials"]["port"]
#    driver = svcs["hana"][0]["credentials"]["driver"]
#
    schema = hana.credentials['schema']
    host = hana.credentials['host']
    port = hana.credentials['port']
    user = hana.credentials['user']
    password = hana.credentials['password']
    

    output += 'schema: ' + schema + '\n'
    output += 'host: ' + host + '\n'
    output += 'port: ' + port + '\n'
    output += 'user: ' + user + '\n'
    output += 'pass: ' + password + '\n'

#    output += 'schema: ' + schema + '\n'
#    output += 'user: ' + user + '\n'
#    output += 'password: ' + password + '\n'
#    output += 'conn_str: ' + conn_str + '\n'
#    output += 'host: ' + host + '\n'
#    output += 'port: ' + port + '\n'
#    output += 'driver: ' + driver + '\n'
#
#    output += '\n'
#    # Connect to the python HANA DB driver using the connection info
#    connection = pyhdb.connect(host,int(port),user,password)
    connection = dbapi.connect(host,int(port),user,password)
#    connection = dbapi.connect(addresst=host,port=int(port),user=user,password=password)
#    # Prep a cursor for SQL execution
    cursor = connection.cursor()
#    # Form an SQL statement to retrieve some data
    cursor.execute('SELECT "tempId", "tempVal", "ts", "created" FROM "' + schema + '"."DAT368.db.data::sensors.temp"')
#    # Execute the SQL and capture the result set
    sensor_vals = cursor.fetchall()
#
#    # Loop through the result set and output
    for sensor_val in sensor_vals:
        output += 'sensor_val: ' + str(sensor_val[1]) + ' at: ' + str(sensor_val[2]) + '\n'
#
#    # Close the DB connection
    connection.close()
#
    # Return the results
    return output

if __name__ == '__main__':
    # Run the app, listening on all IPs with our chosen port number
    # Use this for production 
    #app.run(host='0.0.0.0', port=port)
    # Use this for debugging 
    app.run(debug=True, host='0.0.0.0', port=port)

