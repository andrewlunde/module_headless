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
import time
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
hanass = env.get_service(name='HEADLESS_SS')
ss_conn = ""
chrusr = ""
chrpwd = ""
loggedin = False

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
        
def get_conn(hana):
 
    schema = hana.credentials['schema']
    host = hana.credentials['host']
    port = hana.credentials['port']
    user = hana.credentials['user']
    password = hana.credentials['password']

    # The certificate will available for HANA service instances that require an encrypted connection
    # Note: This was tested to work with python hdbcli-2.3.112 tar.gz package not hdbcli-2.3.14 provided in XS_PYTHON00_0-70003433.ZIP
    if 'certificate' in hana.credentials:
        haascert = hana.credentials['certificate']

    #output += 'schema: ' + schema + '<br >\n'
    #output += 'host: ' + host + '<br >\n'
    #output += 'port: ' + port + '<br >\n'
    #output += 'user: ' + user + '<br >\n'
    #output += 'pass: ' + password + '<br >\n'

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

    return connection
       
def get_unpw():

    global chrusr
    global chrpwd

    output = ""

    ss_conn = get_conn(hanass)

    # Prep a cursor for SQL execution
    cursor = ss_conn.cursor()

    # Form an SQL statement to retrieve some data

#https://blogs.sap.com/2017/07/26/sap-hana-2.0-sps02-new-feature-updated-python-driver/

    import codecs

    hexvalue = cursor.callproc("SYS.USER_SECURESTORE_RETRIEVE", ("ChromeStore", False, "CHRUserName", None))

    if hexvalue[3] is None:
        output += 'key CHRUserName does not exist in store ChromeStore.  Try inserting a value first.' + '<br >\n'
    else:
        retrieved = codecs.decode(hexvalue[3].hex(), "hex").decode()
        chrusr = retrieved
        output += 'key CHRUserName with value ' + retrieved + ' was retrieved from store ChromeStore.' + '<br >\n'


    hexvalue = cursor.callproc("SYS.USER_SECURESTORE_RETRIEVE", ("ChromeStore", False, "CHRPassWord", None))

    if hexvalue[3] is None:
        output += 'key CHRPassWord does not exist in store ChromeStore.  Try inserting a value first.' + '<br >\n'
    else:
        retrieved = codecs.decode(hexvalue[3].hex(), "hex").decode()
        chrpwd = retrieved
        retrieved = "*****"
        output += 'key CHRPassWord with value ' + retrieved + ' was retrieved from store ChromeStore.' + '<br >\n'

#    # Close the DB connection
    ss_conn.close()

    return output



# This module's Flask webserver will respond to these three routes (URL paths)
# If there is no path then just return Hello World and this module's instance number
# Requests passed through the app-router will never hit this route.
@app.route('/')
def hello_world():
    output = '<strong>Hello World! I am instance ' + str(os.getenv("CF_INSTANCE_INDEX", 0)) + '</strong> Try these links.</br>\n'
    output += '<a href="/env">/env</a><br />\n'
    output += '<a href="/headless/test">/headless/test</a><br />\n'
    output += '<a href="/headless/chrome">/headless/chrome</a><br />\n'
    output += '<a href="/headless/db_only">/headless/db_only</a><br />\n'
    output += '<a href="/auth_python/db_valid">/auth_python/db_valid</a><br />\n'
    return output
    
# Satisfy browser requests for favicon.ico so that don't return 404
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, ''),'favicon.ico', mimetype='image/vnd.microsoft.icon')

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
@app.route('/headless/links')
@app.route('/headless/links/')
def headless_links():
    output = '<strong>Hello World! I am instance ' + str(os.getenv("CF_INSTANCE_INDEX", 0)) + '</strong> Try these links.</br>\n'
    output += '<a href="/headless/test">/headless/test</a><br />\n'
    output += '<a href="/headless/admin/links">/headless/admin/links</a><br />\n'
    output += '<a href="/headless/chrome">/headless/chrome</a><br />\n'
    output += '<a href="/headless/db_only">/headless/db_only</a><br />\n'
    output += '<a href="/auth_python/db_valid">/auth_python/db_valid</a><br />\n'
    return output

# If there is a request for a python/test, return Testing message and module's instance number
@app.route('/headless/test')
def unauth_test():
    return 'Python UnAuthorized Test, Yo! <br />\nI am instance ' + str(os.getenv("CF_INSTANCE_INDEX", 0))

@app.route('/headless/admin')
def admin_python_home():
    output = '<strong>Password Administration</strong> Try these links.</br>\n'
    output += '<a href="/headless/admin/links">/headless/admin/links</a><br />\n'
    output += '<a href="/headless/test">/headless/test</a><br />\n'
    return output

@app.route('/headless/admin/links')
def admin_links():
    output = '<strong>Password Administration</strong> Try these links.</br>\n'
    output += '<a href="/headless/admin/getpw">/headless/admin/getpw</a><br />\n'
    output += '<a href="/headless/admin/setpw">/headless/admin/setpw</a><br />\n'
    output += '<a href="/headless/admin/delpw">/headless/admin/delpw</a><br />\n'
    output += '<a href="/headless/admin/authcheck">/headless/admin/authcheck</a><br />\n'
    return output

@app.route('/headless/admin/getpw')
def admin_getpw():
    output = '<strong>Password Administration Current</strong></br>\n'

    global chrusr
    global chrpwd

    output += get_unpw()

    output += '<a href="/headless/admin">Back to Admin</a><br />\n'
    return output

@app.route('/headless/admin/setpw')
def admin_setpw():
    output = '<strong>Password Administration</strong></br>\n'
    output += '<form action="/headless/admin/setpw_result" method="post">\n'
    output += '<table cellspacing="0" cellpadding="0">\n'
    output += '  <tr><td align="right">User Name:</td><td align="left"><input type="text" name="username" size="30" maxlength="25"></td></tr>\n'
    output += '  <tr><td align="right">Password:</td><td align="left"><input type="password" name="password" size="30" maxlength="25"></td></tr>\n'
    output += '  <tr><td align="right"></td><td align="left"><button type="submit">Submit</button></td></tr>\n'
    output += '</table>\n'
    output += '</form>\n'
    return output

@app.route('/headless/admin/setpw_result', methods=['POST'])
def admin_setpw_result():
    output = '<strong>Password Administration Result</strong></br>\n'

    global chrusr
    global chrpwd

    usr = 'unknown'
    pwd  = 'unknown'
    if request.method == 'POST':
        usr = request.form['username']
        pwd  = request.form['password']

    output += 'User: ' + usr + '<br />\n'
    output += 'Pass: ' + "*****" + '<br />\n'

    ss_conn = get_conn(hanass)

#    # Prep a cursor for SQL execution
    cursor = ss_conn.cursor()

#    # Form an SQL statement to retrieve some data

    string2store = 'Whatever!'

    import codecs

    string2store = usr
    hex2store = (codecs.encode(str.encode(string2store), "hex")).decode()

    try:
        cursor.callproc("SYS.USER_SECURESTORE_INSERT", ("ChromeStore", False, "CHRUserName", hex2store))
        output += 'key CHRUserName with value ' + usr + '=' + hex2store + ' was inserted into store ChromeStore.' + '<br >\n'
        chrusr = usr
    except:
        output += 'key CHRUserName likely already exists. Try deleting first.' + '<br >\n'

    string2store = pwd
    hex2store = (codecs.encode(str.encode(string2store), "hex")).decode()

    try:
        cursor.callproc("SYS.USER_SECURESTORE_INSERT", ("ChromeStore", False, "CHRPassWord", hex2store))
        output += 'key CLIUserPass with value ' + "*****" + '=' + hex2store + ' was inserted into store ChromeStore.' + '<br >\n'
        chrpwd = pwd
    except:
        output += 'key CLIUserPass likely already exists. Try deleting first.' + '<br >\n'

#    # Close the DB connection
    ss_conn.close()

    output += '<a href="/headless/admin">Back to Admin</a><br />\n'
    return output

@app.route('/headless/admin/delpw')
def admin_delpw():
    output = '<strong>Password Deletion</strong></br>\n'

    global chrusr
    global chrpwd

    ss_conn = get_conn(hanass)

#    # Prep a cursor for SQL execution
    cursor = ss_conn.cursor()

#    # Form an SQL statement
    cursor.callproc("SYS.USER_SECURESTORE_DELETE", ("ChromeStore", False, "CHRUserName"))
    cursor.callproc("SYS.USER_SECURESTORE_DELETE", ("ChromeStore", False, "CHRPassWord"))

    chrusr = ""
    chrpwd = ""

#    # Close the DB connection
    ss_conn.close()

    output += 'key CHRUserName and CHRPassWord were deleted from store ChromeStore.' + '<br />\n'

    output += '<a href="/headless/admin">Back to Admin</a><br />\n'
    return output

@app.route('/headless/chrome')
def headless_chrome():
    output = "<!DOCTYPE HTML>\n"
    output += "<html>\n"
    output += "<head>\n"
    output += "<meta http-equiv='Content-Type' content='text/html;charset=UTF-8' />\n"
    output += "<title>chrome</title>\n"
    output += "</head>\n"
    output += "<h4>Headless Chrome</h4><br />\n"
    output += '<body style="font-family: Tahoma, Geneva, sans-serif">\n'
    output += '    <a href="/headless/pagelist" target="chrome">Captured Pages</a><br />\n'

    try:
        from selenium import webdriver
        #https://github.com/cryzed/Selenium-Requests
        #from seleniumrequests import webdriver
        from selenium.webdriver.common.keys import Keys
        from selenium.webdriver.common.action_chains import ActionChains
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as cond
        from selenium.common.exceptions import ElementNotVisibleException

        #https://w3c.github.io/webdriver/
        options = webdriver.ChromeOptions()
        options.binary_location = '/opt/google/chrome/chrome'
        options.add_argument('headless')
        options.add_argument('window-size=1200x600')
        options.add_argument('no-sandbox')
        options.add_argument('disable-dev-shm-usage')
        driver = webdriver.Chrome(chrome_options=options)
        driver.implicitly_wait(30)
        #output += '    <p>' + request.args.get('page') + '</p><br />\n'
        driver.get('https://account.us1.hana.ondemand.com/cockpit/#/globalaccount/aTeam/subaccounts')
        #driver.get('https://www.conciletime.com')
        #time.sleep(1)
        try:
            WebDriverWait(driver,10).until(cond.visibility_of_element_located((By.ID, "j_username")))
        except (ElementNotVisibleException) as py_ex:
            print("Element not visible.")
            print (py_ex)
            print (py_ex.args)

        email = driver.find_element_by_id('j_username')
        driver.get_screenshot_as_file('/root/app/pages/' + 'page01.png')

        email.send_keys('andrew@lunde.com') 
        password = driver.find_element_by_id('j_password') 
        password.send_keys('Xxxx###!')
        login = driver.find_element_by_id('logOnFormSubmit') 
        driver.get_screenshot_as_file('/root/app/pages/' + 'page02.png')

        login.click()
        #time.sleep(2) 

        try:
            # Wait as long as required, or maximum of 10 sec for alert to appear
            #WebDriverWait(driver,10).until(cond.alert_is_present())
            WebDriverWait(driver,10).until(cond.visibility_of_element_located((By.ID, "__jsview1--addSubAccount")))

            #Change over the control to the Alert window
            #obj = driver.switch_to.alert

            #Retrieve the message on the Alert window
            #msg=obj.text
            #print ("Alert shows following message: "+ msg )
    
            #Use the accept() method to accept the alert
            #obj.accept()

        except (ElementNotVisibleException) as py_ex:
            print("Element not visible.")
            print (py_ex)
            print (py_ex.args)


        driver.get_screenshot_as_file('/root/app/pages/' + 'page03.png')

        #__jsview1--addSubAccount
        #$("#__jsview1--addSubAccount").tap();
        addSubaccount = driver.find_element_by_id('__jsview1--addSubAccount')
        addSubaccount.click()
        #time.sleep(1)
        try:
            WebDriverWait(driver,10).until(cond.visibility_of_element_located((By.ID, "CreateNewSubAccountDialog--displayName-inner")))
        except (ElementNotVisibleException) as py_ex:
            print("Element not visible.")
            print (py_ex)
            print (py_ex.args)
        driver.get_screenshot_as_file('/root/app/pages/' + 'page04.png')
        #CreateNewSubAccountDialog--displayName-inner
        displayName = driver.find_element_by_id('CreateNewSubAccountDialog--displayName-inner')
        #$("#CreateNewSubAccountDialog--displayName-inner").val("aokheadless");
        displayName.send_keys('abcheadless')
        #CreateNewSubAccountDialog--description-inner
        description = driver.find_element_by_id('CreateNewSubAccountDialog--description-inner')
        #$("#CreateNewSubAccountDialog--description-inner").val("Test subaccount creation via headless browser.");
        description.send_keys('Test subaccount creation via headless browser.')
        
        #https://www.techbeamers.com/selenium-webdriver-coding-tips/
        #Select dropdown = new Select(driver.findElement(By.xpath("//drop_down_x_path")));
        #dropdown.deselectAll()
        #dropdown.selectByVisibleText("selectLabel")

        #CreateNewSubAccountDialog--environmentsCombo
        #$("#CreateNewSubAccountDialog--environmentsCombo-hiddenInput").tap();
        #$("#__item7-CreateNewSubAccountDialog--environmentsCombo-1").tap();
        #environmentsCombo = driver.find_element_by_id('CreateNewSubAccountDialog--environmentsCombo')
        #environmentsCombo.click()
        #CreateNewSubAccountDialog--environmentsCombo-hiddenInput
        #$("#CreateNewSubAccountDialog--environmentsCombo-labelText").html("Cloud Foundry")
        #CreateNewSubAccountDialog--environmentsCombo
        environmentsComboInput = driver.find_element_by_id('CreateNewSubAccountDialog--environmentsCombo')
        #environmentsComboInput.send_keys('Cloud Foundry')
        environmentsComboInput.click()
        environmentsComboSelect = driver.find_element_by_id('__item7-CreateNewSubAccountDialog--environmentsCombo-1')
        environmentsComboSelect.click()
        #time.sleep(1)
        try:
            WebDriverWait(driver,10).until(cond.visibility_of_element_located((By.ID, "CreateNewSubAccountDialog--providersCombo")))
        except (ElementNotVisibleException) as py_ex:
            print("Element not visible.")
            print (py_ex)
            print (py_ex.args)
        driver.get_screenshot_as_file('/root/app/pages/' + 'page05.png')
        #CreateNewSubAccountDialog--providersCombo-hiddenInput
        #$("#CreateNewSubAccountDialog--providersCombo-hiddenInput").tap();
        #$("#__item8-CreateNewSubAccountDialog--providersCombo-0").tap();    # Amazon Web Services(AWS)
        #$("#CreateNewSubAccountDialog--providersCombo-labelText").html("Amazon Web Services (AWS)")
        providersComboInput = driver.find_element_by_id('CreateNewSubAccountDialog--providersCombo')
        providersComboInput.click()
        try:
            WebDriverWait(driver,10).until(cond.visibility_of_element_located((By.ID, "__item8-CreateNewSubAccountDialog--providersCombo-0")))
        except (ElementNotVisibleException) as py_ex:
            print("Element not visible.")
            print (py_ex)
            print (py_ex.args)
        providersComboSelect = driver.find_element_by_id('__item8-CreateNewSubAccountDialog--providersCombo-0')
        providersComboSelect.click()
        try:
            WebDriverWait(driver,10).until(cond.visibility_of_element_located((By.ID, "CreateNewSubAccountDialog--regionsCombo")))
        except (ElementNotVisibleException) as py_ex:
            print("Element not visible.")
            print (py_ex)
            print (py_ex.args)
        driver.get_screenshot_as_file('/root/app/pages/' + 'page06.png')
        ##Amazon Web Services (AWS)
        #providersComboInput.send_keys('Amazon Web Services (AWS)')
        ##CreateNewSubAccountDialog--regionsCombo-hiddenInput
        #$("#CreateNewSubAccountDialog--regionsCombo-hiddenInput").tap();
        #$("#__item9-CreateNewSubAccountDialog--regionsCombo-6").tap();
        time.sleep(1)
        regionsComboInput = driver.find_element_by_id('CreateNewSubAccountDialog--regionsCombo')
        regionsComboInput.click()
        try:
            WebDriverWait(driver,10).until(cond.visibility_of_element_located((By.ID, "__item9-CreateNewSubAccountDialog--regionsCombo-6")))
        except (ElementNotVisibleException) as py_ex:
            print("Element not visible.")
            print (py_ex)
            print (py_ex.args)
        regionsComboSelect = driver.find_element_by_id('__item9-CreateNewSubAccountDialog--regionsCombo-6')
        regionsComboSelect.click()
        try:
            WebDriverWait(driver,10).until(cond.visibility_of_element_located((By.ID, "CreateNewSubAccountDialog--subdomain-inner")))
        except (ElementNotVisibleException) as py_ex:
            print("Element not visible.")
            print (py_ex)
            print (py_ex.args)
        driver.get_screenshot_as_file('/root/app/pages/' + 'page07.png')
        ##US East (VA)
        #regionsComboInput.send_keys('US East (VA)')
        ##CreateNewSubAccountDialog--subdomain-inner
        subdomain = driver.find_element_by_id('CreateNewSubAccountDialog--subdomain-inner')
        #$("#CreateNewSubAccountDialog--subdomain-inner").val("abcheadless");
        subdomain.send_keys('xyzheadless')
        ##CreateNewSubAccountDialog--betaEnabledCF-CB
        #$("#CreateNewSubAccountDialog--betaEnabledCF-CB").tap();
        #$("#CreateNewSubAccountDialog--subdomain-inner").focus();
        #$("#CreateNewSubAccountDialog--subdomain-inner").next().next().next().focus();
        #displayName.sendKeys(Keys.TAB)
        subdomain.send_keys(Keys.TAB)
        #try:
        #    WebDriverWait(driver,20).until(cond.visibility_of_element_located((By.ID, "CreateNewSubAccountDialog--betaEnabledCF-CB")))
        #except (ElementNotVisibleException) as py_ex:
        #    print("Element not visible.")
        #    print (py_ex)
        #    print (py_ex.args)
        driver.get_screenshot_as_file('/root/app/pages/' + 'page08.png')
        #betaEnabledCF = driver.find_element_by_id('CreateNewSubAccountDialog--betaEnabledCF-CB')
        #betaEnabledCF.click()
        #try:
        #    WebDriverWait(driver,5).until(cond.visibility_of_element_located((By.ID, "__button11")))
        #except (ElementNotVisibleException) as py_ex:
        #    print("Element not visible.")
        #    print (py_ex)
        #    print (py_ex.args)
        ##__button11 #Create Button
        #$("#__button11").tap();
        #__button24
        #$("#__button24").mouseup();
        createButton = driver.find_element_by_id('__button11')
        #time.sleep(1)
        createButton.click()
        time.sleep(1)
        try:
            WebDriverWait(driver,2).until(cond.visibility_of_element_located((By.ID, "CreateNewSubAccountDialog--errorStrip")))
            output += "subDomain taken!"
        except (ElementNotVisibleException) as py_ex:
            output += "subDomain is OK!"

        driver.get_screenshot_as_file('/root/app/pages/' + 'page09.png')
        ##__popover8
        #doneMessage = driver.find_element_by_id('__popover8')
        #time.sleep(1)
        ##time.sleep(1)
        #driver.get_screenshot_as_file('/root/app/pages/' + 'page09.png')
        driver.quit()

    except:
        import traceback;traceback.print_exc() 

    output += "</body>\n"
    output += "</html>\n"
    output += '\n'
    return Response(output, mimetype='text/html' , status=200,)

@app.route('/headless/pagelist')
def headless_page_list():
    return send_from_directory('/root/app/pages', 'index.html', mimetype='text/html')

@app.route('/headless/pages')
def headless_pages():
    return send_from_directory('/root/app/pages', 'page' + request.args.get('page') + '.png', mimetype='image/png')

@app.route('/headless/post', methods=['POST'])
def unauth_post():
    output = 'Python Post to DB (Dangerous!). \n'
    output += '\n'
    output += 'Receiving module should check that it came from our approuter and verify or abort if otherwise.\n'
    output += '\n'

    content = request.json

    output += content

    return Response(output, mimetype='application/json' , status=201,)

@app.route('/headless/set_env')
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

@app.route('/headless/env')
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

@app.route('/headless/attach')
def do_attach():
    output = '\n Attaching to debugger... \n'
    attach(5678,"localhost")
    output += '\n Set some breakpoints...\n'
    return output

# If there is a request for a python/test2, return Testing message and then check JWT and connect to the data service and retrieve some data
@app.route('/headless/db_only')
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
@app.route('/headless/admin/authcheck')
def auth_check():
    output = 'Python Authorized DB Validated Request. \n'
    output += '\n'
    output += 'Receiving module should check that it came from our approuter and verify or abort if otherwise.\n'
    output += '\n'
    svcs_json = str(os.getenv("VCAP_SERVICES", 0))
    svcs = json.loads(svcs_json)

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
    output += 'get_subdomain: ' + security_context.get_subdomain() + '\n'
#    output += 'get_clientid: ' + security_context.get_clientid() + '\n'
    output += 'get_identity_zone: ' + security_context.get_identity_zone() + '\n'
    output += 'get_grant_type: ' + security_context.get_grant_type() + '\n'
    
    return output

if __name__ == '__main__':
    # Run the app, listening on all IPs with our chosen port number
    # Use this for production 
    #app.run(host='0.0.0.0', port=port)
    # Use this for debugging 
    app.run(debug=True, host='0.0.0.0', port=port)

