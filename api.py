#!/usr/bin/python
#
# DON'T FORGET TO SET THE API KEY/SECRET.



import urllib
import httplib
import base64
import json
import urlparse
import sys

def apihit(host,conntype,authtoken,queryurl,reqbody):
    retdata = ''
    connection = httplib.HTTPSConnection(host)
    tokenheader = {"Authorization": 'Bearer ' + authtoken, "Content-type": "application/json", "Accept": "text/plain"}
    if conntype == "GET":
        connection.request(conntype, queryurl, '', tokenheader)
    else:
        connection.request(conntype, queryurl, json.dumps(reqbody), tokenheader)
    response = connection.getresponse()
    respbody = response.read().decode('ascii', 'ignore')
    try:
        jsondata = respbody.decode()
        retdata = json.loads(jsondata)
    except:
        retdata = respbody.decode()
    connection.close()
    return retdata

def get_auth_token(host,clientid,clientsecret):
    # Get the access token used for the API calls.
    connection = httplib.HTTPSConnection(host)
    authstring = "Basic " + base64.b64encode(clientid + ":" + clientsecret)
    header = {"Authorization": authstring}
    params = urllib.urlencode({'grant_type': 'client_credentials'})
    connection.request("POST", '/oauth/access_token', params, header)
    response = connection.getresponse()
    jsondata =  response.read().decode()
    data = json.loads(jsondata)
    try:
        if 'read+write' not in data['scope']:
            print "This script requires RW api access.  Exiting"
            sys.exit(2)
    except:
        print "We're having trouble getting a session token.  Please check your API key."
        print "Error output: "
        print data
        sys.exit()
    key = data['access_token']
    connection.close()
    return key

