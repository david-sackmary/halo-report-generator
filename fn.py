#!/usr/bin/python
# General functions
import server
import re
import sys
import getopt
import api
import json
import dumper

def enrich_cve_list(cves):
    retlist = {}
    urlbase = 'https://web.nvd.nist.gov/view/vuln/detail?vulnId='
    for cve in cves:
        name = str(cve)
        url  = urlbase + name
        retlist[name] = url
    return(retlist)

def enrich_cve(cve):
    urlbase = 'https://web.nvd.nist.gov/view/vuln/detail?vulnId='
    name = str(cve)
    url  = urlbase + name
    return(url)

def cve_e_to_html(cve_enriched):
    html = ''
    for c, l in cve_enriched.iteritems():
        html = html + str('<a href="' + str(l) + '">' + str(c) + '</a> ')
    return(html)

def build_server_list(host, authtoken, srch, field):
    queryurl = '/v1/servers'
    jsondata = api.apihit(host, 'GET', authtoken, queryurl, '')
    server_list = []
    if srch == 'ALL':
        prefix = '^.*'
    else:
        prefix = '^'+str(srch)+'.*'
    relevant_servers = distil_server_list(jsondata, prefix, field)
    for s in relevant_servers:
        name = s["hostname"]
        label = s["server_label"]
        ident = s["id"]
        gname = s["group_name"]
        server_list.append(server.Server(name, ident, label, gname))
    if server_list == []:
        print "Did not find any matching servers to report on!"
        sys.exit(2)
    else:
        return(server_list)

def enrich_server_data(host, authtoken, slist):
    returned_dataz = []
    for s in slist:
        s.issues = get_server_issues(host, authtoken, s.id)
        returned_dataz.append(s)
    return(returned_dataz)

def distil_server_list(jdata, prefix, field):
    rexall = re.compile(prefix)
    relevant_list = []
    for s in jdata['servers']:
        svr_dataz = {}
        if s[field] == None:
#We set the label to ' ' instead of None, so we don't have a data type issue later on...
            s[field] = ' '
        if rexall.match(s[field]):
            relevant_list.append(s)
    return(relevant_list)

def get_server_issues(host,authtoken,node_id):
    queryurl = '/v1/servers/'+str(node_id)+'/issues'
    results = api.apihit(host, 'GET', authtoken, queryurl, '')
    return(results)

def set_config_items(config,argv):
    try:
        opts, args = getopt.getopt(argv, "hs:a",["search_string="])
    except getopt.GetoptError:
        print config['usagetext']
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print config['usagetext']
            sys.exit()
        elif opt == '-a':
            config['search_string'] = 'ALL'
        elif opt in ("-s","--search_string"):
            config['search_string'] = arg
    if not sanity_check(config):
        print "Config is not sane!"
        sys.exit(2)
    config['authtoken'] = api.get_auth_token(config['host'], config['clientid'], config['clientsecret'])
    return(config)

def sanity_check(c):
    search_fields = ["server_label", "hostname", "reported_fqdn", "group_name"]
    output_formats = ["text", "pdf", "html",""]
    insane = False
    if c['host'] == '':
        print "No hostname defined!"
        insane = True
    if c['clientid'] == '':
        print "No clientid defined!"
        insane = True
    if c['clientsecret'] == '':
        print "No clientsecret defined!"
        insane = True
    try:
        if not c['search_string']:
            print "No search string defined!"
            insane = True
        elif c['search_string'] == '':
            print "Scope of report not defined!"
            print "Need to state the search prefix!"
            print c['usagetext']
            insane = True
    except:
        print "Bad search string!  Check your syntax!"
        insane = True
    try:
        if not c['output']:
            print "No output defined!"
            insane = True
        elif c['output'] not in output_formats:
            print "Report output not correctly defined!"
            insane = True
    except:
        print "Bad search string!  Check your syntax!"
    if c['search_field'] not in search_fields:
        print "Bad search field value!"
        insane = True
    if insane == True:
        return False
    else:
        return True

def handle_output(config, serverolist):
    if config['output'] != None:
        if config['output'] in ('html','pdf'):
            dumper.html(serverolist, config['search_string'],config['output'])
    if config['output'] == None:
        dumper.print_server_stuff_plain(serverolist)
