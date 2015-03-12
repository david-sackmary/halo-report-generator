#!/usr/bin/python
# We use these functions for crunching data
import csv  # remove later
import json
import urllib
import urllib2

from operator import itemgetter
from collections import OrderedDict

def get_server_csm_stats(server):
    good = 0
    bad = 0
    indeterminate = 0
# may not exist, use try/except to fail through
    try:
        deadvar = server.issues['sca']['findings']
    except:
        return({'good':good,
                'bad':bad,
                'indeterminate':indeterminate})
    for issue in server.issues['sca']['findings']:
        for entry in issue['details']:
            if entry['status'] == 'bad':
                bad += 1
            elif entry['status'] == 'indeterminate':
                indeterminate += 1
            elif entry['status'] == 'good':
                good += 1
    retval = {'good':good,
            'bad':bad,
            'indeterminate':indeterminate}
    return(retval)

def get_server_fim_stats(server):
    virus = 0
    safe = 0
    unknown = 0

    #wamfile = open("wam.txt","w")
    #vtfile = open("vt.txt","w")
    #server_list = list(csv.reader(open("wam.txt", 'rb'), delimiter=', ', skipinitialspace=True))
    #vt_list = list(csv.reader(open("vt.txt", 'rb'), delimiter=' ', skipinitialspace=True))

    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": server.resource,
                  "apikey": "bbcbdebbe6503a2efb02553ffc4a07d9f0d338ae314c70b3556ad0573221545c"}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    jsona = response.read()
    response_dict = json.loads(jsona)
    print response_dict
    print response_dict['total']
    print response_dict['positives']
    print server.name
    print server.resource
#### NOTE - this scan might be only for the 1st hash?  or all hashes for that server?  figure this out@@@
    infected = response_dict['positives']
    safe = response_dict['total'] - response_dict['positives']
    unknown = 1

    retval = {'known_virus':infected, 
              'known_safe':safe,
              'unknown':unknown}
    return(retval)

def get_server_sva_stats(server):
    critical = 0
    non_critical = 0
    # Here if we can' set deadvar, it's assumed that there are no SVA results for that host.  So we fail through.
    try:
        deadvar = server.issues['svm']['findings']
    except:
        retval = {'critical':critical,'non_critical':non_critical}
        return(retval)
    for issue in server.issues['svm']['findings']:
        if issue['status'] == 'bad':
            if issue['critical'] == True:
                critical += 1
            elif issue['critical'] == False:
                non_critical += 1
    retval = {'critical':critical,
            'non_critical':non_critical}
    return(retval)

def all_server_stats(servers):
    all_cves = []
    all_crit_pkgs = []
    all_noncrit_pkgs = []
    retval_cve = {}
    retval_crit_pkg = {}
    retval_noncrit_pkg = {}
    for s in servers:
        try:
            deadvar = s.issues['svm']['findings']
        except:
            continue
        for issue in s.issues['svm']['findings']:
            if issue['status'] == 'bad':
                for entry in issue['cve_entries']:
                    if entry['suppressed'] == False:
                        all_cves.append(entry['cve_entry'])
    cve_consolidate = set(all_cves)
    cve_consolidated = sorted(list(cve_consolidate), key=itemgetter(1))
    for u_cve in cve_consolidated:
        retval_cve[str(u_cve)] = all_cves.count(str(u_cve))
    for t in servers:
        try:
            deadvar = t.issues['svm']['findings']
        except:
            continue
        for issue in t.issues['svm']['findings']:
            if issue['status'] == 'bad':
                if issue['critical'] == True:
                    all_crit_pkgs.append(str(issue['package_name'] + issue['package_version']))
                elif issue['critical'] == False:
                    all_noncrit_pkgs.append(str(issue['package_name'] + issue['package_version']))
    noncrit_pkgs_consolidated = set(all_noncrit_pkgs)
    noncrit_pkgs_consolidated = sorted(list(noncrit_pkgs_consolidated))
    crit_pkgs_consolidated = set(all_crit_pkgs)
    crit_pkgs_consolidated = sorted(list(crit_pkgs_consolidated))
    for u_cpkg in crit_pkgs_consolidated:
        retval_crit_pkg[str(u_cpkg)] = all_crit_pkgs.count(str(u_cpkg))
    for u_ncpkg in noncrit_pkgs_consolidated:
        retval_noncrit_pkg[str(u_ncpkg)] = all_noncrit_pkgs.count(str(u_ncpkg))
    return(retval_cve, retval_noncrit_pkg, retval_crit_pkg)


