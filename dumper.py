#!/usr/bin/python
# This is where all of our printout magic happens

import json
import markdown
import cruncher
import fn
import operator
import itertools
import time
import sys

def write_out(prefix, formt, content):
    engine = ''
    try:
        from xhtml2pdf import pisa
        engine = 'x2p'
    except:
        pass
    try:
        import pdfkit
        engine = 'pdfkit'
        print "Successfully initialized pdfkit."
    except:
        pass
    fullname = './outfiles/' + str(prefix)+'.'+str(formt)
    if formt == 'pdf':
        if engine == '':
            print '''\n\nERROR: No PDF rendering engines available.\n
            Supported engines: xhtml2pdf and pdfkit.\n
            Please change output format or install a supported rendering engine'''
            sys.exit(2)
        elif engine == 'x2p':
            r = open(fullname, 'w+b')
            pisa_status = pisa.CreatePDF(content, dest=r)
            r.close()
            if pisa_status == False:
                print "Bad stuff happened. PDF may not have been written"
            else:
                print fullname + " has been created using xhtml2pdf!"
        elif engine == 'pdfkit':
            try:
                pdfkit.from_string(content, fullname)
                print fullname + " has been created using pdfkit!"
            except IOError as e:
                print "I/O error({0}): {1}".format(e.errno, e.strerror)
                print "Make sure you've installed wkhtmltopdf binaries and they're in your PATH!"
                sys.exit(2)
    else:
        f = open(fullname, 'w')
        f.write(content)
        f.close
        print "Wrote output file: " + fullname

def html(objex,prefix,formt,logo_url):
    raw_reports = {}
    tstamp = str(time.strftime("%Y-%m-%d %H:%M"))
    complete_contents = ''
    csm_contents = ''
    fim_contents = ''
    sva_contents = ''
    head = '''<html><head>
    <meta name="pdfkit-orientation" content="Landscape"/>
    <style>
    @page {size:letter landscape;
           margin: 2cm;
               }
    table {table-layout: fixed;
           width: 100%;}
    td    {border: 1px solid black;
           border-collapse: collapse;
           padding-left: 5px;
           padding-top: 5px;
           padding-right:5px;
           word-wrap:break-word;}
    p     {word-wrap:break-word;}
    body  {padding-left: 20px;}
    </style>
                </head><body>
                '''
    closer = '</body></html>'
    logo = '![Logo](' + logo_url + ')\n'
    masthead_complete = '#Masthead Complete\n##' + tstamp
    masthead_csm = '#Configuration Compliance Report\n##' + tstamp
    masthead_fim = '#File Integrity Management and VirusTotal Report\n##' + tstamp
    masthead_sva = '#Software Vulnerability Report\n##' + tstamp
    cve_summary, ncrit_pkg_summary, crit_pkg_summary = cruncher.all_server_stats(objex)
    summary_content = str(generate_summary_content(cve_summary, ncrit_pkg_summary, crit_pkg_summary))
    for s in objex:
        server, csm, fim, sva = generate_server_content(s)
        complete_contents = complete_contents + str(str(server) + str(csm) + str(fim) + str(sva))
        csm_contents = csm_contents + str(str(server) + str(csm))
        fim_contents = fim_contents + str(str(server) + str(fim))
        sva_contents = sva_contents + str(str(server) + str(sva))
    raw_reports['complete'] = str(logo + masthead_complete + str(summary_content) + str(complete_contents))
    raw_reports['sva'] = str(logo + masthead_sva + str(summary_content) + str(sva_contents))
    raw_reports['csm'] =str(logo + masthead_csm + str(csm_contents))
    raw_reports['fim'] =str(logo + masthead_fim + str(fim_contents))

    for rtype in ['complete', 'csm', 'fim', 'sva']:
        file_name = prefix + '-' + rtype
        html_content_from_md = markdown.markdown(raw_reports[rtype])
        html_content = str(head) + str(html_content_from_md) + str(closer)
        write_out(file_name, formt, html_content)
    return

def generate_summary_content(cve, ncpkg, cpkg):
    ret_csm = ''
    top_ten_cve = sorted(cve.items(), key=operator.itemgetter(1), reverse=True)[:10]
    top_ten_ncp = sorted(ncpkg.items(), key=operator.itemgetter(1), reverse=True)[:10]
    top_ten_cpk = sorted(cpkg.items(), key=operator.itemgetter(1), reverse=True)[:10]
    cve_header = '\n\n###Top Ten CVEs:'
    cve_body = ''
    cpk_header = '\n\n###Top Ten Critically Vulnerable Packages:'
    cpk_body = ''
    ncp_header = '\n\n###Top Ten Non-Critically Vulnerable Packages:'
    ncp_body = ''
    for cve, count in top_ten_cve:
        cve_body = cve_body + str('\n1. [' + str(cve) + '](' + str(fn.enrich_cve(cve)) + ') ' + str(count)  )
    for cpk, count in top_ten_cpk:
        cpk_body = cpk_body + str('\n1. ' + str(cpk) + '       ' + str(count)  )
    for ncp, count in top_ten_ncp:
        ncp_body = ncp_body + str('\n1.     ' + str(ncp) + '       ' + str(count)  )
    ret_csm = str(cve_header) + str(cve_body) + str(cpk_header) + str(cpk_body) + str(ncp_header) + str(ncp_body) + '\n---\n\n'
    return(ret_csm)

def generate_server_content(s):
    mdown_server = ''
    mdown_csm = ''
    mdown_fim = ''
    mdown_sva = ''
    servername = s.name
    serverid = s.id
    serverlabel = s.label
    servergroup = s.group_name
    issues = s.issues
    csm_stats = cruncher.get_server_csm_stats(s)
    fim_stats = cruncher.get_server_fim_stats(s)
    sva_stats = cruncher.get_server_sva_stats(s)
    mdown_server = mdown_server + '\n\n##Host Name: ' + str(servername) + '\n\n###Label: ' + str(serverlabel) + '\n\n###Group: ' + str(s.group_name)
    mdown_csm = mdown_csm + '\n\n###Configuration Compliance Summary:\n* Good: ' + str(csm_stats['good']) + '\n* Bad: ' + str(csm_stats['bad']) + '\n* Indeterminate: ' + str(csm_stats['indeterminate'])
    mdown_fim = mdown_fim + '\n\n###VirusTotal Summary:\n* Infected: ' + str(fim_stats['known_virus']) + '\n* Good: ' + str(fim_stats['known_safe']) + '\n* Unknown: ' + str(fim_stats['unknown'])
    mdown_sva = mdown_sva + '\n\n###Software Vulnerability Assessment Summary:\n* Critical: ' + str(sva_stats['critical']) + '\n* Non-critical: ' + str(sva_stats['non_critical'])
    mdown_csm = mdown_csm + str(md_render_csm(issues))
    mdown_fim = mdown_fim + str(md_render_fim(issues))
    mdown_sva = mdown_sva + str(md_render_sva(issues))
    return(mdown_server, mdown_csm, mdown_fim, mdown_sva)

def md_render_csm(i):
    ret_md = ''
#Gives us json, we give back beautiful text.
    ret_md = ret_md + "\n\n###Configuration Vulnerabilities:\n\n<table><tr><td>Name</td><td>Type</td><td>Target</td><td>Expected</td><td>Actual</td></tr>"
    try:
        for issue in i['sca']['findings']:
            if issue['status'] == 'bad':
                iname = issue['rule_name']
                for entry in issue['details']:
                    if entry['status'] == 'bad':
                        ret_md = ret_md + '<tr><td>' + str(iname) + '</td><td>' + str(entry['type']) + '</td><td><p> ' + str(entry['target']) + '</p></td><td><p>' + str(entry['expected']).replace('\|','\\|') + '</p></td><td><p>' + str(entry['actual']).replace('\|','\\|') + '</p></td></tr>'
        ret_md = ret_md + "</table>\n\n---\n"
    except:
        ret_md = ret_md + '<tr><td style="color:red;">NO CONFIGURATION ASSESSMENT RESULTS AVAILABLE</td><td></td><td></td><td></td><td></td></table>'
    return(ret_md)

def md_render_fim(i):
    ret_md = ''
    ret_md = ret_md + "\n\n###File Integrity:\n\n<table><tr><td>Server</td><td>File</td><td>Hash</td><td>Infection</td></tr>"

#DAVE KNOWS
#open file here and fill in values for the tables
#or maybe values were filled in by get_server_fim_stats
    try:
        for issue in i['fim']['findings']:
            if issue['status'] == 'bad':
                cvelist = []
                for entry in issue['cve_entries']:
                    if entry['suppressed'] == False:
                        cvelist.append(entry['cve_entry'])
                cve_enriched = fn.enrich_cve_list(cvelist)
                cve_html = fn.cve_e_to_html(cve_enriched)
                ret_md = ret_md + '<tr><td>' + str(issue['package_name']) + '</td><td>' + str(issue['package_version']) + '</td><td>' + str(issue['critical']) + '</td><td>' + cve_html + '</td></tr>'
        ret_md = ret_md + "</table>\n\n---\n"
    except:
        ret_md = ret_md + '<tr><td style="color:red;">NO VIRUS TOTAL RESULTS AVAILABLE</td><td></td><td></td><td></td><td></td></table>'
    return(ret_md)

def md_render_sva(i):
    ret_md = ''
    ret_md = ret_md + "\n\n###Software Vulnerabilities:\n\n<table><tr><td>Package</td><td>Version</td><td>Critical</td><td>CVEs</td></tr>"
    try:
        for issue in i['svm']['findings']:
            if issue['status'] == 'bad':
                cvelist = []
                for entry in issue['cve_entries']:
                    if entry['suppressed'] == False:
                        cvelist.append(entry['cve_entry'])
                cve_enriched = fn.enrich_cve_list(cvelist)
                cve_html = fn.cve_e_to_html(cve_enriched)
                ret_md = ret_md + '<tr><td>' + str(issue['package_name']) + '</td><td>' + str(issue['package_version']) + '</td><td>' + str(issue['critical']) + '</td><td>' + cve_html + '</td></tr>'
        ret_md = ret_md + "</table>\n\n---\n"
    except:
        ret_md = ret_md + '<tr><td style="color:red;">NO SOFTWARE VULNERABILITY RESULTS AVAILABLE</td><td></td><td></td><td></td><td></td></table>'
    return(ret_md)

def print_server_stuff_plain(objex):
    for s in objex:
#Accepts a server object
        print "Server ID:"      , s.id
        print "Server Name:"    , s.name
        print "Server Label:"   , s.label
        print "---------------------------------------------------------------\n"
        print str(tabular_text_dump_csm(s.issues))
        print "---------------------------------------------------------------\n"
        print str(tabular_text_dump_sva(s.issues))
        print "---------------------------------------------------------------\n\n\n"

def tabular_text_dump_sva(j):
#Gives us json, we give back beautiful text.
    ret_txt = ''
    ret_txt = ret_txt+"Software Vulnerabilities:\nPackage | Version | Critical | CVEs\n"
    for issue in j['svm']['findings']:
        if issue['status'] == 'bad':
            cvelist = []
            for entry in issue['cve_entries']:
                if entry['suppressed'] == False:
                    cvelist.append(entry['cve_entry'])
            ret_txt = ret_txt + str(issue['package_name']) + " | " + str(issue['package_version']) + ' | ' + str(issue['critical']) + ' | ' + str(cvelist) + '\n'
    return(ret_txt)

def tabular_text_dump_csm(j):
    ret_txt = ''
#Gives us json, we give back beautiful text.
    ret_txt = ret_txt + "Configuration Vulnerabilities: Name | Type | Target | Expected | Actual \n"
    try:
        for issue in j['sca']['findings']:
            if issue['status'] == 'bad':
                iname = issue['rule_name']
                for entry in issue['details']:
                    if entry['status'] == 'bad':
                        ret_txt = ret_txt + str(iname) + " | " + str(entry['type']) + ' | ' + str(entry['target']) + ' | ' + str(entry['expected']) + ' | ' + str(entry['actual']) + '\n'
        return(ret_txt)
    except:
        return("No Configuration Vulnerabilities")






