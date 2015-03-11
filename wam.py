#!/usr/bin/python
# Report generator
import api
import fn
import sys
import dumper
import json
import subprocess
import postfile   # used by VirusTotal API

def main(argv):
    config = {}
    config["usagetext"] = ("repgen.py (-s SEARCHPREFIX|-a) [-c CONFIGFILE]\n"+
            "  This script generates a report for all servers if -a is used,\n"+
            "or just the servers with SEARCHPREFIX in the server label if -s is used.\n\n"+
            "Make sure you correctly configure config.conf.\n"+
            "you can use -c to specify a different configuration file.  Otherwise, ./config.conf is assumed.\n\n"
            "In config.conf: search_field will determine the metadata field that SEARCHPREFIX is applied to\n"+
            "  to create the list of servers that will be reported on.\n"+
            "The output configuration value  will determine the output format for the information.\n"+
            "  Text is mainly for debugging and may not produce as much meaningful information as html or pdf.\n"+
            "  HTML and PDF files are placed in the ./outfile folder.  If it doesn't exist, the script will fail.")
    config["configfile"] = "config.conf"
    serverolist = []
    config = fn.set_config_items(config,argv)
    serverolist = fn.build_server_list(config['host'], config['authtoken'], config['search_string'], config['search_field'], config['prox'])
    serverolist = fn.enrich_server_data(config['host'], config['authtoken'], serverolist, config['prox'])

    #dump here for whack-a-mole
    filenum = 0
    for s in serverolist:
        #for each server, create a file of hashes to send to VirusTotal
        # and create a file of filename/hashes for our report.
        vtfile = open("hashes" + str(filenum) + ".txt","w")
        wamfile = open("wam" + str(filenum) + ".txt","w")
        #filenum increments at bottom of loop

        #Drill down through the JSON to get to the hashes, if they exist
        total_objects = s.issues['baseline']['details']['total_objects']
        targets = s.issues['baseline']['details']['targets']#['objects']['contents']
        #print json.dumps( targets, sort_keys=True, indent=2)
        for objects in targets:
#            print json.dumps(objects, sort_keys=True, indent=4)
            if objects  is None:
                print "no objects"
            else:
                number_of_objects = objects['number_of_objects']
#                print number_of_objects
                if number_of_objects > 0:
                    object = objects['objects']
#                    print json.dumps(objects['objects'], sort_keys=True, indent=4)
                    for i in range(number_of_objects):
                        if object is None:
                            print "no contents"
                        else:
#                            print json.dumps(object, sort_keys=True, indent=4)
                             #print json.dumps(object[0]['contents'], sort_keys=True, indent=4)
                             
                             # Print hashes, culling out &hellip and @.
                             hash = object[0]['contents']
                             if "..." not in hash and "at" not in hash:
                                 wamfile.write(str(s.name) + ", " + str(object[0]['filename']) + ", " + str(hash) + "\n")
                                 vtfile.write(hash + "\n")

        vtfile.close() #input to VirusTotal
        wamfile.close()#same as vtfile plus extra data needed for WAM report

        #send the file of hashes for this server to VirusTotal. 
        #save the 'resource' field to get results later
        host = "www.virustotal.com"
        selector = "https://www.virustotal.com/vtapi/v2/file/scan"
        fields = [("apikey", config['virus_total_key'])]
        file_to_send = open("hashes" + str(filenum) + ".txt", "rb").read()
        files = [("file", "hashes" + str(filenum) + ".txt", file_to_send)]
        vt_out = postfile.post_multipart(host, selector, fields, files)
        vt = json.loads( vt_out )
        if vt["response_code"] == 1:
            s.resource = vt["resource"]
        else:
            print("VirusTotal response_code was %d\n", vt["response_code"])
            print("I'm skipping this file, and there's going to be an error")
            s.resource = None

        #increment filenum for the next iteration through the loop
        filenum = filenum + 1

        #HERE we need to put the contents of 'wamfile' and 'a' and put into 'serverolist'
        # ...but instead I'm writing out to files, then reading them again inside 'handle_output'
        #TO DO this right, use the call below. put output 'a' into serverolist somehow.
        # a = subprocess.Popen("uirusu -f hashes.txt", stdout=subprocess.PIPE, shell=True).stdout.read()
        # print a
        # the above subprocess call works, but so does this:
        #subprocess.Popen("uirusu -f hashes.txt > vt.txt", stdout=subprocess.PIPE, shell=True).stdout.read()

# Here we re-write the config if the logo file is on the local filesystem, because relative paths don't work well with PDF rendering.
    if fn.where_is_img(config['logo_url'])[0] == 'local' and config['output'] == 'pdf':
        try:
            config['logo_url'] = fn.where_is_img(config['logo_url'])[1]
        except:
# Here we empty that field in case the data was bad...
            config['logo_url'] = ''
    fn.handle_output(config, serverolist)

if __name__ == "__main__":
    main(sys.argv[1:])
