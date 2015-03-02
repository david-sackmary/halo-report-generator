#!/usr/bin/python
# Report generator
import api
import fn
import sys
import dumper
import json
#import subprocess
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
    for s in serverolist:
        total_objects = s.issues['baseline']['details']['total_objects']
        targets = s.issues['baseline']['details']['targets']#['objects']['contents']
        #print json.dumps( targets, sort_keys=True, indent=2)

        vtfile = open("hashes.txt","w")
        wamfile = open("wam.txt","w")
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
#                            print json.dumps(object[0]['contents'], sort_keys=True, indent=4)
                             
                             # Print hashes, culling out &hellip and @.
                             hash = object[0]['contents']
                             if "..." not in hash and "at" not in hash:
                                 wamfile.write(str(s.name) + ", " + str(object[0]['filename']) + ", " + str(hash) + "\n")
                                 vtfile.write(hash + "\n")
        vtfile.close()
        wamfile.close()
        host = "www.virustotal.com"
        selector = "https://www.virustotal.com/vtapi/v2/file/scan"
        fields = [("apikey", "bbcbdebbe6503a2efb02553ffc4a07d9f0d338ae314c70b3556ad0573221545c")]
        file_to_send = open("hashes.txt", "rb").read()
        files = [("file", "hashes.txt", file_to_send)]
        json = postfile.post_multipart(host, selector, fields, files)
        print json
#       subprocess.Popen("uirusu -f hashes.txt > vt.txt", stdout=subprocess.PIPE, shell=True).stdout.read()

if __name__ == "__main__":
    main(sys.argv[1:])