#!/usr/bin/python
# Report generator
import api
import fn
import sys
import dumper
import json

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
        #print json.dumps( targets, sort_keys=True, indent=4)
        for objects in targets:
#            print json.dumps(objects, sort_keys=True, indent=4)
            if objects  is None:
                print "no objects"
            else:
                number_of_objects = objects['number_of_objects']
                if number_of_objects > 0:
                    object = objects['objects']
                    print json.dumps(objects['objects'], sort_keys=True, indent=4)

#                    print objects['number_of_objects']
                    for j in objects:
                        object = json.dumps( j, sort_keys=True, indent=4)
                        #if object is "\"objects\"":
                         #   print object
                        if object[1] is 'o':
                            print object
                            #hash = json.dumps( object['contents'], sort_keys=True, indent=4)
                            #print hash                            
#        print targets[3]
#        print json.dumps(targets['objects']['contents'])
#        print total_objects
#        break
#        for i in range(total_objects):
#            print i
#           if targets[i]['number_of_objects'] > 0:
#                print json.dumps(targets[i]['number_of_objects'])
                #print targets[i]['objects']    #This is as as I've gotten to accessing 'contents' without exception.
     
                #print json.dumps( targets[i]['objects']['contents'], sort_keys=True, indent=4)
                #contents = s.issues['baseline']['details']['targets']['objects']['contents']
                #print json.dumps(contents, sort_keys=True, indent=4)

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
