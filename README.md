Whack-A-Mole
=====================

Generate Virus Total reports for FIM Halo modules

###Dependency:
+ **Uirusu**    Must git this too:  https://github.com/arxopia/uirusu
+ 
###Files:
* **README.md**   The one you're reading now...
* **api.py**   The last stop before crossing the interwebs
* **assets/**   This is where we put logo files...
* **config.conf**   This is the default configuration file.
* **cruncher.py**   This contains functions related to data crunching.
* **dumper.py**   This handles output formatting
* **fn.py**   Misc functions here
* **license.txt**   The cure for insomnia
* **outfiles/**   Output files get dropped here
* **server.py**   Server object definition
* **wam.py**   RUN THIS ONE.  Accepts -s SearchString or -a for all.  Optionally declare another config file with -c

###Usage:

>wam.py (-s SEARCHPREFIX|-a) [-c CONFIGFILE]

>This script generates a report for all servers if -a is used, or just the servers with SEARCHPREFIX in the server label if -s is used.

>Make sure you correctly configure config.conf.  You can use -c to specify a different configuration file.  Otherwise, ./config.conf is assumed.  In config.conf: search_field will determine the metadata field that SEARCHPREFIX is applied to
to create the list of servers that will be reported on.

