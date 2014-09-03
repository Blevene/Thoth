Thoth
=====

md5 hash generator + yara rules scanner

Configuration file should be located in /etc/thoth.ini (or edit the script to point to where you want!)

Logs are located in /var/log/Thoth.log, note you may need to make this file and chmod it 644

-------------------
python reporter_poc.py -h

usage: reporter_poc.py [-h] [--rules RULES] [--input INPUT] [-b]

Used to scan a given directory with a provided set of yara rules.

optional arguments:
  
  -h, --help     show this help message and exit
  
  --rules RULES  specify a rules file other than the default, supplied in
                 thoth.ini
  
  --input INPUT  specify a folder or file to be scanned
 
  -b, --bro      mandatory for parsing bro uids from a filename
  
  -m, --move     use this switch to tell the script to move matches to a
                 directory specified in thoth.ini

