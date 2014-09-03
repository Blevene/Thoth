#!/home/blevene/anaconda/bin/python
# "Thoth" file reporter
import yara
import os
import hashlib
import json
import logging
from ConfigParser import SafeConfigParser
import argparse

#Loggin Setup
logging.basicConfig(level=logging.INFO,
    format='%(asctime)s %(message)s', 
    filename='/home/blevene/Thoth.log')

# Define all the crap in a config file
configurator = SafeConfigParser()
configurator.read('/etc/thoth.ini')

#hash the files
def md5sum(filename):
    hashes = []
    for i in filename:
        #print i
        fh = open(i, 'rb')
        m = hashlib.md5()
        while True:
            data = fh.read(8192)
            if not data:
                break
            m.update(data)
        hashes.append(m.hexdigest())
    return hashes
#Move files to another location to mark that they have been analyzed
#and are ready for phase 2 (dynamic analysis)
#taken from MIDAS (https://github.com/Xen0ph0n/MIDAS/blob/master/midas.py)
def moveFiles(movepath, filename, name):
	if not os.path.exists(movepath):
		os.makedirs(movepath)
	shutil.move(filename, movepath + name)
	logging.info(filename + " has been moved to " + movepath + name)

# take all the file names from the directory and put into a list
# taken from MIDAS (https://github.com/Xen0ph0n/MIDAS)
def buildFilelist(directory):
    filelist = []
    for root, dirs, files in os.walk(directory):
        for name in files:
            if os.stat(os.path.join(root, name)).st_size > 0: # 0 byte files make Yara puke
                filelist.append(os.path.join(root, name))
    return filelist

# UID extracter
def uid_extract(files):
    uids = []
    for line in files:
        uid = line.split("-")[2]
        uids.append(uid)
    return uids

# Filename extractor
def file_name(files):
    names = []
    for line in files:
        name = line.split("/")[-1]
        names.append(name)
    return names
 # Scanner module
def scanner(toscan, rules):
    results = []
    for i in toscan:
        try:
            results.append(rules.match(i))
        except:
            logging.error("Could not scan file %s") % i
    return results

# Rules triggered function, to return as a list
# provided by ewatson
def rules_triggered(data):
    counter=0
    rules = []
    #[debug] print counter
    for counter in range(0, len(files)):
        try:
            for item in data[counter]['main']:
                #[debug] print item['rule']
                trig = item['rule']
                rules.append(trig)
        except:
            rules.append("null")
    return rules

def main(args):
	
	if args.rules is not None:
		rules = yara.compile(args.rules)
	else:
		rules = yara.compile(configurator.get('thoth', 'trojans'))

	if args.input is not None:
		pathtofiles = args.input
	else:
		pathtofiles = configurator.get('thoth', 'pathtofiles')

	#build list of files
	#files is used to in rules_triggered so I needed to global it
	global files 
	files = buildFilelist(pathtofiles)
	#print files

	#extract the bro session id from file name 
	#if -b or --bro is specified
	if args.bro is True:
		uids = uid_extract(files)
	else:
		uids = file_name(files)
	
	#hash all the files
	hashes = md5sum(files)

	#yara scan all the files
	scanned = scanner(files, rules)

	#parse triggered rules
	trigged = rules_triggered(scanned)

	#output everything in a sort of pretty(ish) format
	output = {}
	counter = 0
	for line in uids:
		data = {
			"uid":line,
			"md5":hashes[counter],
			"yara":trigged[counter]
		}
		counter+=1
		output[line] = json.dumps(data)
	#filter the "null" matches
	filtered_dict = {k:v for (k,v) in output.iteritems() if not "null" in v}
	print filtered_dict

	#move the files to a specified location
	#specify the location in thoth.ini, example /tmp/
	#note the trailing slash is necessary
	if args.move is True:
		destination = configurator.get('thoth', 'output')
		for line in filtered_dict:
			moveFiles(destination, line, os.path.basename(line))
	else:
		logging.info("Not moving matches, per user configuration.")

	
	logging.info("Analysis and move completed!")
if __name__ == '__main__':

	parser = argparse.ArgumentParser(description="Used to scan a given directory with a provided set of yara rules.")

	parser.add_argument("--rules", action='store', default=None, required=False,
		help="specify a rules file other than the default, supplied in thoth.ini")

	parser.add_argument("--input", action='store', default=None, required=False,
		help="specify a folder or file to be scanned")

	parser.add_argument("-b", "--bro", action='store_true', default=False, required=False,
		help="mandatory for parsing bro uids from a filename")

	parser.add_argument("-m", "--move", action='store_true', default=False, required=False,
		help="use this switch to tell the script to move matches to a directory specified in thoth.ini")

	args = parser.parse_args()
	main(args)


