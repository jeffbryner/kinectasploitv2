#!/usr/bin/python2

import sys
import getopt
from scapy.all import *

def Usage():
	print ("usage: " + sys.argv[0] + "[-F directory containing pcaps] [-f pcap file] [-e ssid] [-v]\nYou must provide at least provide the directory or pcap file\n-v shows the filename in the output")
	sys.exit(2)

def GetSsidAndApName(packet):
	bssid=packet.addr2
	essid=''
	ap=''

	p = packet #.getlayer(Dot11Elt)

	while Dot11Elt in p:
		p = p[Dot11Elt]
		if p.ID == 0:
			if len(p.info) == 0 or p.info[0] == "\x00":
				essid='<hidden>'
			else:
				essid=p.info
		if p.ID == 133:
			ap = p.info[10:]
			ap = ap[:ap.find("\x00")]
		p = p.payload

	return (bssid, essid, ap)

files = []
essids = {}
#Set Scapy verbose to 0
conf.verb = 0

try:
	opts, args = getopt.getopt(sys.argv[1:], "f:F:e:v")
except getopt.GetoptError as err:
	# print help information and exit:
	print(err) # will print something like "option -a not recognized"
	Usage()
	sys.exit(2)

try:
	verbose = False
	for opt, arg in opts:
		if opt == '-h':
			Usage()
		elif opt == '-F':
			for item in os.listdir(arg):
				fullpath = os.path.join(arg, item)
				if os.path.isfile(fullpath) and ('.cap' in item or '.pcap' in item or '.dump' in item):
					files.append(fullpath)
		elif opt == '-f':
			files.append(arg)
		elif opt == '-e':
			essids.append(arg)
		elif opt == '-v':
			verbose = True

	if len(files) == 0:
		Usage()

	for f in files:
		pcap = rdpcap(f)
		for pckt in pcap:
			if (pckt.subtype == 8L or pckt.subtype == 5L) and pckt.type == 0L:
				t = GetSsidAndApName(pckt)
				if t[0] not in essids:
					print t[0] + '\t' + t[1] + '\t' + t[2] + (('\t' + f) if verbose else '')
					essids[t[0]]=t[1]
except Exception, e:
	print e
	print "Send error to: tim[at]securitywhole.com"
	pass

