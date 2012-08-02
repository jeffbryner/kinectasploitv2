#! /usr/bin/env python
import fileinput
import getopt
import os 
import re 
import string, sys, time
#sample snort line: 
#06/29-06:53:10.471599  [**] [119:19:1] (http_inspect) LONG HEADER [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.168.1.102:33319 -> 98.103.44.143:80

#regex parsers
#where to start with the line..at the [sig_gen:sig_id:sig_rev]
snortlogre=re.compile(r"""\[\d{3}\:\d{1,3}\:\d{1,3}\].*""")#the whole line after the [000:0:0] signature marker
snortsigre=re.compile(r"""\[\d{3}\:\d{1,3}\:\d{1,3}\.*?]""")#just the signature marker
classificationre= re.compile(r"""\[Classification: (.*?)\]""",re.IGNORECASE)
priorityre= re.compile(r"""\[Priority: (.*?)\]""",re.IGNORECASE)
protocolre= re.compile(r"""\{(TCP|UDP|ICMP)\}""",re.IGNORECASE)
ipre = re.compile(r"""((?:\d{1,3}\.){3}\d{1,3})""")

def main():
    while 1: 
        line=sys.stdin.readline().strip()
        if not line:
            break
        else:
            #print("< %s >" %line)
            if re.search(snortlogre,line):
                for snorttext in snortlogre.findall(line):
                    #print(snorttext)
                    #defaults
                    signature=""
                    protocol="unknown"
                    sourceport=0
                    destport=0
                    sourceip='0.0.0.0'
                    destip='0.0.0.0'
                    classification=""
                    priority="0"
                    msg=""
                    
                    for asignature in snortsigre.findall(snorttext):
                        signature=asignature
                        
                    for aclassification in classificationre.findall(snorttext):
                        classification=aclassification
                    
                    for apriority in priorityre.findall(snorttext):
                        priority=apriority
                    for aprotocol in protocolre.findall(snorttext):
                        protocol=aprotocol
                    if len(ipre.findall(snorttext))==2:
                        sourceip=ipre.findall(snorttext)[0]
                        destip=ipre.findall(snorttext)[1]

                    if sourceip!='0.0.0.0':
                        #make a regex with the sourceip we just found to get the source port just after it
                        sourceportre=re.compile(sourceip + r"""\:([a-zA-Z0-9]+)""")                        
                        for port in sourceportre.findall(snorttext):
                            sourceport=int(port)
                    if destip!='0.0.0.0':
                        #make a regex with the destination ip we just found to get the destination port just after it                        
                        destportre=re.compile(destip + r"""\:([a-zA-Z0-9]+)""")
                        for port in destportre.findall(snorttext):
                            destport=int(port)

                    #get the message description/filter name now that we know what surrounds it
                    #the signature has [] in it which messes up the regex..remove them and escape them manually
                    resafesignature=signature.replace('[','').replace(']','')
                    msgre=re.compile(resafesignature + r"""\] (.*?) \[""" )
                    for amsg in msgre.findall(snorttext):
                        msg=amsg
                    
                                                    
                    #print ("%s: %s %s:%s:%s --> %s:%s:%s" %(action, protocol, sourceinterface, sourceip, sourceport, destinationinterface, destip, destport))
                    #print(msg,signature,classification,priority,protocol,sourceip,sourceport,destip,destport)
                    print("%s %s: %s %s:%s --> %s:%s " % (priority,msg,classification,sourceip,sourceport,destip,destport))
                    
                
                


main()