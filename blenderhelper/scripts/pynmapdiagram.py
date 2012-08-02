#!/usr/bin/python2
import sys
import lxml.objectify
import pygraphviz

nxml=lxml.objectify.parse(sys.argv[1])
nroot=nxml.getroot()
topology = pygraphviz.AGraph()
lastaddr="scanner"
topology.add_node(lastaddr)

if len(nroot.findall("//*[local-name()='trace']"))==0:
       print("Hmm..no trace information. Try nmap again with --traceroute option")
       sys.exit(1)  

for nhost in nroot.findall("//*[local-name()='host']"):
       #figure out what this host has for child elements
       hosttags=[]
       hostaddr=''
       for child in nhost.getchildren():
              hosttags.append(child.tag)
       
       if 'trace' in hosttags:            
              for nhop in nhost.trace.hop:
                     if nhop.attrib.get("ttl")=='1':
                            #topology.add_node(nhop.attrib.get("ipaddr"))
                            topology.add_edge("scanner",nhop.attrib.get("ipaddr"))
                     else:
                            topology.add_edge(lastaddr,nhop.attrib.get("ipaddr"))
                     lastaddr=nhop.attrib.get("ipaddr")
#write our output:
topology.write('out.dot')
       #dot - filter for drawing directed graphs
       #neato - filter for drawing undirected graphs
       #twopi - filter for radial layouts of graphs
       #circo - filter for circular layout of graphs
       #fdp - filter for drawing undirected graphs
       #sfdp - filter for drawing large undirected graphs
topology.layout(prog='fdp') # use which layout from the list above^
outfile=sys.argv[1].replace('xml','png')
topology.draw(outfile)
