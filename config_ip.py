#!/usr/bin/env python
#python iptable configuration

import sys
import json
#import iptc
import socket
import os

def implementIPTables(file):
    #obtain desired MUD-like object to parse.
    try:
        mudfile = open(file, 'r').read()

    except FileNotFoundError:
        print("File does not exist")
        sys.exit()

    #obtain device ip addr
    head, tail = os.path.split(file)
    filename = head.split('/')[-1]

    #verify and obtain if file content is JSON format
    try:
        json_object = json.loads(mudfile)

    except ValueError:
        print("Incorrect File Content Format: JSON")
        sys.exit()

    #parse mud-like json for ACL
    ACL_array = json_object["ietf-access-control-list:access-lists"]["acl"]


    ACLtoIPTable(ACL_array, filename)

def implementIPTablesByJson(file, filename):
    #obtain desired MUD-like object to parse.
    #verify and obtain if file content is JSON format
    try:
        json_object = json.loads(file)

    except ValueError:
        print("Incorrect File Content Format: JSON")
        sys.exit()

    #parse mud-like json for ACL
    ACL_array = json_object["ietf-access-control-list:access-lists"]["acl"]


    ACLtoIPTable(ACL_array, filename)

#parse device acl to iptable
def ACLtoIPTable(acl, filename):
    match, action, endpoint, protocol, subport = '','','','',''

    #First set of ACES
    ace = acl[0]["aces"]

    #implement IPTables for each matches with their respective demands
    for index in ace:
        matches = index["matches"]

	#Confirm that matches has valid info for dest addr
	if("ietf-acldns:src-dnsname" not in matches["ipv4"]):
	    continue


        #capture essential info
        action = matches["actions"]
        endpoint = matches["ipv4"]
	dest_name = endpoint["ietf-acldns:src-dnsname"][:-1]

	#resolve dest address
	dest_addr = socket.gethostbyname(dest_name)

    source = filename
    destination = dest_addr

    if("tcp" in matches):
        subport = matches["tcp"]
        protocol = "tcp"
    elif("udp" in matches):
        subport = matches["udp"]
        protocol = "udp"
    else:
        print("Error in Matches")
        pass

    target = action["forwarding"].upper()
    dport = str(subport["source-port"]["port"])

    call('iptables -o eth+ -p ' + protocol + '-I OUTPUT -s ' + source + ' -d ' + destination + ' -j ' + target + ' --dport ' + dport + '', shell=True)

    """
	chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")

        #for test, just need one
        rule = iptc.Rule()
        rule.out_interface = "eth+"
        rule.src = filename

        rule.dst = dest_addr
        rule.target = iptc.Target(rule, action["forwarding"].upper())

        if("tcp" in matches):
            protocol = matches["tcp"]
            rule.protocol = "tcp"
	    match = iptc.Match(rule, "tcp")

        elif("udp" in matches):
	    protocol = matches["udp"]
            rule.protocol = "udp"
	    match = iptc.Match(rule, "udp")

        else:
            print("Error in matches")
            pass


        match.dport = str(protocol["source-port"]["port"])
        rule.add_match(match)
	chain.insert_rule(rule)

    	print("IPTables Rules implemented for %s" % rule.src)


    #Deny all packets from any other external endpoints
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
    rule = iptc.Rule()
    rule.out_interface = "eth+"
    rule.src = filename
    rule.target = iptc.Target(rule, "DROP")
    chain.insert_rule(rule)
    """
    target = "DROP"
    call('iptables -o eth+ -I OUTPUT -s ' + source + ' -j ' + target + '', shell=True)



#If developer wants to run script on command line:~$ python config_ip [MUD-like file]
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Incorrect amount of arguments")
        sys.exit()

    arg = sys.argv[1]
    implementIPTables(arg)
