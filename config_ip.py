#!/usr/bin/env python
#python iptable configuration

import sys
import json
import python-iptables

def implementIPTables(file):
    #obtain desired MUD-like object to parse.
    try:
        mudfile = open(file, 'r').read()

    except FileNotFoundError:
        print("File does not exist")
        sys.exit()

    #verify and obtain if file content is JSON format
    try:
        json_object = json.loads(mudfile)

    except ValueError, e:
        print("Incorrect File Content Format: JSON")
        sys.exit()

    #parse mud-like json for ACL
    ACL_array = json_object["ietf-access-control-list:access-lists"]["acl"]


    ACLtoIPTable(ACL_array)


#parse device acl to iptable
def ACLtoIPTable(acl):
    match, action, endpoint, protocol = '','','',''

    #First set of ACES
    ace = acl[0]["aces"]

    #implement IPTables for each matches with their respective demands
    for index in ace:
        match = index["matches"]

#        #TCP FOR NOW FOR TEST
        action = match["actions"]
        endpoint = match["ipv4"]
        protocol = match["tcp"]


        #for test, just need one
        rule = iptc.Rule()
        rule.in_interface = "eth+"
        #rule.src = protocol.text
        rule.protocol = "tcp"

        rule.dest = endpoint["ietf-acldns:src-dnsname"].text
        rule.target = iptc.Target(rule, action["forwarding"].text)
        rule.src = #local ip
        match = rule.create_match("tcp")
        match.dport = protocol["port"].text
        rule.add_match(match)





        break

    print(action, endpoint,protocol)



#If developer wants to run script on command line:~$ python config_ip [MUD-like file]
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Incorrect amount of arguments")
        sys.exit()

    arg = sys.argv[1]
    implementIPTables(arg)
