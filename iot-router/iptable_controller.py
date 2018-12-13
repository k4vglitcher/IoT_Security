#!/usr/bin/env python
#controller that will monitor for new IoT devices joining and
#request MUD Profile from croud-sourcing server to implement

import sys
import json
import os
import urllib2
from config_ip import implementIPTablesByJson
import ssl

def obtainMudProfile(device, ip):

  if(device):
    #send request to API for device's MUD Profile
    req = urllib2.Request('https://morning-brook-63432.herokuapp.com/api/products/MUDProfile/?device=' + device)
    gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    #call config_ip.py function to implement MUD profile
    result = urllib2.urlopen(req, context = gcontext)

    profile = result.read().decode('utf-8')

    implementIPTablesByJson(profile, ip)

  else:
    print('name of device is missing')




if __name__ == "__main__":
    obtainMudProfile('camera', '192.168.1.120')
