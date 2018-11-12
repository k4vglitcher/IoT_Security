#!/usr/bin/env python
#controller that will monitor for new IoT devices joining and
#request MUD Profile from croud-sourcing server to implement

import sys
import json
import os
import urllib.request
from config_ip import implementIPTablesByJson


def obtainMudProfile(device):

  if(device):
    #send request to API for device's MUD Profile
    req = urllib.request.Request('https://morning-brook-63432.herokuapp.com/api/products/MUDProfile/?device=' + device)
    #call config_ip.py function to implement MUD profile
    result = urllib.request.urlopen(req)

    profile = result.read().decode('utf-8')

    implementIPTablesByJson(profile)

  else:
    print('name of device is missing')




if __name__ == "__main__":
    obtainMudProfile('camera')
