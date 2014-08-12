import requests
import xml.etree.ElementTree as ET
import datetime
from logger import log

"""
    Geolocate an IP address.
	results:
	    [0]: country
	    [1]: city
"""
def geolocate(ip):
    response = requests.get('http://ip-api.com/line/' + ip.split(":")[0])
    if response.content.split('\n')[0] == "success":
	country = response.content.split('\n')[1]
        city = response.content.split('\n')[4]
    else:
	return False
    return country, city

"""
    Get external IP address.
"""
def getmyip():
    response = requests.get("http://ipinfo.io/ip")
    return response.content.split()[0]

"""
    Get the current EST time.
"""
def getESTTime():

    response = requests.get("http://api.timezonedb.com/?zone=America/New_York&key=UA0TQHO81DUU")
    try:
	root = ET.fromstring(response.content)
    except Exception as e:
	log("w", "Failed to get the time: " + str(e))
	return ""

    if root.findall('status') and root.findall('status')[0].text == 'OK':
	return datetime.datetime.utcfromtimestamp(float(root.findall('timestamp')[0].text)).isoformat()
    else:
	return ""
