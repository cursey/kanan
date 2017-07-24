###############################################################################
# This was just a development script. It outputs a bunch of information that is
# only really useful if you are debugging a problem or developing a launcher.
# It is provided as-is because it may still be useful for some. A cleaned up
# version of this script is included in kanan.py
###############################################################################
from http import client
from hashlib import sha512
from binascii import hexlify
from base64 import b64encode
from json import loads, dumps
from subprocess import run, Popen, PIPE
from io import StringIO
from pathlib import Path

# Get the UUID
cmd_result = run(['wmic', 'csproduct', 'get', 'uuid'], stdout=PIPE)
cmd_result_str = StringIO(cmd_result.stdout.decode('utf-8'))

# skip the first line
cmd_result_str.readline()

# Grab UUID
uuid = cmd_result_str.readline().strip()

print("Using uuid: '{}'".format(uuid))

username = input("Username: ")
password = input("Password: ")

# immediately convert it.
password = hexlify(sha512(bytes(password, 'utf-8')).digest()).decode('utf-8')

print(password)

headers = {
    'User-Agent': 'NexonLauncher.nxl-17.04.01-290-621f8e0',
    'Content-Type': 'application/json'
}
body = {
    'id': username,
    'password': password,
    'auto_login': False,
    'client_id': '7853644408',
    'scope': 'us.launcher.all',
    'device_id': uuid
}
body_str = dumps(body)

print(body)

connection = client.HTTPSConnection('accounts.nexon.net', 443)

connection.request('POST', '/account/login/launcher', body=body_str,
                   headers=headers)

response = loads(connection.getresponse().read())

print(response)

b64_token = b64encode(bytes(response['access_token'],
                            'utf-8')).decode('utf-8')

print(b64_token)

headers = {
    'User-Agent': 'NexonLauncher.nxl-17.04.01-290-621f8e0',
    'Cookie': 'nxtk=' + response['access_token'] +
              ';domain=.nexon.net;path=/;',
    'Authorization': 'bearer ' + b64_token
}

print("#############################")
print("Cookie = {}".format(headers['Cookie']))
print("Authorization = {}".format(headers['Authorization']))
print("#############################")

connection = client.HTTPSConnection('api.nexon.io', 443)

connection.request('GET', '/users/me/passport', headers=headers)
response = loads(connection.getresponse().read())

print(response)

mabidir = Path("C:\\Nexon\\Library\\mabinogi\\appdata")
mabipath = str(mabidir)
clientpath = str(mabidir / "Client.exe")
args = "code:1622 verstr:248 ver:248 locale:USA env:Regular setting:file://data/features.xml logip:208.85.109.35 logport:11000 chatip:208.85.109.37 chatport:8002 /P:{} -bgloader".format(response['passport'])

Popen(clientpath + " " + args, cwd=mabipath)
