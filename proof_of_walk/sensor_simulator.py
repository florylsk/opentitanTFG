import sys
import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from base64 import b64decode,b64encode
import requests
import json
import pandas as pd
import numpy as np
import time
from pwn import log
import signal

def handler(signum, frame):
    log.info("Exiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, handler)

def getGeohash(lat,lon, range):
    # good public and free api for encoding coordinates to geohash
    url="http://geohash.world/v1/encode/"+str(lat)+","+str(lon)+"?pre=8"
    # api response to json
    reqJson=json.loads(requests.get(url).text)
    # only geohash is needed
    geohash=reqJson["geohash"]
    if range == "0-4":
        return geohash[:4]
    else:
        return geohash[4:8]


keyprivPEM="MIICXgIBAAKBgQDR6J4r+KpEhhAd3bwWSI1oPHrxYvSrZI7CVg3g/bUZtL8Fz0MGmpd8fWzes+akgBsvUsuTjk4Te3PV/b5qleILpePjKYCQVA0cgXKt8r6mW7AMx8pgQ88OIiG+d3vm7IyBkFdTfgQPdXjYKvvvBOqJUehIJAejV9akUm1yb59VjwIDAQABAoGBAL1o+zlQVEwq8OYSTIOLClaRpJqmoYL65TsFLdbk+ILuryRN5vxRiPpjr1ax3SB5HI6yVlKaqWc5Ech6BFXnU6VtCIWV1L2KAvCM3fDVW8xCwn8nGbfbUR1hR+crgy54xzTvp6zwJ3o3zECDGgxzqa4poEBpsYovOQxYo4E0pkk5AkEA/a6kx2r8eZCTySevv4Q6mHGX25bS/zd0svtmWfTc8ORHL2M2PpPs782si/ruJr6xQ0hooVMSZRNnWuU5+JFbLQJBANPTlsdEbqtEy/C8WgYrgmnesmL2OnbILPQq/vAEE27qlCyhp3nDpaCAa71dV2eJTVFhEIBWbgcf+6henaqIOSsCQGL3IeOGMk6+f1kHOYHudOmJzyNkeJYGLWmxt+E6LINxmu+6tau+C74Vr83AK+5DkGXeNqtQ/CkgY77LFE2Lb1UCQQCXCgY269qlkJaCfysJvzhsWPiFi+DAFZfIOmgxqBZbPjSNZm7OaezNdwRbsBTEpKhW4IktmXM27V05/s0ZbaylAkEA/ZYGRWbdGoZtBWNS5i3vHQr0SdoWGwvklQONc0klW0vlKbghNq8e+p6LbMygAi3EzJcpPt0n4C3M2NVIV6LRvw=="
keyprivDER = b64decode(keyprivPEM)
keyPriv=RSA.import_key(keyprivDER)
keyPub="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDR6J4r+KpEhhAd3bwWSI1oPHrxYvSrZI7CVg3g/bUZtL8Fz0MGmpd8fWzes+akgBsvUsuTjk4Te3PV/b5qleILpePjKYCQVA0cgXKt8r6mW7AMx8pgQ88OIiG+d3vm7IyBkFdTfgQPdXjYKvvvBOqJUehIJAejV9akUm1yb59VjwIDAQAB"
log.info("Using RSA-PSS algorithm")
choice = input("(m)Manual Input/(g)Geohash Sensor Simulator: ")
if "m" in choice:
    while True:
        input_op = input("Input operations to sign: ")
        input_op=input_op.strip()
        # get bytes of message
        msg = input_op.encode()
        print("test: "+input_op)
        h = SHA256.new(msg)
        # # generate deterministic PSS signature
        signature = pss.new(keyPriv, salt_bytes=0).sign(h)
        signature_clean = hex(int.from_bytes(signature, byteorder='big'))[2:]
        log.info("Signature: " + signature_clean)
        echoStr = "'" + keyPub + str("\\t") + signature_clean + str("\\t") + input_op + str("\\0") + "'"
        cmd = "echo " + echoStr + ">/tools/opentitanTFG/gpio0-write"
        os.system(cmd)
        print(cmd)
        log.success("Message sent to device")
elif "g" in choice:
    if len(sys.argv) != 2:
        log.failure("No input file specified, exiting...")
        sys.exit(0)
    pathFile=sys.argv[1]
    p1 = log.progress("Geohash to send")
    p2 = log.progress("Sending")
    p3 = log.progress("Signature")
    # read csv with coordinates
    walkingDf = pd.read_csv(pathFile)
    # get only latitude and longitude
    df = walkingDf[["X", "Y"]]
    geoHash=None # need this so we know its the first iteration to send first 4 characters
    for index, row in df.iterrows(): # iterate the coordinates dataframe
        lat = row["Y"]
        lon = row["X"]
        if geoHash is None: # if first geohash only get the first 4 characters
            geoHash = getGeohash(lat, lon,"0-4")
            p1.status(geoHash)
        else: # otherwise always get the last 4
            geoHash = getGeohash(lat, lon,"4-8")
            p1.status(geoHash)
        #because only 16 bits are truly writeable, need do split the geohash in half
        geohashFirstHalf=geoHash[:2]
        geohashSecondHalf=geoHash[2:4]

        # geohash string to binary
        binaryHash = ''.join(format(ord(i), '08b') for i in geohashFirstHalf)
        #need to reverse it
        binaryHash=binaryHash[::-1]
        payload = ""
        # geohash binary to combinations of high and low inputs
        for i in range(0, len(binaryHash)):
            tmp = binaryHash[i]
            if tmp == str(0):
                payload += "L" + str(i) + " "
            elif tmp == str(1):
                payload += "H" + str(i) + " "
        msg=payload.encode()
        h = SHA256.new(msg)
        signature = pss.new(keyPriv, salt_bytes=0).sign(h)
        signature_clean = hex(int.from_bytes(signature, byteorder='big'))[2:]
        p2.status(geohashFirstHalf)
        p3.status(signature_clean)
        echoStr = "'" + keyPub + str("\\t") + signature_clean + str("\\t") + payload + str("\\0") + "'"
        cmd = "echo " + echoStr + ">/tools/opentitanTFG/gpio0-write"
        os.system(cmd)
        # Less than 0.3 seconds produced a race condition on the device, but I suspect it is a hardware dependant value
        time.sleep(0.3)
        # geohash string to binary
        binaryHash = ''.join(format(ord(i), '08b') for i in geohashSecondHalf)
        #need to reverse it
        binaryHash=binaryHash[::-1]
        payload = ""
        # geohash binary to combinations of high and low inputs
        for i in range(0, len(binaryHash)):
            tmp = binaryHash[i]
            if tmp == str(0):
                payload += "L" + str(i) + " "
            elif tmp == str(1):
                payload += "H" + str(i) + " "
        msg=payload.encode()
        h = SHA256.new(msg)
        signature = pss.new(keyPriv, salt_bytes=0).sign(h)
        signature_clean = hex(int.from_bytes(signature, byteorder='big'))[2:]
        p2.status(geohashSecondHalf)
        p3.status(signature_clean)
        echoStr = "'" + keyPub + str("\\t") + signature_clean + str("\\t") + payload + str("\\0") + "'"
        cmd = "echo " + echoStr + ">/tools/opentitanTFG/gpio0-write"
        os.system(cmd)
        # dont wan't to abuse the free api so keep this relatively high
        time.sleep(0.5)

    #send 16 zeroes to signal end of sensor simulation
    p1.success()
    p2.success()
    p3.success()
    log.success("Path finished, sending last payload now...")
    binaryHash = "0"*16
    payload = ""
    # geohash binary to combinations of high and low inputs
    for i in range(0, len(binaryHash)):
        tmp = binaryHash[i]
        if tmp == str(0):
            payload += "L" + str(i) + " "
        elif tmp == str(1):
            payload += "H" + str(i) + " "
    msg=payload.encode()
    h = SHA256.new(msg)
    signature = pss.new(keyPriv, salt_bytes=0).sign(h)
    signature_clean = hex(int.from_bytes(signature, byteorder='big'))[2:]
    echoStr = "'" + keyPub + str("\\t") + signature_clean + str("\\t") + payload + str("\\0") + "'"
    cmd = "echo " + echoStr + ">/tools/opentitanTFG/gpio0-write"
    os.system(cmd)
