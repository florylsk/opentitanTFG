# Copyright 2022
# Florinel Olteanu

import sys
import requests
import pandas as pd
import numpy as np
import json
import csv
import random
import os
from pwn import *
import signal

def handler(signum, frame):
    log.info("Exiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, handler)

def getCoordinates(gh):
    lat=0
    lon=0
    baseUrl="http://geohash.world/v1/decode/"
    reqJson=json.loads(requests.get(baseUrl+gh).text)
    lat=reqJson["lat"]
    lon=reqJson["lon"]
    return lat,lon



p=log.progress("Current path")
p.status("Waiting for input...")
#change this depending on the absolute path of the read named pipe
readPipeLoc="/tools/opentitanTFG/gpio0-read"
with open(readPipeLoc,"r") as pipe:
    #first 4 characters of geohash, once full this string won't change for the same route
    baseGeohash=""
    #last 4 characters of geohash, this string will change every 2 inputs of 2 characters from the device
    geohash=""
    #need this counter to keep track of which second half we are at
    counterHalfs=0
    # store geohashes
    geohashes=[]
    #will only iterate when gpio0-read changes
    while True:
        binaryInput=pipe.readline()
        #only need last 16 bits
        cleanInput=binaryInput[16:]
        # binary to ascii
        firstChar="".join(chr(int(cleanInput[0:8],2)))
        secondChar="".join(chr(int(cleanInput[8:16],2)))
        if firstChar=="\x00" and secondChar=="\x00":
            p.success()
            log.success("Path finished, starting PoWha now...")
            break
        #fill first 4 characters of geohash
        if len(baseGeohash) != 4:
            baseGeohash+= firstChar
            baseGeohash+= secondChar
        else:
            #fill last 4 characters of geohash
            if len(geohash) != 4:
                geohash += firstChar
                geohash += secondChar
            #we already had a full geohash before (most common case)
            else:
                if counterHalfs % 2 == 0:
                    geohash=firstChar+geohash[1:] # equals to geohash[0]=firstChar
                    geohash=geohash[:1]+secondChar+geohash[2:] # equals to geohash[1]=secondChar
                else:
                    geohash=geohash[:2]+firstChar+geohash[3:] #equal to geohash[3]=firstChar
                    geohash=geohash[:3]+secondChar #equal to geohash[4]=secondChar
                counterHalfs+=1
        if len(baseGeohash)==4 and len(geohash)==4 and counterHalfs % 2 != 0:
            fullGeohash="".join(baseGeohash+geohash)
            # dont want to repeat geohashes with the same coordinates
            if len(geohashes) == 0:
                geohashes.append(fullGeohash)
            else:
                if geohashes[-1] != fullGeohash:
                    geohashes.append(fullGeohash)
            p.status(str(geohashes))

    pipe.close()
# write csv with coordinates to feed it to geohash_generator.py later
del geohash
coordinates=[]
for geohash in geohashes:
    tmpLat,tmpLon=getCoordinates(geohash)
    tmpCoords=[tmpLat,tmpLon]
    coordinates.append(tmpCoords)
#create folder to store the coordinates generated
try:
    os.mkdir("coordinates")
except:
    pass
#create the file
tmpCsvFileName="coordinates/coords_"+str(random.randint(0,9))+".csv"
with open(tmpCsvFileName,"w") as f:
    write=csv.writer(f)
    write.writerows(coordinates)
log.info("Successfully written the CSV file with the path's real coordinates to "+tmpCsvFileName)

#generate geohashes from coordinates
cmdGenerateGeohash=("python3 geohash_generator.py "+tmpCsvFileName)
os.system(cmdGenerateGeohash)
log.info("Succesfully generated hashes with coordinates")
#read generated geohashes json
with open("geohash_points.json","r") as geohashFile:
    data=json.load(geohashFile)
    geohashFile.close()
# get geohashes
walk11=str(data[0][1])
walk12=str(data[0][2])
walk21=str(data[1][1])
walk22=str(data[1][2])
walk31=str(data[2][1])
walk32=str(data[2][2])
mind=str(min(data[0][0],data[1][0],data[2][0]) -1)
log.info("Generating proof data...")
#call the proof data generater with the afore created geohashes
os.system("python3 signature_generator/generate_proof_data.py -p 'signature_generator/input_data/' -fn 'first_try' -gh " +walk11+" "+walk12+" "+walk21+" "+walk22+" "+walk31+" "+walk32+" -mind "+mind+" -maxd 500 -maxtc 40 -maxtw 1000 -st 0")
log.info("Calling PoWha...")
# finally, call the main script
os.system("./generate_powha.sh")
