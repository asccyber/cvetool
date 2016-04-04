import urllib
import gzip
import os
import xml.etree.ElementTree as ET
from xml.dom import minidom


#varibles
path = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2016.xml.gz"
gzfile = "test.xml.gz"
xmlfile = "test.xml"


#Grab file to be used for nist website
testfile = urllib.URLopener()
testfile.retrieve(path, gzfile)

#uncompress file
inF = gzip.GzipFile(gzfile, 'rb')
s = inF.read()
inF.close()

#save uncompressed file
outF = file (xmlfile, 'wb')
outF.write(s)
outF.close()

#remove compressed file
os.remove(gzfile)

#parse data

xmldoc = minidom.parse("test.xml")
mapping = {} #Sets mapping variable for dictionary dataset
for nodeEntry in xmldoc.getElementsByTagName("entry"): #for loop to get entry ID and and vulnerable SW
    entryid = nodeEntry.getAttribute("id")
    software = nodeEntry.getElementsByTagName("vuln:product")
    for nodeSoftware in software: #for loop to get vulnerable sw readable data
        vulnsw = nodeSoftware.childNodes[0].data
        mapping.setdefault(entryid, []).append(vulnsw) #appends multiple SW values to CVE key

#print(mapping) # prints dictionary with mapped cve and vuln sw
search_sw = raw_input("Provide SW: ") #searchs sw for SW values and retures applicable CVE. Must be exact vuln sw name
for entryid, vulnsw in mapping.items():
    if search_sw in vulnsw:
        print entryid





