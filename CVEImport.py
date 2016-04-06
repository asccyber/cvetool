import urllib
import gzip
import os
from xml.dom import minidom
import psycopg2 as dbapi2
import time


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

#open connection with database
conn = dbapi2.connect (database="CVE", host="localhost", user="postgres", password="postgres")

#Establish a cursor
cur = conn.cursor()

#parse data
xmldoc = minidom.parse("test.xml")
mapping = {}                                                                                                            #Sets mapping variable for dictionary dataset
for nodeEntry in xmldoc.getElementsByTagName("entry"):                                                                  #for loop to get entry ID and and vulnerable SW
    entryid = nodeEntry.getAttribute("id")
    software = nodeEntry.getElementsByTagName("vuln:product")
    pubdate = nodeEntry.getElementsByTagName("vuln:published-datetime")[0]
    pubvalue = pubdate.childNodes[0].data[:10]
    lastmod = nodeEntry.getElementsByTagName("vuln:last-modified-datetime")[0]
    modvalue = lastmod.childNodes[0].data[:10]
    for nodeSoftware in software:                                                                                       #for loop to get vulnerable sw readable data
        vulnsw = nodeSoftware.childNodes[0].data
        SQLstr = vulnsw[7:]  # Strips off prefix
        SQLinsert = "INSERT INTO cve_list (cve_id, software_package, pub_date, mod_date) VALUES (%s, %s, %s, %s)"  # Defines SQL insert function to be used
        cur.execute(SQLinsert, (entryid, SQLstr, pubvalue, modvalue))  # Insert data  #Executes SQL statement in postgres
        conn.commit()

#Create Reference Table
cur.execute("CREATE TABLE cv2 AS SELECT * FROM cve_list;")
conn.commit()

#Delete Duplicates by checking package name and keeping first occurence of package
cur.execute("DELETE FROM cve_list USING cve_list cv2 WHERE cve_list.cve_id \
 = cv2.cve_id AND cve_list.software_package = cv2.software_package AND \
 cve_list.pub_date = cv2.pub_date AND cve_list.mod_date = cv2.mod_date AND \
 cve_list.key_column > cv2.key_column;")
conn.commit()

#Delete Reference Table
cur.execute("DROP TABLE cv2;")
conn.commit()

#Close connection
conn.close()
