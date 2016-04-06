import psycopg2 as dbapi2
import urllib
import gzip
import os

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
    for nodeSoftware in software:                                                                                       #for loop to get vulnerable sw readable data
        vulnsw = nodeSoftware.childNodes[0].data
        SQLstr = vulnsw[7:]                                                                                             #Strips off prefix
        SQLinsert = "INSERT INTO software_list (software_name) VALUES (%s)"                                             #Defines SQL insert function to be used
        cur.execute(SQLinsert, (SQLstr,))                                                                               #Insert data  #Executes SQL statement in postgres
        conn.commit()                                                                                                   #Saves change to database

#Create Reference Table
cur.execute("CREATE TABLE sl2 AS SELECT * FROM software_list;")
conn.commit()

#Delete Duplicates by checking package name and keeping first occurence of package 
cur.execute("DELETE FROM software_list USING software_list sl2 WHERE software_list.software_name \
 = sl2.software_name AND software_list.key_column > sl2.key_column;")
conn.commit()

#Delete Reference Table
cur.execute("DROP TABLE sl2;")
conn.commit()

#Close connection
conn.close()
