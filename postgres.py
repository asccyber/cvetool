import psycopg2 as dbapi2

#open connection with database
conn = dbapi2.connect (database="CVE", host="localhost", user="postgres", password="postgres")

#Establish a cursor
cur = conn.cursor()

#Insert data
cur.execute("INSERT INTO software_list (software_name) VALUES ('test')");
conn.commit()
print "Records created successfully";
conn.close()
