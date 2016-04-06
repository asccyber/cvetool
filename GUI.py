import psycopg2 as dbapi2
import urllib
import gzip
import os
import Tkinter as tk
from Tkinter import *
from xml.dom import minidom

#open connection with database
conn = dbapi2.connect (database="CVE", host="localhost", user="postgres", password="postgres")
xmldoc = minidom.parse("test.xml")
xmlfile = "test.xml"

#Establish a cursor
cur = conn.cursor()

class App(tk.Frame):
    def __init__(self, master):
        tk.Frame.__init__(self,master)
        self.master=master
        self.grid()
        self.ichose = []

        self.l = Listbox(self, height=20, width=100, selectmode=MULTIPLE)
        # Selectmode can be SINGLE, BROWSE, MULTIPLE or EXTENDED. Default BROWSE
        self.l.grid(column=0, row=0, sticky=(N,W,E,S))

        s = Scrollbar(self, orient=HORIZONTAL, command=self.l.yview)
        s.grid(column=0, row=0, sticky=(N,S,E))
        self.l['yscrollcommand'] = s.set

        software = xmldoc.getElementsByTagName("vuln:product")

        #for nodeSoftware in software:
         #   vulnsw = nodeSoftware.childNodes[0].data

        cur.execute("SELECT software_name FROM software_list;")
        for row in cur:
            (cur.fetchone())
            self.l.insert('end', row)


            # appends multiple SW values to CVE key


        #for i in range(1,101):
         #   self.l.insert('end', 'Line %d of 100' % i)

        # Create Textbox that will display selected items from list
        self.selected_list = Text(self,width=50, height=10,wrap=WORD)
        self.selected_list.grid(row=12, column=0, sticky=W)

        # Now execute the poll() function to capture selected list items
        self.ichose = self.poll()

    def poll(self):
        items =[]
        self.ichose = []
        # Set up an automatically recurring event that repeats after 200 millisecs
        self.selected_list.after(200, self.poll)
        # curselection retrieves the selected items as a tuple of strings. These
        # strings are the list indexes ('0' to whatever) of the items selected.
        # map applies the function specified in the 1st parameter to every item
        # from the 2nd parameter and returns a list of the results. So "items"
        # is now a list of integers
        items = map(int,self.l.curselection())

        # For however many values there are in "items":
        for i in range(len(items)):
            # Use each number as an index and get from the listbox the actual
            # text strings corresponding to each index, and append each to
            # the list "ichose".
            self.ichose.append(self.l.get(items[i]))
        # Write ichose to the textbox to display it.
        self.update_list()
        return self.ichose

    def update_list(self):
        self.selected_list.delete(0.0, END)
        self.selected_list.insert(0.0, self.ichose)




root=tk.Tk()
root.title('Relevant Software Selection')
root.geometry('500x1000')
app=App(root)
root.mainloop()

print app.ichose
