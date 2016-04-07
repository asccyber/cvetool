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

#establish a cursor
cur = conn.cursor()

#create gui
class App(tk.Frame):
    def __init__(self, master):
        tk.Frame.__init__(self,master)
        self.master=master
        self.grid()
        self.ichose = []
        self.input = input

        #creates listbox for software
        self.listB = Listbox(self, height=20, width=80, selectmode=MULTIPLE)
        self.listB.grid(row=1, sticky=(N,W))

        #creates scrollbar
        scrollB = Scrollbar(self, orient=HORIZONTAL, command=self.listB.yview)
        scrollB.grid(column=0, row=0, sticky=(N,E))
        self.listB['yscrollcommand'] = scrollB.set

        #creates submit button
        submitB = Button(self, text='Submit', fg='red', command=self.quit)
        submitB.grid(column=0, row=13)

        # creates system name entry field and label
        eLabel= Label(master, text='System Name').grid(column=0, row=15)
        userE = Entry(self, fg='black').grid(column=0, row=14)

        #pulls software list from db to add to listbox
        cur.execute("SELECT software_name FROM software_list;")
        for row in cur:
            (cur.fetchone())
            self.listB.insert('end', row)

        # create textbox that will display selected items from list
        self.selected_list = Text(self,width=91, height=20,wrap=WORD)
        self.selected_list.grid(row=2, column=0, sticky=(S,W))

        # executes the poll() function to capture selected list items
        self.ichose = self.poll()

    def poll(self):
        items =[]
        self.ichose = []

        # set up an automatically recurring event that repeats after 200 millisecs
        # curselection retrieves the selected items as a tuple of strings
        # strings are the list indexes ('0' to whatever) of the items selected.
        self.selected_list.after(200, self.poll)


        # map applies the function specified in the 1st parameter to every item
        # from the 2nd parameter and returns a list of the results so "items"
        # is now a list of integers
        items = map(int,self.listB.curselection())

        # for however many values there are in "items"
        # use each number as an index and get from the listbox the actual
        # text strings corresponding to each index, and append each to
        for i in range(len(items)):
            # the list "ichose".
            self.ichose.append(self.listB.get(items[i]))

        # write ichose to the textbox to display it
        self.update_list()
        return self.ichose

    def update_list(self):
        self.selected_list.delete(0.0, END)
        self.selected_list.insert(0.0, self.ichose)

cveGui=tk.Tk()
cveGui.title('Relevant Software Selection')
cveGui.geometry('1280x800+200+200')
app=App(cveGui)
cveGui.mainloop()

loopval = len(app.ichose)

#for i in range(loopval):
#    sqlinsert = "INSERT INTO system_software (software_name, system_name) VALUES (%s, %s)"
#    cur.execute(sqlinsert, (app.ichose[i], sys_name))
#    conn.commit()

for i in range(loopval):
    sqlpull = "SELECT * FROM cve_list WHERE software_package = (%s)"
    cur.execute(sqlpull, (app.ichose[i],))
    results = cur.fetchall()
    for r in results:
        print r
