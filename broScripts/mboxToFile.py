import sys
import mailbox

def createFile(inbox):
    i = 0
    for msg in inbox:
        if i >= 50:
            break
        print(i)
        line = "["
        for header, value in msg.items():
            value = value.replace("\r", "")
            value = value.replace("\n", "")
            if header == "From":
                header = "FROM"
            if len(line) == 1:
                line += "('"+ header + "','" + value +"')"
            else:
                line += ", ('"+ header + "','" + value +"')"
        line += "]"
        outputFile.write(line + "\n")
        i += 1



mboxFile = "/home/apoorva/Documents/Research/PhishingResearch/Inbox.mbox"
outputFile = open("emailFile.log", "w")
inbox = mailbox.mbox(mboxFile)
createFile(inbox)
