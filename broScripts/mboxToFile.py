import sys
import mailbox
import progressbar

def createFile(inbox, num_emails):
    progress = progressbar.ProgressBar()
    for i in progress(range(num_emails)):
        msg = inbox[i]
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

if len(sys.argv) < 2:
    print("Please specify the absolute path to the mbox as an argument")
    sys.exit()
mboxFile = sys.argv[1]
outputFile = open("mbox.log", "w")
inbox = mailbox.mbox(mboxFile)
inbox_length = len(inbox)
num_emails = inbox_length
if len(sys.argv) == 3:
    try:
        # the number of emails passed in must be less than the total number of emails in the mbox
        num_emails = min(int(sys.argv[2]), inbox_length)
    except:
        print("The second (optional) argument should be a number")
createFile(inbox, num_emails)
