import smtplib

######################### INSTRUCTIONS #########################
# 1. ssh into the VPS: root@spmailserver2016.com
# 2. On the VPS, run: tcpdump -vv -w output.pcap -s 2000 port 25
# 3. On your local computer, run: python generatePcaps.py
# 	 - follow the prompts to add as many email senders
#	   you would like
# 4. When the script is done, stop tcpdump on the VPS
# 5. Copy output.pcap on the VPS to your local computer:
#    - scp root@spmailserver2016.com:~/output.pcap input/
################################################################

msUsers = ["apoorva", "matthew", "david", "jenna", "mike", "jerry"]
NUM_EMAILS_SENT_2_USER = 10

def generatePcaps(senders, passwords):
	subject = "Email"
	for j in range(len(senders)):
		for i in range(NUM_EMAILS_SENT_2_USER):
			for receiver in msUsers:
				receiverEmail = receiver + "@spmailserver2016.com"
				headers = "From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n" % ("spresearch", receiverEmail, subject)
				message = headers + "Hello "+ receiver + "! This is email number " + str(i) + "." 

				print("Sending email number " + str(i) + " to " + receiver)

				s = smtplib.SMTP_SSL('smtp.gmail.com',465)
				s.ehlo()
				s.login(senders[j], passwords[j])
				s.sendmail(senders[j], [receiverEmail], message)
				s.close()
				print("Done!")

cont = True
emails = []
passwords = []
print("NOTE: You can only send emails from a gmail email.")
while(cont):
	e = raw_input("Email: ")
	p = raw_input("Password: ")
	b = raw_input("Enter 1 to add another email or anything else to start sending emails: ")
	emails.append(e)
	passwords.append(p)
	if b != "1":
		cont = False
generatePcaps(emails, passwords)
