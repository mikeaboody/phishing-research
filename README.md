# Phishing Research

Research on constructing "finerprints" of users' email structures in an attempt to identify phishing emails

### Python Modules Used

* [mailbox]- for extracting email headers and data
* [pylab]- for graphing
* [numpy]- for graphing
* [re]- regex for python

### Downloading Your Emails from Gmail in .mbox Email Format
For reference, the specifications of the mailbox module can be found at [https://docs.python.org/2/library/mailbox.html].

This is how you would download your emails from gmail in a .mbox format:
* Visit https://www.google.com/settings/takeout/custom/gmail,calendar
* Go down to the table under "Select Data to Include". 
* Check "Mail" if it is unchecked and uncheck "Calendar" if it is checked.
* You can customize what mail is downloaded by clicking the down arrow to the left of the checkbox and following its options
* Click "Next"
* Choose your file type as .zip and any delivery method
* Click "Create archive"
* You should see something like "An archive of 1 product is currently being prepared".
* You can manage your archives to see if it's done by clicking "Manage Archives"
* Wait until it's done, then download the .zip file which will contain the .mbox file inside when you unzip it.

### Using Mailbox for .mbox Email Format

First, you will want to import the module:
```python
import mailbox
```
Then create a ```mailbox.mbox``` instance that will help analyze your .mbox file:
```python
mbox_instance = mailbox.mbox("<file_name>.mbox")
```
You can access each message (which is of the ```email.message``` instance, the specifications of which can be found at [https://docs.python.org/2/library/email.message.html]) with the ```__getitem__``` method. For example, here is how we would get the 3rd message in ```mailbox.mbox``` instance:
```python
third_message = mbox_instance[2]
```
Now extract header fields with the ```__getitem__``` method, where the key is the key of the header field and the item returned is the value of the header field. For example, here is how we would print out each email's "X-Mailer" value:
```python
for msg in mbox_instance:
    xmailer = msg["X-Mailer"]
    print(xmailer)
```

