import re

def troll(text):
     text = text.strip(" \t\r\n")
     return text

print(troll("\r\n troll"))
print(troll("\r\n troll \t"))

x , y = ["111", "@2"]
print(x, y)
