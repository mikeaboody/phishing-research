import re

def troll(text):
     text = text.strip(" \t\r\n")
     return text

print(troll("\r\n troll"))
print(troll("\r\n troll \t"))

x , y = ["111", "@2"]
print(x, y)

def quotes(text):
    return re.match("\".*\"", text) is not None

a = "\"hahaha\""
b = '"whatw  kwejrhe ---==="'
c = "ahha ok by"
d = "\" blahblah "
e = "llll elle \""
print(a)
print(b)
print(c)
print(d)
print(e)
print(quotes(a))
print(quotes(b))
print(quotes(c))
print(quotes(d))
print(quotes(e))


a = {"-01100": 1}
b = "-11100"
c = "+00001100"
d = "-01100"
e = "+01100"
print(b in a)
print(c in a)
print(d in a)
print(e in a)


def convert_to_binary(text):
    res = ""
    if quotes(text):
        res += "+"
        text = text[1:len(text) - 1]
    for c in text:
        if c in "=-_.?:/":
            res += "0"
        else:
            res += "1"
    return res

print(convert_to_binary("==?_troll_"))
print(convert_to_binary("====_troll_2939jkd934.3387432"))


def list_out(lst, lmt=None):
    more = 0
    if lmt != None:
        diff = len(lst) - lmt
        if diff != 0:
            more = diff
    res = ""
    for x in lst[:len(lst) - 1]:
        res += x + " "
    res += "and "
    res += lst[-1]
    return res

print(list_out(["a","b","c"]))

def format_string(text):
    return re.sub("[a-zA-Z0-9]+", "@", text)

print(format_string("=b92ues2bgwtbw3aupds64qdfwt4f6g"))
print(format_string("----=_Part_110017119_330207364.1440422234350"))
print(format_string("--==_mimepart_55db197f1c8fc_15b8ddfe143713436"))
print(format_string("\"----=_Part_167594_662016207.1440422412560\""))


def convert_to_partition(text):
    text = text.lower()
    res = ""
    curr = ""
    other = "=-_.?:/\""
    alpha_num = "[a-zA-Z0-9]"
    words = ["part", "multipart", "mime", "boundary", "mimepart", "boundary","nextpart", "mcpart", "msg", "border", "b1", "av"]
    pattern = other if text[0] in other else alpha_num
    for c in text:
        if (pattern == other and c in pattern) or (re.match(pattern, c) != None):
            curr += c
        else:
            if pattern == alpha_num and curr not in words:
                curr = str(len(curr))
                curr = "@"
            pattern = alpha_num if pattern == other else other
            res += curr
            curr = c
    if pattern == alpha_num and curr not in words:
        curr = "@"
    res += curr
    return res

val = convert_to_partition("\"----=_Part_167594_662016207.1440422412560\"")
val2 = convert_to_partition("--boundary_1_1-1-1-1-ae2ac657f566")
print(val2)
print(re.split("([0-9]+)", val2))
        
        
def modify_partition(text):
    case1 = ['"-@-@-@=:@"', "-@-@-@=:@"]
    case2= ['"_av-@-@-@"', '"_av-@-@"', '"_av-@"']
    if text in case1:
        return text.replace("-", "", 1)
    if text in case2:
        return '"_av-@"'
    return text

print(modify_partition("-@-@-@=:@"))
print(modify_partition("@-@-@=:@"))
print(modify_partition('"-@-@-@=:@"'))
print(modify_partition('"_av-@-@-@"'))
print(modify_partition('"_av-@-@"'))


def filter(header):
    parts = header.split("-", 2)
    if len(parts) == 1:
        return parts[0]
    else:
        return parts[0] + "-" + parts[1]

print(filter("x-mailer-version"))
print(filter("content-type"))
print(filter("trollo"))
print(filter("x-1and1-spam-lvel"))








