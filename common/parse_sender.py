import email.utils

def parse_sender(sender):
    sender = sender.replace("\x09", " ")
    humanname, email_addr = email.utils.parseaddr(sender)
    email_addr = email_addr.strip().lower()
    humanname = humanname.strip().lower()

    if humanname == '':
        # If the field is nameless, just use the email addr as the human name
        humanname = email_addr

    return (humanname, email_addr)

def extract_name(headerval):
    if not headerval:
        return None
    return parse_sender(headerval)[0]

def extract_full_from(headerval):
    if not headerval:
        return None
    return headerval.replace("\x09", " ").strip().lower()

def dir_for_sender(sender, output_dir):
    name, addr = parse_sender(sender)
    name = name.replace("/", "")
    addr = addr.replace("/", "")
    if name == "":
        name = "noname"
    if addr == "":
        addr = "noaddr"
    first_subdir = name[:3]
    second_subdir = name[3:6]
    if second_subdir == "":
        second_subdir = "none"
    third_subdir = name[:32]

    # We don't use the email address, because if use_name_in_from=1
    # we want all emails associated with this name in the same directory,
    # regardless of their email address.  It's hard to tell whether
    # we'll have use_name_in_from=1 at this point, since we haven't
    # read the config file yet.  So, just collapse all email addresses
    # associated with this name into the same subdir.  Fixes #82.
    # (Alternative strategy: we could use the addr in the directory name,
    # but if use_name_in_from=1, set addr='alladdrs'.  Not implemented
    # because of the difficulty of plumbing the config parsing here.)

    return '{}/{}/{}/{}'.format(output_dir, first_subdir, second_subdir, third_subdir)

