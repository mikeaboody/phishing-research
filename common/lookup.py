import re
import os
from netaddr import IPNetwork, IPAddress

class Lookup:
    seen_pairings_keys = []
    seen_pairings = {}
    seen_domain_ip = {}
    seen_domain_org = {}
    privateCIDR = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

    @classmethod
    def loadAll(cls):
        Lookup.loadCIDRs("cidr")
        Lookup.loadDomainIPPairings("domains.txt")
        Lookup.loadDomainOrgPairings("domain2Org.txt")

    @classmethod
    def loadCIDRs(cls, directory):
        for item in os.listdir(directory):
            filename = os.path.join(directory, item)
            with open(filename, "r") as f:
                for line in f:
                    line_split = line.split("/")
                    ip, cidr = line_split[0], int(line_split[1])
                    if cidr not in Lookup.seen_pairings:
                        Lookup.seen_pairings[cidr] = set()
                    Lookup.seen_pairings[cidr].add(getBinaryRep(ip, cidr))
        Lookup.seen_pairings_keys = sorted(Lookup.seen_pairings.keys(), reverse=True)

    @classmethod
    def loadDomainIPPairings(cls, filename):
        with open(filename, "r") as f:
            for line in f:
                line_split = line.split()
                domain, ip = line_split[0], line_split[1]
                Lookup.seen_domain_ip[domain] = ip

    @classmethod
    def loadDomainOrgPairings(cls, filename):
        with open(filename, "r") as f:
            for line in f:
                line_split = line.split()
                domain, org = line_split[0], line_split[1]
                Lookup.seen_domain_org[domain] = org


    # returns cidr of public IP or returns false if there is no IP or if the IP is private
    @classmethod
    def public_IP(cls, fromHeader):
        ip = extract_ip(fromHeader)
        if ip and not (IPAddress(ip) in IPNetwork(Lookup.privateCIDR[0]) or IPAddress(ip) in IPNetwork(Lookup.privateCIDR[1]) or IPAddress(ip) in IPNetwork(Lookup.privateCIDR[2])):
            return ip
        return None

    # returns false if domain is invalid or private domain
    @classmethod
    def public_domain(cls, fromHeader):
        domain = extract_domain(fromHeader)
        if domain and domain in Lookup.seen_domain_ip:
            return Lookup.seen_domain_ip[domain]
        return False

    # returns false if domain is invalid or private domain
    @classmethod
    def public_domainOld(cls, fromHeader):
        domain = extract_domain(fromHeader)
        if domain:
            domain = get_endMessageIDDomain(domain)
            try:
                if (domain in Lookup.seen_domain_ip):
                    return Lookup.seen_domain_ip[domain]
                else:
                    ip = socket.gethostbyname(domain)
                    Lookup.seen_domain_ip[domain] = ip
                    return ip
            except:
                return False

    @classmethod
    def getCIDR(cls, ip):
        for cidr in Lookup.seen_pairings_keys:
            ip_bin = getBinaryRep(ip, cidr)
            if ip_bin in Lookup.seen_pairings[cidr]:
                return cidr
        return 32
        
    @classmethod
    def getCIDROld(cls, ip):
        try:
            if ip in Lookup.seen_pairings:
                return Lookup.seen_pairings[ip]
            else:
                obj = IPWhois(ip)
                results = obj.lookup()
                if "nets" not in results.keys() or "cidr" not in results["nets"][0].keys():
                    cidr = ip + "/32"
                else:
                    cidr = results["nets"][0]["cidr"]
                Lookup.seen_pairings[ip] = cidr
                return cidr
        except:
            Lookup.seen_pairings[ip] = "Invalid"
            return "Invalid"

def getBinaryRep(ip, cidr):
    ip_bin = ''.join([bin(int(x)+256)[3:] for x in ip.split('.')])
    return ip_bin[:cidr]

def get_endMessageIDDomain(domain):
    if domain == None:
        return domain
    if '.' in domain:
        indexLastDot = len(domain) - domain[::-1].index(".") - 1
        rest = domain[:indexLastDot]
        if '.' in rest:
            indexNextDot = len(rest) - rest[::-1].index(".") - 1
            return domain[indexNextDot+1:]
    return domain

def extract_ip(content):
    r = re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", content)
    return r.group() if r else None

def extract_domain(content):
    if ("(" in content):
        firstParen = content.index("(")
    else:
        return None
    return content[:firstParen-1]