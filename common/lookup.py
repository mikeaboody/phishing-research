import re
import os
from netaddr import IPNetwork, IPAddress
import socket
from ipwhois import IPWhois

class Lookup:
    offline = False
    seen_pairings_keys = []
    seen_pairings = {}
    seen_domain_ip = {}
    seen_domain_org = {}
    privateCIDR = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    cidr_hit = 0
    cidr_tot = 0
    domain_hit = 0
    domain_tot = 0

    @classmethod
    def initialize(cls, offline=True):
        Lookup.offline = offline
        if Lookup.offline:
            Lookup.loadCIDRs("cidr")
            Lookup.loadDomainIPPairings("domains.txt")
            Lookup.loadDomainOrgPairings("domain2Org.txt")
        if os.path.exists("output/hit_rate.txt"):
            os.remove("output/hit_rate.txt")

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
        if Lookup.offline:
            domain = extract_domain(fromHeader)
            if domain:
                Lookup.domain_tot += 1
                if domain in Lookup.seen_domain_ip:
                    Lookup.domain_hit += 1
                    return Lookup.seen_domain_ip[domain]
            return False
        else:
            domain = extract_domain(fromHeader)
            if domain:
                Lookup.domain_tot += 1
                domain = get_endMessageIDDomain(domain)
                try:
                    if (domain in Lookup.seen_domain_ip):
                        Lookup.domain_hit += 1
                        return Lookup.seen_domain_ip[domain]
                    else:
                        ip = socket.gethostbyname(domain)
                        Lookup.seen_domain_ip[domain] = ip
                        if ip:
                            Lookup.domain_hit += 1
                        return ip
                except:
                    return False

    @classmethod
    def getCIDR(cls, ip):
        if Lookup.offline:
            Lookup.cidr_tot += 1
            for cidr in Lookup.seen_pairings_keys:
                ip_bin = getBinaryRep(ip, cidr)
                if ip_bin in Lookup.seen_pairings[cidr]:
                    Lookup.cidr_hit += 1
                    return cidr
            return 32
        else:
            Lookup.cidr_tot += 1
            try:
                if ip in Lookup.seen_pairings:
                    Lookup.cidr_hit += 1
                    return Lookup.seen_pairings[ip]
                else:
                    obj = IPWhois(ip)
                    results = obj.lookup_whois()
                    if "nets" not in results.keys() or "cidr" not in results["nets"][0].keys():
                        cidr = ip + "/32"
                    else:
                        cidr = results["nets"][0]["cidr"]
                    Lookup.seen_pairings[ip] = cidr
                    if cidr:
                        Lookup.cidr_hit += 1
                    return cidr
            except:
                Lookup.seen_pairings[ip] = "Invalid"
                return "Invalid"

    @classmethod
    def writeStatistics(cls):
        if (not os.path.exists("output")):
            os.makedirs("output")
        with open("output/hit_rate.txt", "a+") as f:
            f.write("Total number of cidr blocks looked up: " + str(Lookup.cidr_tot) + "\n")
            f.write("Total number of cidr blocks found: " + str(Lookup.cidr_hit) + "\n")
            f.write("Total number of domains looked up: " + str(Lookup.domain_tot) + "\n")
            f.write("Total number of domains found: " + str(Lookup.domain_hit) + "\n")

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