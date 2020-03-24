######################################################################
######################################################################
############  SimpleProbe - detect OS by ttl value        ############
############    tjr3xx - Ferris State University - 2020   ############
######################################################################
######################################################################


import ipaddress, threading, queue, time, argparse, random
from scapy.all import *

#####################################################################
########## Command line interface ###################################
#####################################################################

parser = argparse.ArgumentParser()
parser.add_argument("-T","--threads",dest="thread_count", metavar="<threads>", type=int, default=50, help="number of threads to use (default: 50 threads)")
parser.add_argument("-d","--delay", dest="packet_delay", metavar="<seconds>", type=int, default=0, help="seconds to wait before sending the next packet (default: 0 seconds)")
parser.add_argument("-t","--timeout", dest="connection_timeout", metavar="<seconds>", type=int, default=5, help="seconds to wait for target to respond (default: 1 second)")
parser.add_argument("--dns",dest="dns_server", metavar="<server>", type=str, default="8.8.8.8", help="dns server used to makre queries (default: 8.8.8.8)")
parser.add_argument("-n", "--no-resolve", dest="resolve_ip", action="store_false", default=True, help="do not resolve ips to names (default: resolve ip addresses)")
parser.add_argument("host", metavar="<host|cidr|domain>", nargs="+", help="target host: ip, cidr, or domain")

args = parser.parse_args()


#####################################################################
############ Helper Functions #######################################
#####################################################################

#https://stackoverflow.com/questions/2130016/splitting-a-list-into-n-parts-of-approximately-equal-length
def splitList(a, n):
    k, m = divmod(len(a), n)
    return (a[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n))

def cidrToIPList(inCidr):
    return [str(ip) for ip in ipaddress.IPv4Network(inCidr) if (str(ip).split(".")[-1]!="0") and (str(ip).split(".")[-1]!="255")]


#####################################################################
########### Scapy Functions #########################################
#####################################################################

def sendPacket(inPacket):
    return sr1(inPacket, verbose=0, timeout=args.connection_timeout)

def ipToDomain(inIP):
    queryAddress  = ".".join(inIP.split(".")[::-1]) + ".in-addr.arpa"
    sourcePort = random.randint(49200,55000)               #generate random ephemeral port
    dnsRequest = IP(dst=args.dns_server)/UDP(sport=sourcePort)/DNS(rd=1,qd=DNSQR(qname=queryAddress, qtype='PTR'))
    dnsResponse = sendPacket(dnsRequest)
    domainNameList = []
    for i in range(dnsResponse[DNS].ancount):
        domainNameList.append(dnsResponse[DNSRR][i].rdata.decode("UTF8")[:-1])
    return domainNameList

def domainToIP(inDomain):
    sourcePort = random.randint(49200,55000)               #generate random ephemeral port
    dnsRequest = IP(dst=args.dns_server)/UDP(sport=sourcePort)/DNS(rd=1,qd=DNSQR(qname=inDomain))
    dnsResponse = sendPacket(dnsRequest)
    ipList = []
    for i in range(dnsResponse[DNS].ancount):
        ipList.append(dnsResponse[DNSRR][i].rdata)
    return ipList

def scanHost(inTarget):
    domainList = []
    if len(inTarget) > 1:
        inDstIP, inDomain = inTarget
    else:
        inDstIP = inTarget

    pingRequest = IP(dst=inDstIP)/ICMP()
    packetResponse = sendPacket(pingRequest)

    #if target doesn't respond to ping, send a tcp to port 80
    if not packetResponse:
        time.sleep(args.packet_delay)
        sourcePort = random.randint(49200,55000)               #generate random ephemeral port
        httpRequest =  IP(dst=inDstIP)/TCP(sport=sourcePort,dport=80)
        packetResponse = sendPacket(httpRequest)

    #ttl vaules https://subinsb.com/default-device-ttl-values/
    if packetResponse:
        target_ttl = packetResponse.ttl
        if target_ttl > 128:
            hops = 255 - target_ttl
            remoteOS = "Solaris/AIX"
        elif target_ttl > 64:
            hops = 128 - target_ttl
            remoteOS = "Windows"
        else:
            hops = 64 - target_ttl
            remoteOS = "*nix"

        if args.resolve_ip:
            domainList += ipToDomain(inDstIP)
        if inDomain not in domainList:
            domainList.append(inDomain)

        return [inDstIP,remoteOS,hops,domainList]
    return []


############################################################
############## Multithreading Support ######################
############################################################

def threadWorker(que,inIPList):
    for dstIP in inIPList:
        results = scanHost(dstIP)
        if results != []:
            que.put(results)
        time.sleep(args.packet_delay)


###########################################################
############### MAIN ######################################
###########################################################

if __name__ == "__main__":
    # Parse user args for target ips
    ipScanList = []
    for host in args.host:
        if any(letter.isalpha() for letter in host):
            ipScanList += [[ip,host] for ip in domainToIP(host)]
        elif host.find("/") > -1:
            try:
               ipScanList += [[ip,] for ip in cidrToIPList(host)]
            except:
               print("[!] Error invalid subnet: " + host)
               exit()
        else:
            ipScanList.append([host,])

    # Create threads to distribute work
    que = queue.Queue()
    threads = []
    for ipListSlice in splitList(ipScanList, args.thread_count):
        if ipListSlice != []:
            t = threading.Thread(target=threadWorker, args=(que,ipListSlice,))
            threads.append(t)
            t.start()

    # Wait for threads to finish
    for t in threads:
        t.join()

    # Pretty print results
    breakLength = 99
    print("\n" + "-" * breakLength)
    print("| {0:15} | {1:12} | {2:4} | {3:55} |".format("IP","OS","HOPS","DOMAINS"))

    while not que.empty():
        target_ip, target_os, target_hop, target_domains = que.get()
        print("-" * breakLength)
        print("| {0:15} | {1:12} | {2:4} | {3:55} |".format(target_ip, target_os, target_hop, ", ".join(target_domains)))

    print("-" * breakLength + "\n")

