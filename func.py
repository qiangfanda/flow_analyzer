#!/usr/bin/env python
# coding=utf-8


from collections import Counter
from cmd2 import Cmd,make_option,options
from optparse import OptionParser
import sys
from pymongo import MongoClient
from scapy.all import *
import urllib2
import re

class bcolors:
    HEADER = '\033[95m'
    PROMPT = '\033[94m'
    TXT = '\033[93m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

class Func(Cmd):

    def __init__(self,filename):
        Cmd.__init__(self)
        self.prompt = bcolors.PROMPT + "ForPCAP >>> " + bcolors.ENDC
        self.loadPcap(filename)
        self.cmd=""
        

    def loadPcap(self,filename):
        sys.stdout.write(bcolors.TXT + "## Loading PCAP " + filename + " ... ")
	sys.stdout.flush()
        self.pcap = rdpcap(filename)
        sys.stdout.write("OK." + bcolors.ENDC + "\n")

    #获取数据包数目
    def do_count(self, arg, opts=None):
        sys.stdout.write(bcolors.TXT + "##counting all packets...")
        sys.stdout.flush()
        count=len(self.pcap)
        sys.stdout.write("OK.\n")
        count = bytes(count)
        print bcolors.TXT + "##RESULT:" + count + "packets" + bcolors.ENDC
        self.cmd = "count"


    #获取包内容
    def do_layer(self, arg, opts=None):
        layer = {}
        packet = self.pcap[int(arg)] 
        
        if Ether in packet:
            p = {}
            p['dst'] = packet.getlayer(Ether).dst
            p['src'] = packet.getlayer(Ether).src
            p['type'] = packet.getlayer(Ether).type
        
            layer['Ether'] = p

        if IP in packet:
            p = {}
        
            p['version'] = packet.getlayer(IP).version
            p['ihl'] = packet.getlayer(IP).ihl
            p['tos'] = packet.getlayer(IP).tos
            p['len'] = packet.getlayer(IP).len
            p['id'] = packet.getlayer(IP).id
            p['flags'] = packet.getlayer(IP).flags
            p['frag'] = packet.getlayer(IP).frag
            p['ttl'] = packet.getlayer(IP).ttl
            p['proto'] = packet.getlayer(IP).proto
            p['chksum'] = packet.getlayer(IP).chksum
            p['src'] = packet.getlayer(IP).src
            p['dst'] = packet.getlayer(IP).dst
            p['options'] = packet.getlayer(IP).options
        
            layer['IP'] = p
    
        if TCP in packet:
            p = {}

            p['sport'] = packet.getlayer('TCP').sport
            p['dport'] = packet.getlayer('TCP').sport
            p['seq'] = packet.getlayer('TCP').seq
            p['ack'] = packet.getlayer('TCP').ack
            p['dataofs'] = packet.getlayer('TCP').dataofs
            p['reserved'] = packet.getlayer('TCP').reserved
            p['flags'] = packet.getlayer('TCP').flags
            p['window'] = packet.getlayer('TCP').window
            p['chksum'] = packet.getlayer('TCP').chksum
            p['urgptr'] = packet.getlayer('TCP').urgptr
            p['options'] = packet.getlayer('TCP').option

            layer['TCP'] = p

        if UDP in packet:
            p = {}
        
            p['sport'] = packet.getlayer('UDP').sport
            p['dport'] = packet.getlayer('UDP').dport
            p['len'] = packet.getlayer('UDP').len
            p['chksum'] = packet.getlayer('UDP').chksum

            layer['UDP'] = p

        if ICMP in packet:
            p = {}

            p['type'] = packet.getlayer('ICMP').type
            p['code'] = packet.getlayer('ICMP').code
            p['chksum'] = packet.getlayer('ICMP').chksum
            p['id'] = packet.getlayer('ICMP').id
            p['seq'] = packet.getlayer('ICMP').seq

            layer['ICMP'] = p

        if ARP in packet:
            p = {}
    
            p['hwtype'] = packet.getlayer('ARP').hwtype
            p['ptype'] = packet.getlayer('ARP').ptype
            p['hwlen'] = packet.getlayer('ARP').hwlen
            p['plen'] = packet.getlayer('ARP').plen
            p['op'] = packet.getlayer('ARP').op
            p['hwsrc'] = packet.getlayer('ARP').hwsrc
            p['psrc'] = packet.getlayer('ARP').psrc
            p['hwdst'] = packet.getlayer('ARP').hwdst
            p['pdst'] = packet.getlayer('ARP').pdst

            layer['ARP'] = p

        if DNS in packet:
            p = {}

            p['id'] = packet.getlayer('DNS').id
            p['qr'] = packet.getlayer('DNS').qr
            p['opcode'] = packet.getlayer('DNS').opcode
            p['aa'] = packet.getlayer('DNS').aa
            p['tc'] = packet.getlayer('DNS').tc
            p['rd'] = packet.getlayer('DNS').rd
            p['ra'] = packet.getlayer('DNS').ra
            p['z'] = packet.getlayer('DNS').z
            p['rcode'] = packet.getlayer('DNS').rcode
            p['qdcount'] = packet.getlayer('DNS').qdcount
            p['ancount'] = packet.getlayer('DNS').ancount
            p['nscount'] = packet.getlayer('DNS').nscount
            p['arcount'] = packet.getlayer('DNS').arcount
            if packet.getlayer('DNS').an != None:
                p['an_rrname'] = packet.gatlayer('DNS').an.rrname
                p['an_type']  = packet.gatlayer('DNS').an.type
                p['an_rclass'] = packet.gatlayer('DNS').an.rclass
                p['an_ttl'] = packet.gatlayer('DNS').an.ttl
                p['an_rdata'] = packet.gatlayer('DNS').an.rdata
            if packet.getlayer('DNS').ar == None: 
                p['ar'] = packet.getlayer('DNS').ar
            if DNSQR in packet:
                p['DNSQR'] = True
                p['qname'] = packet.gatlayer('DNS').qd.qname
                p['qtype'] = packet.gatlayer('DNS').qd.qtype
                p['qclass'] = packet.gatlayer('DNS').qd.qclass
            if DNSRR in packet:
                p['DNSRR'] = True
                p['rrname'] = packet.gatlayer('DNS').ns.rrname
                p['type'] = packet.gatlayer('DNS').ns.type
                p['rclass'] = packet.gatlayer('DNS').ns.rclass
                p['ttl'] = packet.gatlayer('DNS').ns.ttl
                p['rdata'] = packet.gatlayer('DNS').ns.rdata
        
            layer['DNS'] = p
        

        sys.stdout.write(bcolors.TXT + "##NO." + bytes(arg) + "PACKET...")
        sys.stdout.flush()
        print '\n'
        for lay in layer:
            print "-----" + lay + "-----"
            for i in layer[lay]:
                print i + ' : ' + bytes(layer[lay][i])
        self.cmd = "layer"





    #获取包类型及个数
    def do_stat(self, arg, opts=None):
        sys.stdout.write(bcolors.TXT + "## Calculating statistics about the PCAP ... ")
	sys.stdout.flush()
        tcp = 0
        udp = 0
        arp = 0
        icmp = 0
        other = 0
        pcapstat = {}
        for packet in self.pcap:
            if TCP in packet:
                tcp = tcp + 1
            elif UDP in packet:
                udp = udp + 1
            elif ARP in packet:
                arp = arp + 1
            elif ICMP in packet:
                icmp = icmp + 1
            else:
                other = other + 1
        sys.stdout.write("OK.\n"+ bcolors.ENDC)
	print "## Statistics :"
	print "TCP : " + str(tcp) + " packet(s)"
	print "UDP : " + str(udp) + " packet(s)"
	print "ARP : " + str(arp) + " packet(s)"
	print "ICMP : " + str(icmp) + " packet(s)"
	print "Other : " + str(other) + " packet(s)"
	print "Total : " + str(tcp + udp + arp + icmp + other) + " packet(s)"
	print "## End of statistics"
		
	self.cmd = "stat"

    '''
    查询以太网卡生产厂商
    传入mac地址(macad)
    返回生产厂商名(name)
    '''
    def do_macprod(self, arg, opts=None):
        maclist = str(arg).split(':')
        macstr = '-'.join(maclist).strip()
        url = 'http://api.macvendors.com/' + macstr
        name = urllib2.urlopen(url,timeout=3).read()
        if name:
            print macstr + " ===> " + name
        else:
            print "sorry can't found"
        
        self.cmd = "macprod"
    '''
    查询dst_mac
    '''
    '''
    def do_d_mac(self,opts=None):
        pcap =  self.pcap
        dst = str(arg)
        packets = []
        for packet in pcap:
            if Ether in packet:
                if packet.getlayer(Ether).dst == dst:
                    src = packet.getlayer(Ether).src 
                    if src not in packets:
                        packets.append(src)
        
        sys.stdout.write(bcolors.TXT + "## they send to "+ str(arg)  + " ... ")
        sys.stdout.flush()
        print '\n'
        for i in packets:
            print i + "\n"

        sys.stdout.write("OK.\n" + bcolors.ENDC)
        
        self.cmd = "d_mac"

    '''
    
    def do_followtcpstream(self, arg, opts=None):
	sys.stdout.write(bcolors.TXT + "## Searching TCP Stream in PCAP ... ")
	sys.stdout.flush()
	l = self.pcap[int(arg)]
	ipsrc = l.getlayer("IP").src
	ipdst = l.getlayer("IP").dst
	portsrc = l.getlayer("TCP").sport
	portdst = l.getlayer("TCP").dport
		
	pkt = []
	pkt.append([])
	for i,p in enumerate(self.pcap):
		if p.haslayer('TCP'):
		    if p[IP].src == ipsrc and p[IP].dst == ipdst and p[TCP].sport == portsrc and p[TCP].dport == portdst:
			pkt.append([i, p])
		    if p[IP].src == ipdst and p[IP].dst == ipsrc and p[TCP].sport == portdst and p[TCP].dport == portsrc:
			pkt.append([i, p])
					
	sys.stdout.write("OK\n" + bcolors.ENDC)
        for i in  pkt:
            print i

	self.cmd = "followTCPStream"
 

    def do_follow(self, arg, opts=None):
	sys.stdout.write(bcolors.TXT + "## Searching TCP Stream in PCAP ... ")
	sys.stdout.flush()
	l = self.pcap[int(arg)]
	ipsrc = l.getlayer("IP").src
	ipdst = l.getlayer("IP").dst
	portsrc = l.getlayer("TCP").sport
	portdst = l.getlayer("TCP").dport
		
	pkt = []
	pkt.append([])
	for i,p in enumerate(self.pcap):
		if p.haslayer('TCP'):
		    if p[IP].src == ipsrc and p[IP].dst == ipdst and p[TCP].sport == portsrc and p[TCP].dport == portdst:
			pkt.append([i, p])
		    if p[IP].src == ipdst and p[IP].dst == ipsrc and p[TCP].sport == portdst and p[TCP].dport == portsrc:
			pkt.append([i, p])
					
	sys.stdout.write("OK\n" + bcolors.ENDC)
        for i in  pkt:
            print i

	self.cmd = "followTCPStream"

    '''
    检测是否arp欺骗
    如果同一mac地址但发包ipsrc不同或
    ipdst总是同一个地址，可能在进行arp-poison
    num是包的编号，且该包为arp包
    '''
    def do_farp(self, arg, opts=None):
        pcap = self.pcap
        packets = []

        for i,p in enumerate(pcap):
            if p.haslayer(ARP):
                if p.getlayer(ARP).op == 2 and bytes(p.getlayer(ARP).hwdst)==arg:
                    packets.append(bytes(i)+'=>'+p.getlayer(ARP).psrc)

        for i in packets:
            print i

        self.cmd = "farp"


          

    '''
    检测ip-spoofing
    num为包编号，且该包为icmp包
    '''
    def do_fip(self, arg, opts=None):
        pcap = self.pcap
        packet = {}
        ip = pcap[int(arg)].getlayer('IP').dst
        for i,p in enumerate(pcap):
            if p.haslayer('ICMP'):
                if p.getlayer('IP').dst == ip and 00:
                    packet['(' + bytes(i)  + ')' + "p.getlayer('IP').src"] = p.getlayer('IP').dst

        for i in packet:
            print i + '===>' + packet[i]

        self.cmd = "fip"


    def do_fdns(self, arg, opts=None):
        dns = []
        dns.append([])

        for i,packet in enumerate(self.pcap):
            if DNS in packet:
	        res = packet.getlayer('DNS').qd.qname
	        if res[len(res) - 1] == '.':
		    res = res[:-1]
                dns.append([i, res])
        for i in dns:
            print i


        self.cmd = "fdns"
		
    def do_fdstports(self, arg, opts=None): 
        pcap = self.pcap
        ports = []
        ports.append([])
    
        for i,packet in enumerate(pcap):
	    if TCP in packet: 
    	        res = packet.getlayer('TCP').dport
	        test = 0
	        for port in ports:
		    if len(port) == 2:
	                if int(res) == int(port[1]):
			    test = 1
		            break
	        if test == 0:
	            ports.append([i, res])
        for i in ports:
            for j in i[1:]:
                if j<1024:
                    print j

        self.cmd = "fdstports"


    #检测SYN Flood
    def do_syn(self, arg, opts=None):
        pcap = self.pcap
        packet = {}
        for i,p in enumerate(pcap):
            if p.haslayer(TCP):
                if p.getlayer(TCP).flags == 2:
                    packet['(' +bytes(i) + ')' + p.getlayer(IP).src] = p.getlayer(IP).dst
        for i in packet:
            print i + "===>" + bytes(packet[i]) 

        self.cmd = "syn"

    #检测UDP Flood
    #该包为udp 
    def do_fudp(self, arg, opts=None):
        pcap = self.pcap
        packet = {}
        ip_dst = pcap[int(arg)].getlayer('IP').dst
        for i,p in enumerate(pcap):
            if p.haslayer('UDP'):
                if p.getlayer('IP').dst == ip_dst:
                    packet['(' + bytes(i)+ ')' + p.getlayer('IP').src] = p.getlayer('UDP').sport
        for i in packet:
            print  i + "===>"  + bytes(packet[i])

        self.cmd = "fudp"

    #获取包来源地址
    def do_ipsrc(self, arg, opts=None):
        ipsrc = []
        pcap = self.pcap
        for packet in pcap:
            if TCP in packet:
                # if packet.getlayer('TCP').flags == 2:
                    ipsrc.append(packet.getlayer('IP').src)
        ipsrclist = Counter(ipsrc).most_common()
        
        for i in ipsrclist:
            print i 
        self.cmd = "ipsrc"

    #获取包去向地址
    def do_ipdst(self, arg, opts=None):
        ipdst = []
        pcap = self.pcap
        for packet in pcap:
            if TCP in packet:
                # if packet.getlayer('TCP').flags == 2:
                    ipdst.append(packet.getlayer('IP').dst)
        ipdstlist = Counter(ipdst).most_common()
        for i in ipdstlist:
            print i 
        self.cmd = "ipdst"

    #获取包去向端口
    def do_portdst(self, arg, opts=None):
        dstport = []
        dstportlist=()
        pcap = self.pcap
        for packet in pcap:
            if TCP in packet:
                dstport.append(packet.getlayer('TCP').dport)
        dstportlist = Counter(dstport).most_common()
        for i in dstportlist:
            print i 
        self.cmd = "portdst"

    #获取DNS请求
    def do_getdns(self, arg, opts=None):
        dns = []
        pcap = self.pcap
        for packet in pcap:
            if DNS in packet:
                    res = packet.getlayer('DNS').qd.qname
                    if res[len(res) - 1] == '.':
                        res = res[:-1]
                    dns.append(res)
        dns = Counter(dns).most_common()
        for i in dns:
            print i 
        self.cmd = "getdns"
    #邮件数据包提取
    def do_getmail(self, arg, opts=None):
        mailpkts = []
        result = []
        matchs=[]
        pcap = self.pcap
        pattern1 = re.compile(r'USER (\w+)*@((\w+)\.)*(\w+)')
        pattern2 = re.compile(r'PASS (\w+)*')
        for packet in pcap:
            if TCP in packet:
                if packet.getlayer('TCP').dport == 25 or packet.getlayer('TCP').sport == 25 or packet.getlayer('TCP').dport == 110 or packet.getlayer('TCP').sport == 110 :
                    mailpkts.append(packet)
        for packet in mailpkts:
            if packet.getlayer('TCP').flags == 24:
                result.append(packet.getlayer(Raw).load)
        for i in result:
            match1 = pattern1.search(i)
            match2 = pattern2.search(i)
            if match1:
                matchs.append(match1.group())
            elif match2:
                matchs.append(match2.group())
        for i in matchs:
            print i + "\n" 
        self.cmd = "getmail"
    #Web数据包提取 提取host
    def do_getweb(self, arg, opts=None):
        webpkts = []
        results = []
        matchs = []
        pcap = self.pcap
        for packet in pcap:
            if TCP in packet:
                if packet.getlayer('TCP').dport == 80 or packet.getlayer('TCP').dport == 8080:
                    webpkts.append(packet)
        for packet in webpkts:
            if packet.getlayer('TCP').flags == 24:
                results.append(packet.getlayer(Raw).load)
        for result in results:
            pattern = re.compile(r'Host: ((\w+)\.)*(\w+)')
            match = pattern.search(result)
            matchs.append(match.group())
        
        for i in matchs:
            print i + "\n"

        self.cmd = "getweb"



def main():
	
	shell = Func(sys.argv[1])
	shell.cmdloop()

if __name__ == '__main__':
	main()
