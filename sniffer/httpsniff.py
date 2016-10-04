#! /usr/bin/env python
"""
This will listen for all http GET requests on the given interface.
"""

import sys
import pcap
import string
import socket
import struct

protocols = {
    socket.IPPROTO_TCP: 'tcp',
    socket.IPPROTO_UDP: 'udp',
    socket.IPPROTO_ICMP: 'icmp'
}


def decode_ip_packet(s):
    d = {}
    d['version'] = (ord(s[0]) & 0xf0) >> 4
    d['header_len'] = ord(s[0]) & 0x0f
    d['tos'] = ord(s[1])
    d['total_len'] = socket.ntohs(struct.unpack('H', s[2:4])[0])
    d['id'] = socket.ntohs(struct.unpack('H', s[4:6])[0])
    d['flags'] = (ord(s[6]) & 0xe0) >> 5
    d['fragment_offset'] = socket.ntohs(struct.unpack('H', s[6:8])[0] & 0x1f)
    d['ttl'] = ord(s[8])
    d['protocol'] = ord(s[9])
    d['checksum'] = socket.ntohs(struct.unpack('H', s[10:12])[0])
    d['source_address'] = pcap.ntoa(struct.unpack('i', s[12:16])[0])
    d['destination_address'] = pcap.ntoa(struct.unpack('i', s[16:20])[0])
    if d['header_len'] > 5:
        d['options'] = s[20:4*(d['header_len']-5)]
    else:
        d['options'] = None
    d['data'] = s[4*d['header_len']:]
    return d


def decode_tcp_packet(s):
    d = {}
    d['source_port'] = socket.ntohs(struct.unpack('H', s[0:2])[0])
    d['dest_port'] = socket.ntohs(struct.unpack('H', s[2:4])[0])
    d['sequence'] = socket.ntohl(struct.unpack('I', s[4:8])[0])
    d['ack'] = socket.ntohl(struct.unpack('I', s[8:12])[0])
    d['offset'] = (ord(s[12]) & 0xf0) >> 4
    d['cksum'] = socket.ntohs(struct.unpack('H', s[16:18])[0])
    d['urgent'] = socket.ntohs(struct.unpack('H', s[18:20])[0])
    d['NS'] = (ord(s[12]) & 0x01) != 0
    d['CWR'] = (ord(s[13]) & 0x80) != 0
    d['ECE'] = (ord(s[13]) & 0x40) != 0
    d['URG'] = (ord(s[13]) & 0x20) != 0
    d['ACK'] = (ord(s[13]) & 0x10) != 0
    d['PSH'] = (ord(s[13]) & 0x08) != 0
    d['RST'] = (ord(s[13]) & 0x04) != 0
    d['SYN'] = (ord(s[13]) & 0x02) != 0
    d['FIN'] = (ord(s[13]) & 0x01) != 0

    d['data'] = s[4*d['offset']:]
    return d


def print_http_packet(pktlen, data, timestamp):
    if not data:
        return

    if data[12:14] == '\x08\x00':
        decoded = decode_ip_packet(data[14:])
        tcp = decode_tcp_packet(decoded['data'])
        if tcp['PSH'] and tcp['data'][0:4] == 'GET ':
            # then this is an http request
            f = open('%d.pkt' % timestamp, 'w')
            f.write(tcp['data'])
            f.close()
            print 'Wrote: %d' % timestamp

if __name__ == '__main__':

    if len(sys.argv) < 2:
        print 'usage: httpsniff.py <interface>'
        sys.exit(0)

    p = pcap.pcapObject()
    dev = sys.argv[1]
    net, mask = pcap.lookupnet(dev)
    p.open_live(dev, 1600, 0, 100)
    p.setfilter(string.join(sys.argv[2:], ' '), 0, 0)

    # try-except block to catch keyboard interrupt.    Failure to shut
    # down cleanly can result in the interface not being taken out of promisc.
    # mode
    # p.setnonblock(1)
    try:
        while 1:
            p.dispatch(1, print_http_packet)
    except KeyboardInterrupt:
        print '%s' % sys.exc_type
        print 'shutting down'
        print '%d packets received, %d packets dropped'
        print '%d packets dropped by interface' % p.stats()

# vim:set ts=4 sw=4 et:
