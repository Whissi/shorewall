#!/usr/bin/env python2

"""
getreserved.py - Copyright (c) 2002 by Andy Wiggin
Licenced under the GPL

Script to write a stream of reserved addresses
from an IANA address allocation file. This list
is apparently similiar to RFC 1466.

The file can be obtained at

  http://www.iana.org/assignments/ipv4-address-space

Download this file to a local file, then run the following:
  
  cat local_file | ./getreserved.py

to produce a list of reserved subnets which can be used
in a shell script.
"""
import sys

__script_debug = 0
__output_style = 'rfc1918'

class IpNet:
    def __init__(self):
        self.netnum  = 0
        self.maskind = 0

    def __str__(self):
        return "%u.%u.%u.%u/%d"%\
            (self.GetNetByte(3), self.GetNetByte(2),
             self.GetNetByte(1), self.GetNetByte(0), self.maskind)

    def Set(self, netnum, maskind):
        self.netnum = int(netnum)
        self.maskind = int(maskind)

    def GetNetNum(self): return self.netnum

    def GetMaskIndex(self): return self.maskind

    def GetMaskBits(self):
        numbits = 32 - self.maskind
        retmask = 0
        for i in range(numbits):
            retmask = (retmask << 1) + 0x1
        return retmask

    def GetNetByte(self, byteind):
        if byteind < 0 or byteind > 3:
            raise RuntimeError, "bad byte index"
        shiftcount = 8 * byteind
        mask = 0xff << shiftcount
        byte = self.netnum & mask
        return (byte >> shiftcount) & 0xff


def GetIpNetList(fd):
    ipnets = []
    for l in fd.xreadlines():
        if l.find('IANA - Reserved') > 0 or \
           l.find('IANA - Private Use') > 0:
            # Get the range and net size from the first field
            fields = l.split()
            (ip_range, mask_size) = fields[0].split('/')
            if __script_debug:
                print '\t\t', ip_range, mask_size

            # Convert the range to numbers
            ip_range = ip_range.split('-')
            ip_min = int(ip_range[0])
            if len(ip_range) > 1:
                ip_max = int(ip_range[1])
            else:
                ip_max = ip_min

            # For each number in the range, add an ip net string to the output
            # list
            for ip_num in range(ip_min, ip_max+1):
                #ipel = "%d.0.0.0/%s"%(ip_num, mask_size)
                ipel = IpNet()
                ipel.Set(ip_num << 24, int(mask_size))
                if __script_debug:
                    print str(ipel)
                ipnets.append(ipel)

    return ipnets

def CompactIpNetList(ipnets):
    """
    Combine an many nets as possible.
    """
    done = 0
    ipnets.sort(IpCmpFunc)
    oldlist = ipnets
    while not done:
        done = 1
        newlist = []
        head = None
        while len(oldlist) > 0:
            if not head:
                # Consume one item from the list
                head = oldlist.pop(0)
            else:
                # Consume head, and maybe an item from the list
                next = oldlist.pop(0)
                # Determine of head and next can be merged
                # The merge condition is that two element have the same netmask,
                # their net numbers are different by just one bit, and that
                # bit is the least significant bit after the mask bits.
                canmerge = 0
                if head.GetMaskIndex() == next.GetMaskIndex():
                    # Get the net numbers
                    nnxor = head.GetNetNum() ^ next.GetNetNum()

                    # Calculate what the XOR would have to be for a merge
                    mask = head.GetMaskBits()
                    nextbit = (mask << 1) & ~mask

                    if nnxor == nextbit:
                        canmerge = 1

                if canmerge:
                    # Because the list is sorted and we know that the xor was
                    # different by just one bit, the element occuring earier
                    # in the list (head) already has the correct net number,
                    # since it must have a 0 in the bit being merged. Therefore
                    # we can just use head, and decrease the mask index by one
                    nn = head.GetNetNum()
                    mindex =  head.GetMaskIndex()
                    head.Set(nn, mindex-1)
                    newlist.append(head)
                    head = None
                    next = None # This element is just abandoned

                    # We'll need to loop again
                    done = 0 
                else:
                    newlist.append(head)
                    head = next

        # There might be a valid head element sitting around at the end
        if head:
            newlist.append(head)

        # Make newlist the current list
        oldlist = newlist

    return oldlist

def IpCmpFunc(el1, el2):
    n1 = el1.GetNetNum()
    n2 = el2.GetNetNum()

    # Not sure how to do unsigned comparisons in python, so
    # if the 32'nd bit is set, create a long out of it, add
    # twice the value of the 32 bit (the 33rd bit), and compare.
    if n1 < 0:
        n1 = long(n1) + 0x100000000L
    if n2 < 0:
        n2 = long(n2) + 0x100000000L

    v = n1 - n2
    if v < 0:
        return -1
    elif v > 0:
        return 1
    else:
        return 0

def main():
    infd = sys.stdin
    outfd = sys.stdout

    # Get the list
    iplist = GetIpNetList(infd)
    iplist = CompactIpNetList(iplist)

    if __output_style == 'shlist':
        # Write a list of strings, compatible with a shell script list.
        # Fomats four on each line, indented by one TAB.
        numperline = 4
        numinline = 0
        for ip in iplist:
            if numinline == 0:
                outfd.write( '\t\t' )

            outfd.write("'%s' "%ip)
            numinline += 1

            if numinline == numperline:
                outfd.write( "\\\n" )
                numinline = 0

        if numinline > 0:
            outfd.write( "\n" )

    elif __output_style == 'rfc1918':
        for ip in iplist:
            outfd.write("%s\t\tlogdrop\t\t# Reserved\n"%ip)

if __name__ == '__main__':
    main()
