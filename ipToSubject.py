import os
import re
from subprocess import Popen, PIPE

DEVNULL = open(os.devnull, 'wb')

outFile = open('no_SNI_CN.out','w')

with open("no_SNI_fastpath.out", "r") as ins:
    array = []
    for line in ins:
        DEVNULL_IN = open(os.devnull, 'rb')
        [count, addr] = line.split() # [1]
        #print '######'
        #print addr
        #print '######'
        p = Popen(["timeout", "5", "openssl", "s_client", "-connect", addr + ":443"],stdout=PIPE,stdin=DEVNULL_IN,stderr=PIPE)
        commonName = 'unknown'
        #print "done!!"
        #sout, serr = p.communicate()
        for out in p.stdout:
            #the real code does filtering here
            
            outLine = out.rstrip()
            #print outLine
            subMatch = re.match('subject', outLine)
            if subMatch:
                #print addr + "" + out.rstrip()
                certParams = outLine.split('/')
                for param in certParams:
                    if re.match('CN=', param):
                        commonName = param.split('=')[1]

        p2 = Popen(["nslookup", addr],stdout=PIPE,stdin=DEVNULL_IN,stderr=PIPE)
        domainName = 'unknown'
        #print "done!!"
        #sout, serr = p.communicate()
        for out in p2.stdout:
            #the real code does filtering here
            
            outLine = out.rstrip()
            #print "nslookup : " + outLine
            nameMatch = re.match('.*name = ', outLine)
            if nameMatch:
                #print "DNS match : " + out.rstrip()
                dnsParams = outLine.split(' ')
                #for dnsParam in dnsParams:
                #    print dnsParam
                domainName = dnsParams[2]

        #p2.close()

        #p.stdin.close()
        #print addr + "\t" + commonName
        report = '{:5s} {:20s} {:30s} {:30s}'.format(count, addr, commonName, domainName)
        print report
        outFile.write(count + " " + addr + " " + commonName +  " " + domainName + '\n')
        outFile.flush()
        os.fsync(outFile.fileno())
        DEVNULL_IN.close()


outFile.close();
