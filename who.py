import whois
import sys
import json


if len(sys.argv) is 1:
        print "You should write option."

read=sys.argv[1]
f=open(read,'r')
out=open("result.txt",'w')
while True:
        line=f.readline()
        if not line:break
        domain = whois.query(line)
        dict1 = domain.__dict__
       result=json.dumps(dict1,indent=4,sort_keys=True)
        print dict1
        out.write(dict1+"\n")


f.close()
out.close()

