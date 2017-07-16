import whois
import pythonwhois
import sys
import json

line=[]

if len(sys.argv) is 1:
	print "You should write option."

read=sys.argv[1]
f=open(read,'r')
line=f.read()


data=pythonwhois.net.get_whois_raw(line,with_server_list=False)
#domain=whois.query(line)
#output=data.split("\\n")
dict1={'test':data}
#dict1=domain.__dict__
result=json.dumps(dict1)
f.close()
out=open('result.txt','w')
out.write(result)
