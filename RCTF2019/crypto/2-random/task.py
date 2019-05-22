import os,random,sys,string
from hashlib import sha256
import SocketServer
import signal
#!/usr/bin/python

from Crypto.Util.number import *
import gmpy2

Nbits = 128
from flag import FLAG
def add(A, B, a, b, p): # y**2 = x ** 3 + ax + b
    x1, y1 = A
    x2, y2 = B
    if x1 == x2:
        lam =  (3 * x1 * x1 + a) * gmpy2.invert(2 * y1, p)
    else:
        lam = (y2 - y1) * gmpy2.invert(x2-x1, p)
    x3 = (lam ** 2 - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p 
    return (x3, y3)


def mul(n, A, a, b, p, B=0):
    if not n:
        return B
    else:
        return mul(n//2, add(A,A,a,b,p), a, b, p, B if not n&1 else add(B,A,a,b,p) if B else A)

def gen_point(A, B, M):
    while True:
        x = getRandomInteger(Nbits) % M
        y2 = (x**3 + A*x + B) % M
        if legrend(y2, M) == 1:
            break
    y = quadratic_residue(y2, M)
    assert (y** 2) % M == (x**3 + A * x + B) % M
    return (x, y)

def quadratic_residue(a, p):
    s = p - 1
    t = 0
    pa = gmpy2.invert(a, p)
    while s % 2 == 0:
        s = s / 2
        t = t + 1
    i = 2
    while True:
        if legrend(i, p) == -1:
            break
        i = i + 1
    b = pow(i, s, p)
    x = pow(a, (s + 1) / 2, p)
    for i in range(t):
        if pow((pa * x * x) % p, int(2 ** (t - i - 2)), p) == p - 1:
            x = x * pow(b, int(2**i), p) % p
    return x
    
def legrend(a, p):
    if a == 1:
        return 1;
    elif p % a == 0:
        return 0;
    elif a % 2 == 0:
        return legrend(a//2, p) * pow(-1, (p**2 - 1) / 8)
    return legrend(p % a, a) * pow(-1, (a - 1) * (p - 1) / 4)


class Task(SocketServer.BaseRequestHandler):
    def proof_of_work(self):
        random.seed(os.urandom(8))
        proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in xrange(20)])
        digest = sha256(proof).hexdigest()
        self.request.send("sha256(XXXX+%s) == %s\n" % (proof[4:],digest))
        self.request.send('Give me XXXX:')
        x = self.request.recv(10)
        x = x.strip()
        if len(x) != 4 or sha256(x+proof[4:]).hexdigest() != digest: 
            return False
        return True
    def recvnum(self,sz):
        try:
            print sz
            r = sz
            res =""
            while r>0:
                res += self.request.recv(r)
                if res.endswith('\n'):
                    r = 0
                else:
                    r = sz - len(res)
            res = res.strip()
            t = int(res)
        except:
            res = ''
            t = 0
        return t


    def dosend(self, msg):
        try:
            self.request.sendall(msg + '\n')
        except:
            pass

    def handle(self):
        signal.alarm(500)
        if not self.proof_of_work():
            return
        signal.alarm(450)

        M = getPrime(Nbits)
        
        A = getRandomInteger(Nbits) % M
        B = getRandomInteger(Nbits) % M
        
        assert 4 * A ** 3 + 27 * B ** 2 != 0
        
        self.dosend("y**2 = x**3 + %s*x + B" % (A))
        self.dosend("M = %s"%(M))
        

        P = gen_point(A, B, M)
        
        d = getRandomInteger(0x20)
        Q = mul(d, P, A, B, M)
        
        self.dosend("P = (%d, %d)" % P)
        self.dosend("Q = (%d, %d)" % Q)
        
        s = getRandomInteger(Nbits) % M
                
        for i in range(10):
            s = mul(s, P, A, B, M)[0]
            r = mul(s, Q, A, B, M)[0]
            self.dosend("r%d: %d" % (i, r))
        
        self.dosend("r10 = ?")
        
        t = self.recvnum(1024)
        
        s = mul(s, P, A, B, M)[0]
        r = mul(s, Q, A, B, M)[0]
        
        if t == r:
            self.dosend("%s\n" % FLAG)
        else:
            self.dosend("Nonono")
        self.request.close()

class ForkingServer(SocketServer.ForkingTCPServer, SocketServer.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 20000
    print HOST
    print PORT
    server = ForkingServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()
        

