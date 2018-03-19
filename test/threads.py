#!/usr/bin/env python3
import hashlib, queue, threading, time
import ed25519

class JobThread(threading.Thread):
    
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue
        
    def run(self):
        
        while True:
            item = self.queue.get()
            if item is None:
                break
                
            message, signature, pubkey = item
            ok = ed25519.verify(signature, message, pubkey)
            assert ok

def create_context():
    return hashlib.sha512()

def init(context):
    pass

def update(context, arg):
    context.update(arg)

def final(context):
    return context.digest()

def hash(message):
    h = hashlib.sha512()
    h.update(message)
    return h.digest()

if True:
    ed25519.custom_hash_function(create_context, init, update, final, hash)

message = b'1234567890123456789012345678901234567890123456789012345678901234'

seed = ed25519.create_seed()
pubkey, privkey = ed25519.create_keypair(seed)
signature = ed25519.sign(message, pubkey, privkey)

# Total number of work items over all threads
N = 100000  

# Number of threads
t_base = None
for T in [1, 2, 4, 8]:
    
    jobs = queue.Queue()

    for i in range(N):
        jobs.put((message, signature, pubkey))
        
    for i in range(T):
        jobs.put(None)
        
    t0 = time.time()

    threads = []
    for i in range(T):
        t = JobThread(jobs)
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    t1 = time.time()
    tdiff = t1 - t0
    if T == 1:
        t_base = tdiff
        print('[t=%d] %d jobs in %.3f seconds' % (T, N, tdiff))
    else:
        print('[t=%d] %d jobs in %.3f seconds (%.2fx)' % (T, N, tdiff, t_base/tdiff))
        
    
