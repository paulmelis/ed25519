#!/usr/bin/env python3
# After sign.py from https://ed25519.cr.yp.to/software.html
import sys
import binascii
import ed25519

# examples of inputs: see sign.input
# should produce no output: python sign.py < sign.input

# warning: currently 37 seconds/line on a fast machine

# fields on each input line: sk, pk, m, sm
# each field hex
# each field colon-terminated
# sk includes pk at end
# sm includes m at end

with open('sign.input', 'rt') as f:

    for line in f.readlines():
        
        x = line.split(':')
        
        sk = binascii.unhexlify(x[0])
        print(len(sk))
        #pk = ed25519.get_pubkey(sk)
        pk = binascii.unhexlify(x[1])
        
        m = binascii.unhexlify(x[2])
        
        #print(m, len(pk), len(sk))
        
        s = ed25519.sign(m, pk, sk)
        
        if not ed25519.verify(s, m, pk):
            
            sys.stdout.write('!')
        
        else:
            if len(m) == 0:
                forgedm = "x"
            else:
                forgedmlen = len(m)
                forgedm = ''.join([chr(ord(m[i])+(i==forgedmlen-1)) for i in range(forgedmlen)])
            
            forgedsuccess = ed25519.verify(s, forgedm, pk)
            assert not forgedsuccess
            
            assert x[0] == (sk + pk).hex()
            assert x[1] == pk.hex()
            assert x[3] == (s + m).hex()
            
            sys.stdout.write('.')
            
        sys.stdout.flush()

sys.stdout.write('\n')