#!/usr/bin/env python3
# After sign.py from https://ed25519.cr.yp.to/software.html
import sys
import binascii
import ed25519

# examples of inputs: see sign.input
# should produce no output: python sign.py < sign.input

# fields on each input line: sk, pk, m, sm
# each field hex
# each field colon-terminated
# sk includes pk at end
# sm includes m at end

with open('sign.input', 'rt') as f:

    for line in f.readlines():
        
        x = line.split(':')
        
        sk_ref10 = binascii.unhexlify(x[0])
        sk = ed25519.privkey_from_ref10(sk_ref10)
        
        pk = ed25519.get_pubkey(sk)
        
        #assert x[0] == (sk_ref10 + pk).hex()       # XXX
        assert x[1] == pk.hex()
        
        m = binascii.unhexlify(x[2])
        
        s = ed25519.sign(m, pk, sk)
        assert ed25519.verify(s, m, pk)
        
        if x[3] == binascii.hexlify(s + m):

            sys.stdout.write('!')
        
        """else:
            if len(m) == 0:
                forgedm = b'x'
            else:
                forgedmlen = len(m)
                forgedm = bytes([m[i]+(i==forgedmlen-1) for i in range(forgedmlen)])
            
            forgedsuccess = ed25519.verify(s, forgedm, pk)
            assert not forgedsuccess
            
            sys.stdout.write('.')
        """
        sys.stdout.flush()

sys.stdout.write('\n')
