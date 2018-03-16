#!/usr/bin/env python3
# After sign.py from https://ed25519.cr.yp.to/software.html
import sys
import binascii
import ed25519

with open('sign.input', 'rt') as f:

    # fields on each input line: sk+pk, pk, m, sm+m
    # each field hex
    # each field colon-terminated
    
    # binascii.unhexlify(): hex string -> binary (bytes object)

    for line in f.readlines():
        
        x = line.split(':')
        
        seed_ref10 = binascii.unhexlify(x[0][:64])
        #public_key_ref10 = binascii.unhexlify(x[0][64:])
        
        sk_ref10 = binascii.unhexlify(x[0])
        sk = ed25519.privkey_from_ref10(sk_ref10)
        
        pk = ed25519.get_pubkey(sk)
        
        assert x[1] == pk.hex()
        assert x[0] == (seed_ref10 + pk).hex()
        
        m = binascii.unhexlify(x[2])
        
        s = ed25519.sign(m, pk, sk)
        assert ed25519.verify(s, m, pk)
        
        if x[3] != (s + m).hex():
            sys.stdout.write('\n')
            sys.stdout.write('! ')
            sys.stdout.write(line)
            sys.stdout.write('\n')
        
        """
        # This part is broken in the original code
        if len(m) == 0:
            forgedm = b'x'
        else:
            forgedmlen = len(m)
            print(m.hex())
            forgedm = bytes([m[i]+(i==forgedmlen-1) for i in range(forgedmlen)])
        
        forgedsuccess = ed25519.verify(s, forgedm, pk)
        assert not forgedsuccess
        """
        
        sys.stdout.write('.')
        sys.stdout.flush()

sys.stdout.write('\n')
