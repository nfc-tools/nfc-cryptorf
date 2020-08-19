**From http://nfc-tools.org/index.php/Nfc-cryptorf**

This example demonstrates the use of (ATMEL, now) Microchip [CryptoRF](https://www.microchip.com/design-centers/security-ics/mature-products/cryptorf/cryptorf) tags and a libnfc compatible NFC device.

The CryptoRF cards use the ISO/IEC 14443 type B modulation protocol, which is only supported by the PN532 and PN533 chip, not by the PN531.

Research Article
================

[Dismantling SecureMemory, CryptoMemory and CryptoRF (pdf)](https://eprint.iacr.org/2010/169.pdf)   
Flavio D. Garcia and Peter van Rossum and Roel Verdult and Ronny Wichers Schreur   
[Faculty of Science - Digital Security - Radboud University Nijmegen](https://www.ru.nl/dis)

Sourcecode
==========
To demonstrate the results of the article we release a few simple simulation tools for CryptoMemory and SecureMemory.   
In addition to this we constructed a tool based on libnfc that executes an active authentication and encrypted communication with a CryptoRF tag.

This repo contains only the libnfc tool.   
See https://github.com/RfidResearchGroup/proxmark3/tree/master/tools/cryptorf for the other standalone tools.

CryptoMemory Simulation
=======================

Authenticate
```
       Gc: 4f 79 4a 46 3f f8 1d 81 
       Ci: ff 6b da 58 ff 26 41 c6 
        Q: c7 53 2c 21 d0 8a 2f 04 
       Ch: 04 10 a1 eb 5b 49 da 18 
     Ci+1: ff 62 fa c5 9e 2d 99 99 
     Ci+2: 38 db e4 85 5e 23 a5 f2
```
Verify Crypto (Session Key)
```
    Gc(s): 38 db e4 85 5e 23 a5 f2 
    Ci(s): ff 62 fa c5 9e 2d 99 99 
     Q(s): 69 98 a5 52 5d 5a 13 1d 
    Ch(s): 69 81 38 2b b8 20 3d 00 
  Ci+1(s): ff 1b 04 9d a8 07 e0 0e 
  Ci+2(s): d6 c4 5c b9 c9 a4 ac 50
```


CryptoRF Trace
==============
A complete trace which was eavesdropped using the Proxmark RFID Research Tool.

```
   +  81634:    :     11 02 1c a0   
   +    458: 181: TAG 11 00 00 85 19   
   +    828:    :     16 00 18 07 0b 5b   
   +    786: 172: TAG 16 00 cf ff ff ff ff ff ff ff 00 67 b7   
   +   1062:    :     16 00 50 07 ad d3   
   +    786: 162: TAG 16 00 ff 6b da 58 ff 26 41 c6 00 45 cc   
   +  37436:    :     18 00 c7 53 2c 21 d0 8a 2f 04 04 10 a1 eb 5b 49 da 18 f3 66   
   +   1082: 193: TAG 18 00 00 9b 85   
   +    824:    :     16 00 50 07 ad d3   
   +    784: 169: TAG 16 00 ff 62 fa c5 9e 2d 99 99 00 18 02   
   + 251272:    :     18 10 69 98 a5 52 5d 5a 13 1d 69 81 38 2b b8 20 3d 00 f9 69   
   +   1084: 181: TAG 18 00 00 9b 85   
   +    822:    :     16 00 50 07 ad d3   
   +    786: 162: TAG 16 00 ff 1b 04 9d a8 07 e0 0e 00 0c a2   
```

