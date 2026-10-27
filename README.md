Compile:

```bash
gcc -o kdc kdc.c aes.c   

gcc -o client client.c aes.c
```

Run:

- KDC
``` bash
./kdc <port>
```

- Client (Alice & Bob)
```bash
./client alice <kdc ip> <kdc port> <bob ip> <bob port>

./client bob <bob port>
```

Default Key:
``` txt
Alice: alicemasterkey12 

Bob: bobmasterkey1234
```