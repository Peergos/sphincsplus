# SPHINCS+
A Java implementation of the SPHINCS+ post-quantum signature scheme - SPHINCS+-128f(SHA256)

Ported from the [reference C implementation](https://github.com/sphincs/sphincsplus/).

# Usage
Just include the single file: [JavaSphincsplus.java](https://github.com/Peergos/sphincsplus/blob/main/src/java/peergos/shared/crypto/JavaSphincsplus.java)

# Building shared library from reference implementation
> /usr/bin/gcc -fPIC -Wall -Wextra -Wpedantic -O3 -std=c99 -DPARAMS=sphincs-sha2-128f -shared -o libsphincsplus.so address.c randombytes.c merkle.c wots.c wotsx1.c utils.c utilsx1.c fors.c sign.c sha2.c hash_sha2.c thash_sha2_robust.c
