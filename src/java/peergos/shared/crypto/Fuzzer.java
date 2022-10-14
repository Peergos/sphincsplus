package peergos.shared.crypto;

import jnr.ffi.*;
import jnr.ffi.Runtime;
import jnr.ffi.byref.*;

import java.util.*;

import static peergos.shared.crypto.JavaSphincsplus.*;

public class Fuzzer {

    /** Run with -Djava.library.path=native
     *
     * @param a
     */
    public static void main(String[] a) {
        var lib = LibraryLoader.create(NativeSphincsplus.class).load("sphincsplus");
        var runtime = Runtime.getRuntime(lib);

        Random r =  new Random(666);

        byte[] pk = new byte[SPX_PK_BYTES];
        byte[] sk = new byte[SPX_SK_BYTES];
        byte[] seed = new byte[CRYPTO_SEED_BYTES];
        byte[] m = new byte[36];
        byte[] java_pk = new byte[SPX_PK_BYTES];
        byte[] java_sk = new byte[SPX_SK_BYTES];

        byte[] nativeSigned = new byte[SPX_BYTES + m.length];
        byte[] nativeOpened = new byte[nativeSigned.length - SPX_BYTES];

        for (int i=0; i < 100; i++) {
            r.nextBytes(seed);
            r.nextBytes(m);
            lib.crypto_sign_seed_keypair(pk, sk, seed);
            JavaSphincsplus.crypto_sign_seed_keypair(java_pk, java_sk, seed);
            if (!Arrays.equals(java_pk, pk))
                throw new IllegalStateException("Difference!");
            if (!Arrays.equals(java_sk, sk))
                throw new IllegalStateException("Difference!");

            NativeLongByReference len = new NativeLongByReference();
            lib.crypto_sign(nativeSigned, len, m, m.length, sk);
            byte[] javaSigned = crypto_sign(m, java_sk);
            if (!Arrays.equals(nativeSigned, javaSigned))
                throw new IllegalStateException("Difference!");

            lib.crypto_sign_open(nativeOpened, len, nativeSigned, nativeSigned.length, pk);
            byte[] javaOpened = crypto_sign_open(javaSigned, java_pk);
            if (!Arrays.equals(nativeOpened, javaOpened))
                throw new IllegalStateException("Difference!");
        }
    }
}
