package peergos.shared.crypto;

import java.util.*;

import static peergos.shared.crypto.JavaSphincsplus.*;

public class Benchmark {

    public static void main(String[] a) {
        byte[] pk = new byte[SPX_PK_BYTES];
        byte[] sk = new byte[SPX_SK_BYTES];
        byte[] seed = new byte[CRYPTO_SEED_BYTES];
        Random r = new Random(24);
        r.nextBytes(seed);
        crypto_sign_seed_keypair(pk, sk, seed);

        byte[] m = new byte[36];
        r.nextBytes(m);
        benchmark(m, pk, sk);
    }

    private static int benchmark(byte[] m, byte[] pk, byte[] sk) {
        int res = 0;
        for (int i=0; i  < 100000; i++) {
            long t0 = System.nanoTime();
            byte[] t = crypto_sign(m, sk);
            long t1 = System.nanoTime();
            res ^= t[45];
            System.out.println("SIGN: " + (t1-t0)/1000_000);
            byte[] opened = crypto_sign_open(t, pk);
            long t2 = System.nanoTime();
            System.out.println("OPEN: " + (t2-t1)/1000_000);
        }
        return res;
    }
}
