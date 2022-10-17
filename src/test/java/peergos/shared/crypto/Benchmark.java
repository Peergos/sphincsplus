package peergos.shared.crypto;

import java.util.*;

import static peergos.shared.crypto.JavaSphincsplus.*;

public class Benchmark {

    public static void main(String[] a) {
        int runs = 1000;
        byte[] pk = new byte[SPX_PK_BYTES];
        byte[] sk = new byte[SPX_SK_BYTES];
        byte[] seed = new byte[CRYPTO_SEED_BYTES];
        Random r = new Random(24);
        r.nextBytes(seed);
        crypto_sign_seed_keypair(pk, sk, seed);

        byte[] m = new byte[36];
        r.nextBytes(m);
        benchmark(runs, m, pk, sk);
    }

    private static int benchmark(int runs, byte[] m, byte[] pk, byte[] sk) {
        int res = 0;
        long bestSign = Long.MAX_VALUE;
        long bestOpen = Long.MAX_VALUE;
        for (int i=0; i < runs; i++) {
            long t0 = System.nanoTime();
            byte[] t = crypto_sign(m, sk);
            long t1 = System.nanoTime();
            res ^= t[45];
            long duration = (t1-t0)/1000_000;
            bestSign = Math.min(bestSign, duration);
            System.out.println("SIGN: " + duration + ", best: " + bestSign);
            byte[] opened = crypto_sign_open(t, pk);
            long t2 = System.nanoTime();
            duration = (t2-t1)/1000_000;
            bestOpen = Math.min(bestOpen, duration);
            System.out.println("OPEN: " + duration + ", best: " + bestSign);
        }
        return res;
    }
}
