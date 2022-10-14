package peergos.shared.crypto;

import jnr.ffi.byref.*;
import jnr.ffi.types.*;

public interface NativeSphincsplus {

    int crypto_sign_seed_keypair(byte[] pk, byte[] sk, byte[] seed);

    int crypto_sign(byte[] sm, NativeLongByReference smlen, byte[] m, @u_int64_t long mlen, byte[] sk);

    int crypto_sign_open(byte[] m, NativeLongByReference mlen, byte[] signed, @u_int64_t long signedlen, byte[] pk);
}
