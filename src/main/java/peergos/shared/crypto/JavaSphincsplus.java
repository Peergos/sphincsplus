package peergos.shared.crypto;

import java.security.*;
import java.util.*;

public class JavaSphincsplus {

    // Sphincs+ 128f-sha2

    public static final int SPX_N = 16; // Hash output length in bytes
    
    public static final int SPX_FULL_HEIGHT = 66; /* Height of the hypertree. */
    public static final int SPX_D = 22; // Number of subtree layers

    /* FORS tree dimensions. */
    public static final int SPX_FORS_HEIGHT = 6;
    public static final int SPX_FORS_TREES = 33;
    /* Winternitz parameter, */
    public static final int SPX_WOTS_W = 16;

    /* For clarity */
    public static final int SPX_ADDR_BYTES = 32;
    public static final int SPX_WOTS_LOGW = SPX_WOTS_W == 256 ? 8 : 4;

    public static final int SPX_WOTS_LEN1 = (8 * SPX_N / SPX_WOTS_LOGW); // 32

    public static final int SPX_WOTS_LEN2 = len2(); // 3

    public static final int len2() {
	if (SPX_WOTS_W == 256) {
	    if (SPX_N <= 1)
		return 1;
	    else if (SPX_N <= 256)
		return 2;
	    else
		throw new IllegalStateException("Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
    
	} else if (SPX_WOTS_W == 16) {
	    if (SPX_N <= 8)
		return 2;
	    else if (SPX_N <= 136)
		return 3;
	    else if (SPX_N <= 256)
		return 4;
	    else
		throw new IllegalStateException("Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
	} else
	    throw new IllegalStateException("Unknown SPX_WOTS_W");
    }

    public static final int SPX_WOTS_LEN = (SPX_WOTS_LEN1 + SPX_WOTS_LEN2); //  35
    public static final int SPX_WOTS_BYTES = (SPX_WOTS_LEN * SPX_N); // 560
    public static final int SPX_WOTS_PK_BYTES = SPX_WOTS_BYTES;

    /* Subtree size. */
    public static final int SPX_TREE_HEIGHT = (SPX_FULL_HEIGHT / SPX_D);

    static {
	if (SPX_TREE_HEIGHT * SPX_D != SPX_FULL_HEIGHT)
	    throw new IllegalStateException("SPX_D should always divide SPX_FULL_HEIGHT");
    }

    /* FORS parameters. */
    public static final int SPX_FORS_MSG_BYTES = ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8); // 25
    public static final int SPX_FORS_BYTES = ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N);
    public static final int SPX_FORS_PK_BYTES = SPX_N;

    /* Resulting SPX sizes. */
    public static final int SPX_BYTES = (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N);
    public static final int SPX_PK_BYTES = (2 * SPX_N);
    public static final int SPX_SK_BYTES = (2 * SPX_N + SPX_PK_BYTES);
    
    /*
     * Offsets of various fields in the address structure when we use SHA2 as
     * the Sphincs+ hash function
     */
    public static final int SPX_OFFSET_LAYER = 0;   /* The byte used to specify the Merkle tree layer */
    public static final int SPX_OFFSET_TREE = 1;   /* The start of the 8 byte field used to specify the tree */
    public static final int SPX_OFFSET_TYPE = 9;   /* The byte used to specify the hash type (reason) */
    public static final int SPX_OFFSET_KP_ADDR2= 12;  /* The high byte used to specify the key pair (which one-time signature) */
    public static final int SPX_OFFSET_KP_ADDR1 = 13;  /* The low byte used to specify the key pair */
    public static final int SPX_OFFSET_CHAIN_ADDR =17;  /* The byte used to specify the chain address (which Winternitz chain) */
    public static final int SPX_OFFSET_HASH_ADDR = 21;  /* The byte used to specify the hash address (where in the Winternitz chain) */
    public static final int SPX_OFFSET_TREE_HGT = 17;  /* The byte used to specify the height of this node in the FORS or Merkle tree */
    public static final int SPX_OFFSET_TREE_INDEX =  18; /* The start of the 4 byte field used to specify the node in the FORS or Merkle tree */
	
    public static final int SPX_SHA2 = 1;
    
    public static final int CRYPTO_SEED_BYTES = 3*SPX_N;

    public static byte[] crypto_sign(byte[] m, byte[] sk) {
	byte[] sig = new byte[SPX_BYTES + m.length];
	Spx_ctx ctx = new Spx_ctx();
	byte[] sk_prf = Arrays.copyOfRange(sk, SPX_N,  sk.length);;
	byte[] pk = Arrays.copyOfRange(sk, 2*SPX_N, sk.length);

	byte[] optrand = new byte[SPX_N];
	byte[] mhash = new byte[SPX_FORS_MSG_BYTES];
	byte[] root = new byte[SPX_N];
	int i;
	long[] tree = new long[1];
	int[] idx_leaf = new int[1];
	int[] wots_addr = new int[8];
	int[] tree_addr = new int[8];

	ctx.pub_seed = Arrays.copyOfRange(sk, 2*SPX_N, 2*SPX_N + SPX_N);
	ctx.sk_seed = Arrays.copyOfRange(sk, 0, SPX_N);	 

	/* This hook allows the hash function instantiation to do whatever
	   preparation or computation it needs, based on the public seed. */
	initialize_hash_function(ctx);

	set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
	set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

	/* Optionally, signing can be made non-deterministic using optrand.
	   This can help counter side-channel attacks that would benefit from
	   getting a large number of traces when the signer uses the same nodes. */
	//randombytes(optrand, SPX_N);
    
	/* Compute the digest randomization value. */
	gen_message_random(sig, sk_prf, optrand, m, ctx);

	/* Derive the message digest and leaf index from R, PK and M. */
	hash_message(mhash, tree, idx_leaf, sig, pk, m, ctx);
	int sigOffset = SPX_N;

	set_tree_addr(wots_addr, tree[0]);
	set_keypair_addr(wots_addr, idx_leaf[0]);

	/* Sign the message hash using FORS. */
	fors_sign(sig, sigOffset, root, mhash, ctx, wots_addr);
	sigOffset += SPX_FORS_BYTES;
	for (i = 0; i < SPX_D; i++) {
	    set_layer_addr(tree_addr, i);
	    set_tree_addr(tree_addr, tree[0]);
	    
	    copy_subtree_addr(wots_addr, tree_addr);
	    set_keypair_addr(wots_addr, idx_leaf[0]);
	    
	    merkle_sign(sig, sigOffset, root, 0, ctx, wots_addr, tree_addr, idx_leaf[0]);

	    sigOffset += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;
	    
	    /* Update the indices for the next layer. */
	    idx_leaf[0] = ((int)tree[0] & ((1 << SPX_TREE_HEIGHT)-1));
	    tree[0] = tree[0] >> SPX_TREE_HEIGHT;
	}
	
	System.arraycopy(m, 0, sig, SPX_BYTES, m.length);
	return sig;
    }

    /**
     * Verifies a detached signature and message under a given public key.
     */
    public static byte[] crypto_sign_open(byte[] sig, byte[] pk)
    {
		Spx_ctx ctx = new Spx_ctx();
		byte[] pub_root = Arrays.copyOfRange(pk, SPX_N, pk.length);
		byte[] mhash = new byte[SPX_FORS_MSG_BYTES];
		byte[] wots_pk = new byte[SPX_WOTS_BYTES];
		byte[] root = new byte[SPX_N];
		byte[] leaf = new byte[SPX_N];
		int i;
		long[] tree = new long[1];
		int[] idx_leaf = new int[1];
		int[]  wots_addr = new int[8];
		int[] tree_addr = new int[8];
		int[] wots_pk_addr = new int[8];
		byte[] m = Arrays.copyOfRange(sig, SPX_BYTES, sig.length);
		int sigOffset = 0;
	
		if (sig.length <= SPX_BYTES) {
			throw new IllegalStateException("Signature too short!");
		}
	
		System.arraycopy(pk, 0, ctx.pub_seed, 0, SPX_N);
	
		/* This hook allows the hash function instantiation to do whatever
	   preparation or computation it needs, based on the public seed. */
		initialize_hash_function(ctx);
	
		set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
		set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
		set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);
	
		/* Derive the message digest and leaf index from R || PK || M. */
		/* The additional SPX_N is a result of the hash domain separator. */
		hash_message(mhash, tree, idx_leaf, sig, pk, m, ctx);
		sigOffset += SPX_N;
	
		/* Layer correctly defaults to 0, so no need to set_layer_addr */
		set_tree_addr(wots_addr, tree[0]);
		set_keypair_addr(wots_addr, idx_leaf[0]);
	
		fors_pk_from_sig(root, sig, sigOffset, mhash, ctx, wots_addr);
		sigOffset += SPX_FORS_BYTES;
	
		/* For each subtree.. */
		for (i = 0; i < SPX_D; i++) {
			set_layer_addr(tree_addr, i);
			set_tree_addr(tree_addr, tree[0]);
	    
			copy_subtree_addr(wots_addr, tree_addr);
			set_keypair_addr(wots_addr, idx_leaf[0]);
	    
			copy_keypair_addr(wots_pk_addr, wots_addr);
	    
			/* The WOTS public key is only correct if the signature was correct. */
			/* Initially, root is the FORS pk, but on subsequent iterations it is
	       the root of the subtree below the currently processed subtree. */
			wots_pk_from_sig(wots_pk, sig, sigOffset, root, ctx, wots_addr);
			sigOffset += SPX_WOTS_BYTES;
	    
			/* Compute the leaf node using the WOTS public key. */
			thash(leaf, 0, wots_pk, 0, SPX_WOTS_LEN, ctx, wots_pk_addr);
	    
			/* Compute the root node of this subtree. */
			compute_root(root, 0, leaf, idx_leaf[0], 0, sig, sigOffset, SPX_TREE_HEIGHT,
					ctx, tree_addr);
			sigOffset += SPX_TREE_HEIGHT * SPX_N;
	    
			/* Update the indices for the next layer. */
			idx_leaf[0] = (int)(tree[0] & ((1 << SPX_TREE_HEIGHT)-1));
			tree[0] = tree[0] >> SPX_TREE_HEIGHT;
		}
	
		/* Check if the root node equals the root node in the public key. */
		if (! Arrays.equals(root, pub_root)) {
			throw new IllegalStateException("Invalid signature!");
		}
	
		return Arrays.copyOfRange(sig, SPX_BYTES, sig.length);
	}

	/**
	 * Derives the FORS public key from a signature.
	 * This can be used for verification by comparing to a known public key, or to
	 * subsequently verify a signature on the derived public key. The latter is the
	 * typical use-case when used as an FTS below an OTS in a hypertree.
	 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
	 */
	private static void fors_pk_from_sig(byte[] pk,
										 byte[] sig,
										 int sigOffset,
										 byte[] m,
										 Spx_ctx ctx,
										 int[] fors_addr) {
		int[] indices = new int[SPX_FORS_TREES];
		byte[] roots = new byte[SPX_FORS_TREES * SPX_N];
		byte[] leaf = new byte[SPX_N];
		int[] fors_tree_addr = new int[8];
		int[] fors_pk_addr = new int[8];
		int idx_offset;
	
		copy_keypair_addr(fors_tree_addr, fors_addr);
		copy_keypair_addr(fors_pk_addr, fors_addr);
	
		set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
		set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);
	
		message_to_indices(indices, m);
	
		for (int i = 0; i < SPX_FORS_TREES; i++) {
			idx_offset = i * (1 << SPX_FORS_HEIGHT);
	    
			set_tree_height(fors_tree_addr, 0);
			set_tree_index(fors_tree_addr, indices[i] + idx_offset);
	    
			/* Derive the leaf from the included secret key part. */
			fors_sk_to_leaf(leaf, 0, sig, sigOffset, ctx, fors_tree_addr);
			sigOffset += SPX_N;
	    
			/* Derive the corresponding root node of this tree. */
			compute_root(roots, i*SPX_N, leaf, indices[i], idx_offset,
					sig, sigOffset, SPX_FORS_HEIGHT, ctx, fors_tree_addr);
			sigOffset += SPX_N * SPX_FORS_HEIGHT;
		}
	
		/* Hash horizontally across all tree roots to derive the public key. */
		thash(pk, 0, roots, 0, SPX_FORS_TREES, ctx, fors_pk_addr);
	}

	/**
	 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
	 *
	 * Writes the computed public key to 'pk'.
	 */
	private static void wots_pk_from_sig(byte[] pk, byte[] sig, int sigOffset, byte[] msg, Spx_ctx ctx, int[] addr) {
		int[] lengths = new int[SPX_WOTS_LEN];
	
		chain_lengths(lengths, msg, 0);
	
		for (int i = 0; i < SPX_WOTS_LEN; i++) {
			set_chain_addr(addr, i);
			gen_chain(pk, i*SPX_N, sig, sigOffset + i*SPX_N, lengths[i], SPX_WOTS_W - 1 - lengths[i], ctx, addr);
		}
	}

	/**
	 * Computes the chaining function.
	 * out and in have to be n-byte arrays.
	 *
	 * Interprets in as start-th value of the chain.
	 * addr has to contain the address of the chain.
	 */
	static void gen_chain(byte[] out, int outOffset, byte[] in, int inOffset, int start, int steps, Spx_ctx ctx, int[] addr) {
	
		/* Initialize out with the value at position 'start'. */
		System.arraycopy(in, inOffset, out, outOffset, SPX_N);
	
		/* Iterate 'steps' calls to the hash function. */
		for (int i = start; i < (start+steps) && i < SPX_WOTS_W; i++) {
			set_hash_addr(addr, i);
			thash(out, outOffset, out, outOffset, 1, ctx, addr);
		}
	}
    
	/**
	 * Computes a root node given a leaf and an auth path.
	 * Expects address to be complete other than the tree_height and tree_index.
	 */
	private static void compute_root(byte[] root, int rootOffset,
									 byte[] leaf,
									 int leaf_idx, int idx_offset,
									 byte[] auth_path, int auth_pathIndex,
									 int tree_height,
									 Spx_ctx ctx, int[] addr) {
		byte[] buffer = new byte[2 * SPX_N];
	
		/* If leaf_idx is odd (last bit = 1), current path element is a right child
	   and auth_path has to go left. Otherwise it is the other way around. */
		if ((leaf_idx & 1) != 0) {
			System.arraycopy(leaf, 0, buffer, SPX_N, SPX_N);
			System.arraycopy(auth_path, auth_pathIndex, buffer, 0, SPX_N);
		}
		else {
			System.arraycopy(leaf, 0, buffer, 0, SPX_N);
			System.arraycopy(auth_path, auth_pathIndex, buffer, SPX_N, SPX_N);
		}
		auth_pathIndex += SPX_N;
	
		for (int i = 0; i < tree_height - 1; i++) {
			leaf_idx >>= 1;
			idx_offset >>= 1;
			/* Set the address of the node we're creating. */
			set_tree_height(addr, i + 1);
			set_tree_index(addr, leaf_idx + idx_offset);
	    
			/* Pick the right or left neighbor, depending on parity of the node. */
			if ((leaf_idx & 1) != 0) {
				thash(buffer, SPX_N, buffer, 0, 2, ctx, addr);
				System.arraycopy(auth_path, auth_pathIndex, buffer, 0, SPX_N);
			}
			else {
				thash(buffer, 0, buffer, 0, 2, ctx, addr);
				System.arraycopy(auth_path, auth_pathIndex, buffer, SPX_N, SPX_N);
			}
			auth_pathIndex += SPX_N;
		}
	
		/* The last iteration is exceptional; we do not copy an auth_path node. */
		leaf_idx >>= 1;
		idx_offset >>= 1;
		set_tree_height(addr, tree_height);
		set_tree_index(addr, leaf_idx + idx_offset);
		thash(root, rootOffset, buffer, 0, 2, ctx, addr);
	}
    
	/**
	 * Computes the message-dependent randomness R, using a secret seed as a key
	 * for HMAC, and an optional randomization value prefixed to the message.
	 * This requires m to have at least SPX_SHAX_BLOCK_BYTES + SPX_N space
	 * available in front of the pointer, i.e. before the message to use for the
	 * prefix. This is necessary to prevent having to move the message around (and
	 * allocate memory for it).
	 */
	public static void gen_message_random(byte[] R,
										  byte[] sk_prf,
										  byte[] optrand,
										  byte[] m,
										  Spx_ctx ctx) {
		byte[] buf = new byte[SPX_SHAX_BLOCK_BYTES + SPX_SHAX_OUTPUT_BYTES];
		int i;
	
		if (SPX_N > SPX_SHAX_BLOCK_BYTES)
			throw new IllegalStateException("Currently only supports SPX_N of at most SPX_SHAX_BLOCK_BYTES");
			
		/* This implements HMAC-SHA */
		for (i = 0; i < SPX_N; i++) {
			buf[i] = (byte) (0x36 ^ sk_prf[i]);
		}
		for (int j=0; j < SPX_SHAX_BLOCK_BYTES - SPX_N; j++)
			buf[SPX_N + j] = (byte)0x36;
	
		MessageDigest hash = newSha256();
		hash.update(buf, 0, 64);
	
		System.arraycopy(optrand, 0, buf, 0, SPX_N);
	
		/* If optrand + message cannot fill up an entire block */
		if (SPX_N + m.length < SPX_SHAX_BLOCK_BYTES) {
			System.arraycopy(m, 0, buf, SPX_N, m.length);
			hash.update(buf, 0, m.length + SPX_N);
			byte[]  digest = hash.digest();
			System.arraycopy(digest, 0, buf, SPX_SHAX_BLOCK_BYTES, 32);
		}
		/* Otherwise first fill a block, so that finalize only uses the message */
		else {
			int initialCopySize = SPX_SHAX_BLOCK_BYTES - SPX_N;
			System.arraycopy(m, 0, buf, SPX_N, initialCopySize);
			hash.update(buf, 0, 64);
			hash.update(m, initialCopySize, m.length - initialCopySize);
			byte[] digest = hash.digest();
			System.arraycopy(digest, 0, buf, SPX_SHAX_BLOCK_BYTES, 32);
		}
	
		for (i = 0; i < SPX_N; i++) {
			buf[i] = (byte) (0x5c ^ sk_prf[i]);
		}
		for (int j=0; j < SPX_SHAX_BLOCK_BYTES - SPX_N; j++)
			buf[SPX_N + j] = 0x5c;
	
		sha256(buf, 0, buf, 0, SPX_SHAX_BLOCK_BYTES + SPX_SHAX_OUTPUT_BYTES);
		System.arraycopy(buf, 0, R, 0, SPX_N);
	}

	/**
	 * Computes the message hash using R, the public key, and the message.
	 * Outputs the message digest and the index of the leaf. The index is split in
	 * the tree index and the leaf index, for convenient copying to an address.
	 */
	public static void hash_message(byte[] digest, long[] tree, int[] leaf_idx,
									byte[] R, byte[] pk,
									byte[] m,
									Spx_ctx ctx) {
		int SPX_TREE_BITS = (SPX_TREE_HEIGHT * (SPX_D - 1)); // 3 * 21 = 63
		int SPX_TREE_BYTES = ((SPX_TREE_BITS + 7) / 8); // 8
		int SPX_LEAF_BITS = SPX_TREE_HEIGHT; // 3
		int SPX_LEAF_BYTES = ((SPX_LEAF_BITS + 7) / 8); // 1
		int SPX_DGST_BYTES = (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES); // 25 + 8 + 1 = 34
	
		byte[] seed = new byte[2*SPX_N + SPX_SHAX_OUTPUT_BYTES];
	
		/* Round to nearest multiple of SPX_SHAX_BLOCK_BYTES */
		if ((SPX_SHAX_BLOCK_BYTES & (SPX_SHAX_BLOCK_BYTES-1)) != 0)
			throw new IllegalStateException("Assumes that SPX_SHAX_BLOCK_BYTES is a power of 2");
	
		int SPX_INBLOCKS =  (((SPX_N + SPX_PK_BYTES + SPX_SHAX_BLOCK_BYTES - 1) & -SPX_SHAX_BLOCK_BYTES) / SPX_SHAX_BLOCK_BYTES);
		byte[] inbuf = new byte[SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES];
	
		byte[] buf = new byte[SPX_DGST_BYTES];
		int bufp = 0;
	
		// seed: SHA-X(R ‖ PK.seed ‖ PK.root ‖ M)
		System.arraycopy(R, 0, inbuf, 0, SPX_N);
		System.arraycopy(pk, 0, inbuf, SPX_N, SPX_PK_BYTES);
	
		/* If R + pk + message cannot fill up an entire block */
		if (SPX_N + SPX_PK_BYTES + m.length < SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES) {
			System.arraycopy(m, 0, inbuf, SPX_N + SPX_PK_BYTES, m.length);
			sha256(seed, 2*SPX_N, inbuf, 0, SPX_N + SPX_PK_BYTES + m.length);
		}
		/* Otherwise first fill a block, so that finalize only uses the message */
		else {
			int initialCopySize = SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES - SPX_N - SPX_PK_BYTES;
			System.arraycopy(m, 0, inbuf, SPX_N + SPX_PK_BYTES, initialCopySize);
	    
			Sha256 hash = new Sha256();
			hash.update(inbuf);
			hash.update(m, initialCopySize, m.length - initialCopySize);
			byte[] res = hash.digest();
			System.arraycopy(res, 0, seed, 2*SPX_N, 32);
		}
	
		// H_msg: MGF1-SHA-X(R ‖ PK.seed ‖ seed)
		System.arraycopy(R,  0, seed, 0, SPX_N);
		System.arraycopy(pk,  0, seed, SPX_N, SPX_N);
	
		/* By doing this in two steps, we prevent hashing the message twice;
	   otherwise each iteration in MGF1 would hash the message again. */
		mgf1_256(buf, bufp, SPX_DGST_BYTES, seed, 2*SPX_N + SPX_SHAX_OUTPUT_BYTES);

		System.arraycopy(buf, bufp, digest, 0, SPX_FORS_MSG_BYTES);
		bufp += SPX_FORS_MSG_BYTES;
	
		if (SPX_TREE_BITS > 64)
			throw new IllegalStateException("For given height and depth, 64 bits cannot represent all subtrees");
				    
		tree[0] = bytes_to_ull(buf, bufp, SPX_TREE_BYTES);
		tree[0] &= ((1L << SPX_TREE_BITS) - 1);//(~(long)0) >> (64 - SPX_TREE_BITS);
		bufp += SPX_TREE_BYTES;
	
		leaf_idx[0] = (int)bytes_to_ull(buf, bufp, SPX_LEAF_BYTES);
		leaf_idx[0] &= ((1 << SPX_LEAF_BITS) - 1);//(~(int)0) >> (32 - SPX_LEAF_BITS);
	}

	/**
	 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
	 */
	public static long bytes_to_ull(byte[] in, int inOffset, int inlen)
	{
		long retval = 0;
		int i;
	
		for (i = 0; i < inlen; i++) {
			retval |= (in[inOffset + i] & 0xFFL) << (8*(inlen - 1 - i));
		}
		return retval;
	}
    
	static class Fors_gen_leaf_info {
		int[] leaf_addrx = new int[8];
	};

	/**
	 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
	 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
	 */
	public static void fors_sign(byte[] sig,
								 int sigOffset,
								 byte[] pk,
								 byte[] m,
								 Spx_ctx ctx,
								 int[] fors_addr) {
		int[] indices = new int[SPX_FORS_TREES];
		byte[] roots = new byte[SPX_FORS_TREES * SPX_N];
		int[] fors_tree_addr = new int[8];
		Fors_gen_leaf_info fors_info = new Fors_gen_leaf_info();
		int[] fors_leaf_addr = fors_info.leaf_addrx;
		int[] fors_pk_addr = new int[8];
		int idx_offset;
		int i;
	
		copy_keypair_addr(fors_tree_addr, fors_addr);
		copy_keypair_addr(fors_leaf_addr, fors_addr);
	
		copy_keypair_addr(fors_pk_addr, fors_addr);
		set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);
	
		message_to_indices(indices, m);

		for (i = 0; i < SPX_FORS_TREES; i++) {
			idx_offset = i * (1 << SPX_FORS_HEIGHT);
	    
			set_tree_height(fors_tree_addr, 0);
			set_tree_index(fors_tree_addr, indices[i] + idx_offset);
			set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);
	    
			/* Include the secret key part that produces the selected leaf node. */
			fors_gen_sk(sig, sigOffset, ctx, fors_tree_addr);
			set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
			sigOffset += SPX_N;
	    
			/* Compute the authentication path for this leaf node. */
			treehashx1(roots, i*SPX_N, sig, sigOffset, ctx,
					indices[i], idx_offset, SPX_FORS_HEIGHT, (a, b, c, d) -> fors_gen_leafx1(a, b, c, d, fors_info),
					fors_tree_addr);

			sigOffset += SPX_N * SPX_FORS_HEIGHT;
		}
	
		/* Hash horizontally across all tree roots to derive the public key. */
		thash(pk, 0, roots, 0, SPX_FORS_TREES, ctx, fors_pk_addr);
	}

	static void fors_gen_sk(byte[] sk, int skOffset, Spx_ctx ctx, int[] fors_leaf_addr) {
		prf_addr(sk, skOffset, ctx, fors_leaf_addr);
	}
    
	static void fors_gen_leafx1(byte[] leaf, int leafOffset, Spx_ctx ctx, int addr_idx, Fors_gen_leaf_info info) {
		Fors_gen_leaf_info fors_info = info;
		int[] fors_leaf_addr = fors_info.leaf_addrx;
	
		/* Only set the parts that the caller doesn't set */
		set_tree_index(fors_leaf_addr, addr_idx);
		set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF);
		fors_gen_sk(leaf, leafOffset, ctx, fors_leaf_addr);

		set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
		fors_sk_to_leaf(leaf, leafOffset, leaf, leafOffset, ctx, fors_leaf_addr);
	}

	static void fors_sk_to_leaf(byte[] leaf, int leafOffset, byte[] sk, int skOffset, Spx_ctx ctx, int[] fors_leaf_addr) {
		thash(leaf, leafOffset, sk, skOffset, 1, ctx, fors_leaf_addr);
	}
    
	/**
	 * Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
	 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
	 * Assumes indices has space for SPX_FORS_TREES integers.
	 */
	static void message_to_indices(int[] indices, byte[] m) {
		int i, j;
		int offset = 0;
	
		for (i = 0; i < SPX_FORS_TREES; i++) {
			indices[i] = 0;
			for (j = 0; j < SPX_FORS_HEIGHT; j++) {
				indices[i] ^= ((m[offset >> 3] >> (offset & 0x7)) & 0x1) << j;
				offset++;
			}
		}
	}
    
	public static class Spx_ctx {
		byte[] pub_seed = new byte[SPX_N];
		byte[] sk_seed = new byte[SPX_N];
		byte[] state_seeded;
	}
    
	/*
     * Generates an SPX key pair given a seed of length
     * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
     * Format pk: [PUB_SEED || root]
     */
	public static void crypto_sign_seed_keypair(byte[] pk, byte[] sk, byte[] seed) {
		Spx_ctx ctx = new Spx_ctx();
		System.arraycopy(seed, 0, sk, 0, CRYPTO_SEED_BYTES);
		System.arraycopy(sk, 2*SPX_N, pk, 0, SPX_N);
		ctx.pub_seed = Arrays.copyOfRange(pk, 0, SPX_N);
		ctx.sk_seed = Arrays.copyOfRange(sk, 0, SPX_N);
	
		/* This hook allows the hash function instantiation to do whatever
	   preparation or computation it needs, based on the public seed. */
		initialize_hash_function(ctx);

		/* Compute root node of the top-most subtree. */
		merkle_gen_root(sk, 3*SPX_N, ctx);

		System.arraycopy(sk, 3*SPX_N, pk, SPX_N, SPX_N);
	}

	public static void initialize_hash_function(Spx_ctx ctx) {
		seed_state(ctx);
	}

	/**
	 * Absorb the constant pub_seed using one round of the compression function
	 * This initializes state_seeded and state_seeded_512, which can then be
	 * reused in thash
	 **/
	public static void seed_state(Spx_ctx ctx) {
		byte[] block = new byte[SPX_SHA256_BLOCK_BYTES];
		int i;
	
		for (i = 0; i < SPX_N; ++i) {
			block[i] = ctx.pub_seed[i];
		}
		/* block has been properly initialized for both SHA-256 and SHA-512 */

		Sha256 hash = new Sha256();
		hash.update(block);
		ctx.state_seeded = hash.getState();
	}

	public static void merkle_gen_root(byte[] root, int rootOffset, Spx_ctx ctx) {
		/* We do not need the auth path in key generation, but it simplifies the
	   code to have just one treehash routine that computes both root and path
	   in one function. */
		byte[] auth_path = new byte[SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES];
		int[] top_tree_addr = new int[8];
		int[] wots_addr = new int[8];
	
		set_layer_addr(top_tree_addr, SPX_D - 1);
		set_layer_addr(wots_addr, SPX_D - 1);
	
		merkle_sign(auth_path, 0, root, rootOffset, ctx,
				wots_addr, top_tree_addr,
				~0 /* ~0 means "don't bother generating an auth path */ );
	}

	/*
     * Specify which level of Merkle tree (the "layer") we're working on
     */
	public static void set_layer_addr(int[] addr, int layer) {
		if (SPX_OFFSET_LAYER == 0)
			addr[0] = layer;
		else throw new IllegalStateException("Unimplemented bit munging!");
	}

	/*
     * This is here to provide an interface to the internal wots_gen_leafx1
     * routine.  While this routine is not referenced in the package outside of
     * wots.c, it is called from the stand-alone benchmark code to characterize
     * the performance
     */
	public static class Leaf_info_x1 {
		byte[] wots_sig;
		int wots_sigOffset=0;
		int wots_sign_leaf; /* The index of the WOTS we're using to sign */
		int[] wots_steps;
		int[] leaf_addr = new int[8];
		int[] pk_addr = new int[8];
	};
    
	/*
     * This generates a Merkle signature (WOTS signature followed by the Merkle
     * authentication path).  This is in this file because most of the complexity
     * is involved with the WOTS signature; the Merkle authentication path logic
     * is mostly hidden in treehashx4
     */ 
	public static void merkle_sign(byte[] sig, int sigOffset, byte[] root, int rootOffset, Spx_ctx ctx, int[] wots_addr, int[] tree_addr, int idx_leaf) {
		Leaf_info_x1 info = new Leaf_info_x1();
		int[] steps = new int[SPX_WOTS_LEN];
		info.wots_sig = sig;
		info.wots_sigOffset = sigOffset;
		chain_lengths(steps, root, rootOffset);
		info.wots_steps = steps;

		set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
		set_type(info.pk_addr, SPX_ADDR_TYPE_WOTSPK);
		copy_subtree_addr(info.leaf_addr, wots_addr);
		copy_subtree_addr(info.pk_addr, wots_addr);

		info.wots_sign_leaf = idx_leaf;

		treehashx1(root, rootOffset, sig, sigOffset + SPX_WOTS_BYTES, ctx, idx_leaf, 0, SPX_TREE_HEIGHT, (a, b, c, d) -> wots_gen_leafx1(a, b, c, d, info), tree_addr);
	}

	public static void chain_lengths(int[] lengths, byte[] msg, int offset) {
		base_w(lengths, 0, SPX_WOTS_LEN1, msg, offset);
		wots_checksum(lengths, SPX_WOTS_LEN1);
	}

	/**
	 * base_w algorithm as described in draft.
	 * Interprets an array of bytes as integers in base w.
	 * This only works when log_w is a divisor of 8.
	 */
	public static void base_w(int[] output, int outputOffset, int out_len,  byte[] input, int inputOffset) {
		int in = 0;
		int out = 0;
		int total = 0;
		int bits = 0;
		int consumed;
	
		for (consumed = 0; consumed < out_len; consumed++) {
			if (bits == 0) {
				total = input[inputOffset + in] & 0xFF;
				in++;
				bits += 8;
			}
			bits -= SPX_WOTS_LOGW;
			output[outputOffset + out] = (total >> bits) & (SPX_WOTS_W - 1);
			out++;
		}
	}

	/* Computes the WOTS+ checksum over a message (in base_w). */
	public static void wots_checksum(int[] csum_base_w, int offset) {
		int[] msg_base_w = csum_base_w;
		int csum = 0;
		byte[] csum_bytes = new byte[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
		int i;

		/* Compute checksum. */
		for (i = 0; i < SPX_WOTS_LEN1; i++) {
			csum += SPX_WOTS_W - 1 - msg_base_w[i];
		}

		/* Convert checksum to base_w. */
		/* Make sure expected empty zero bits are the least significant bits. */
		csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
		ull_to_bytes(csum_bytes, csum);
		base_w(csum_base_w, offset, SPX_WOTS_LEN2, csum_bytes, 0);
	}

	public static void ull_to_bytes(byte[] out, int in) {
		int i;

		/* Iterate over out in decreasing order, for big-endianness. */
		for (i = out.length - 1; i >= 0; i--) {
			out[i] = (byte)in;
			in = in >> 8;
		}
	}
    
	public static final int SPX_ADDR_TYPE_WOTS = 0;
	public static final int SPX_ADDR_TYPE_WOTSPK = 1;
	public static final int SPX_ADDR_TYPE_HASHTREE = 2;
	public static final int SPX_ADDR_TYPE_FORSTREE = 3;
	public static final int SPX_ADDR_TYPE_FORSPK = 4;
	public static final int SPX_ADDR_TYPE_WOTSPRF = 5;
	public static final int SPX_ADDR_TYPE_FORSPRF = 6;

	/*
     * Specify the reason we'll use this address structure for, that is, what
     * hash will we compute with it.  This is used so that unrelated types of
     * hashes don't accidentally get the same address structure.  The type will be
     * one of the SPX_ADDR_TYPE constants
     */
	public static void  set_type(int[] addr, int type) {
		setByte(addr, SPX_OFFSET_TYPE, (byte) type);
	}

	/*
     * Copy the layer and tree fields of the address structure.  This is used
     * when we're doing multiple types of hashes within the same Merkle tree
     */
	public static void copy_subtree_addr(int[] out, int[] in) {
		System.arraycopy(in, 0, out, 0, 2);
		setByte(out, 8 + SPX_OFFSET_TREE - 1, getByte(in, 8 + SPX_OFFSET_TREE - 1));
	}

	public static interface GenLeaf {
		void apply(byte[] dest, int destOffset, Spx_ctx ctx, int leaf_idx);
	}

	/*
     * This generates a WOTS public key
     * It also generates the WOTS signature if leaf_info indicates
     * that we're signing with this WOTS key
     */
	public static void wots_gen_leafx1(byte[] dest, int destOffset, Spx_ctx ctx, int leaf_idx, Leaf_info_x1 v_info) {
		Leaf_info_x1 info = v_info;
		int[] leaf_addr = info.leaf_addr;

		int[] pk_addr = info.pk_addr;
		int i, k;
		byte[] pk_buffer = new byte[SPX_WOTS_BYTES];
		byte[] buffer;
		int wots_k_mask;

		if (leaf_idx == info.wots_sign_leaf) {
			/* We're traversing the leaf that's signing; generate the WOTS */
			/* signature */
			wots_k_mask = 0;
		} else {
			/* Nope, we're just generating pk's; turn off the signature logic */
			wots_k_mask = ~0;
		}
	
		set_keypair_addr( leaf_addr, leaf_idx );
	
		set_keypair_addr( pk_addr, leaf_idx );
	
		int bufferOffset = 0;
		for (i = 0, buffer = pk_buffer; i < SPX_WOTS_LEN; i++, bufferOffset += SPX_N) {
			int wots_k = info.wots_steps[i] | wots_k_mask; /* Set wots_k to */
			/* the step if we're generating a signature, ~0 if we're not */
	    
			/* Start with the secret seed */
			set_chain_addr(leaf_addr, i);
			set_hash_addr(leaf_addr, 0);
			set_type(leaf_addr, SPX_ADDR_TYPE_WOTSPRF);

			prf_addr(buffer, bufferOffset, ctx, leaf_addr);

			set_type(leaf_addr, SPX_ADDR_TYPE_WOTS);
	    
			/* Iterate down the WOTS chain */
			for (k=0;; k++) {
				/* Check if this is the value that needs to be saved as a */
				/* part of the WOTS signature */
				if (k == wots_k) {
					System.arraycopy(buffer, bufferOffset, info.wots_sig, info.wots_sigOffset + i * SPX_N, SPX_N);
				}
		
				/* Check if we hit the top of the chain */
				if (k == SPX_WOTS_W - 1) break;
		
				/* Iterate one step on the chain */
				set_hash_addr(leaf_addr, k);

				thash(buffer, bufferOffset, buffer, bufferOffset, 1, ctx, leaf_addr);
			}
		}

		/* Do the final thash to generate the public keys */
		thash(dest, destOffset, pk_buffer, 0, SPX_WOTS_LEN, ctx, pk_addr);
	}

	/*
     * Computes PRF(pk_seed, sk_seed, addr).
     */
	public static void prf_addr(byte[] out, int outOffset, Spx_ctx ctx, int[] addr)
	{
		byte[] sha2_state = new byte[40];
		byte[] buf = new byte[SPX_SHA256_ADDR_BYTES + SPX_N];
    
		/* Retrieve precomputed state containing pub_seed */
		System.arraycopy(ctx.state_seeded, 0, sha2_state, 0, 40);
	
		/* Remainder: ADDR^c ‖ SK.seed */
		System.arraycopy(intsToBytes(addr, SPX_SHA256_ADDR_BYTES), 0, buf, 0, SPX_SHA256_ADDR_BYTES);
		System.arraycopy(ctx.sk_seed, 0, buf, SPX_SHA256_ADDR_BYTES, SPX_N);

		Sha256 res = new Sha256(sha2_state, 64);
		res.update(buf);
		byte[] state = res.digest();

		System.arraycopy(state, 0, out, outOffset, SPX_N);
	}

	public static void setByte(int[] out, int byteOffset, byte val) {
		int index = byteOffset / 4;
		int mod = byteOffset % 4;
		int prior = out[index];
		out[index] = (prior & ~(0xFF << (mod * 8))) | ((val & 0xFF) << (mod * 8));
	}
    
	public static byte getByte(int[] in, int byteOffset) {
		int index = byteOffset / 4;
		int mod = byteOffset % 4;
		return (byte) (in[index] >> (mod * 8));
	}
    
	/*
     * Specify which Merkle leaf we're working on; that is, which OTS keypair
     * we're talking about.
     */
	public static void set_keypair_addr(int[] addr, int keypair)
	{
		if (SPX_FULL_HEIGHT/SPX_D > 8) {
			/* We have > 256 OTS at the bottom of the Merkle tree; to specify */
			/* which one, we'd need to express it in two bytes */
			setByte(addr, SPX_OFFSET_KP_ADDR2, (byte) (keypair >> 8));
		}
		setByte(addr, SPX_OFFSET_KP_ADDR1, (byte) keypair);
	}

	/*
     * Copy the layer, tree and keypair fields of the address structure.  This is
     * used when we're doing multiple things within the same OTS keypair
     */
	public static void copy_keypair_addr(int[] out, int[] in)
	{
		out[0] = in[0];
		out[1] = in[1];
		setByte(out, SPX_OFFSET_TREE+8-1, getByte(in, SPX_OFFSET_TREE+8-1));
	
		if (SPX_FULL_HEIGHT/SPX_D > 8)
			setByte(out, SPX_OFFSET_KP_ADDR2, getByte(in, SPX_OFFSET_KP_ADDR2));

		setByte(out, SPX_OFFSET_KP_ADDR1, getByte(in, SPX_OFFSET_KP_ADDR1));
	}
    
	/*
     * Specify which Merkle chain within the OTS we're working with
     * (the chain address)
     */
	public static void set_chain_addr(int[] addr, int chain)
	{
		setByte(addr, SPX_OFFSET_CHAIN_ADDR, (byte) chain);
	}
    
	/*
     * Specify where in the Merkle chain we are
     * (the hash address)
     */
	public static void set_hash_addr(int[] addr, int hash)
	{
		setByte(addr, SPX_OFFSET_HASH_ADDR, (byte) hash);
	}

	/*
     * Specify which Merkle tree within the level (the "tree address") we're working on
     */
	public static void set_tree_addr(int[] addr, long tree)
	{
		if ((SPX_TREE_HEIGHT * (SPX_D - 1)) > 64)
			throw new IllegalStateException("Subtree addressing is currently limited to at most 2^64 trees");

		for (int i=0; i < 8; i++)
			setByte(addr, SPX_OFFSET_TREE + i, (byte) (tree >> (56 - 8 * i)));
	}

	/*
     * Specify the height of the node in the Merkle/FORS tree we are in
     * (the tree height)
     */
	public static void set_tree_height(int[] addr, int tree_height)
	{
		setByte(addr, SPX_OFFSET_TREE_HGT, (byte) tree_height);
	}

	/*
     * Specify the distance from the left edge of the node in the Merkle/FORS tree
     * (the tree index)
     */
	public static void set_tree_index(int[] addr, int tree_index)
	{
		setByte(addr, SPX_OFFSET_TREE_INDEX + 3, (byte) tree_index);
		setByte(addr, SPX_OFFSET_TREE_INDEX + 2, (byte) (tree_index >> 8));
		setByte(addr, SPX_OFFSET_TREE_INDEX + 1, (byte) (tree_index >> 16));
		setByte(addr, SPX_OFFSET_TREE_INDEX + 0, (byte) (tree_index >> 24));
	}

	/*
     * Generate the entire Merkle tree, computing the authentication path for
     * leaf_idx, and the resulting root node using Merkle's TreeHash algorithm.
     * Expects the layer and tree parts of the tree_addr to be set, as well as the
     * tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE)
     *
     * This expecta tree_addr to be initialized to the addr structures for the 
     * Merkle tree nodes
     *
     * Applies the offset idx_offset to indices before building addresses, so that
     * it is possible to continue counting indices across trees.
     *
     * This works by using the standard Merkle tree building algorithm,
     */
	public static void treehashx1(byte[] root, int rootOffset, byte[] auth_path, int auth_pathOffset, Spx_ctx ctx, int leaf_idx, int idx_offset,
								  int tree_height, GenLeaf gen_leaf, int[] tree_addr) {
		/* This is where we keep the intermediate nodes */
		byte[] stack = new byte[tree_height*SPX_N];
	
		int idx;
		int max_idx = (1 << tree_height) - 1;
		for (idx = 0;; idx++) {
			byte[] current = new byte[2*SPX_N];   /* Current logical node is at */
			/* index[SPX_N].  We do this to minimize the number of copies */
			/* needed during a thash */
			gen_leaf.apply(current, SPX_N, ctx, idx + idx_offset);

			/* Now combine the freshly generated right node with previously */
			/* generated left ones */
			int internal_idx_offset = idx_offset;
			int internal_idx = idx;
			int internal_leaf = leaf_idx;
			int h;     /* The height we are in the Merkle tree */
			for (h=0;; h++, internal_idx >>= 1, internal_leaf >>= 1) {
		
				/* Check if we hit the top of the tree */
				if (h == tree_height) {
					/* We hit the root; return it */
					System.arraycopy(current, SPX_N, root, rootOffset, SPX_N);
					return;
				}
		
				/*
		 		* Check if the node we have is a part of the
		 		* authentication path; if it is, write it out
		 		*/
				if ((internal_idx ^ internal_leaf) == 0x01) {
					System.arraycopy(current, SPX_N, auth_path, auth_pathOffset + h * SPX_N, SPX_N);
				}
		
				/*
		 		* Check if we're at a left child; if so, stop going up the stack
		 		* Exception: if we've reached the end of the tree, keep on going
		 		* (so we combine the last 4 nodes into the one root node in two
		 		* more iterations)
				*/
				if ((internal_idx & 1) == 0 && idx < max_idx) {
					break;
				}
		
				/* Ok, we're at a right node */
				/* Now combine the left and right logical nodes together */
		
				/* Set the address of the node we're creating. */
				internal_idx_offset >>= 1;
				set_tree_height(tree_addr, h + 1);
				set_tree_index(tree_addr, internal_idx/2 + internal_idx_offset );

				System.arraycopy(stack, h * SPX_N, current, 0, SPX_N);
				thash(current, 1 * SPX_N, current, 0, 2, ctx, tree_addr);
			}
	    
			/* We've hit a left child; save the current for when we get the */
			/* corresponding right right */
			System.arraycopy(current, SPX_N, stack, h * SPX_N, SPX_N);
		}
	}

	public static final int SPX_SHA256_BLOCK_BYTES = 64;
	public static final int SPX_SHA256_OUTPUT_BYTES = 32;  /* This does not necessarily equal SPX_N */

	public static final int SPX_SHA512_BLOCK_BYTES = 128;
	public static final int SPX_SHA512_OUTPUT_BYTES = 64;

	public static final int SPX_SHAX_BLOCK_BYTES = SPX_SHA256_BLOCK_BYTES;
	public static final int SPX_SHAX_OUTPUT_BYTES = SPX_SHA256_OUTPUT_BYTES;

	static {
		if (SPX_SHA256_OUTPUT_BYTES < SPX_N)
			throw new IllegalStateException("Linking against SHA-256 with N larger than 32 bytes is not supported");
	}

	public static final int SPX_SHA256_ADDR_BYTES = 22;
    
	public static void thash(byte[] out, int outOffset, byte[] in, int inOffset, int inblocks, Spx_ctx ctx, int[] addr) {
		byte[] buf = new byte[SPX_N + SPX_SHA256_ADDR_BYTES + inblocks*SPX_N];
		byte[] bitmask = new byte[inblocks * SPX_N];
		byte[] sha2_state = new byte[40];
	
		System.arraycopy(ctx.pub_seed, 0, buf, 0, SPX_N);
		System.arraycopy(intsToBytes(addr, SPX_SHA256_ADDR_BYTES), 0, buf, SPX_N, SPX_SHA256_ADDR_BYTES);
		mgf1_256(bitmask, 0, inblocks * SPX_N, buf, SPX_N + SPX_SHA256_ADDR_BYTES);

		/* Retrieve precomputed state containing pub_seed */
		System.arraycopy(ctx.state_seeded, 0, sha2_state, 0, 40);
	
		for (int i = 0; i < inblocks * SPX_N; i++) {
			buf[SPX_N + SPX_SHA256_ADDR_BYTES + i] = (byte)(in[inOffset + i] ^ bitmask[i]);
		}

		Sha256 res = new Sha256(sha2_state, 64);
		res.update(buf, SPX_N, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
		byte[] digest = res.digest();
		System.arraycopy(digest, 0, out, outOffset, SPX_N);
	}

	private static byte[] intsToBytes(int[] in, int bytes) {
		int intCount = (bytes + 3)/4;
		byte[] res = new byte[bytes+4];
		for (int i=0; i < intCount; i++) {
			res[i*4] = (byte)in[i];
			res[i*4 + 1] = (byte)(in[i] >> 8);
			res[i*4 + 2] = (byte)(in[i] >> 16);
			res[i*4 + 3] = (byte)(in[i] >> 24);
		}
		return Arrays.copyOfRange(res, 0, bytes);
	}

	/**
	 * mgf1 function based on the SHA-256 hash function
	 * Note that inlen should be sufficiently small that it still allows for
	 * an array to be allocated on the stack. Typically 'in' is merely a seed.
	 * Outputs outlen number of bytes
	 */
	public static void mgf1_256(byte[] out, int outIndex, int outlen, byte[] in, int inlen)
	{
		byte[] inbuf = new byte[inlen + 4];
		byte[] outbuf = new byte[SPX_SHA256_OUTPUT_BYTES];
		int i;
	
		System.arraycopy(in, 0, inbuf, 0, inlen);
	
		/* While we can fit in at least another full block of SHA256 output.. */
		for (i = 0; (i+1)*SPX_SHA256_OUTPUT_BYTES <= outlen; i++) {
			u32_to_bytes(inbuf, inlen, i);
			sha256(out, outIndex, inbuf);
			outIndex += SPX_SHA256_OUTPUT_BYTES;
		}
		/* Until we cannot anymore, and we fill the remainder. */
		if (outlen > i*SPX_SHA256_OUTPUT_BYTES) {
			u32_to_bytes(inbuf, inlen, i);
			sha256(outbuf, 0, inbuf);
			System.arraycopy(outbuf, 0, out, outIndex, outlen - i*SPX_SHA256_OUTPUT_BYTES);
		}
	}

	public static void u32_to_bytes(byte[] out, int outOffset, int in) {
		out[outOffset + 0] = (byte)(in >> 24);
		out[outOffset + 1] = (byte)(in >> 16);
		out[outOffset + 2] = (byte)(in >> 8);
		out[outOffset + 3] = (byte)in;
	}

	public static void sha256(byte[] out, int outIndex, byte[] in, int inStart, int inSize) {
		sha256(out, outIndex, Arrays.copyOfRange(in, inStart, inStart + inSize));
	}

	private static final ThreadLocal<MessageDigest> sha2 = ThreadLocal.withInitial(() -> getInstance());

	private static MessageDigest getInstance() {
		try {
			return MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
   
	public static void sha256(byte[] out, int outIndex, byte[] in) {
		MessageDigest md = sha2.get();
		md.update(in);
		byte[] res = md.digest();
		System.arraycopy(res, 0, out, outIndex, res.length);
	}

	public static MessageDigest newSha256() {
		try {
			return MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	/*************************************************/
	public static abstract class BaseHash
	{
		/** The canonical name prefix of the hash. */
		protected String name;
	
		/** The hash (output) size in bytes. */
		protected int hashSize;
	
		/** The hash (inner) block size in bytes. */
		protected int blockSize;
	
		/** Number of bytes processed so far. */
		protected long count;
	
		/** Temporary input buffer. */
		protected byte[] buffer;
	
		/**
		 * Trivial constructor for use by concrete subclasses.
		 *
		 * @param name the canonical name prefix of this instance.
		 * @param hashSize the block size of the output in bytes.
		 * @param blockSize the block size of the internal transform.
		 */
		protected BaseHash(String name, int hashSize, int blockSize)
		{
			super();
	    
			this.name = name;
			this.hashSize = hashSize;
			this.blockSize = blockSize;
			this.buffer = new byte[blockSize];
	    
			resetContext();
		}
	
		public String name()
		{
			return name;
		}
	
		public int hashSize()
		{
			return hashSize;
		}
	
		public int blockSize()
		{
			return blockSize;
		}
	
		public void update(byte b)
		{
			// compute number of bytes still unhashed; ie. present in buffer
			int i = (int) (count % blockSize);
			count++;
			buffer[i] = b;
			if (i == (blockSize - 1))
				transform(buffer, 0);
		}
	
		public void update(byte[] b)
		{
			update(b, 0, b.length);
		}
	
		public void update(byte[] b, int offset, int len)
		{
			int n = (int) (count % blockSize);
			count += len;
			int partLen = blockSize - n;
			int i = 0;
	    
			if (len >= partLen)
			{
				System.arraycopy(b, offset, buffer, n, partLen);
				transform(buffer, 0);
				for (i = partLen; i + blockSize - 1 < len; i += blockSize)
					transform(b, offset + i);
		    
				n = 0;
			}
	    
			if (i < len)
				System.arraycopy(b, offset + i, buffer, n, len - i);
		}
	
		public byte[] digest()
		{
			byte[] tail = padBuffer(); // pad remaining bytes in buffer
			update(tail, 0, tail.length); // last transform of a message
			byte[] result = getResult(); // make a result out of context
	    
			reset(); // reset this instance for future re-use
	    
			return result;
		}
	
		public void reset()
		{ // reset this instance for future re-use
			count = 0L;
			for (int i = 0; i < blockSize;)
				buffer[i++] = 0;
	    
			resetContext();
		}
	
		public abstract Object clone();
	
		/**
		 * Returns the byte array to use as padding before completing a hash
		 * operation.
		 *
		 * @return the bytes to pad the remaining bytes in the buffer before
		 *         completing a hash operation.
		 */
		protected abstract byte[] padBuffer();
	
		/**
		 * Constructs the result from the contents of the current context.
		 *
		 * @return the output of the completed hash operation.
		 */
		protected abstract byte[] getResult();

		/** Resets the instance for future re-use. */
		protected abstract void resetContext();
	
		/**
		 * The block digest transformation per se.
		 *
		 * @param in the <i>blockSize</i> long block, as an array of bytes to digest.
		 * @param offset the index where the data to digest is located within the
		 *          input buffer.
		 */
		protected abstract void transform(byte[] in, int offset);
	}

	public static class Sha256
			extends BaseHash
	{
		private static final int[] k = {
				0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
				0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
				0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
				0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
				0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
				0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
				0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
				0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
				0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
				0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
				0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
				0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
				0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
				0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
				0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
				0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
		};
	
		private static final int BLOCK_SIZE = 64; // inner block size in bytes
	
		private static final int[] w = new int[64];
	
		/** caches the result of the correctness test, once executed. */
		private static Boolean valid;
	
		/** 256-bit interim result. */
		private int h0, h1, h2, h3, h4, h5, h6, h7;
	
		/** Trivial 0-arguments constructor. */
		public Sha256()
		{
			super("SHA-256", 32, BLOCK_SIZE);
		}
	
		public Sha256(byte[] state, int count)
		{
			super("SHA-256", 32, BLOCK_SIZE);
			this.h0 = parseInt(state, 0);
			this.h1 = parseInt(state, 4);
			this.h2 = parseInt(state, 8);
			this.h3 = parseInt(state, 12);
			this.h4 = parseInt(state, 16);
			this.h5 = parseInt(state, 20);
			this.h6 = parseInt(state, 24);
			this.h7 = parseInt(state, 28);
			this.count = count;
		}

		public void completeBlock() {
			byte[] tail = padBuffer(); // pad remaining bytes in buffer
			update(tail, 0, tail.length); // last transform of a message
		}

		public byte[] getState() {
			byte[] res = new byte[40];
			storeInt(res, 0, h0);
			storeInt(res, 4, h1);
			storeInt(res, 8, h2);
			storeInt(res, 12, h3);
			storeInt(res, 16, h4);
			storeInt(res, 20, h5);
			storeInt(res, 24, h6);
			storeInt(res, 28, h7);
			storeBigendianLong(res, 32, count);
			return res;
		}

		private static int parseInt(byte[] data, int offset) {
			return data[offset + 3] & 0xFF | ((data[offset + 2] & 0xFF) <<  8) | ((data[offset + 1] & 0xFF) <<  16) | ((data[offset + 0] & 0xFF) <<  24);
		}

		private static void storeInt(byte[] data, int offset, int val) {
			data[offset + 0] = (byte)(val >> 24);
			data[offset + 1] = (byte)(val >> 16);
			data[offset + 2] = (byte)(val >> 8);
			data[offset + 3] = (byte) val;
		}

		private static void storeBigendianLong(byte[] data, int offset, long val) {
			for (int i=0; i < 8; i++)
				data[offset + i] = (byte) (val >> (56 - i*8));
		}
	
		/**
		 * Private constructor for cloning purposes.
		 *
		 * @param md the instance to clone.
		 */
		private Sha256(Sha256 md)
		{
			this();
	    
			this.h0 = md.h0;
			this.h1 = md.h1;
			this.h2 = md.h2;
			this.h3 = md.h3;
			this.h4 = md.h4;
			this.h5 = md.h5;
			this.h6 = md.h6;
			this.h7 = md.h7;
			this.count = md.count;
			System.arraycopy(md.buffer, 0, this.buffer, 0, md.buffer.length);
		}
	
		public static final int[] G(int hh0, int hh1, int hh2, int hh3, int hh4,
									int hh5, int hh6, int hh7, byte[] in, int offset)
		{
			return sha(hh0, hh1, hh2, hh3, hh4, hh5, hh6, hh7, in, offset);
		}
	
		public Object clone()
		{
			return new Sha256(this);
		}
	
		protected void transform(byte[] in, int offset)
		{
			int[] result = sha(h0, h1, h2, h3, h4, h5, h6, h7, in, offset);
			h0 = result[0];
			h1 = result[1];
			h2 = result[2];
			h3 = result[3];
			h4 = result[4];
			h5 = result[5];
			h6 = result[6];
			h7 = result[7];
		}
	
		protected byte[] padBuffer()
		{
			int n = (int)(count % BLOCK_SIZE);
			int padding = (n < 56) ? (56 - n) : (120 - n);
			byte[] result = new byte[padding + 8];
			// padding is always binary 1 followed by binary 0s
			result[0] = (byte) 0x80;
			// save number of bits, casting the long to an array of 8 bytes
			long bits = count << 3;
			result[padding++] = (byte)(bits >>> 56);
			result[padding++] = (byte)(bits >>> 48);
			result[padding++] = (byte)(bits >>> 40);
			result[padding++] = (byte)(bits >>> 32);
			result[padding++] = (byte)(bits >>> 24);
			result[padding++] = (byte)(bits >>> 16);
			result[padding++] = (byte)(bits >>> 8);
			result[padding  ] = (byte) bits;
			return result;
		}
	
		protected byte[] getResult()
		{
			return new byte[] {
					(byte)(h0 >>> 24), (byte)(h0 >>> 16), (byte)(h0 >>> 8), (byte) h0,
					(byte)(h1 >>> 24), (byte)(h1 >>> 16), (byte)(h1 >>> 8), (byte) h1,
					(byte)(h2 >>> 24), (byte)(h2 >>> 16), (byte)(h2 >>> 8), (byte) h2,
					(byte)(h3 >>> 24), (byte)(h3 >>> 16), (byte)(h3 >>> 8), (byte) h3,
					(byte)(h4 >>> 24), (byte)(h4 >>> 16), (byte)(h4 >>> 8), (byte) h4,
					(byte)(h5 >>> 24), (byte)(h5 >>> 16), (byte)(h5 >>> 8), (byte) h5,
					(byte)(h6 >>> 24), (byte)(h6 >>> 16), (byte)(h6 >>> 8), (byte) h6,
					(byte)(h7 >>> 24), (byte)(h7 >>> 16), (byte)(h7 >>> 8), (byte) h7 };
		}
	
		protected void resetContext()
		{
			// magic SHA-256 initialisation constants
			h0 = 0x6a09e667;
			h1 = 0xbb67ae85;
			h2 = 0x3c6ef372;
			h3 = 0xa54ff53a;
			h4 = 0x510e527f;
			h5 = 0x9b05688c;
			h6 = 0x1f83d9ab;
			h7 = 0x5be0cd19;
		}
	
		private static synchronized final int[] sha(int hh0, int hh1, int hh2,
													int hh3, int hh4, int hh5,
													int hh6, int hh7, byte[] in,
													int offset)
		{
			int A = hh0;
			int B = hh1;
			int C = hh2;
			int D = hh3;
			int E = hh4;
			int F = hh5;
			int G = hh6;
			int H = hh7;
			int r, T, T2;
			for (r = 0; r < 16; r++)
				w[r] = (in[offset++]         << 24
						| (in[offset++] & 0xFF) << 16
						| (in[offset++] & 0xFF) << 8
						| (in[offset++] & 0xFF));
			for (r = 16; r < 64; r++)
			{
				T =  w[r -  2];
				T2 = w[r - 15];
				w[r] = ((((T >>> 17) | (T << 15)) ^ ((T >>> 19) | (T << 13)) ^ (T >>> 10))
						+ w[r - 7]
						+ (((T2 >>> 7) | (T2 << 25))
						^ ((T2 >>> 18) | (T2 << 14))
						^ (T2 >>> 3)) + w[r - 16]);
			}
			for (r = 0; r < 64; r++)
			{
				T = (H
						+ (((E >>> 6) | (E << 26))
						^ ((E >>> 11) | (E << 21))
						^ ((E >>> 25) | (E << 7)))
						+ ((E & F) ^ (~E & G)) + k[r] + w[r]);
				T2 = ((((A >>> 2) | (A << 30))
						^ ((A >>> 13) | (A << 19))
						^ ((A >>> 22) | (A << 10))) + ((A & B) ^ (A & C) ^ (B & C)));
				H = G;
				G = F;
				F = E;
				E = D + T;
				D = C;
				C = B;
				B = A;
				A = T + T2;
			}
			return new int[] {
					hh0 + A, hh1 + B, hh2 + C, hh3 + D,
					hh4 + E, hh5 + F, hh6 + G, hh7 + H };
		}
	}
}