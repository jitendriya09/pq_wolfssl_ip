/* xmss_wots.c
 *
 * Modified by: Yulia Kuzovkova (CR/APA3), Robert Bosch GmbH, 2020
 * This file was modified due to the integration of post-quantum cryptography
 * into wolfSSL library and uses the reference implementation
 * from https://github.com/XMSS.
 *
 * This work has been partially founded by the German Federal Ministry of Education
 * and Research (BMBF) under the project FLOQI (ID 16KIS1074).
 */

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_XMSS

#include <stdint.h>
#include <string.h>
#include <wolfssl/wolfcrypt/xmss_utils.h>
#include <wolfssl/wolfcrypt/xmss_hash.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/xmss_wots.h>
#include <wolfssl/wolfcrypt/xmss_hash_address.h>
#include <wolfssl/wolfcrypt/xmss.h>

#define XMSS_HASH_PADDING_PRF 3
#define XMSS_HASH_PADDING_PRF_KEYGEN 4
/**
 * Helper method for pseudorandom key generation.
 * Expands an n-byte array into a len*n byte array using the `prf_keygen` function.
 */
/*static void expand_seed(unsigned char *outseeds, const unsigned char *inseed,
                        const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;
    unsigned char buf[XMSS_N + 32];

    xmss_set_hash_addr(addr, 0);
    set_key_and_mask(addr, 0);
    memcpy(buf, pub_seed, XMSS_N);
    for (i = 0; i < XMSS_WOTS_LEN; i++) {
        xmss_set_chain_addr(addr, i);
        addr_to_bytes(buf + XMSS_N, addr);
        prf_keygen(outseeds + i*XMSS_N, buf, inseed);
    }
}*/

static void expand_seed(unsigned char *outseeds, const unsigned char *inseed,
                        const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;
    if (XMSS_N == 64) {
        unsigned char buf[XMSS_PADDING_LEN + 2*XMSS_N + 16];
        unsigned char addr_buf[32];

        xmss_set_hash_addr(addr, 0);
        set_key_and_mask(addr, 0);
        xmss_ull_to_bytes(buf, XMSS_PADDING_LEN, XMSS_HASH_PADDING_PRF_KEYGEN);
        memcpy(buf + XMSS_PADDING_LEN, inseed, XMSS_N);
        memcpy(buf + XMSS_PADDING_LEN + XMSS_N, pub_seed, XMSS_N);
        addr_to_bytes(addr_buf, addr);
        memcpy(buf + XMSS_PADDING_LEN + 2*XMSS_N, addr_buf, 16);

        wc_Shake master_ctx;
        wc_InitShake256(&master_ctx, NULL, 0);
        wc_Shake256_Update(&master_ctx, (const byte*)buf, XMSS_PADDING_LEN + 2*XMSS_N + 16);

        for (i = 0; i < XMSS_WOTS_LEN; i++) {
            wc_Shake working_ctx;
            xmss_set_chain_addr(addr, i);
            addr_to_bytes(addr_buf, addr);
            wc_Shake256_Copy(&master_ctx, &working_ctx);
            wc_Shake256_Update(&working_ctx, (const byte*)addr_buf+16,16);
            wc_Shake256_Final(&working_ctx, outseeds + i*XMSS_N, 64);
            wc_Shake256_Free(&working_ctx);
        }
    }
    else if(XMSS_N == 32) {
        unsigned char buf[XMSS_N + 32];

        xmss_set_hash_addr(addr, 0);
        set_key_and_mask(addr, 0);
        memcpy(buf, pub_seed, XMSS_N);
        for (i = 0; i < XMSS_WOTS_LEN; i++) {
            xmss_set_chain_addr(addr, i);
            addr_to_bytes(buf + XMSS_N, addr);
            prf_keygen(outseeds + i*XMSS_N, buf, inseed);
        }
    }
}

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */
/*static void gen_chain(unsigned char *out, const unsigned char *in,
                      unsigned int start, unsigned int steps,
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;

    // Initialize out with the value at position 'start'. 
    memcpy(out, in, XMSS_N);

    // Iterate 'steps' calls to the hash function. 
    for (i = start; i < (start+steps) && i < XMSS_WOTS_W; i++) {
        xmss_set_hash_addr(addr, i);
        thash_f(out, out, pub_seed, addr);
    }
}*/

static void gen_chain(unsigned char *out, const unsigned char *in,
                      unsigned int start, unsigned int steps,
                      const unsigned char *pub_seed, uint32_t addr[8], wc_Shake *master_ctx_prf)
{
    uint32_t i;

    // Initialize out with the value at position 'start'. 
    memcpy(out, in, XMSS_N);

    // Iterate 'steps' calls to the hash function. 
    for (i = start; i < (start+steps) && i < XMSS_WOTS_W; i++) {
        xmss_set_hash_addr(addr, i);
        if(XMSS_N == 64) {
            thash_f(out, out, pub_seed, addr,master_ctx_prf);
        }
        else if(XMSS_N == 32) {
            thash_f(out, out, pub_seed, addr,NULL);
        }
    }
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void base_w(int *output, const int out_len, const unsigned char *input)
{
    int in = 0;
    int out = 0;
    unsigned char total;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= XMSS_WOTS_LOG_W;
        output[out] = (total >> bits) & (XMSS_WOTS_W - 1);
        out++;
    }
}

/* Computes the WOTS+ checksum over a message (in base_w). */
static void wots_checksum(int *csum_base_w, const int *msg_base_w)
{
    int csum = 0;
    unsigned char csum_bytes[(XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W + 7) / 8];
    unsigned int i;

    /* Compute checksum. */
    for (i = 0; i < XMSS_WOTS_LEN1; i++) {
        csum += XMSS_WOTS_W - 1 - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << (8 - ((XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W) % 8));
    xmss_ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    base_w(csum_base_w, XMSS_WOTS_LEN2, csum_bytes);
}

/* Takes a message and derives the matching chain lengths. */
static void chain_lengths(int *lengths, const unsigned char *msg)
{
    base_w(lengths, XMSS_WOTS_LEN1, msg);
    wots_checksum(lengths + XMSS_WOTS_LEN1, lengths);
}

/**
 * WOTS key generation. Takes a 32 byte seed for the private key, expands it to
 * a full WOTS private key and computes the corresponding public key.
 * It requires the seed pub_seed (used to generate bitmasks and hash keys)
 * and the address of this WOTS key pair.
 *
 * Writes the computed public key to 'pk'.
 */
/*void wots_pkgen(unsigned char *pk, const unsigned char *seed,
                const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;

    //The WOTS+ private key is derived from the seed. 
    expand_seed(pk, seed, pub_seed, addr);

    for (i = 0; i < XMSS_WOTS_LEN; i++) {
        xmss_set_chain_addr(addr, i);
        gen_chain(pk + i*XMSS_N, pk + i*XMSS_N,
                  0, XMSS_WOTS_W - 1, pub_seed, addr);
    }
}*/
void wots_pkgen(unsigned char *pk, const unsigned char *seed,
                const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;
    wc_Shake master_ctx_prf;
    // The WOTS+ private key is derived from the seed. 
    expand_seed(pk, seed, pub_seed, addr);

    if (XMSS_N == 64) {
        unsigned char buf[XMSS_PADDING_LEN + XMSS_N + 8];
        unsigned char addr_as_bytes[32];

        // Creating buf with opcode | pub seed | addr [1..8] to take snapshot (136 byte)
        xmss_ull_to_bytes(buf, XMSS_PADDING_LEN, XMSS_HASH_PADDING_PRF);
        memcpy(buf + XMSS_PADDING_LEN, pub_seed, XMSS_N);
        addr_to_bytes(addr_as_bytes, addr);
        memcpy(buf + XMSS_PADDING_LEN + XMSS_N, addr_as_bytes, 8);

        
        wc_InitShake256(&master_ctx_prf, NULL, 0);
        wc_Shake256_Update(&master_ctx_prf, (const byte*)buf, XMSS_PADDING_LEN + XMSS_N + 8);
    }
    for (i = 0; i < XMSS_WOTS_LEN; i++) {
        xmss_set_chain_addr(addr, i);
        if (XMSS_N == 64) {
            gen_chain(pk + i*XMSS_N, pk + i*XMSS_N,
                0, XMSS_WOTS_W - 1, pub_seed, addr,&master_ctx_prf);
        }
        else if(XMSS_N == 32) {
            gen_chain(pk + i*XMSS_N, pk + i*XMSS_N,
                0, XMSS_WOTS_W - 1, pub_seed, addr,NULL);
        }
    }

    if(XMSS_N == 64) {
        wc_Shake256_Free(&master_ctx_prf);
    }
    
}

/**
 * Takes a n-byte message and the 32-byte seed for the private key to compute a
 * signature that is placed at 'sig'.
 */
/*void xmss_wots_sign(unsigned char *sig, const unsigned char *msg,
               const unsigned char *seed, const unsigned char *pub_seed,
               uint32_t addr[8])
{
    int lengths[XMSS_WOTS_LEN];
    uint32_t i;

    chain_lengths(lengths, msg);

    // The WOTS+ private key is derived from the seed. 
    expand_seed(sig, seed, pub_seed, addr);

    for (i = 0; i < XMSS_WOTS_LEN; i++) {
        xmss_set_chain_addr(addr, i);
        gen_chain(sig + i*XMSS_N, sig + i*XMSS_N,
                  0, lengths[i], pub_seed, addr);
    }
}*/

void xmss_wots_sign(unsigned char *sig, const unsigned char *msg,
               const unsigned char *seed, const unsigned char *pub_seed,
               uint32_t addr[8])
{
    int lengths[XMSS_WOTS_LEN];
    uint32_t i;
    wc_Shake master_ctx_prf;

    chain_lengths(lengths, msg);

    // The WOTS+ private key is derived from the seed. 
    expand_seed(sig, seed, pub_seed, addr);

    if (XMSS_N == 64) {
        unsigned char buf[XMSS_PADDING_LEN + XMSS_N + 8];
        unsigned char addr_as_bytes[32];

        // Creating buf with opcode | pub seed | addr [1..8] to take snapshot (136 byte)
        xmss_ull_to_bytes(buf, XMSS_PADDING_LEN, XMSS_HASH_PADDING_PRF);
        memcpy(buf + XMSS_PADDING_LEN, pub_seed, XMSS_N);
        addr_to_bytes(addr_as_bytes, addr);
        memcpy(buf + XMSS_PADDING_LEN + XMSS_N, addr_as_bytes, 8);

        
        wc_InitShake256(&master_ctx_prf, NULL, 0);
        wc_Shake256_Update(&master_ctx_prf, (const byte*)buf, XMSS_PADDING_LEN + XMSS_N + 8);
    }

    for (i = 0; i < XMSS_WOTS_LEN; i++) {
        xmss_set_chain_addr(addr, i);
        if (XMSS_N == 64) {
            gen_chain(sig + i*XMSS_N, sig + i*XMSS_N,
                  0, lengths[i], pub_seed, addr,&master_ctx_prf);
        }
        else if(XMSS_N == 32) {
            gen_chain(sig + i*XMSS_N, sig + i*XMSS_N,
                  0, lengths[i], pub_seed, addr,NULL);
        }
        
    }

    if(XMSS_N == 64) {
        wc_Shake256_Free(&master_ctx_prf);
    }
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
/*void xmss_wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    int lengths[XMSS_WOTS_LEN];
    uint32_t i;

    chain_lengths(lengths, msg);

    for (i = 0; i < XMSS_WOTS_LEN; i++) {
        xmss_set_chain_addr(addr, i);
        gen_chain(pk + i*XMSS_N, sig + i*XMSS_N,
                  lengths[i], XMSS_WOTS_W - 1 - lengths[i], pub_seed, addr);
    }
}*/
void xmss_wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    int lengths[XMSS_WOTS_LEN];
    uint32_t i;
    wc_Shake master_ctx_prf;

    chain_lengths(lengths, msg);

    if (XMSS_N == 64) {
        unsigned char buf[XMSS_PADDING_LEN + XMSS_N + 8];
        unsigned char addr_as_bytes[32];

        // Creating buf with opcode | pub seed | addr [1..8] to take snapshot (136 byte)
        xmss_ull_to_bytes(buf, XMSS_PADDING_LEN, XMSS_HASH_PADDING_PRF);
        memcpy(buf + XMSS_PADDING_LEN, pub_seed, XMSS_N);
        addr_to_bytes(addr_as_bytes, addr);
        memcpy(buf + XMSS_PADDING_LEN + XMSS_N, addr_as_bytes, 8);

        
        wc_InitShake256(&master_ctx_prf, NULL, 0);
        wc_Shake256_Update(&master_ctx_prf, (const byte*)buf, XMSS_PADDING_LEN + XMSS_N + 8);
    }

    for (i = 0; i < XMSS_WOTS_LEN; i++) {
        xmss_set_chain_addr(addr, i);
        if (XMSS_N == 64) {
            gen_chain(pk + i*XMSS_N, sig + i*XMSS_N,
                  lengths[i], XMSS_WOTS_W - 1 - lengths[i], pub_seed, addr,&master_ctx_prf);
        }
        else if(XMSS_N == 32) {
            gen_chain(pk + i*XMSS_N, sig + i*XMSS_N,
                  lengths[i], XMSS_WOTS_W - 1 - lengths[i], pub_seed, addr,NULL);
        }
        
    }

    if(XMSS_N == 64) {
        wc_Shake256_Free(&master_ctx_prf);
    }
}

#endif /* HAVE_XMSS */
