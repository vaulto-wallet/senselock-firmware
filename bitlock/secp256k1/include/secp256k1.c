#include "../sb_sw_context.h"
#include "../sb_sw_lib.h"
#include "secp256k1.h"


sb_sw_context_t ctx;

SECP256K1_API secp256k1_context* secp256k1_context_create(unsigned int flags){
	return (secp256k1_context*)&ctx;
}


SECP256K1_API void secp256k1_context_destroy(secp256k1_context* ctx){
	return;
}



int secp256k1_ec_pubkey_create(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *seckey) {
	sb_sw_public_t public_key;
	sb_sw_compute_public_key(ctx, &public_key, seckey, NULL,
                                    SB_SW_CURVE_SECP256K1,
                                    SB_DATA_ENDIAN_BIG);
									
	memcpy(pubkey, &public_key, sizeof(secp256k1_pubkey));
}


static int secp256k1_ge_is_infinity(const secp256k1_ge *a) {
    return a->infinity;
}

static void secp256k1_ge_set_xy(secp256k1_ge *r, const secp256k1_fe *x, const secp256k1_fe *y) {
    r->infinity = 0;
    r->x = *x;
    r->y = *y;
}



SECP256K1_INLINE static int secp256k1_fe_is_odd(const secp256k1_fe *a) {
    return a->words[0] & 1;
}


static int secp256k1_eckey_pubkey_serialize(secp256k1_ge *elem, unsigned char *pub, size_t *size, int compressed) {
    if (secp256k1_ge_is_infinity(elem)) {
        return 0;
    }
    if (compressed) {
        *size = 33;
		sb_fe_to_bytes(&pub[1], &elem->x, SB_DATA_ENDIAN_BIG);
        pub[0] = 0x02 | (secp256k1_fe_is_odd(&elem->y) ? 0x01 : 0x00);
    } else {
        *size = 65;
        pub[0] = 0x04;
		sb_fe_to_bytes(&pub[1], &elem->y, SB_DATA_ENDIAN_BIG);
    }
    return 1;
}

static int secp256k1_pubkey_load(const secp256k1_context* ctx, secp256k1_ge* ge, const secp256k1_pubkey* pubkey) {
	secp256k1_fe x, y;
	sb_fe_from_bytes(&x, pubkey->data, SB_DATA_ENDIAN_BIG);
	sb_fe_from_bytes(&x, pubkey->data + 32, SB_DATA_ENDIAN_BIG);
	secp256k1_ge_set_xy(ge, &x, &y);
    return 1;
}


int secp256k1_ec_pubkey_serialize(const secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const secp256k1_pubkey* pubkey, unsigned int flags) {
    secp256k1_ge Q;
    size_t len;
    int ret = 0;

    len = *outputlen;
    *outputlen = 0;
    memset(output, 0, len);
    if (secp256k1_pubkey_load(ctx, &Q, pubkey)) {
        ret = secp256k1_eckey_pubkey_serialize(&Q, output, &len, flags & SECP256K1_FLAGS_BIT_COMPRESSION);
        if (ret) {
            *outputlen = len;
        }
    }
    return ret;
}


SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_context_randomize(
    secp256k1_context* ctx,
    const unsigned char *seed32
){
	return 0;
}

SECP256K1_API int secp256k1_ecdsa_sign(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature *sig,
    const unsigned char *msg32,
    const unsigned char *seckey,
    secp256k1_nonce_function noncefp,
    const void *ndata
){
	sb_sw_sign_message_digest(ctx, sig, seckey, msg32,
                                     NULL, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG);
	return 0;
}




static void secp256k1_scalar_set_b32(secp256k1_scalar *r, const unsigned char *bin, int *overflow){
	sb_fe_from_bytes( r, bin, SB_SW_CURVE_SECP256K1);
}

void secp256k1_scalar_get_b32(unsigned char *buf, secp256k1_scalar* scalar){
	sb_fe_to_bytes(buf, scalar,SB_DATA_ENDIAN_BIG);
}


static void secp256k1_ecdsa_signature_load(const secp256k1_context* ctx, secp256k1_scalar* r, secp256k1_scalar* s, const secp256k1_ecdsa_signature* sig) {
    (void)ctx;
    secp256k1_scalar_set_b32(r, &sig->data[0], NULL);
    secp256k1_scalar_set_b32(s, &sig->data[32], NULL);
}


static int secp256k1_ecdsa_sig_serialize(unsigned char *sig, size_t *size, const secp256k1_scalar* ar, const secp256k1_scalar* as) {
    unsigned char r[33] = {0}, s[33] = {0};
    unsigned char *rp = r, *sp = s;
    size_t lenR = 33, lenS = 33;
	

    secp256k1_scalar_get_b32(&r[1], ar);
    secp256k1_scalar_get_b32(&s[1], as);
    while (lenR > 1 && rp[0] == 0 && rp[1] < 0x80) { lenR--; rp++; }
    while (lenS > 1 && sp[0] == 0 && sp[1] < 0x80) { lenS--; sp++; }
    if (*size < 6+lenS+lenR) {
        *size = 6 + lenS + lenR;
        return 0;
    }
    *size = 6 + lenS + lenR;
    sig[0] = 0x30;
    sig[1] = 4 + lenS + lenR;
    sig[2] = 0x02;
    sig[3] = lenR;
    memcpy(sig+4, rp, lenR);
    sig[4+lenR] = 0x02;
    sig[5+lenR] = lenS;
    memcpy(sig+lenR+6, sp, lenS);
    return 1;
}



SECP256K1_API int secp256k1_ecdsa_signature_serialize_der(
    const secp256k1_context* ctx,
    unsigned char *output,
    size_t *outputlen,
    const secp256k1_ecdsa_signature* sig
){
	secp256k1_scalar r, s;

	secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    return secp256k1_ecdsa_sig_serialize(output, outputlen, &r, &s);
}



SECP256K1_API int secp256k1_ecdsa_signature_serialize_compact(const secp256k1_context* ctx, unsigned char *output64, const secp256k1_ecdsa_signature* sig) {
	secp256k1_scalar r, s;

	secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    secp256k1_scalar_get_b32(&output64[0], &r);
    secp256k1_scalar_get_b32(&output64[32], &s);
    return 1;
}


static int secp256k1_scalar_add(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b) {
    int overflow=0;
	uint64_t t = 0;
	
    for(unsigned int i = 0; i <= sizeof(secp256k1_scalar)/sizeof(sb_word_t); i ++){
			t += a->words[i] + b->words[i];
			r->words[i] = (sb_word_t)(t & 0xFFFFFFFF);
			t >>= 32;
	}
    return overflow;
}


SECP256K1_INLINE static int secp256k1_scalar_is_zero(const secp256k1_scalar *a) {
    return (a->words[0] | a->words[1] | a->words[2] | a->words[3] | a->words[4] | a->words[5] | a->words[6] | a->words[7]) == 0;
}


static int secp256k1_eckey_privkey_tweak_add(secp256k1_scalar *key, const secp256k1_scalar *tweak) {
    secp256k1_scalar_add(key, key, tweak);
    if (secp256k1_scalar_is_zero(key)) {
        return 0;
    }
    return 1;
}

SECP256K1_INLINE static void secp256k1_scalar_clear(secp256k1_scalar *r) {
    r->words[0] = 0;
    r->words[1] = 0;
    r->words[2] = 0;
    r->words[3] = 0;
    r->words[4] = 0;
    r->words[5] = 0;
    r->words[6] = 0;
    r->words[7] = 0;
}




int secp256k1_ec_privkey_tweak_add(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak) {
    secp256k1_scalar term;
    secp256k1_scalar sec;
    int ret = 0;
    int overflow = 0;
    
    secp256k1_scalar_set_b32(&term, tweak, &overflow);
    secp256k1_scalar_set_b32(&sec, seckey, NULL);

    ret = !overflow && secp256k1_eckey_privkey_tweak_add(&sec, &term);
    memset(seckey, 0, 32);
    if (ret) {
        secp256k1_scalar_get_b32(seckey, &sec);
    }

    secp256k1_scalar_clear(&sec);
    secp256k1_scalar_clear(&term);
    return ret;
}
