#include "secp256k1/sb_sw_curves.h"
#include "secp256k1/sb_sw_lib.h"
//#include "sign/sha512.h"
//#include "encoding/libbase58.h"
#include "libbtc/btc/bip32.h"

static const sb_sw_message_digest_t TEST_MESSAGE = {
    {
        0xAF, 0x2B, 0xDB, 0xE1, 0xAA, 0x9B, 0x6E, 0xC1,
        0xE2, 0xAD, 0xE1, 0xD6, 0x94, 0xF4, 0x1F, 0xC7,
        0x1A, 0x83, 0x1D, 0x02, 0x68, 0xE9, 0x89, 0x15,
        0x62, 0x11, 0x3D, 0x8A, 0x62, 0xAD, 0xD1, 0xBF
    }
};

static const sb_sw_signature_t TEST_SIG = {
    {
        0xEF, 0xD4, 0x8B, 0x2A, 0xAC, 0xB6, 0xA8, 0xFD,
        0x11, 0x40, 0xDD, 0x9C, 0xD4, 0x5E, 0x81, 0xD6,
        0x9D, 0x2C, 0x87, 0x7B, 0x56, 0xAA, 0xF9, 0x91,
        0xC3, 0x4D, 0x0E, 0xA8, 0x4E, 0xAF, 0x37, 0x16,
        0xF7, 0xCB, 0x1C, 0x94, 0x2D, 0x65, 0x7C, 0x41,
        0xD4, 0x36, 0xC7, 0xA1, 0xB6, 0xE2, 0x9F, 0x65,
        0xF3, 0xE9, 0x00, 0xDB, 0xB9, 0xAF, 0xF4, 0x06,
        0x4D, 0xC4, 0xAB, 0x2F, 0x84, 0x3A, 0xCD, 0xA8
    }
};

static const sb_sw_private_t TEST_PRIV_2 = {
    {
        0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16,
        0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6, 0x93,
        0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12,
        0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21
    }
};

static const sb_byte_t TEST_H1[] = {
    0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
    0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
    0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
    0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
};

static const sb_byte_t TEST_M2[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"; // what the heck

sb_sw_signature_t out;
sb_sw_public_t pub_out;
sb_sw_context_t ct;


void test_fe_1(){
	static const sb_fe_t p256_r_inv =
    SB_FE_CONST(0xFFFFFFFE00000003, 0xFFFFFFFD00000002,
                    0x00000001FFFFFFFE, 0x0000000300000000);
    sb_fe_t t = SB_FE_ZERO;

    sb_fe_t r = SB_FE_ZERO;
    assert(sb_fe_sub(&r, &r, &SB_CURVE_P256_P.p) == 1); // r = R mod P

    sb_fe_mont_square(&t, &SB_FE_ONE, &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &p256_r_inv));
    // aka R^-1 mod P

    sb_fe_mont_mult(&t, &r, &SB_FE_ONE, &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &SB_FE_ONE));

    sb_fe_mont_mult(&t, &SB_CURVE_P256_P.r2_mod_p, &SB_FE_ONE,
                    &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &r));

    sb_fe_mont_mult(&t, &SB_CURVE_P256_P.r2_mod_p,
                    &p256_r_inv, &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &SB_FE_ONE));

    sb_fe_t t2;
    sb_fe_mont_mult(&t2, &SB_CURVE_P256_N.p, &SB_CURVE_P256_P.r2_mod_p,
                    &SB_CURVE_P256_P);
    sb_fe_mont_reduce(&t, &t2, &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &SB_CURVE_P256_N.p));

    r = SB_FE_ZERO;
    assert(sb_fe_sub(&r, &r, &SB_CURVE_P256_N.p) == 1); // r = R mod N
    assert(sb_fe_equal(&r, &SB_CURVE_P256_N.r_mod_p));

    sb_fe_mont_mult(&t, &SB_CURVE_P256_N.r2_mod_p, &SB_FE_ONE,
                    &SB_CURVE_P256_N);
    assert(sb_fe_equal(&t, &r));
    assert(sb_fe_lt(&t, &r));

    sb_fe_mont_mult(&t, &r, &SB_FE_ONE, &SB_CURVE_P256_N);
    assert(sb_fe_equal(&t, &SB_FE_ONE));

    static const sb_fe_t a5 = SB_FE_CONST(0xAA55AA55AA55AA55,
                                          0x55AA55AA55AA55AA,
                                          0xAA55AA55AA55AA55,
                                          0x55AA55AA55AA55AA);

    sb_fe_mont_mult(&t, &SB_CURVE_P256_P.p, &a5,
                    &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &SB_CURVE_P256_P.p));
	
}

static void sb_fe_mod_expt(sb_fe_t x[static const 1], const sb_fe_t e[static const 1],
                           sb_fe_t t2[static const 1], sb_fe_t t3[static const 1],
                           const sb_prime_field_t p[static const 1])
{
    sb_fe_mont_mult(t2, x, &p->r2_mod_p, p);
    *x = *t2;
    sb_fe_mod_expt_r(x, e, t2, t3, p);
    sb_fe_mont_mult(t2, x, &SB_FE_ONE, p);
    *x = *t2;
}

void sb_fe_mod_inv(sb_fe_t dest[static const 1], sb_fe_t t2[static const 1], sb_fe_t t3[static const 1],
                   const sb_prime_field_t p[static const 1])
{
    sb_fe_mod_expt(dest, &p->p_minus_two, t2, t3, p);
}

void sb_fe_mod_expt_r(sb_fe_t x[static const 1], const sb_fe_t e[static const 1],
                             sb_fe_t t2[static const 1], sb_fe_t t3[static const 1],
                             const sb_prime_field_t p[static const 1])
{
    *t2 = p->r_mod_p;

    for (size_t i = 1; i <= p->bits; i++) {
        const size_t idx = p->bits - i;
        const sb_word_t b = sb_fe_test_bit(e, idx);
        sb_fe_ctswap(b, t2, x);
        *t3 = *x;
        sb_fe_mont_mult(x, t2, t3, p);
        *t3 = *t2;
        sb_fe_mont_mult(t2, t3, t3, p);
        sb_fe_ctswap(b, t2, x);
    }
    *x = *t2;
}


void test_fe_2(){
	const sb_fe_t two = SB_FE_CONST(0, 0, 0, 2);
    const sb_fe_t thirtytwo = SB_FE_CONST(0, 0, 0, 32);
    const sb_fe_t two_expt_thirtytwo = SB_FE_CONST(0, 0, 0, 0x100000000);
    sb_fe_t t, t2, t3;
    t = two;
    sb_fe_mod_expt(&t, &thirtytwo, &t2, &t3, &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &two_expt_thirtytwo));

    t = SB_CURVE_P256_N.p;
    sb_fe_mod_expt(&t, &SB_CURVE_P256_P.p, &t2, &t3, &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &SB_CURVE_P256_N.p)); // n^p == n

    t = SB_CURVE_P256_N.p;
    sb_fe_mod_expt(&t, &SB_FE_ONE, &t2, &t3, &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &SB_CURVE_P256_N.p)); // n^1 = n

    t = SB_CURVE_P256_P.p;
    sb_fe_sub(&t, &t, &SB_FE_ONE);
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_P);
    sb_fe_add(&t, &t, &SB_FE_ONE);
    assert(sb_fe_equal(&t, &SB_CURVE_P256_P.p)); // (p-1)^-1 == (p-1)

    t = SB_FE_ONE;
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &SB_FE_ONE)); // 1^-1 == 1

    // t = B * R^-1
    sb_fe_mont_mult(&t, &SB_CURVE_P256.b, &SB_FE_ONE, &SB_CURVE_P256_P);

    // t = B^-1 * R
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_P);

    // t2 = B^-1 * R * B * R^-1 = 1
    sb_fe_mont_mult(&t2, &t, &SB_CURVE_P256.b, &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t2, &SB_FE_ONE));

    // and again, mod N
    sb_fe_mont_mult(&t, &SB_CURVE_P256.b, &SB_FE_ONE, &SB_CURVE_P256_N);
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_N);
    sb_fe_mont_mult(&t2, &t, &SB_CURVE_P256.b, &SB_CURVE_P256_N);
    assert(sb_fe_equal(&t2, &SB_FE_ONE));

}