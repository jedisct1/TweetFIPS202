
#ifndef SHA3_H

#ifdef __cplusplus
# if __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

int crypto_hash_shake128(unsigned char *h, const unsigned char *m,
                         unsigned long long n);

int crypto_hash_shake256(unsigned char *h, const unsigned char *m,
                         unsigned long long n);

int crypto_hash_sha3224(unsigned char *h, const unsigned char *m,
                        unsigned long long n);

int crypto_hash_sha3256(unsigned char *h, const unsigned char *m,
                        unsigned long long n);

int crypto_hash_sha3384(unsigned char *h, const unsigned char *m,
                        unsigned long long n);

int crypto_hash_sha3512(unsigned char *h, const unsigned char *m,
                        unsigned long long n);

#ifdef __cplusplus
}
#endif

#endif
