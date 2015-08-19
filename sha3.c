
/*
 * TweetFIPS202
 *
 * Readable version of https://twitter.com/TweetFIPS202
 *
 * A self-contained implementation of SHAKE-128, SHAKE-256,
 * SHA3-224, SHA3-256, SHA3-384 and SHA3-512.
 */

static unsigned long long
ROL(unsigned long long a, unsigned char n)
{
    return (a << n) | (a >> (64 - n));
}

static unsigned long long
L64(const unsigned char *x)
{
    unsigned long long r = 0, i;

    for (i = 0; i < 8; ++i) {
        r |= (unsigned long long)x[i] << 8 * i;
    }
    return r;
}

static void
F(unsigned long long *s)
{
    unsigned char x, y, j, R = 1, r, n;
    unsigned long long t, B[5], Y;

    for (n = 0; n < 24; ++n) {
        for (x = 0; x < 5; ++x) {
            B[x] = 0;
            for (y = 0; y < 5; ++y) {
                B[x] ^= s[x + 5 * y];
            }
        }
        for (x = 0; x < 5; ++x) {
            t = B[(x + 4) % 5] ^ ROL(B[(x + 1) % 5], 1);
            for (y = 0; y < 5; ++y) {
                s[x + 5 * y] ^= t;
            }
        }
        t = s[1];
        y = r = 0;
        x = 1;
        for (j = 0; j < 24; ++j) {
            r += j + 1;
            Y = 2 * x + 3 * y;
            x = y;
            y = Y % 5;
            Y = s[x + 5 * y];
            s[x + 5 * y] = ROL(t, r % 64);
            t = Y;
        }
        for (y = 0; y < 5; ++y) {
            for (x = 0; x < 5; ++x) {
                B[x] = s[x + 5 * y];
            }
            for (x = 0; x < 5; ++x) {
                s[x + 5 * y] = B[x] ^ (~B[(x + 1) % 5] & B[(x + 2) % 5]);
            }
        }
        for (y = 0; y < 7; ++y) {
            if ((R=(R<<1)^(113*(R>>7)))&2) {
                *s^=1ULL<<((1<<y)-1);
            }
        }
    }
}

static void
Keccak(unsigned char r, const unsigned char *m, unsigned long long n,
       unsigned char p, unsigned char *h, unsigned long long d)
{
    unsigned long long s[25], i;
    unsigned char t[200];

    for (i = 0; i < 25; ++i) {
        s[i] = 0;
    }
    while (n >= r) {
        for (i = 0; i < r / 8; ++i) {
            s[i] ^= L64(m + 8 * i);
        }
        F(s);
        n -= r;
        m += r;
    }
    for (i = 0; i < r; ++i) {
        t[i] = 0;
    }
    for (i = 0; i < n; ++i) {
        t[i] = m[i];
    }
    t[i] = p;
    t[r - 1] |= 128;
    for (i = 0; i < r / 8; ++i) {
        s[i] ^= L64(t + 8 * i);
    }
    F(s);
    for (i = 0; i < d; ++i) {
        h[i] = s[i / 8] >> 8 * (i % 8);
    }
}

int
crypto_hash_shake128(unsigned char *h, const unsigned char *m,
                     unsigned long long n)
{
    Keccak(21 * 8, m, n, 6 + 25 * 1, h, 168);
    return 0;
}

int
crypto_hash_shake256(unsigned char *h, const unsigned char *m,
                     unsigned long long n)
{
    Keccak(17 * 8, m, n, 6 + 25 * 1, h, 136);
    return 0;
}

int
crypto_hash_sha3224(unsigned char *h, const unsigned char *m,
                    unsigned long long n)
{
    Keccak(18 * 8, m, n, 6 + 25 * 0, h, 28);
    return 0;
}

int
crypto_hash_sha3256(unsigned char *h, const unsigned char *m,
                    unsigned long long n)
{
    Keccak(17 * 8, m, n, 6 + 25 * 0, h, 32);
    return 0;
}

int
crypto_hash_sha3384(unsigned char *h, const unsigned char *m,
                    unsigned long long n)
{
    Keccak(13 * 8, m, n, 6 + 25 * 0, h, 48);
    return 0;
}

int
crypto_hash_sha3512(unsigned char *h, const unsigned char *m,
                    unsigned long long n)
{
    Keccak(9 * 8, m, n, 6 + 25 * 0, h, 64);
    return 0;
}
