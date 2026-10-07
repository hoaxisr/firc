/* BLAKE3 (src/lib/blake3.h) against reference values taken by a Go program with
 * lukechampine.com/blake3 v1.4.1, the library Xray-core uses (proxy/vless/encryption). The input
 * is the bytes i mod 251, at lengths on the block (64), chunk (1024) and tree (2, 3, 4, 31 and 100
 * chunks) boundaries. The second value is DeriveKey with those bytes as the context and
 * "VLESS-material-<length>" as the material: the shape of the NewAEAD call, where a context longer
 * than a kilobyte goes through the tree. Last, DeriveKey with 64 bytes out (context "ctx",
 * material "m").
 *
 * blake3.h is self-contained, so this test needs no library and runs in `make test`. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/lib/blake3.h"

static const struct { size_t n; const char *hash, *dk; } V[] = {
    { 0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "a3feb76305dee655e0c6b6cb1bc263d89de05fd018c7d6d76c47a4d9879f0a07" },
    { 1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213", "5b72245a5a97313c82dd4dc74a54dffc970eb9078e9c5f2b6dad8a4aff4361be" },
    { 63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b", "6ab077956b8d7965b5fec1937a34853d7dee76780ebd8cc891e3795f24b1dbcf" },
    { 64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98", "4e24fc2343ba989f5b7fe3f6a42c937dea076e4bab01f05e1adcfe76e9fc30eb" },
    { 65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee", "a186790bc8ff614ad26cb080ece36b189643c5ad46d2af68753fb6dd2ba225df" },
    { 127, "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d", "8fcb83c99f3e018f9d416fb2aa91b6852e35da5ede11bb0f7394c645109c2542" },
    { 128, "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef", "a25c14a32121db42a854ff985c5d7659da45954d1270d4a48e1caffdee9246e1" },
    { 129, "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12", "5be909845172c3825030b169bd956a7312b06bc072f0cd8178a4b7193ee96359" },
    { 1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11", "1969c87ec37dc191a62bb0fc5004302ead129e7bbfb67b9895e23ab05faef570" },
    { 1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7", "ddf39869d6de68c7fe5662ae137a26d4378307fbb030aeb46061a6d011212dce" },
    { 1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444", "e7d53a49e153ec7a62f2ae5dab9fd553ae5c4f68cc29e4cfe7057311576b29e1" },
    { 2047, "58830fbf51a4423c573b164471690570e544cfe793bead46225664796b4b1467", "f174695e061cbf542e8fbe8600c1033b4d914ae71b86eac610b51c63ba3b692f" },
    { 2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a", "df37e64062c0cffe647a3a68aad21b2be76ef19d6b5caf4e6bc6ab71b633bf63" },
    { 2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030", "a369d2582830b68033bcdcb5a3388214594f02d90ddc0636f631fdca457020c7" },
    { 3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2", "4b45f3ba5bfc896d02f6bfcd49a812021732be0b4321b036b22a5a30837f9258" },
    { 3073, "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3", "677f488291b41fcf6bff73cc68ff1bfad5f0ab76e30e25d117d7a734ade40271" },
    { 4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969", "fc64e49c219866b380ba23ef38bd3d25b68d15f1ae784bc718eba536e6c25dd4" },
    { 31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47", "b6dcd0f6ab8195c1fd9a32fad17956b7c082132b7d2c56208ec8a4a860190418" },
    { 102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085", "77bf0b8179d75aa191d733fce13288ce4d793771aab44c624f9d7468076d15d9" },
};

static void hex(char *o, const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) sprintf(o + 2 * i, "%02x", b[i]);
}

int main(void) {
    int fails = 0;
    for (size_t i = 0; i < sizeof(V) / sizeof(V[0]); i++) {
        unsigned char *in = malloc(V[i].n + 1);
        for (size_t j = 0; j < V[i].n; j++) in[j] = (unsigned char)(j % 251);
        unsigned char h[32], k[32];
        char hh[65], kh[65], mat[64];
        b3_hash(h, in, V[i].n);
        snprintf(mat, sizeof mat, "VLESS-material-%zu", V[i].n);
        b3_derive_key(k, 32, in, V[i].n, mat, strlen(mat));
        hex(hh, h, 32); hex(kh, k, 32);
        int ok = !strcmp(hh, V[i].hash) && !strcmp(kh, V[i].dk);
        if (!ok) fails++;
        printf("BLAKE3 length %-6zu hash and derive_key %s\n", V[i].n, ok ? "ok" : "FAIL");
        free(in);
    }
    {
        /* 64 bytes out, the most sc_blake3_derive_key allows: the upper half comes from the other
         * eight state words, which no 32-byte value above reaches. Values from the same library. */
        static const char *DK64 =
            "6b30698a17fbfdebd8ed654e7235532153c6d15504aa25b0249e2f24304702e2"
            "fcfd47ecbccd67bba72197c9a50ce689cdfc168ac36615eb26353d960d65deb2";
        unsigned char a[32], b[64];
        char ah[65], bh[129];
        b3_derive_key(a, 32, "ctx", 3, "m", 1);
        b3_derive_key(b, 64, "ctx", 3, "m", 1);
        hex(ah, a, 32); hex(bh, b, 64);
        int ok = !strncmp(ah, DK64, 64) && !strcmp(bh, DK64);
        if (!ok) fails++;
        printf("BLAKE3 derive_key with 32 and 64 bytes out %s\n", ok ? "ok" : "FAIL");
    }
    printf(fails ? "FAILED: %d\n" : "b3match: all matched\n", fails);
    return fails ? 1 : 0;
}
