/*
    Author Jieyab89 
    Compile : gcc -o decrypt  decrypt.c -lcurl
    Usage ./decrypt
*/

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

// Replace with your own API endpoint.
// Tested on Rasbbery pi on my IoT Projects 

static const unsigned char decrypt_map[] = {
  [';'] = '1',
  ['J'] = '2',
  ['v'] = '3',
  ['K'] = '4',
  ['A'] = '5',
  ['E'] = '6',
  ['W'] = '7',
  ['l'] = '8',
  ['0'] = '9',
  ['4'] = '0',
  ['+'] = '-',
  ['F'] = '=',
  ['h'] = '!',
  ['}'] = '@',
  [']'] = '#',
  ['T'] = '$',
  ['Y'] = '%',
  ['o'] = '^',
  ['s'] = '&',
  ['%'] = '*',
  ['!'] = '(',
  ['B'] = ')',
  ['j'] = '_',
  ['p'] = '+',
  ['w'] = 'Q',
  ['u'] = 'W',
  ['b'] = 'E',
  ['D'] = 'R',
  ['<'] = 'T',
  ['$'] = 'Y',
  ['#'] = 'U',
  ['.'] = 'I',
  ['8'] = 'O',
  ['q'] = 'P',
  ['U'] = '[',
  ['/'] = ']',
  ['M'] = '\'',
  ['G'] = 'q',
  ['|'] = 'w',
  ['&'] = 'e',
  ['c'] = 'r',
  ['d'] = 't',
  ['\\'] = 'y',
  ['z'] = 'u',
  ['{'] = 'i',
  ['6'] = 'o',
  ['g'] = 'p',
  [')'] = '{',
  ['7'] = '}',
  ['k'] = '|',
  ['['] = 'a',
  ['Q'] = 's',
  ['_'] = 'd',
  ['3'] = 'f',
  ['x'] = 'g',
  ['X'] = 'h',
  ['t'] = 'j',
  ['>'] = 'k',
  ['@'] = 'l',
  ['m'] = ';',
  ['='] = '\'',
  [','] = 'A',
  ['-'] = 'S',
  ['\''] = 'D',
  ['N'] = 'F',
  ['P'] = 'G',
  ['r'] = 'H',
  ['('] = 'J',
  ['n'] = 'K',
  ['1'] = 'L',
  ['R'] = 'X',
  ['I'] = 'C',
  ['y'] = 'V',
  ['f'] = 'B',
  ['i'] = 'N',
  ['2'] = 'M',
  ['^'] = ',',
  ['V'] = '.',
  ['5'] = '/',
  ['9'] = 'x',
  ['O'] = 'c',
  ['Z'] = 'v',
  ['H'] = 'b',
  ['S'] = 'n',
  ['e'] = 'm',
  ['*'] = '<',
  ['C'] = '>',
  ['a'] = 'Z',
  ['L'] = 'z',
};

static void decrypt_buffer(unsigned char *map, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = decrypt_map[(size_t)map[i]];
        if (!c)
            continue;
        map[i] = c;
    }
}

static int decrypt_file(const char *file)
{
    int fd;
    int ret;
    unsigned char *map;
    size_t file_size;
    struct stat statbuf;

    printf("Decrypting file %s ...\n", file);

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

    decrypt_buffer(map, file_size);
    msync(map, file_size, MS_ASYNC);
    munmap(map, statbuf.st_size);
    return 0;
}

static int decrypt_files(const char *folder)
{
    int ret = 0;
    DIR *dirp;
    struct dirent *dir;
    struct stat statbuf;
    char fullpath[8192 + sizeof(".loli")];
    char newpath[8192];

    dirp = opendir(folder);
    if (!dirp) {
        perror("opendir");
        return 1;
    }

    while (1) {
        size_t len;
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

        // Recursive: masuk subdirektori
        if (S_ISDIR(statbuf.st_mode)) {
            decrypt_files(fullpath);
            continue;
        }

        if (!S_ISREG(statbuf.st_mode))
            continue;

        ret = decrypt_file(fullpath);
        if (ret)
            break;

        len = strlen(fullpath);
        memcpy(newpath, fullpath, len - 5);
        newpath[len - 5] = '\0';  // fix: index off-by-one
        printf("Restored: %s\n", newpath);
        rename(fullpath, newpath);
    }

    closedir(dirp);
    return ret;
}

static int decrypt_folder(void)
{
    char folder[1024];
    size_t len;

    printf("Enter the folder name to be decrypted: ");
    if (!fgets(folder, sizeof(folder), stdin)) {
        puts("stdin closed!");
        return 1;
    }

    len = strlen(folder);

    if (folder[len - 1] == '\n') {
        folder[len - 1] = '\0';
    }

    return decrypt_files(folder);
}

int main(void)
{
    FILE * file;
    int exit_code = 0;
    char text[255];
    FILE *name;
    char path[255];
    FILE *dir;
    FILE *distro;
    char buffer[255];
    distro = popen("cat /etc/os-release", "r");
    fgets(buffer, sizeof(buffer), distro);
    dir = popen("pwd", "r");
    fgets(path, sizeof(path), dir);
    name = popen("whoami", "r");
    fgets(text, sizeof(text), name);

    buffer[strlen(buffer) - 1] = '\0';

    printf("\n");
    printf("Name : %s \n", text);
    printf("Path : %s \n", path);
    #ifdef _WIN32
    printf("Systems : Windows32\n");
    #endif
    #ifdef _WIN64
    printf("Systems : Windows32\n");
    #endif
    #ifdef __linux__
    printf("Systems : Linux %s Based\n", buffer);
    #else
  	printf("Can't detect OS\n");
  	#endif

    exit_code = decrypt_folder();

    return exit_code;
}