/*
    Author Jieyab89 

    Compile : x86_64-w64-mingw32-gcc calc-shellc0de.c -o calc64.bin
*/

#include <windows.h>

int main() {
    WinExec("calc.exe", SW_SHOW);
    return 0;
}