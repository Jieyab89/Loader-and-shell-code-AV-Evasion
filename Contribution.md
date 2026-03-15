# Contribution 

If you want to contrib. Following the format on source code 

example add the comment for each your source code. Add the auhor name and add how to compile and usage, please do not obfuscate your code 

```
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
    x86_64-w64-mingw32-gcc -O2 -s -mwindows loader-fake-windows-update \ -lm -lwininet -lbcrypt \ -o Windows Update.exe
*/
```

After that on pull request description, please make a documentation and proof your code work and compile how to usage with the image 