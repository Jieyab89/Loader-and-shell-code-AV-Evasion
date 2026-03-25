# List Shellcode Payload and Loader 

A collection of shellcode payloads, loaders, and encoders for red teaming and research. It includes payloads and loaders capable of bypassing antivirus software such as Windows Defender, Avira, McAfee, and others. This collection is sourced from the open-source community as well as the author’s own research, and the repository will continue to grow over time

# Please Take a Note

For educational purposes only!

> Please dont upload on Virus Total or virus scanner sandbox machine in other platform 
>
Tested date "24 March 2026"

## Requirements  

- IDE code editor like Microsoft Visual Studio Code, Code Blocks and etc 
- Compiler C like Clang, Mingw, g++, gcc, MSCV
- Virtual machine like Virtual Box, Vmware and etc 
- Anti virus for testing 
- Reverse engineering toolkit 
- HTTP Interceptor 
- Intercept TCP 
- Proccess monitor 
- Resouce Hacker 
- PyInstaller 
- Auto-py-to-exe
- ExeOutput for PHP
- NativePHP 
- Go compiler 
- Netcat 
- Metasploit framework like msfconsole, msfrpc, msfvenom

Other 

Generate your own SSL cert for testing with HTTPS 

```
openssl req -x509 -nodes -newkey rsa:2048 -keyout server.rsa.key -out server.rsa.crt -days 3650
```

## Usage 

You can integrated with your own C2 or available C2 for example 

1. Use API msfrpc and msfconsole (metasploit framework)
2. Your own C2 server 
3. Available C2 server like Cobalt, Adaptix and so on 
4. Check and read the code for compile and usage the payload and loader 

Here the image 

Tested Adaptix C2 

<img width="1278" height="515" alt="image" src="https://github.com/user-attachments/assets/aa1b3859-c26a-4672-bffe-533153f52a32" />

Tested my own C2 server 

<img width="1366" height="599" alt="image" src="https://github.com/user-attachments/assets/68286724-72f9-460e-ad01-9af31fff54f7" />

Logen API Encryption 

<img width="1365" height="579" alt="image" src="https://github.com/user-attachments/assets/95b80b32-f9aa-4754-82e7-da5e84cb88cc" />

# Maintence or Problem Solving (Troubleshooting)

## php troubleshooting

If you're using PHP as shellcode and an API and want to customize settings such as file size limits and maximum execution time, you can modify them in your PHP.ini file. Check the web server you've installed or use Linux or Windows commands to locate your PHP.ini file. Here's an example of a custom php.ini configuration

```
upload_max_filesize = 10M
post_max_size = 12M
memory_limit = 128M
max_execution_time = 60
```

## Notes for Troubleshooting

### php.ini 

- On php.ini u can do a comment on variabel or u can change the value at variabel 

### Other 

If there is any issue and trouble i will update on here. Please let me know  

# Reference

- https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference