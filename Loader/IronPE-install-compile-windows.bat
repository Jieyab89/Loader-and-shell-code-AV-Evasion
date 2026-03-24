@echo off
echo [*] Building x64...
cargo build --release --target x86_64-pc-windows-msvc

echo [*] Building x86...
cargo build --release --target i686-pc-windows-msvc

echo [+] Done!
echo x64: target\x86_64-pc-windows-msvc\release\IronPE.exe
echo x86: target\i686-pc-windows-msvc\release\IronPE.exe