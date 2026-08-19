#!/bin/bash
# ============================================================
# Build: Evasive C# AES Shellcode Loader (Linux/macOS)
# Usage:
#   ./build_loader.sh           — compile with mcs (Mono)
#   ./build_loader.sh dotnet    — compile with dotnet SDK
# ============================================================

set -e

MODE="${1:-mcs}"

if [ "$MODE" == "dotnet" ]; then
    echo "[*] Building with dotnet SDK..."
    rm -rf /tmp/build_temp 2>/dev/null
    mkdir -p /tmp/build_temp
    cp Loader.cs /tmp/build_temp/
    cd /tmp/build_temp
    dotnet new console --force >/dev/null 2>&1
    cp Loader.cs Program.cs
    dotnet build -c Release -o "$OLDPWD/out" >/dev/null 2>&1
    cd "$OLDPWD"
    rm -rf /tmp/build_temp
    echo "[+] Done: out/Loader (or out/Loader.dll, run via 'dotnet out/Loader.dll')"
elif command -v mcs &>/dev/null; then
    echo "[*] Building with Mono (mcs)..."
    mkdir -p out
    mcs -target:exe -out:out/Loader.exe -platform:x64 -unsafe -optimize+ Loader.cs
    echo "[+] Done: out/Loader.exe"
elif command -v csc &>/dev/null; then
    echo "[*] Building with csc..."
    mkdir -p out
    csc -target:exe -out:out/Loader.exe -platform:x64 -unsafe -optimize+ Loader.cs
    echo "[+] Done: out/Loader.exe"
else
    echo "[!] No C# compiler found. Install mono-mcs, dotnet-sdk, or copy to a Windows machine with Visual Studio."
    exit 1
fi
