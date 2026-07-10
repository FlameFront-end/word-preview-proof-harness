# shellCodeGenerator
 
Generates x64 WinExec Shellcode which you can use for [Threadless Injections](https://github.com/CCob/ThreadlessInject), the code was stolen from [Adopting Position Independent Shellcodes](https://snovvcrash.rocks/2023/02/14/pic-generation-for-threadless-injection.html) and [PIC-Get-Privileges](https://github.com/paranoidninja/PIC-Get-Privileges)


## Examples
Open a simple executable as a window:
```bash
./shellGenerator.sh 'calc.exe' 10
```

Open another simple executable as a window:

```bash
./shellGenerator.sh 'notepad.exe' 10
```

`CMD` is intentionally limited to simple command strings. Single quotes, backslashes,
and newlines are rejected so template rendering fails closed instead of producing
broken C source.
