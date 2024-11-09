# Stack Canary

스택 카나리란?
- 스택 버퍼 오버플로우 보호 기법 중 하나
- 함수의 프롤로그에서 스택 버퍼와 반환 주소 사이에 임의의 값 삽입 -> 함수의 에필로그에서 해당 값의 변조를 확인
- 만약 카나리 값의 변조가 확인되면 프로세스는 강제종료

Ubuntu 22.04의 gcc는 기본적으로 스택 카나리를 적용하여 바이너리를 컴파일한다. 컴파일 옵션으로 `-fno-stack-protector`옵션을 추가해야 카나리 없이 컴파일 가능하다.

```bash
gcc -o no_canary cnary.c -fno-stack-protector
```

위와 같이 컴파일하면 스택 버퍼 오버플로우가 발생하여 `Segmentation fault`가 나타난다.

```bash
gcc -o canary canary.c
```

와 같은 일반적인 카나리는 `stack smashing detected`와 `Abort`라는 에러가 발생한다.

이 경우 스택 오버플로우가 발생하여 값이 덮여진 게 아니라 이것이 탐지되어 프로세스가 강제 종료되었음을 의미한다.

# 카나리 생성 과정

카나리 값은 프로세스가 시작될 때 `TLS`에 전역 변수로 저장되고 각 함수마다 프롤로그와 에필로그에서 이 값을 참조한다.

`fs`: TLS을 가리킨다. 그렇다면 저것의 값을 알면 TLS의 주소를 알아내고 카나리 값도 알 수 있을 것.
그러나 여기에는 이슈가 있는데 `fs`의 값은 특정 시스템 콜을 사용해야만 조회 및 설정이 가능함.

## fs 조사하기
`arch_prctl(int code, unsigned long addr)`에 중단점을 설정하여 fs의 값을 조사할 수 있겠다. 저걸 `arch_prctil(ARCH_SET_FS, addr)`의 형태로 호출하면 fs의 값은 `addr`로 설정됨.

다시 gdb를 켜서 
```bash
gdb -q ./canary
pwndbg> catch syscall arch_prctl
Catchpoint 1 (syscall 'arch_prctl' [158])
run
```

를 하고 캐치포인트 찾을때까지 눌러주자.

```bash
pwndbg> c
Continuing.

Catchpoint 1 (call to syscall arch_prctl), init_tls (naudit=naudit@entry=0) at ./elf/rtld.c:818
818	./elf/rtld.c: No such file or directory.
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
```

```bash

────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────
*RAX  0xffffffffffffffda
*RBX  0x7fffffffe110 ◂— 1
*RCX  0x7ffff7fe3dff (init_tls+239) ◂— test eax, eax
*RDX  0xffff800008279eb0
*RDI  0x1002
*RSI  0x7ffff7d85740 ◂— 0x7ffff7d85740
*R8   0xffffffff
```

캐치포인트 도달 시 레지스터 친구들을 보면 저렇다.
여기서 눈여겨볼 것은 RDI의 값이 `0x1002`이다. 이건 `ARCH_SET_FS`의 상숫값이다. `rsi`의 값이 `0x7ffff7d85740`인데 이 프로세스는 TLS를 `0x7ffffd85740`에 저장하고 `fs`가 이를 가리키게 될 것이다.
그런데 아직 여기까지는 저 주소에 어떤 값도 설정되어있지 않다. 그치만 여기까지 알아낸 것으로 저게 카나리 값이 들어갈 주소라는 뜻


`watch` 명령어: 특정 주소에 저장된 값이 변경되면 프로세스를 중단시키는 명령어

# 카나리 우회
카나리는 스택 오버플로우를 방지하는 보호 기법이지만, 이것들을 우회할 수 있는 방법들도 있다.

## 브루트 포스
무차별 대입으로 넣어보는 것인데 x64로 가게되면 실제로 하기 어렵다.

## TLS 접근
카나리는 TLS에 저장되므로 TLS을 알아내면 우회 가능한데, 이것은 실행마다 달라질 수 있기 때문에 실행 중에 알아내야 한다.

## 스택 카나리 릭
스택 카나리 자체를 읽어버릴 수 있는 취약점이다.

```C
#include <stdio.h>
#include <unistd.h>

int main() {
    char memo[8];
    char name[8];

    printf("Name: ");
    read(0, name, 64);
    printf("hello %s\n", name);

    printf("memo: ");
    read(0, memo, 64);
    printf("memo %s\n", memo);
    return 0;
}
```

 위 코드에서 name은 memo의 뒤에 위치하게 되는데, name에 8바이트(x64에서 카나리가 8바이트니까)보다 큰 값을 넣으면 카나리 값에 덮어버릴 수 있다.
