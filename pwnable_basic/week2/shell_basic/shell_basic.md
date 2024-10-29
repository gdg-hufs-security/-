# Description

입력한 셸코드를 실행하는 프로그램이 서비스로 등록되어 작동하고 있습니다.

main 함수가 아닌 다른 함수들은 execve, execveat 시스템 콜을 사용하지 못하도록 하며, 풀이와 관련이 없는 함수입니다.

flag 파일의 위치와 이름은 /home/shell_basic/flag_name_is_loooooong입니다.
감 잡기 어려우신 분들은 아래 코드를 가지고 먼저 연습해보세요!

플래그 형식은 DH{...} 입니다. DH{와 }도 모두 포함하여 인증해야 합니다.

---

# 문제 분석
문제가 위와 같다고 한다. 친절하게도 main 이외는 풀이와 무관하다고 한다.
일단은 가상머신 서버를 부팅해서 접속해보자.

```bash
╭─     ~/ha/24-2_pwnable/p/week1     main 
╰─ nc host3.dreamhack.games 16625
shellcode: mollu
```
shellcode를 입력하는 창이 나오고, 아무거나 입력(~~몰루~~)해보니 아무 일도 일어나지 않고 종료되었다. 플래그를 얻기 위해 무엇을 해야할지 분석하기 위해 소스 코드를 열어봐야겠다.

파일을 다운받고, shell_basic.c코드를 열어보면 아래와 같다.

```c
// Compile: gcc -o shell_basic shell_basic.c -lseccomp
// apt install seccomp libseccomp-dev

#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(10);
}

void banned_execve() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (ctx == NULL) {
    exit(0);
  }
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);

  seccomp_load(ctx);
}
// 문제가 메인함수만 보라고 했었다
void main(int argc, char *argv[]) {
  char *shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);   
  void (*sc)();
  
  init();
  
  banned_execve();

  printf("shellcode: "); //shellcode를 입력하라는 곳이 여기서 나온다.
  read(0, shellcode, 0x1000); //shellcode를 0x1000만큼 읽는군

  sc = (void *)shellcode;
  sc();
}
```

결과적으로 우리한테 필요한 건 orw셸코드이다.
이건 크게 두 가지 방식으로 작성이 가능한데, 우리가 만들어야하는 로직은

```c
char buf[30];
int f = open("/home/shell_basic/flag_name_is_loooooong", RD_ONLY, NULL);
read(f, buf, 0x30);
write(1, buf, 0x30);
```
와 같은 것인데 이러한 과정을 정석적으로 어셈블리로도 작성이 가능하고, pwntools로도 가능하다.

코드는 마크다운과 별개로 첨부되어있다.

