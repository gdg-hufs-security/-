# Intro
카나리와는 또 다른 방어 기법이다.
카나리 때 워게임의 쉘코드가 성공했던 이유는

- 반환 주소를 임의 주소로 덮을 수 있었고
- 버퍼의 주소를 알 수 있었고
- 버퍼가 실행 가능했다.

따라서 위와 같은 문제점을 해결하려면
- 공격자가 임의 버퍼의 주소를 알기 어렵게 하고
- 메모리 영역에서 불필요한 실행 권한을 제거

하면 임의 주소로 반환 주소를 덮고 버퍼를 실행하기 어려울 것.

---

# NX(No-eXecute)
이름 그대로 실행권한을 건드리는 친구. 실행에 사용되는 메모리 영역과 쓰기에 사용되는 메모리 영역을 분리하는 보호 기법이다.
메모리 영역에 쓰기 권한과 실행 권한이 함께 있으면 시스템이 취약해지기 쉽다.

gdb에서 `vmmap`으로 NX 적용 전후를 확인하면 NX가 적용된 바이너리에는 코드 영역 이외에는 실행 권한이 없음을 확인 가능하다.

카나리를 확인할 때 했던 것처럼 `checksec`을 사용하면 NX 여부를 판단 가능하다.

# ASLR(Address Space Layout Randomization)
바이너리가 실행될 때마다 스택, 힙, 공유 라이브러리 등을 임의의 주소에 할당하는 보호 기법이다. r2s는 ASLR이 적용되기는 했으나 실행할 때마다 buf의 주소를 출력해줬기 때문에 공격에 활용하는 게 어렵지 않았다.

```bash
     ~/pwn ▓▒░                     ░▒▓ 6m 54s    max@pwnmax  09:35:08   
❯ gcc addr.c -o addr -ldl -no-pie -fno-PIE

      ~/pwn ▓▒░                                ░▒▓ max@pwnmax  09:35:47   
❯ ./addr
buf_stack addr: 0x7ffc0e4ab4d0
buf_heap addr: 0x91a2a0
libc_base addr :0x7f3bcf12c000
printf addr: 0x7f3bcf18c6f0
main addr: 0x4011b6

      ~/pwn ▓▒░                                ░▒▓ max@pwnmax  09:35:57   
❯ ./addr
buf_stack addr: 0x7ffc8d013450
buf_heap addr: 0x1f8f2a0
libc_base addr :0x7f365fc74000
printf addr: 0x7f365fcd46f0
main addr: 0x4011b6
```

로드맵에 있는 코드르 계속 돌려보면 저런다. 저기서 봐야하는것은 메인 주소는 같은데 그 위에 있는 친구들은 실행 때마다 바뀐다는 것. 정리하자면

- `main` 함수를 제외한 다른 영역의 주소들은 실행할 때마다 값이 변경됨.
- 따라서 실행하기 전까지 알 수 없다
- `libc_base`와 `printf`의 주소 차이는 항상 같다.
