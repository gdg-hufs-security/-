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


