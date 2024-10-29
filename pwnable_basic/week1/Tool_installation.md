
# Tool Installation

pwndbg 깃허브에 들어가면 README 파일에

```bash
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

를 통해 쉽게 설치 가능하다.

![](https://i.imgur.com/MMzt9ZP.png)

---

# pwntools

- 우분투에서는 쉽게 설치가 가능하다.
- 아치리눅스에서도 마찬가지로 설치할 수 있고 잘 작동한다.
- 우분투에서는 가이드대로 따라가면 별 문제 없이 설치 가능하고, 아치리눅스는 시스템의 파이썬에 직접 설치하는 것에 제한이 있으므로 가상환경이 필수적이다.

```bash
python -m venv ~/venv
source ~/venv/bin/activate
pip install pwntools
```

와 같이 진행할 수 있으며,

![](https://i.imgur.com/bZOzEuQ.png)

정상적으로 설치된 것을 볼 수 있다. 
