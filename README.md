# SecureCoding | LD_PRELOAD
## [시큐어코딩] LD_PRELOAD 이용해 MBR locker 우회
> LD_PRELOAD를 이용해 'fopen', 'fwrite', 'system'을 가로채
> 위험 경로(/dev/sda) 접근을 감지하고 위험 명령어(reboot)을 차단하는 코드로
> 공격 페이로드 추출도 함께 진행합니다.

---

## 기능
- `fopen` 훅 : 위험 경로일 경우 더미 파일(`~/code/mbr/dummy.img`)로 리다이렉트
- `fwrite` 훅 : 더미 파일에 공격 페이로드 덮어쓰기
- `system` 훅 : reboot 명령어 차단

---

## 실행 (Ubuntu)

```bash
# 빌드
gcc -shared -fPIC -O2 -pthread -o assignment.so assignment.c -ldl

# 실행
sudo LD_PRELoAD=$PWD/assignment.so ./hw1.elf
