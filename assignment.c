#define _GNU_SOURCE
#include <dlfcn.h>        // dlsym, RTLD_NEXT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>


// 위험 경로 판별
// /dev/sda
static int is_dangerous_path(const char *path) {
    if (!path)
    {
	return 0;
    }

    if (strstr(path, "/dev/sd"))
    {
        return 1;
    }

    return 0;
}

// fopen : 프로그램이 위험 경로를 fopen하려 하면 더미 파일로 우회
typedef FILE *(*orig_fopen_t)(const char*, const char*);
static orig_fopen_t orig_fopen = NULL;

FILE *fopen(const char *path, const char *mode) // 가짜 fopen
{
    if (!orig_fopen)
    {
	orig_fopen = (orig_fopen_t)dlsym(RTLD_NEXT, "fopen"); // 원본 심볼 획득
    }

    if (path && is_dangerous_path(path)) // 위험 대상이면 더미 파일로 우회
    {
        const char *home = getenv("HOME");
        static char dummy[512];

        if (home)
	{
	    snprintf(dummy, sizeof(dummy), "%s/code/mbr/dummy.img", home);
	}
        else
	{
	    snprintf(dummy, sizeof(dummy), "/tmp/dummy.img");
	}

	// 더미 파일 없으면 생성
	int fd = open(dummy, O_RDWR | O_CREAT, 0600);
	if (fd >= 0)
	{
	    close(fd);
	}

        printf("[SAFE] fopen redirect: %s -> %s\n", path, dummy);

	// 더미 파일 반환
        return orig_fopen(dummy, mode);
    }

    // 안전 경로면 원본 fopen
    return orig_fopen(path, mode);
}

// fwrite : 위험 경로일 경우 쓰기 차단
typedef size_t (*orig_fwrite_t)(const void*, size_t, size_t, FILE*);
static orig_fwrite_t orig_fwrite = NULL;

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) // 가짜 fwrite
{
    if (!orig_fwrite)
    {
	orig_fwrite = (orig_fwrite_t)dlsym(RTLD_NEXT, "fwrite"); // 원본 심볼 획득
    }

    // 총 바이트 수
    size_t total = size * nmemb;

    // 대상 경로 알아내기 위해 /proc/self/fd/<fd> 따라감
    char pathbuf[512] = {0}; // 실제 경로 담을 버퍼
    if (stream)
    {
        int fd = fileno(stream);
        if (fd >= 0)
	{
            char link[64];
	    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
            ssize_t r = readlink(link, pathbuf, sizeof(pathbuf)-1);
            if (r>0) pathbuf[r]=0;
        }
    }    

    // 위험 경로면 쓰기 차단
    if (pathbuf[0] && is_dangerous_path(pathbuf))
    {
        printf("[SAFE] Blocked fwrite to %s (len=%zu)\n", pathbuf, total);
        errno = EACCES;
	return 0;
    }

    // 안전 경로면 원본 fwrite
    return orig_fwrite(ptr, size, nmemb, stream);
}

// system : reboot 무력화
typedef int (*orig_system_t)(const char*);
static orig_system_t orig_system = NULL;

int system(const char *command) { // 가짜 system
    if (!orig_system)
    {
	orig_system = (orig_system_t)dlsym(RTLD_NEXT, "system"); // 원본 심볼 획득
    }

    if (!command) // NULL 처리
    {
	return orig_system(command);
    }

    // 재부팅 차단
    if (strstr(command, "reboot"))
    {
        printf("[SAFE] Blocked dangerous system() call: %s\n", command);
        errno = EPERM; // 권한 없음
	    return -1; // 실패 반환
    }

    // 나머지는 원본
    return orig_system(command);
}
