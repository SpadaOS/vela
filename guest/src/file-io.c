// file-io guest（0.0.2 M1 出口验收，规格 PLAN-0.0.2）：
// 静态 musl C 程序，验收 open/write/lseek/read/fstat/stat/fcntl/opendir(readdir)
// 全链路。操作固定落 /mnt/c/Windows/Temp（vela-fs 映射到 C:\Windows\Temp），
// 测试运行后由宿主侧清理产物文件。
//
// 编译（Windows）：zig cc -target x86_64-linux-musl -fPIE -pie -O2 -o guest/file-io guest/src/file-io.c
// Linux/WSL：    musl-gcc -static-pie -O2 -o guest/file-io guest/src/file-io.c
//
// 失败时向 stdout 打印 "file-io FAIL <step>" 并 exit 1；
// 全部通过打印 "file-io all ok" 并 exit 0。

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>

static const char *DIR_ = "/mnt/c/Windows/Temp";
static const char *FILE_ = "/mnt/c/Windows/Temp/vela-file-io.txt";
static const char *MSG = "file-io ok";

static void fail(const char *step) {
    write(1, "file-io FAIL ", 13);
    write(1, step, strlen(step));
    write(1, "\n", 1);
    _exit(1);
}

static void w(const char *s) {
    write(1, s, strlen(s));
}

int main(void) {
    // 1) open + write + lseek + read 回读
    int fd = open(FILE_, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) fail("open");
    if (write(fd, MSG, strlen(MSG)) != (long)strlen(MSG)) fail("write");
    if (lseek(fd, 0, SEEK_SET) != 0) fail("lseek");
    char buf[32];
    memset(buf, 0, sizeof(buf));
    if (read(fd, buf, sizeof(buf)) != (long)strlen(MSG)) fail("read");
    if (strcmp(buf, MSG) != 0) fail("mismatch");

    // 2) fstat：尺寸与类型
    struct stat st;
    if (fstat(fd, &st) != 0) fail("fstat");
    if (st.st_size != (long)strlen(MSG)) fail("fstat-size");
    if (!S_ISREG(st.st_mode)) fail("fstat-notreg");
    close(fd);

    // 3) fcntl：F_GETFL 不得失败
    int fd2 = open(FILE_, O_RDONLY);
    if (fd2 < 0) fail("reopen");
    if (fcntl(fd2, F_GETFL) < 0) fail("fcntl");
    close(fd2);

    // 4) stat 目录 + getdents64 遍历（至少能看到我们刚写的文件）
    if (stat(DIR_, &st) != 0) fail("stat-dir");
    if (!S_ISDIR(st.st_mode)) fail("notdir");
    DIR *d = opendir(DIR_);
    if (!d) fail("opendir");
    int n = 0;
    int saw_file = 0;
    struct dirent *e;
    while ((e = readdir(d)) != 0) {
        n++;
        if (strcmp(e->d_name, "vela-file-io.txt") == 0) saw_file = 1;
    }
    closedir(d);
    if (n <= 0) fail("empty");
    if (!saw_file) fail("dir-missing-file");

    // 5) getcwd 不失败
    char cwd[256];
    if (getcwd(cwd, sizeof(cwd)) == 0) fail("getcwd");

    char tail[64];
    snprintf(tail, sizeof(tail), " (%d entries, cwd %s)\n", n, cwd);
    w("file-io all ok");
    w(tail);
    _exit(0);
}
