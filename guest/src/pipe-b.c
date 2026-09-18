/* guest/src/pipe-b.c —— PLAN-0.0.5 M2 验收：管道读侧（stdin 直通）。
 * 从 stdin 逐块读取并统计字节/行数，输出统计。与 pipe-a 组成
 * `vela run guest/bin/pipe-a | vela run guest/bin/pipe-b` 端到端验收。 */
#include <unistd.h>

int main(void) {
    unsigned long bytes = 0;
    unsigned long lines = 0;
    char buf[512];
    for (;;) {
        long n = read(0, buf, sizeof buf);
        if (n < 0) {
            const char e[] = "pipe-b: stdin read failed\n";
            write(2, e, sizeof e - 1);
            return 1;
        }
        if (n == 0) break; /* EOF */
        bytes += (unsigned long)n;
        for (long i = 0; i < n; i++)
            if (buf[i] == '\n') lines++;
    }
    const char p1[] = "pipe-b ok: ";
    const char p2[] = " bytes, ";
    const char p3[] = " lines\n";
    char out[80];
    char *p = out;
    for (const char *s = p1; *s; s++) *p++ = *s;
    /* 手写无符号转十进制（musl 下用 sprintf 亦可，这里保持零依赖） */
    unsigned long v = bytes;
    char tmp[24];
    int t = 0;
    do { tmp[t++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (t) *p++ = tmp[--t];
    for (const char *s = p2; *s; s++) *p++ = *s;
    v = lines; t = 0;
    do { tmp[t++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (t) *p++ = tmp[--t];
    for (const char *s = p3; *s; s++) *p++ = *s;
    write(1, out, (size_t)(p - out));
    return 0;
}
