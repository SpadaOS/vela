/* guest/src/pipe-a.c —— PLAN-0.0.5 M2 验收：管道写侧。
 * 向 stdout 写 3 行，供 `vela run pipe-a | vela run pipe-b` 验证。 */
#include <unistd.h>

int main(void) {
    write(1, "line one\n", 9);
    write(1, "line two\n", 9);
    write(1, "line three\n", 11);
    return 0;
}
