// demo4: 递归算法 + 多函数合并 (merge/fla/sub)
// 验证: 递归函数 + merge 混淆
#include <cstdio>

__attribute((__annotate__(("mergefunction"))))
unsigned long long fib(unsigned n) {
    if (n < 2) return n;
    return fib(n - 1) + fib(n - 2);
}

__attribute((__annotate__(("flatten,substitution"))))
unsigned long long collatz_steps(unsigned n) {
    unsigned long long steps = 0;
    while (n != 1) {
        n = (n % 2 == 0) ? n / 2 : 3 * n + 1;
        steps++;
    }
    return steps;
}

int main() {
    unsigned long long f = fib(15);
    unsigned long long c = collatz_steps(27);
    printf("fib(15)=%llu collatz(27)=%llu\n", f, c);
    return 0;
}
