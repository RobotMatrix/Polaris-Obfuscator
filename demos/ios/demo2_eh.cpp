// demo2: 异常处理 + STL 容器 (invoke/EH 场景, 不开 MIR)
// 验证: EH + fla/bcf 在 iOS 目标上的正确性
#include <cstdio>
#include <stdexcept>
#include <vector>

__attribute((__annotate__(("flatten,boguscfg"))))
int risky(int op) {
    std::vector<int> v;
    v.push_back(10);
    v.push_back(20);
    if (op == 0) throw std::runtime_error("zero-op");
    int acc = 0;
    for (int x : v) acc += x * op;
    if (acc > 100) throw std::out_of_range("overflow");
    return acc;
}

int main() {
    int a = 0, b = 0;
    try { a = risky(3); } catch (const std::exception &e) { a = -1; }
    try { b = risky(0); } catch (const std::exception &e) { b = -2; }
    printf("risky(3)=%d risky(0)=%d\n", a, b);
    return 0;
}
