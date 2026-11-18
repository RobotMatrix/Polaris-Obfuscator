// Timing probe for the S2 computed-branch measurement.
//
// Same shortestPath body as demo6_mir_noeh.cpp (same `backend-obfu` marker, so
// the MIR pass treats it identically), but the nine printf calls are replaced
// by a returned checksum and main calls it N times in a loop: the point is to
// compare the *dispatch* cost of the split edges, not stdio.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>

#define V 9
#define INF 0x3f3f3f3f

__attribute((__annotate__(("sub,bcf,fla"))))
uint32_t shortestPath(uint32_t graph[V][V], int src) {
    asm("backend-obfu");
    uint32_t dist[V];
    bool visited[V];
    for (int i = 0; i < V; i++) { dist[i] = INF; visited[i] = false; }
    dist[src] = 0;
    for (int count = 0; count < V - 1; count++) {
        int u = -1;
        uint32_t min = INF;
        for (int v = 0; v < V; v++)
            if (!visited[v] && dist[v] <= min) { min = dist[v]; u = v; }
        visited[u] = true;
        for (int v = 0; v < V; v++)
            if (!visited[v] && graph[u][v] && dist[u] != INF &&
                dist[u] + graph[u][v] < dist[v])
                dist[v] = dist[u] + graph[u][v];
    }
    uint32_t sum = 0;
    for (int i = 0; i < V; i++)
        sum += dist[i];
    return sum;
}

int main(int argc, char **argv) {
    uint32_t graph[V][V] = {
        {0, 4, 0, 0, 0, 0, 0, 8, 0},
        {4, 0, 8, 0, 0, 0, 0, 11, 0},
        {0, 8, 0, 7, 0, 4, 0, 0, 2},
        {0, 0, 7, 0, 9, 14, 0, 0, 0},
        {0, 0, 0, 9, 0, 10, 0, 0, 0},
        {0, 0, 4, 14, 10, 0, 2, 0, 0},
        {0, 0, 0, 0, 0, 2, 0, 1, 6},
        {8, 11, 0, 0, 0, 0, 1, 0, 7},
        {0, 0, 2, 0, 0, 0, 6, 7, 0}};
    int n = (argc > 1) ? atoi(argv[1]) : 20000;
    volatile uint32_t sink = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < n; i++)
        sink += shortestPath(graph, i % V);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ns = (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);
    // stdout: ns per call and the checksum, so a wrong answer is visible too.
    printf("%.2f %u\n", ns / n, (unsigned)sink);
    return 0;
}
