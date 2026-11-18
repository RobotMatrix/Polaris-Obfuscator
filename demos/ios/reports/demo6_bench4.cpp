// Timing probe for the S4 measurement.
//
// Same four-source-function Dijkstra as demos/ios/demo6_merge4.cpp (same
// `mergefunction` annotation, same `backend-obfu` markers), with the nine
// printf calls replaced by a checksum and main calling the pipeline N times in
// a loop: the point is the cost of the merged dispatch plus the split's
// per-chunk reload sequences, not stdio.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>

#define V 9
#define INF 0x3f3f3f3f

__attribute((__annotate__(("mergefunction"))))
void s4_init(uint32_t dist[V], bool visited[V], int src) {
    asm("backend-obfu");
    for (int i = 0; i < V; i++) { dist[i] = INF; visited[i] = false; }
    dist[src] = 0;
}

__attribute((__annotate__(("mergefunction"))))
void s4_pick(uint32_t dist[V], bool visited[V], int *uout) {
    asm("backend-obfu");
    int u = -1;
    uint32_t min = INF;
    for (int v = 0; v < V; v++)
        if (!visited[v] && dist[v] <= min) { min = dist[v]; u = v; }
    *uout = u;
}

__attribute((__annotate__(("mergefunction"))))
void s4_relax(uint32_t graph[V][V], uint32_t dist[V], bool visited[V], int u) {
    asm("backend-obfu");
    for (int v = 0; v < V; v++)
        if (!visited[v] && graph[u][v] && dist[u] != INF &&
            dist[u] + graph[u][v] < dist[v])
            dist[v] = dist[u] + graph[u][v];
}

__attribute((__annotate__(("mergefunction"))))
uint32_t s4_sum(uint32_t dist[V]) {
    asm("backend-obfu");
    uint32_t s = 0;
    for (int i = 0; i < V; i++)
        s += dist[i];
    return s;
}

static uint32_t run(uint32_t graph[V][V], int src) {
    uint32_t dist[V];
    bool visited[V];
    s4_init(dist, visited, src);
    for (int count = 0; count < V - 1; count++) {
        int u = -1;
        s4_pick(dist, visited, &u);
        visited[u] = true;
        s4_relax(graph, dist, visited, u);
    }
    return s4_sum(dist);
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
        sink += run(graph, i % V);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ns = (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);
    printf("%.2f %u\n", ns / n, (unsigned)sink);
    return 0;
}
