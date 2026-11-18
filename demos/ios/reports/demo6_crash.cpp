// Crash probe for the S1/S3 verdicts: demo6 with one line added inside
// shortestPath, so a crash lands in a *split chunk* rather than in main.
// Built and linked exactly like demos/ios/demo6_mir_noeh.cpp (same flags), then
// run with CRASH=1; the faulting thread of the resulting .ips is what
// SPLIT-SYMBOLS-AB.md reports. Nothing here is part of a shipped artifact.
#include <cstdio>
#include <cstdint>
#include <cstdlib>

#define V 9
#define INF 0x3f3f3f3f

__attribute((__annotate__(("sub,bcf,fla"))))
void shortestPath(uint32_t graph[V][V], int src) {
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
    if (getenv("CRASH")) *(volatile int *)0 = 1;   // <- the probe
    for (int i = 0; i < V; i++)
        printf("%d\t%u\n", i, dist[i]);
}

int main() {
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
    shortestPath(graph, 0);
    return 0;
}
