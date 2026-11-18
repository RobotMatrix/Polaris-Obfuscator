// demo6_merge4: the demo6 Dijkstra body cut into four source functions.
//
// Purpose (S4, merge-then-split): the merge pass puts all four into one
// `__merged_function` symbol interval, and the MIR split then cuts that
// interval into chunks, so no symbol interval carries one source function any
// more.  Every function is annotated `mergefunction` and carries the
// `backend-obfu` marker, so the MIR pass sees the merged body exactly the way
// it sees demo6_mir_noeh.cpp.
//
// The algorithm and the output are demo6's: 9 lines, `i<TAB>dist[i]`, src = 0,
// same stdout sha256 as the S1 baseline.
#include <cstdio>
#include <cstdint>

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
void s4_report(uint32_t dist[V]) {
    asm("backend-obfu");
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
    uint32_t dist[V];
    bool visited[V];
    s4_init(dist, visited, 0);
    for (int count = 0; count < V - 1; count++) {
        int u = -1;
        s4_pick(dist, visited, &u);
        visited[u] = true;
        s4_relax(graph, dist, visited, u);
    }
    s4_report(dist);
    return 0;
}
