#include "hashtable.h"
#include <stdlib.h>
#include <string.h>
static uint32_t ht_hash(const char *key) {
    uint32_t h = 5381;
    while (*key) h = ((h << 5) + h) ^ (uint8_t)*key++;
    return h % HT_SIZE;
}
struct Hashtable *ht_create(void) {
    return (struct Hashtable *)calloc(1, sizeof(struct Hashtable));
}
void ht_free(struct Hashtable *ht) {
    for (int i = 0; i < HT_SIZE; i++) {
        struct HTEntry *e = ht->buckets[i];
        while (e) { struct HTEntry *n = e->next; free(e->key); free(e); e = n; }
    }
    free(ht);
}
int ht_set(struct Hashtable *ht, const char *key, const uint8_t *val) {
    uint32_t idx = ht_hash(key);
    for (struct HTEntry *e = ht->buckets[idx]; e; e = e->next) {
        if (strcmp(e->key, key) == 0) { memcpy(e->value, val, 16); return 0; }
    }
    struct HTEntry *e = (struct HTEntry *)malloc(sizeof(*e));
    e->key = strdup(key);
    memcpy(e->value, val, 16);
    e->next = ht->buckets[idx];
    ht->buckets[idx] = e;
    ht->count++;
    return 1;
}
uint8_t *ht_get(struct Hashtable *ht, const char *key) {
    for (struct HTEntry *e = ht->buckets[ht_hash(key)]; e; e = e->next)
        if (strcmp(e->key, key) == 0) return e->value;
    return NULL;
}
int ht_del(struct Hashtable *ht, const char *key) {
    uint32_t idx = ht_hash(key);
    struct HTEntry *prev = NULL;
    for (struct HTEntry *e = ht->buckets[idx]; e; prev = e, e = e->next) {
        if (strcmp(e->key, key) == 0) {
            if (prev) prev->next = e->next;
            else ht->buckets[idx] = e->next;
            free(e->key); free(e);
            ht->count--;
            return 1;
        }
    }
    return 0;
}
size_t ht_count(struct Hashtable *ht) { return ht->count; }
