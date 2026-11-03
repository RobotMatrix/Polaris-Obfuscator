#ifndef HASHTABLE_H
#define HASHTABLE_H
#include <stdint.h>
#include <stddef.h>
#define HT_SIZE 64
struct HTEntry { char *key; uint8_t value[16]; struct HTEntry *next; };
struct Hashtable { struct HTEntry *buckets[HT_SIZE]; size_t count; };
struct Hashtable *ht_create(void);
void ht_free(struct Hashtable *ht);
int ht_set(struct Hashtable *ht, const char *key, const uint8_t *val);
uint8_t *ht_get(struct Hashtable *ht, const char *key);
int ht_del(struct Hashtable *ht, const char *key);
size_t ht_count(struct Hashtable *ht);
#endif
