#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include <bitmap.h>
#include <string.h>

/* Size of buffer cache in blocks */
#define CACHE_SIZE_B 64

/* Size of buffer cache in pages (8 pages)
   Note: PGSIZE = 4096, BLOCK_SECTOR_SIZE = 512 */
#define CACHE_SIZE_PG (BLOCK_SECTOR_SIZE * CACHE_SIZE_B) / PGSIZE

/* Number of threads in a read-ahead pool */
#define READ_AHEAD_POOL 30

/* Sleep time for write-all thread after cache infrastructure launched */
#define WRITE_ALL_SLEEP_AC 15
/* Sleep time for write-all thread before cache infrastructure launched */
#define WRITE_ALL_SLEEP_INAC 50

/* Bit map to keep track of free space in the cache */
struct bitmap *cache_map;

/* Lock guarding operations on cache map */
struct lock cache_map_lock;

/* Start address of memory allocated for buffer cache */
void *cache_base;

/* Buffer cache iterator - for writing all dirty entries */
struct hash_iterator cache_iter;

 /* Eviction buffer cache */
 struct hash ev_buffer_cache;
 /* Current value of clock hand for buffer cache eviction */
 void *bc_clock_h;
 /* Min value of clock hand for buffer cache eviction */
 void *bc_ini_clock_h;
 /* Max value of clock hand for buffer cache eviction */
 void *bc_max_clock_h;

 /* Buffer cache */
 struct hash buffer_cache;
  /* Lock guarding operations on cache */
 struct lock cache_lock;
 /* Condition for waiting on cache entries to unpin */
 struct condition pinned_cond;

 /* Read-ahead lock and condition variable */
 struct condition read_ahead_av;
 struct lock read_ahead_lock;

/* Function definitions */
unsigned
cache_hash (const struct hash_elem *p_, void *aux);
bool
cache_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux);
void
cache_destructor (struct hash_elem *ce_, void *aux UNUSED);

unsigned
ev_cache_hash (const struct hash_elem *p_, void *aux UNUSED);
bool
ev_cache_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux);

struct cache_elem *cache_lookup (block_sector_t sector);
struct cache_elem *ev_cache_lookup (void* ch_addr);
struct cache_elem *put (block_sector_t sector, bool is_readahead);
struct cache_elem *evict_and_put (block_sector_t sector, bool is_readahead);
void get (const void *ch_addr, void *buffer, size_t read_bytes);
void write_to_sector (void *ch_addr, const void *buffer, size_t write_bytes);
struct cache_elem *choose_cache_elem (void);

void write_to_disk (struct cache_elem *ce);
void read_ahead_cache (void *aux);


/* Initialize bufer cache */
void init_buffer_cache (void) {
	/* Allocate full cache */
	cache_base = palloc_get_multiple(PAL_ASSERT | PAL_ZERO, CACHE_SIZE_PG);
	/* Init bitmap to track cache usage */
    cache_map = bitmap_create(CACHE_SIZE_B);
	/* Lock to operate on cache */
	lock_init(&cache_lock);
	lock_init(&cache_map_lock);
	cond_init(&pinned_cond);
	/* Init hash table of cache contents */
	hash_init(&buffer_cache, cache_hash, cache_less, NULL);
	/* Init hash table of for eviction algo */
	hash_init(&ev_buffer_cache, ev_cache_hash, ev_cache_less, NULL);
	bc_clock_h = bc_ini_clock_h = cache_base;
	bc_max_clock_h = cache_base + (CACHE_SIZE_B-1)*BLOCK_SECTOR_SIZE;


	/* Thread that periodically writes back to disk */
	ch_teminate = false;
	ch_begin = true;

	lock_init(&read_ahead_lock);
	read_ahead_lock_ptr = &read_ahead_lock;
	cond_init(&read_ahead_av);
	read_ahead_av_ptr = &read_ahead_av;
	list_init(&read_ahead_queue);

	/* Create read-ahead thread pool */
	int i = READ_AHEAD_POOL;
	while (i != 0) {
		thread_create("read-ahead-" + i, PRI_DEFAULT, read_ahead_cache, NULL);
		i--;
	}
}


/* Looks up cache entry for the given sector_idx, if
   such entry no found in cache, adds it */
 void
 read_from_cache (block_sector_t sector_idx, void *buffer,
				  int sector_ofs, int chunk_size) {
     /* Lookup and pin cache entry - cache_lock */
	 lock_acquire(&cache_lock);
	 struct cache_elem *ce = cache_lookup (sector_idx);
	 if (ce != NULL) {
		 ce->pin_cnt++;
	 }
	 lock_release(&cache_lock);

	 /* Entry not found, create new */
	 if (ce == NULL) {
		 ce = put (sector_idx, /* is readahead */ false);
	 }

	 /* Read data to process buffer */
	 get (ce->ch_addr + sector_ofs, buffer, chunk_size);
 
	 /* Unpin cache entry - cache_lock */
	 lock_acquire(&cache_lock);
	 ce->isUsed = true;
	 /* Signal to choosing for evict threads */
	 if (--ce->pin_cnt == 0)
		cond_signal(&pinned_cond, &cache_lock);
	 lock_release(&cache_lock);
}

void read_ahead_cache (void *aux UNUSED) {
	 while (!ch_teminate) {
		 struct list_elem *e = NULL;
		 lock_acquire(&read_ahead_lock);
		 do {
			 if (!list_empty(&read_ahead_queue)) {
				e = list_pop_front(&read_ahead_queue);
			 }
			 else {
				cond_wait(&read_ahead_av, &read_ahead_lock);
			 }
		 } while (e == NULL);
		 lock_release(&read_ahead_lock);
		 struct read_ahead_entry *rae = list_entry(e, struct read_ahead_entry, elem);
		 block_sector_t sector_idx = rae->sector_idx;
		 free(rae);

		 lock_acquire(&cache_lock);
		 struct cache_elem *ce = cache_lookup(sector_idx);
		 if (ce != NULL) {

			 lock_release(&cache_lock);
			 /* Late read-ahead.. Stop */
			 continue;
		 }
		 lock_release(&cache_lock);

		 /* Not in cache */
		 ce = put (sector_idx, /* is readahead */ true);
	 }
}

 void
 write_to_cache (block_sector_t sector_idx, const void *buffer,
				  int sector_ofs, int chunk_size) {
	 /* Lookup and pin cache entry - cache_lock */
	 lock_acquire(&cache_lock);
	 struct cache_elem *ce = cache_lookup(sector_idx);
	 if (ce != NULL) {
		 ce->pin_cnt++;
	 }
	 lock_release(&cache_lock);

	 /* Entry not found - add a new one */
	 if (ce == NULL) {
		 ce = put(sector_idx, /* is readahead */ false);
	 }

     /* Write to cache entry data*/
	 write_to_sector (ce->ch_addr + sector_ofs, buffer, chunk_size);


	 /* Update cache entry */
	 lock_acquire(&cache_lock);
	 ce->isUsed = true;
	 ce->isDirty = true;
	 /* Signal to choosing for evict threads */
	 if (--ce->pin_cnt == 0)
		cond_signal(&pinned_cond, &cache_lock);
	 lock_release(&cache_lock);
}

/* Write given buffer to sector at given address from cache */
void write_to_sector (void *ch_addr, const void *buffer, size_t write_bytes)
{
	memcpy(ch_addr, buffer, write_bytes);
}

/* Put given sector into cache */
struct cache_elem *put (block_sector_t sector, bool is_readahead)
{
  /* Find and mark place in cache map - cache_map_lock*/
  lock_acquire(&cache_map_lock);
  size_t idx = bitmap_scan (cache_map, 0, 1, false);
  if (idx == BITMAP_ERROR) {
	  /* No free space - evict and put */
	  lock_release(&cache_map_lock);
	  return evict_and_put(sector, is_readahead);
  }
  bitmap_set (cache_map, idx, true);
  lock_release(&cache_map_lock);

  void *ch_addr  = cache_base + BLOCK_SECTOR_SIZE * idx;

  /* Write sector to cache */
  block_read(fs_device, sector, ch_addr);

  /* Initialize cache entry */
  struct cache_elem *ce = malloc(sizeof (struct cache_elem));
  ce->ch_addr = ch_addr;
  ce->secId = sector;
  ce->pin_cnt = 0;

  /* Add into cache contents - cache_lock*/
  lock_acquire(&cache_lock);
  struct cache_elem *ce_cache = cache_lookup(sector);
  if (ce_cache == NULL) {
	ce->pin_cnt += is_readahead ? 0 : 1;
	ce->isUsed = true;
	hash_insert(&buffer_cache, &ce->buf_hash_elem);
	hash_insert(&ev_buffer_cache, &ce->evic_buf_hash_elem);
  }
  else {
	  ce_cache->pin_cnt += is_readahead ? 0 : 1;
	  ce_cache->isUsed = true;
	  lock_acquire(&cache_map_lock);
	  bitmap_set (cache_map, idx, false);
	  lock_release(&cache_map_lock);
	  free(ce);
  }
  lock_release(&cache_lock);
  return ce_cache == NULL ? ce : ce_cache;
}

/* Put given sector into cache, after evicting other cache entry */
struct cache_elem *evict_and_put (block_sector_t sector, bool is_readahead)
{
	/* Choose entry to evict by deleting from cache - cache_lock */
	lock_acquire(&cache_lock);
	struct cache_elem *ce_evict = choose_cache_elem();
	lock_release(&cache_lock);

	/* Initialize cache entry */
	struct cache_elem *ce = malloc(sizeof (struct cache_elem));
	ce->ch_addr = ce_evict->ch_addr;
	ce->secId = sector;
	ce->pin_cnt = 0;

	/* Write sector to cache */
	block_read(fs_device, sector, ce->ch_addr);

	/* Add entry to cache */
	lock_acquire(&cache_lock);
	struct cache_elem *ce_cache = cache_lookup(sector);
	if (ce_cache == NULL) {
		ce->pin_cnt += is_readahead ? 0 : 1;
		ce->isUsed = true;
		hash_insert(&buffer_cache, &ce->buf_hash_elem);
		hash_insert(&ev_buffer_cache, &ce->evic_buf_hash_elem);
	}
	else {
		ce_cache->pin_cnt += is_readahead ? 0 : 1;
		ce_cache->isUsed = true;
		lock_acquire(&cache_map_lock);
		bitmap_set(cache_map, (ce->ch_addr -cache_base)/BLOCK_SECTOR_SIZE, false);
		lock_release(&cache_map_lock);
		free(ce);
	}
	lock_release(&cache_lock);

	free(ce_evict);
	return ce_cache == NULL ? ce : ce_cache;
}

/* Read sector at given address from cache into given buffer*/
void get (const void *ch_addr, void *buffer, size_t read_bytes)
{
	memcpy(buffer, ch_addr, read_bytes);
}

void write_to_disk (struct cache_elem *ce) {
	block_write(fs_device, ce->secId, ce->ch_addr);
}

void write_all_cache_thread (void) {
  while(true) {
	if (ch_begin) {
		lock_acquire(&cache_lock);
		if (ch_teminate) {
			lock_release(&cache_lock);
			break;
		}

		lock_release(&cache_lock);
		write_all_cache(/* Exiting */ false);
		thread_sleep(WRITE_ALL_SLEEP_AC);
	}
	else {
		thread_sleep(WRITE_ALL_SLEEP_INAC);
	}
  }
}

void write_all_cache (bool exiting) {
    lock_acquire(&cache_lock);
	ch_teminate = exiting;
	hash_first(&cache_iter, &buffer_cache);
	while (hash_next (&cache_iter)) {
		struct cache_elem *ce = hash_entry (hash_cur(&cache_iter), struct cache_elem, buf_hash_elem);
		if (ce->isDirty && (exiting || ce->pin_cnt == 0)) {
			write_to_disk(ce);
			ce->isDirty = false;
		}
	}
	lock_release(&cache_lock);
}

/* Choose entry to evict */
struct cache_elem *choose_cache_elem (void) {
	
	struct cache_elem *ce;
	struct cache_elem *ce_fst_clrd = NULL;
	struct cache_elem *ce_fst_clrd_dirty = NULL;
	
	while (ce_fst_clrd == NULL && ce_fst_clrd_dirty == NULL) {
		void *start = bc_clock_h == bc_ini_clock_h ? bc_max_clock_h : bc_clock_h - BLOCK_SECTOR_SIZE;
		while (bc_clock_h != start) {
			if (bc_clock_h >= bc_max_clock_h) {
				bc_clock_h = bc_ini_clock_h;
			}
			ce = ev_cache_lookup(bc_clock_h);
			if (ce == NULL) {
				bc_clock_h += BLOCK_SECTOR_SIZE;
				continue;
			}
			if (ce->isUsed) {
				ce->isUsed = false;
				if (ce->pin_cnt == 0) {
					if (!ce->isDirty && ce_fst_clrd == NULL) {
						ce_fst_clrd = ce;
					}
					else if (ce->isDirty && ce_fst_clrd_dirty == NULL) {
						ce_fst_clrd_dirty = ce;
					}

				}
				bc_clock_h += BLOCK_SECTOR_SIZE;
				continue;
			}
			else {
				if (ce->pin_cnt != 0) {
					bc_clock_h += BLOCK_SECTOR_SIZE;
					continue;
				}
				if (ce->isDirty) {
					/* Write from cache to filesystem */
					write_to_disk(ce);
					ce->isDirty = false;
				}
				hash_delete (&buffer_cache, &ce->buf_hash_elem);
				hash_delete (&ev_buffer_cache, &ce->evic_buf_hash_elem);
				return ce;
			}
		}
		if (ce_fst_clrd != NULL || ce_fst_clrd_dirty != NULL) continue;
		cond_wait(&pinned_cond, &cache_lock);
	}
	struct cache_elem *ce_chosen = ce_fst_clrd != NULL ? ce_fst_clrd : ce_fst_clrd_dirty;
	if (ce_chosen == ce_fst_clrd_dirty) {
		/* Write from cache to filesystem */
		write_to_disk(ce_chosen);
		ce_chosen->isDirty = false;
	}
	hash_delete (&buffer_cache, &ce_chosen->buf_hash_elem);
	hash_delete (&ev_buffer_cache, &ce_chosen->evic_buf_hash_elem);
	return ce_chosen;
}

/* Returns a hash value for sector p. */
unsigned
cache_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct cache_elem *p = hash_entry (p_, struct cache_elem, buf_hash_elem);
  return p->secId;
}

/* Returns true if sector a precedes sector b. */
bool
cache_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct cache_elem *a = hash_entry (a_, struct cache_elem, buf_hash_elem);
  const struct cache_elem *b = hash_entry (b_, struct cache_elem, buf_hash_elem);
  return a->secId < b->secId;
}

/* Returns a hash value cache entry ce indexed by cache address. */
unsigned
ev_cache_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct cache_elem *ce = hash_entry (p_, struct cache_elem, evic_buf_hash_elem);
  return (unsigned)ce->ch_addr;
}

/* Returns true if sector a precedes sector b. */
bool
ev_cache_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct cache_elem *a = hash_entry (a_, struct cache_elem, evic_buf_hash_elem);
  const struct cache_elem *b = hash_entry (b_, struct cache_elem, evic_buf_hash_elem);
  return (unsigned)a->ch_addr < (unsigned)b->ch_addr;
}

/* Returns cache enry for the given sector, or NULL if sector
   is not in cache */
struct cache_elem *cache_lookup (block_sector_t sector)
{
  struct cache_elem ce;
  struct hash_elem *e;

  ce.sector = sector;
  e = hash_find (&buffer_cache, &ce.buf_hash_elem);
  return e != NULL ? hash_entry (e, struct cache_elem, buf_hash_elem) : NULL;
}

/* Returns cache enry for the given sector, or NULL if sector
   is not in cache */
struct cache_elem *ev_cache_lookup (void* ch_addr)
{
  struct cache_elem ce;
  struct hash_elem *e;

  ce.ch_addr = ch_addr;
  e = hash_find (&ev_buffer_cache, &ce.evic_buf_hash_elem);
  return e != NULL ? hash_entry (e, struct cache_elem, evic_buf_hash_elem) : NULL;
}

/* Returns a hash value for sector p. */
void
cache_destructor (struct hash_elem *ce_, void *aux UNUSED)
{
  struct cache_elem *ce = hash_entry (ce_, struct cache_elem, buf_hash_elem);
  free(ce);
}

/* Loads inode cache entry and keeps it pinned*/
void *load_inode_metadata (block_sector_t sector_idx) {
	/* Lookup and pin cache entry - cache_lock */
	 lock_acquire(&cache_lock);
	 struct cache_elem *ce = cache_lookup (sector_idx);
	 if (ce != NULL) {
		 ce->pin_cnt++;
	 }
	 lock_release(&cache_lock);

	 /* Entry not found, create new */
	 if (ce == NULL) {
		 ce = put (sector_idx, /* is readahead */ false);
	 }
	 

	 return ce->ch_addr;
}


/* Unpins inode cache entry */
void release_inode_metadata (block_sector_t sector_idx, bool dirty) {
	 lock_acquire(&cache_lock);
	 struct cache_elem *ce = cache_lookup (sector_idx);
	 /* As it was pinned, should be always retrievable */
	 ASSERT(ce != NULL);
	 ce->isUsed = true;
	 ce->isDirty = ce->isDirty ? true : dirty;
	 /* Signal to choosing for evict threads */
	 if (--ce->pin_cnt == 0)
		cond_signal(&pinned_cond, &cache_lock);
	 lock_release(&cache_lock);
}

void set_cache_exiting (void) {
	lock_acquire(&cache_lock);
	ch_teminate = true;
	lock_release(&cache_lock);
}