
/* singularly linked-list */

#ifndef OSCAM_LLIST_H_
#define OSCAM_LLIST_H_

typedef struct llnode LL_NODE;
struct llnode
{
	void *obj;
	LL_NODE *nxt;
};

typedef struct llist LLIST;
struct llist
{
	//    void *obj;
	LL_NODE *initial;
	LL_NODE *last;
	int32_t count;
	CS_MUTEX_LOCK lock;
	int32_t flag;
	uint32_t version;       // updated on every modification of the list - exception is on prepends and appends as this should not have impacts on iterations!
};

typedef struct lliter LL_ITER;
struct lliter
{
	LLIST *l;
	LL_NODE *cur, *prv;
	uint32_t ll_version;
};

typedef struct llistlockiter LL_LOCKITER;
struct llistlockiter
{
	LLIST *l;
	int32_t writelock;
	LL_ITER it;
};

LLIST *ll_create(const char *name); // create llist, return ptr to llist
void ll_destroy(LLIST *l);      // same as ll_clear_abstract() but frees up LLIST mem as well
void ll_destroy_data(LLIST *l); // same as ll_clear_data() but frees up obj allocations as well
void ll_clear(LLIST *l);        // frees up all llnodes nodes but not data held in obj ptrs
void ll_clear_data(LLIST *l);   // same as ll_clear_data() but frees up obj allocations as well

#define ll_destroy_NULL(X) {if (X) {LLIST *tmpX=X; X=NULL;ll_destroy(tmpX);}}
#define ll_destroy_data_NULL(X) {if (X) {LLIST *tmpX=X; X=NULL;ll_destroy_data(tmpX);}}

void **ll_sort(const LLIST *l, void *compare, int32_t *size); // sorts the list, compare = int func(const T *a, const T *b)
LL_NODE *ll_append(LLIST *l, void *obj);                // append obj to llist
LL_NODE *ll_prepend(LLIST *l, void *obj);               // prepend obj to llist

//clones a list, duplicates data
LLIST *ll_clone(LLIST *l, uint32_t copysize);

//New type of lock, list is locked during iterate! create=lock, destroy=unlock
LL_LOCKITER *ll_li_create(LLIST *l, int32_t writelock);
void ll_li_destroy(LL_LOCKITER *li);
void *ll_li_next(LL_LOCKITER *li);

//Old Iterators:
LL_ITER ll_iter_create(LLIST *l);               // return ptr to iterator obj
void *ll_iter_next(LL_ITER *it);                // iterate to and return next llnode obj, returns NULL at end
void *ll_iter_next_remove(LL_ITER *it);                // iterate to and return next llnode obj, returns NULL at end, removing it
void *ll_iter_peek(const LL_ITER *it, int32_t offset); // return obj at offset from iterator but do not iterate
void ll_iter_reset(LL_ITER *it);                // reset itrerator to first llnode
void ll_iter_insert(LL_ITER *it, void *obj);    // insert obj at iterator node
void *ll_iter_remove(LL_ITER *it);              // remove llnode at iterator, returns ptr to the llnode obj removed
void ll_iter_remove_data(LL_ITER *it);          // remove llnode and free llnode obj
void *ll_iter_move(LL_ITER *it, int32_t offset);// moves the iterator position
int32_t ll_iter_move_first(LL_ITER *it);        // moves an entry to top
static inline int32_t ll_count(const LLIST *l)                  // return number of items in list
{
	if(!l || l->flag)
		{ return 0; }

	return l->count;
}
void *ll_has_elements(const LLIST *l);          // returns first obj if has one
void *ll_last_element(const LLIST *l);
int32_t ll_contains(const LLIST *l, const void *obj);
const void *ll_contains_data(const LLIST *l, const void *obj, uint32_t size);
int32_t ll_remove(LLIST *l, const void *obj);
void ll_remove_data(LLIST *l, void *obj);
int32_t ll_remove_all(LLIST *l, const LLIST *elements_to_remove); // removes all elements from l where elements are in elements_to_remove

void ll_putall(LLIST *dest, LLIST *src);

void *ll_remove_first(LLIST *l);
void ll_remove_first_data(LLIST *l);

#endif
