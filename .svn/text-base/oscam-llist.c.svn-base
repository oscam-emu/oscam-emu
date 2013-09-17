
/* singularly linked-list */

#include "globals.h"
#include "oscam-garbage.h"
#include "oscam-lock.h"
#include "oscam-string.h"

extern char *LOG_LIST;

/*
  Locking rules:

  mutex lock is needed when...
  1. l->initial + l->last is modified/accessed
  2. LL_NODE nxt modified/accessed


*/

#ifdef WITH_DEBUG
static int8_t chk_debuglog(LLIST *l)
{
	return (l && l->lock.name != LOG_LIST);
}
#endif

static void _destroy(LLIST *l)
{
	if (!l) return;
	if (!l->flag++) {
	        cs_writelock(&l->lock); //just getting sure noone is using it
	        cs_writeunlock(&l->lock);
	        
		cs_lock_destroy(&l->lock);
		add_garbage(l);
	}
}

LLIST *ll_create(const char *name)
{
    LLIST *l;
    if (!cs_malloc(&l, sizeof(LLIST)))
        return NULL;
    cs_lock_create(&l->lock, 5, name);
    return l;
}

void ll_destroy(LLIST *l)
{
    if (!l || l->flag) return;
    ll_clear(l);

    _destroy(l);
}

void ll_destroy_data(LLIST *l)
{
    if (!l) return;
    ll_clear_data(l);

    _destroy(l);
}

/* Internal iteration function. Make sure that you don't have a lock and that it and it->l are set. */
static void *ll_iter_next_nolock(LL_ITER *it)
{
	if (it->l->version != it->ll_version) {
#ifdef WITH_DEBUG
		if (chk_debuglog(it->l))
			cs_debug_mask_nolock(D_TRACE, "list changed, searching new position");
#endif

		LL_NODE *ptr;
		//cs_readlock(&it->l->lock);
		if (!it->cur && !it->prv) {
			it->cur = it->l->initial;
		} else {
			for (ptr = it->l->initial; ptr; ptr = ptr->nxt) {
				if (ptr == it->cur) {
					it->prv = ptr;
					it->cur = ptr->nxt;
					break;
				}
			}
			if (!ptr) {
				ll_iter_reset(it); // restart iteration
				it->cur = it->l->initial;
			}
		}
		it->ll_version = it->l->version;
		//cs_readunlock(&it->l->lock);

		if (it->cur)
			return it->cur->obj;

	} else {
		if (it->cur) {
			it->prv = it->cur;
			it->cur = it->cur->nxt;
		} else if (it->l->initial && !it->prv)
			it->cur = it->l->initial;

		if (it->cur)
			return it->cur->obj;
	}
	return NULL;
}

static void ll_clear_int(LLIST *l, int32_t clear_data)
{
    if (!l||l->flag) return;

    cs_writelock(&l->lock);

    LL_NODE *n=l->initial, *nxt;
    while (n) {
    	nxt = n->nxt;
    		if (clear_data)
    			add_garbage(n->obj);
    		add_garbage(n);
		n = nxt;
    }
    l->version++;
    l->count = 0;
    l->initial = 0;
    l->last = 0;
    cs_writeunlock(&l->lock);
}

void ll_clear(LLIST *l)
{
	ll_clear_int(l, 0);
}


void ll_clear_data(LLIST *l)
{
	ll_clear_int(l, 1);
}

/* Appends to the list. Do not call this from outside without having a lock! */
static LL_NODE* ll_append_nolock(LLIST *l, void *obj)
{
    if (l && obj && !l->flag) {
        LL_NODE *new;
        if (!cs_malloc(&new, sizeof(LL_NODE)))
            return NULL;
        new->obj = obj;

        if (l->last)
            l->last->nxt = new;
        else
            l->initial = new;
		l->last = new;

        l->count++;
        return new;
    }

    return NULL;
}

LL_NODE* ll_append(LLIST *l, void *obj)
{
    if (l && obj && !l->flag) {
        cs_writelock(&l->lock);

        LL_NODE *n = ll_append_nolock(l, obj);
        cs_writeunlock(&l->lock);
        return n;
    }
    return NULL;
}

LL_NODE *ll_prepend(LLIST *l, void *obj)
{
    if (l && obj && !l->flag) {
        LL_NODE *new;
        if (!cs_malloc(&new, sizeof(LL_NODE)))
            return NULL;
        new->obj = obj;

        cs_writelock(&l->lock);

        new->nxt = l->initial;

        l->initial = new;
        if (!l->last)
        	l->last = l->initial;
        l->count++;
        cs_writeunlock(&l->lock);

        return new;
    }

    return NULL;
}

LL_ITER ll_iter_create(LLIST *l)
{
	LL_ITER it;
	memset(&it, 0, sizeof(it));
	it.l = l;
	if (it.l)
		it.ll_version = it.l->version;
	return it;
}


void *ll_iter_next(LL_ITER *it)
{
	if (it && it->l && !it->l->flag) {
		cs_readlock(&it->l->lock);
		void *res = ll_iter_next_nolock(it);
		cs_readunlock(&it->l->lock);
		return res;
	}
	return NULL;
}

void *ll_iter_remove_nolock(LL_ITER *it)
{
	void *obj = NULL;
	if (it) {
		LL_NODE *del = it->cur;
		if (del) {
			obj = del->obj;
			LL_NODE *prv = it->prv;
			if (it->ll_version != it->l->version || !prv) { // List has been modified so it->prv might be wrong!
				LL_NODE *n = it->l->initial;
				prv = NULL;
				while (n && n != del) {
					prv = n;
					n = n->nxt;
				}
				if (n != del)
					return NULL;
			}

			if (prv)
				prv->nxt = del->nxt;
			else
				it->l->initial = del->nxt;
			if (!it->l->initial)
				it->l->last = NULL;
			else if (del == it->l->last)
				it->l->last = prv;

			it->cur = it->l->initial;
			it->prv = NULL;
			if (prv != NULL) {
				while (it->cur && it->cur != prv) {
					it->prv = it->cur;
					it->cur = it->cur->nxt;
				}
			} else
				it->cur = NULL;
			it->l->count--;
			it->ll_version = ++it->l->version;

			add_garbage(del);
		}
	}
	return obj;
}

void *ll_iter_next_remove(LL_ITER *it)
{
	if (it && it->l && !it->l->flag) {
		cs_writelock(&it->l->lock);
		void *res = ll_iter_next_nolock(it);
		ll_iter_remove_nolock(it);
		cs_writeunlock(&it->l->lock);
		return res;
	}
	return NULL;
}

void *ll_iter_move(LL_ITER *it, int32_t offset)
{
	if (it && it->l && !it->l->flag) {
		int32_t i;
		void *res = NULL;
		for (i=0; i<offset; i++) {
			res = ll_iter_next_nolock(it);
			if (!res) break;
		}

		return res;
	}
	return NULL;
}

void *ll_iter_peek(const LL_ITER *it, int32_t offset)
{
	if (it && it->l && !it->l->flag) {
		cs_readlock(&((LL_ITER*)it)->l->lock);

		LL_NODE *n = it->cur;
		int32_t i;

		for (i = 0; i < offset; i++) {
			if (n)
				n = n->nxt;
			else
				break;
		}
		cs_readunlock(&((LL_ITER*)it)->l->lock);

		if (!n)
			return NULL;
		return n->obj;
	}
	return NULL;
}

void ll_iter_reset(LL_ITER *it)
{
    if (it) {
        it->prv = NULL;
        it->cur = NULL;
    }
}

void ll_iter_insert(LL_ITER *it, void *obj)
{
    if (it && obj && !it->l->flag) {
	cs_writelock(&it->l->lock);

        if (!it->cur || !it->cur->nxt)
            ll_append_nolock(it->l, obj);
        else {
            LL_NODE *n;
            if (!cs_malloc(&n, sizeof(LL_NODE))) {
                cs_writeunlock(&it->l->lock);
                return;
            }

            n->obj = obj;
            n->nxt = it->cur->nxt;
            it->cur->nxt = n;

            it->l->count++;
            it->ll_version = ++it->l->version;
        }
        cs_writeunlock(&it->l->lock);
    }
}

/* Removes the element to which the iterator currently points. */
void *ll_iter_remove(LL_ITER *it)
{
	void *obj = NULL;
	if (it && it->l && !it->l->flag) {
		LL_NODE *del = it->cur;
		if (del) {
			cs_writelock(&it->l->lock);
			obj = ll_iter_remove_nolock(it);
			cs_writeunlock(&it->l->lock);
		}
	}

	return obj;
}

/* Moves the element which is currently pointed to by the iterator to the head of the list.*/
int32_t ll_iter_move_first(LL_ITER *it)
{
	int32_t moved = 0;
	if (it && it->l && !it->l->flag) {
		LL_NODE *move = it->cur;
		if (move) {
		        if (move == it->l->initial) //Can't move self to first
		                return 1;
		                
			LL_NODE *prv = it->prv;
			cs_writelock(&it->l->lock);
			if(it->ll_version != it->l->version || !prv){		// List has been modified so it->prv might be wrong!
				LL_NODE *n = it->l->initial;
				prv = NULL;
				while(n && n != move){
					prv = n;
					n = n->nxt;
				}
				if(n != move) {
					cs_writeunlock(&it->l->lock);
					return moved;
				}
			}

			if (prv)
				prv->nxt = move->nxt;
			else
				it->l->initial = move->nxt;

			if (prv && it->l->last == move)
				it->l->last = prv;
			move->nxt = it->l->initial;
			it->l->initial = move;

			it->ll_version = ++it->l->version;
			it->prv = NULL;
			cs_writeunlock(&it->l->lock);
			moved = 1;
		}
	}
	return moved;
}

void ll_iter_remove_data(LL_ITER *it)
{
    void *obj = ll_iter_remove(it);
    add_garbage(obj);
}

void *ll_has_elements(const LLIST *l) {
  if (!l || !l->initial || l->flag)
    return NULL;
  return l->initial->obj;
}

void *ll_last_element(const LLIST *l) {
  if (!l || !l->last || l->flag)
    return NULL;
  return l->last->obj;
}

int32_t ll_contains(const LLIST *l, const void *obj)
{
    if (!l || !obj || l->flag)
      return 0;
    LL_ITER it = ll_iter_create((LLIST *) l);
    const void *data;
    while ((data=ll_iter_next(&it))) {
      if (data==obj)
        break;
    }
    return (data==obj);
}

const void *ll_contains_data(const LLIST *l, const void *obj, uint32_t size) {
    if (!l || !obj || l->flag)
      return NULL;
    LL_ITER it = ll_iter_create((LLIST*) l);
    const void *data;
    while ((data=ll_iter_next(&it))) {
      if (!memcmp(data,obj,size))
        break;
    }
    return data;
}

int32_t ll_remove(LLIST *l, const void *obj)
{
    int32_t n = 0;
    LL_ITER it = ll_iter_create(l);
    void *data;
    while ((data=ll_iter_next(&it))) {
      	if (data==obj) {
        	ll_iter_remove(&it);
        	n++;
        }
    }
    return n;
}

void ll_remove_data(LLIST *l, void *obj)
{
    LL_ITER it = ll_iter_create(l);
    void *data;
    while ((data=ll_iter_next(&it))) {
      if (data==obj)
        ll_iter_remove_data(&it);
    }
}

// removes all elements from l where elements are in elements_to_remove
int32_t ll_remove_all(LLIST *l, const LLIST *elements_to_remove)
{
		int32_t count = 0;
		LL_ITER it1 = ll_iter_create(l);
		LL_ITER it2 = ll_iter_create((LLIST*) elements_to_remove);

		const void *data1, *data2;
		while ((data1=ll_iter_next(&it1))) {
				ll_iter_reset(&it2);
				while ((data2=ll_iter_next(&it2))) {
						if (data1 == data2) {
								ll_iter_remove(&it1);
								count++;
								break;
						}
				}
		}

		return count;
}

/* Returns an array with all elements sorted, the amount of elements is stored in size. We do not sort the original linked list
   as this might harm running iterations. Furthermore, we need the array anyway for qsort() to work. Remember to free() the result. */
void **ll_sort(const LLIST *l, void *compare, int32_t *size)
{
	if (!l || !l->initial || !compare){
		*size = 0;
		return NULL;
	}
	int32_t i=0;
	LL_NODE *n;

	cs_readlock(&((LLIST*)l)->lock);
	*size = l->count;
	void **p;
	if (!cs_malloc(&p, l->count * sizeof(p[0]))) {
		cs_readunlock(&((LLIST*)l)->lock);
		return NULL;
	}
	for (n = l->initial; n; n = n->nxt) {
		p[i++] = n->obj;
	}
	cs_readunlock(&((LLIST*)l)->lock);
#ifdef WITH_DEBUG
	//	if (chk_debugLog(it->l))
	//cs_debug_mask(D_TRACE, "sort: count %d size %d", l->count, sizeof(p[0]));
#endif
	qsort(p, l->count, sizeof(p[0]), compare);

	return p;
}

void ll_putall(LLIST *dest, LLIST *src)
{
	LL_ITER it = ll_iter_create(src);
	void *data;
	while ((data=ll_iter_next(&it))) {
		ll_append(dest, data);
	}
}

//New Iterator:
LL_LOCKITER *ll_li_create(LLIST *l, int32_t writelock)
{
        if (!l||l->flag) return NULL;
        
        LL_LOCKITER *li;
        if (!cs_malloc(&li, sizeof(LL_LOCKITER)))
                return NULL;

        li->l = l;
        li->writelock = writelock;
        if (writelock)
                cs_writelock(&l->lock);
        else
                cs_readlock(&l->lock);
        li->it = ll_iter_create(l);
        return li;
}

void ll_li_destroy(LL_LOCKITER *li)
{
        if (li && li->l) {
                if (li->writelock)
                        cs_writeunlock(&li->l->lock);
                else
                        cs_readunlock(&li->l->lock);
                li->l = NULL;
                add_garbage(li);
        }
}

void *ll_li_next(LL_LOCKITER *li)
{
        if (li && li->l) {
                return ll_iter_next_nolock(&li->it);
        }
        return NULL;
}

LLIST *ll_clone(LLIST *l, uint32_t copysize)
{
        if (!l||l->flag) return NULL;

        LLIST *cloned = ll_create(l->lock.name);
        LL_LOCKITER *li = ll_li_create(l, 0);
        void *data;
        while ((data=ll_li_next(li))) {
                void *new_data;
                if (!cs_malloc(&new_data, copysize))
                        break;
                memcpy(new_data, data, copysize);
                ll_append_nolock(cloned, new_data);
        }
        ll_li_destroy(li);
        return cloned;
}

void *ll_remove_first(LLIST *l) {
        if (l && !l->flag) {
                LL_ITER it = ll_iter_create(l);
                void *data = ll_iter_next(&it);
                if (data) ll_iter_remove(&it);
                return data;
        }
        return NULL;
}

void ll_remove_first_data(LLIST *l) {
        void *data = ll_remove_first(l);
        if (data) free(data);
}
