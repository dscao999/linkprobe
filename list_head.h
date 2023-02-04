#ifndef LIST_HEAD_DSCAO__ 
#define LIST_HEAD_DSCAO__

#ifndef offsetof
#define offsetof(type, member)  __builtin_offsetof(type, member)
#endif
#define container_of(ptr, type, member) \
	({ \
	 const typeof(((type *)0)->member) *__mptr = (ptr); \
	 (type *)((char *)__mptr - offsetof(type, member)); \
	 })
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)
#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)
#define list_for_each_entry(pos, head, member) \
	for (pos = list_entry((head)->next, typeof(*pos), member); \
		&pos->member != (head); \
		pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_safe(pos, n, head) \
	    for (pos = (head)->next, n = pos->next; pos != (head); \
			            pos = n, n = n->next)
#define list_for_each_entry_safe(pos, n, head, member) \
	for (pos = list_entry((head)->next, typeof(*pos), member), \
		n = list_entry(pos->member.next, typeof(*pos), member); \
		&pos->member != (head); \
		pos = n, n = list_entry(n->member.next, typeof(*pos), member))

struct list_head;
struct list_head {
	struct list_head *prev, *next;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

static inline void INIT_LIST_HEAD(struct list_head *lst)
{
	lst->next = lst;
	lst->prev = lst;
}

static inline int list_empty(const struct list_head *node)
{
	return (node->prev == node && node->next == node);
}

static inline void list_add(struct list_head *node, struct list_head *head)
{
	struct list_head *naf = head->prev;

	node->prev = naf;
	node->next = naf->next;
	node->next->prev = node;
	naf->next = node;
}

static inline void list_del(struct list_head *node, struct list_head *head)
{
	struct list_head *prev, *next;

	if (node == head)
		return;
	prev = node->prev;
	next = node->next;
	prev->next = next;
	next->prev = prev;
}
#endif  /* LIST_HEAD_DSCAO__ */
