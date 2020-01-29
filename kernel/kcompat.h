#ifndef _KCOMPAT_H
#define _KCOMPAT_H

#undef hlist_entry
#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#undef hlist_entry_safe
#define hlist_entry_safe(ptr, type, member) \
	(ptr) ? hlist_entry(ptr, type, member) : NULL

#undef hlist_for_each_entry
#define hlist_for_each_entry(pos, head, member)                             \
	for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member); \
	     pos;                                                           \
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

#undef hlist_for_each_entry_safe
#define hlist_for_each_entry_safe(pos, n, head, member) 		    \
	for (pos = hlist_entry_safe((head)->first, typeof(*pos), member);   \
	     pos && ({ n = pos->member.next; 1; });			    \
	     pos = hlist_entry_safe(n, typeof(*pos), member))

#endif
