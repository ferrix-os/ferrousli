#ifndef	_DLFCN_H
#define	_DLFCN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

#define RTLD_LAZY   1
#define RTLD_NOW    2
#define RTLD_NOLOAD 4
#define RTLD_NODELETE 4096
#define RTLD_GLOBAL 256
#define RTLD_LOCAL  0

#define RTLD_NEXT    ((void *)-1)
#define RTLD_DEFAULT ((void *)0)

#define RTLD_DI_LINKMAP 2

int    dlclose(void *);
char  *dlerror(void);
void  *dlopen(const char *, int);
void  *dlsym(void *__restrict, const char *__restrict);

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
typedef struct {
	const char *dli_fname;
	void *dli_fbase;
	const char *dli_sname;
	void *dli_saddr;
} Dl_info;
int dladdr(const void *, Dl_info *);
int dlinfo(void *, int, void *);
#endif

#if defined(_GNU_SOURCE) && __SIZEOF_POINTER__ == 8
/* What an unwinder asks about the loaded object holding an address. The
 * 64-bit layout only: i386 and 32-bit Arm have a field more, and there
 * _dl_find_object answers -1. */
#define DLFO_STRUCT_HAS_EH_DBASE 0
#define DLFO_STRUCT_HAS_EH_COUNT 0
struct dl_find_object {
	unsigned long long dlfo_flags;
	void *dlfo_map_start;
	void *dlfo_map_end;
	struct link_map *dlfo_link_map;
	void *dlfo_eh_frame;
	unsigned long long __dlfo_reserved[7];
};
int _dl_find_object(void *, struct dl_find_object *);
#endif

#if _REDIR_TIME64
__REDIR(dlsym, __dlsym_time64);
#endif

#ifdef __cplusplus
}
#endif

#endif
