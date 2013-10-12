#ifndef ziplibb_h
#define ziplib_h

int compress(const char *src, const char *dst, double *ratio);
int expand(const char *src, const char *dst);

#endif
