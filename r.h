/* r.h (platform-specific stuff) -- esl */

#pragma once

/* path name components */
/* returns trailing file name */
extern char *getfname(const char *path);
/* returns file base (up to, but not including last .) */
extern size_t spanfbase(const char* path);
/* returns trailing file extension ("" or ".foo") */
extern char* getfext(const char* path);

/* portable version of filesystem stat */
typedef struct fsstat_tag {
  bool isreg, isdir;
  time_t atime, ctime, mtime;
  uint64_t size;
} fsstat_t;
/* retrieve status of a file system object; return false on error */
extern bool fsstat(const char *path, fsstat_t *ps);

/* list full dir content as file/dir names */
extern bool dir(const char *dirpath, dsbuf_t *pdsv);
/* opens new tmp file in w+b; it is deleted when file closed or program exits/crashes */
extern FILE *etmpopen(const char *mode);
/* sets stdin/stdout into binary mode (no-op on Unix) */
extern void fbinary(FILE *stdfile);
/* check that file is a tty */
extern bool fisatty(FILE *fp);
/* long long file positioning */
extern int fseekll(FILE *fp, long long off, int org);
extern long long ftellll(FILE *fp);
