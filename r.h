/* r.h (platform stuff) -- esl */

#pragma once

extern int dirsep; /* '/' on Un*x, '\\' on Windows */
/* dirpath manipulations (dirpath is "", "/", ".../dir", ".../dir/") */
extern bool hasdpar(const char* pname); /* ends in "dir/" or "dir" */
/* for dirpath answering true to hasdpar, spandpar and getdname are defined */
extern size_t spandpar(const char* pname); /* all up to last "dir/" or "dir" */
extern char *getdname(const char* pname); /* last "dir/" or "dir" */
/* file pathname manipulations */
extern size_t spanfdir(const char* pname); /* spans "", "/", ".../foo/" */
extern char *getfname(const char* pname); /* all after last / or : */
extern size_t spanfbase(const char* pname); /* all before last . */
extern char *getfext(const char* pname); /* trailing "" or ".foo" */
/* parse path as <root> <relpath> */
extern bool pathparse2(const char *path, size_t *proot, size_t *prelpath);
/* trim optional separator at the end of pname */
extern char *trimdirsep(char *pname);
/* add dir separator to the end of pcb */
extern void chbputdirsep(chbuf_t *pcb);

/* portable version of filesystem stat */
typedef struct fsstat_tag {
  bool isreg, isdir;
  time_t atime, ctime, mtime;
  uint64_t size;
} fsstat_t;
/* retrieve status of a file system object; return false on error */
extern bool fsstat(const char *path, fsstat_t *ps);
/* check that path points to existing file */
extern bool fexists(const char *path);
/* check that path points to existing dir */
extern bool direxists(const char *path);

/* list full dir content as file/dir names */
extern bool dir(const char *dirpath, dsbuf_t *pdsv);
/* create new last dir on the path, bail out on errors */
extern void emkdir(const char *dir);
/* remove empty last dir on the path, bail out on errors */
extern void ermdir(const char *dir);
/* creates final dirs on the path as needed */
extern void emkdirp(const char *path);
/* opens new tmp file in w+b; it is deleted when file closed or program exits/crashes */
extern FILE *etmpopen(const char *mode);

/* sets stdin/stdout into binary mode (no-op on Unix) */
extern void fbinary(FILE *stdfile);
/* check that file is a tty */
extern bool fisatty(FILE *fp);

/* long long file positioning */
extern int fseekll(FILE *fp, long long off, int org);
extern long long ftellll(FILE *fp);

/* set utf-8 code page */
extern void setu8cp(void);
