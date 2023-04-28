/* r.c (platform-specific stuff) -- esl */

#define _LARGEFILE64_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <wchar.h>
#include <assert.h>

#if defined(_MSC_VER)
#ifdef _POSIX_
#undef _POSIX_
#endif
#if (_WIN32_WINNT < 0x0500)
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0500
#endif
#include <fcntl.h>
#include <io.h>
#include <share.h> /* for _SH_DENYNO */
#include <direct.h>
#include <sys/types.h>
#include <process.h> /* for getpid */
#include <sys/stat.h> /* for _S_IREAD|_S_IWRITE */
#include <windows.h>
#if _MSC_VER >= 1600
#include <crtversion.h>
#endif
#if defined(_VC_CRT_MAJOR_VERSION) && (_VC_CRT_MAJOR_VERSION >= 14)
void __cdecl __acrt_errno_map_os_error(unsigned long const oserrno);
#define _dosmaperr(oserrno) __acrt_errno_map_os_error(oserrno)
#else
_CRTIMP void __cdecl _dosmaperr(unsigned long);
#endif
#define getcwd _getcwd
#define chdir _chdir
#define mkdir(d,m) _mkdir(d)
#define rmdir _rmdir
#define stat(a,b) _stat(a,b)
#define isatty _isatty
#define fileno _fileno
#define setbmode(fp) _setmode(_fileno(fp),_O_BINARY)
typedef struct _stat stat_t;
#define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
#define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#ifdef _DEBUG
#include <crtdbg.h>
#endif
#elif defined(__GNUC__) && defined(__APPLE__) 
#include <mach-o/dyld.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#define setbmode(fp) /* nothing */
typedef struct stat stat_t; 
#elif defined(__GNUC__) && defined(__linux)
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#define setbmode(fp) /* nothing */
#ifdef _LFS64_LARGEFILE
#define stat(a,b) stat64(a,b)
typedef struct stat64 stat_t; 
#else
typedef struct stat stat_t; 
#endif
#elif defined(__GNUC__) && (defined(_WIN32) || defined(__INTERIX))
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#define setbmode(fp) /* nothing */
#ifdef _LFS64_LARGEFILE
#define stat(a,b) stat64(a,b)
typedef struct stat64 stat_t; 
#else
typedef struct stat stat_t; 
#endif
#if defined(__INTERIX)
#include <signal.h>
#include <strings.h>
#endif
#elif defined(__SVR4) && defined(__sun)
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#define setbmode(fp) /* nothing */
#ifdef _LFS64_LARGEFILE
#define stat(a,b) stat64(a,b)
typedef struct stat64 stat_t; 
#else
typedef struct stat stat_t; 
#endif
#include <libgen.h>
#include <signal.h>
#else
#error "b.c: add your platform here" 
#endif

#include "b.h"
#include "r.h"

/* path name components */

/* returns trailing file name */
char *getfname(const char *path)
{
  char *s1, *s2, *s3, *s = (char*)path;
  s1 = strrchr(path, '\\'), s2 = strrchr(path, '/'), s3 = strrchr(path, ':');
  if (s1 && s < s1+1) s = s1+1; 
  if (s2 && s < s2+1) s = s2+1; 
  if (s3 && s < s3+1) s = s3+1;
  return s;
}

/* returns file base (up to, but not including last .) */
size_t spanfbase(const char* path)
{
  char* fn; char* pc;
  assert(path);
  fn = getfname(path); 
  if ((pc = strrchr(path, '.')) != NULL && pc >= fn)
    return pc-path;
  return strlen(path);
}

/* returns trailing file extension ("" or ".foo") */
char* getfext(const char* path)
{
  char* fn; char* pc;
  assert(path);
  fn = getfname(path); 
  if ((pc = strrchr(path, '.')) != NULL && pc >= fn)
    return (char*)pc;
  return (char*)(path+strlen(path));
}


#if defined(_MSC_VER)
static char *fixapath(const char *apath, chbuf_t *pcb)
{
  /* _wstat & friends don't like dir paths ending in slash */
  size_t len = strlen(apath);
  if (len > 1 && apath[len-2] != ':' && (apath[len-1] == '\\' || apath[len-1] == '/')) {
    return chbset(pcb, apath, len-1);
  }
  /* also, they don't like drive current dir's */
  if (len == 2 && isalpha(apath[0]) && apath[1] == ':') {
    chbsets(pcb, apath);
    chbputc('.', pcb); /* X:. is ok */
    return chbdata(pcb);
  }
  /* looks kosher */
  return (char*)apath;
}
#endif

/* simplified version of stat */
bool fsstat(const char *path, fsstat_t *ps)
{
#if defined(_MSC_VER)
  int res = -1;
  struct _stati64 s;
  DWORD r = 0xffffffff;
  chbuf_t cb = mkchb();
  assert(ps);
  path = fixapath(path, &cb);
  res = _stati64(path, &s);
  if (res < 0 && path[0] == '\\' && path[1] == '\\') r = GetFileAttributesA(path);
  chbfini(&cb);
  if (res < 0 && r != 0xffffffff && (r & FILE_ATTRIBUTE_DIRECTORY)) {
    /* //server/share - pretend it's a directory */
    ps->isreg = false;
    ps->isdir = true;
    ps->atime = ps->ctime = ps->mtime = (time_t)-1;
    ps->size = 0;
    return true;
  }
  if (res < 0) return false;
#else
  /* Un*x? assume utf-8 is native to OS */
  stat_t s;
  assert(path); assert(ps);
  if (stat(path, &s) < 0) return false;
#endif
  ps->atime = s.st_atime;
  ps->ctime = s.st_ctime;
  ps->mtime = s.st_mtime;
  ps->isreg = S_ISREG(s.st_mode);
  ps->isdir = S_ISDIR(s.st_mode);
  ps->size = (uint64_t)s.st_size;
  return true; 
}

/* Windows dirent */
#if defined(_MSC_VER)

/* Windows implementation of the directory stream type (taken from SCM).
 * The miscellaneous Unix `readdir' implementations read directory data
 * into a buffer and return `struct dirent *' pointers into it. */

#include <sys/types.h>

typedef struct dirstream {
  void* fd;           /* File descriptor.  */
  char *data;         /* Directory block.  */
  size_t allocation;  /* Space allocated for the block.  */
  size_t size;        /* Total valid data in the block.  */
  size_t offset;      /* Current offset into the block.  */
  off_t filepos;      /* Position of next entry to read.  */
  wchar_t *mask;      /* Initial file mask. */
} DIR;

struct dirent {
  off_t d_off;
  size_t d_reclen;
  char d_name[FILENAME_MAX];
};

DIR *opendir (const char *name);
struct dirent *readdir(DIR *dir);
int closedir (DIR *dir);
void rewinddir (DIR *dir);
void seekdir (DIR *dir, off_t offset);
off_t telldir (DIR *dir);

DIR *opendir(const char *name)
{
  DIR *dir;
  HANDLE hnd;
  char *file;
  WIN32_FIND_DATAW find;
  buf_t pwcv; /* to store wide chars */
  wchar_t *wfile, *ws;
  
  if (!name || !*name) return NULL;

  pwcv = mkbuf(sizeof(wchar_t));
  file = exmalloc(strlen(name) + 3);
  strcpy(file, name);
  if (file[strlen(name) - 1] != '/' && file[strlen(name) - 1] != '\\')
    strcat(file, "/*");
  else
    strcat(file, "*");
  
  { /* convert from ANSI code page multibyte */
    bufresize(&pwcv, FILENAME_MAX);
    wfile = bufdata(&pwcv);
    if (mbstowcs(wfile, file, FILENAME_MAX) == (size_t) -1)
      wfile = NULL;
  }
  
  if (wfile == NULL ||
      (hnd = FindFirstFileW(wfile, &find)) == INVALID_HANDLE_VALUE) {
    free(file);
    buffini(&pwcv);
    return NULL;
  }
  
  ws = excalloc(wcslen(wfile)+1, sizeof(wchar_t));
  wcscpy(ws, wfile);

  dir = exmalloc(sizeof(DIR));
  dir->mask = ws;
  dir->fd = hnd;
  dir->data = malloc(sizeof(WIN32_FIND_DATAW));
  dir->allocation = sizeof(WIN32_FIND_DATAW);
  dir->size = dir->allocation;
  dir->filepos = 0;
  memcpy(dir->data, &find, sizeof(WIN32_FIND_DATAW));
  free(file);
  buffini(&pwcv);
  return dir;
}

struct dirent *readdir(DIR *dir)
{
  static struct dirent entry; /* non-reentrant! */
  WIN32_FIND_DATAW *find;
  chbuf_t cb; /* to store utf-8 chars */
  char *fname;
  
  assert(dir);
  assert((HANDLE)(dir->fd) != INVALID_HANDLE_VALUE);
  find = (WIN32_FIND_DATAW *)(dir->data);

  if (dir->filepos) {
    if (!FindNextFileW((HANDLE)(dir->fd), find))
      return NULL;
  }

  cb = mkchb();
  entry.d_off = dir->filepos;
  { /* convert to ANSI code page multibyte */
    fname = chballoc(&cb, sizeof(entry.d_name));
    if (wcstombs(fname, find->cFileName, sizeof(entry.d_name)) == (size_t)-1)
      fname = NULL;
  }
  if (fname == NULL) {
    chbfini(&cb);
    return NULL;
  }
  entry.d_reclen = strlen(fname);
  if (entry.d_reclen+1 > sizeof(entry.d_name)) {
    chbfini(&cb);
    return NULL;
  }
  strncpy(entry.d_name, fname, sizeof(entry.d_name));
  dir->filepos++;
  
  chbfini(&cb);
  return &entry;
}

int closedir(DIR *dir)
{
  HANDLE hnd = (HANDLE)(dir->fd);
  free(dir->data);
  free(dir->mask);
  free(dir);
  return FindClose(hnd) ? 0 : -1;
}

void rewinddir(DIR *dir)
{
  HANDLE hnd = (HANDLE)(dir->fd);
  WIN32_FIND_DATAW *find = (WIN32_FIND_DATAW *)(dir->data);
  FindClose(hnd);
  hnd = FindFirstFileW(dir->mask, find);
  dir->fd = hnd;
  dir->filepos = 0;
}

void seekdir(DIR *dir, off_t offset)
{
  off_t n;
  rewinddir(dir);
  for (n = 0; n < offset; n++) {
    if (FindNextFileW((HANDLE)(dir->fd), (WIN32_FIND_DATAW *)(dir->data)))
       dir->filepos++;
  }
}

off_t telldir(DIR *dir)
{
  return dir->filepos;
}

#endif /* Windows dirent */

/* list full dir content as file/dir names */
bool dir(const char *dirpath, dsbuf_t *pdsv)
{
   DIR *pdir;
   struct dirent *pde;
   assert(pdsv);
   assert(dirpath);
   dsbclear(pdsv);
   /* NB: dirent is not reentrant! */
   pdir = opendir(dirpath);
   if (!pdir) return false;
   while ((pde = readdir(pdir)) != NULL) {
     char *name = pde->d_name;
     dsbpushbk(pdsv, &name);
   }
   closedir(pdir);
   return true;
}

/* opens new tmp file in w+b; it is deleted when file closed or program exits/crashes */
/* mode should be "w+b" or "w+t" (makes difference on Windows) */
FILE *etmpopen(const char *mode)
{
  FILE *fp = NULL;
#if defined(_MSC_VER) 
  /* standard tmpnam is no good; use ours */
  char *fname, fnbuf[100];
  int c = 'a';
  int pid = _getpid(); 
  int fd = -1;
  bool text = false;
  assert(mode);
  if (mode && strchr(mode, 't')) text = true;
  for (;;) {
    sprintf(fnbuf, "cutmp_%c%d", c, pid); 
    fname = _tempnam(NULL, fnbuf);
    if (!fname) break;
    fd = _sopen(fname,
            _O_CREAT|_O_EXCL|_O_RDWR|
            (text ? _O_TEXT : _O_BINARY)|
            _O_TEMPORARY|_O_SHORT_LIVED,
            _SH_DENYNO,
            _S_IREAD|_S_IWRITE);
    if (fd != -1) break;
    if (errno != EEXIST) break;
    if (c >= 'z') break; 
    ++c;
  }
  /* shouldn't have problems opening good fd if got enough FILEs */
  if (fd != -1) fp = _fdopen(fd, mode ? mode : "w+b");
#else
  /* linuxes tmpfile fits the bill; let's use it */
  assert(mode); /* required but ignored: makes no difference here */
  fp = tmpfile();
#endif  
  if (!fp) exprintf("out of temp files");
  return fp;
}

/* sets stdin/stdout into binary mode (no-op on Unix) */
void fbinary(FILE *stdfile)
{
  setbmode(stdfile);
}

/* check that file is a tty */
bool fisatty(FILE *fp)
{
  assert(fp);
  return isatty(fileno(fp)); 
}

#if defined(_MSC_VER) && (_MSC_VER >= 1400)
#define fseeki64 _fseeki64
#define ftelli64 _ftelli64
#elif !defined(__64BIT__) && (PLATFORM_POSIX_VERSION >= 200112L)
#define fseeki64 fseeko
#define ftelli64 fseeko
#elif defined(__MINGW32__) && defined(__MSVCRT__) && !defined(__STRICT_ANSI__) && !defined(__NO_MINGW_LFS)
#define fseeki64 fseeko64
#define ftelli64 fseeko64
#else
#define fseeki64 fseek
#define ftelli64 ftell
#endif

int fseekll(FILE *fp, long long off, int org)
{
  return fseeki64(fp, off, org);
}

long long ftellll(FILE *fp)
{
  return ftelli64(fp);
}
