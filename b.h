/* b.h (base) -- esl */

#pragma once

#define STR_az "abcdefghijklmnopqrstuvwxyz"
#define STR_AZ "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define STR_09 "0123456789"

/* argument parsing and usage */
extern  void  setprogname(const char *s);
extern  const char *progname(void);
extern  void  setusage(const char *s);
extern  const char *usage(void);
extern  void  eusage(const char *fmt, ...);
extern  const char *cutillit(void);
/* warning levels */
extern  void  setwlevel(int l);
extern  int   getwlevel(void);
/* logging */
extern  void  setquietness(int q);
extern  int   getquietness(void);
extern  void  incquietness(void);
extern  void  logenf(int n, const char *fmt, ...);
extern  void  logef(const char *fmt, ...);
extern  void  llogef(const char *fmt, ...);
extern  void  lllogef(const char *fmt, ...);
/* verbosity (debug-style logging) */
extern  void  setverbosity(int n);
extern  int   getverbosity(void);
extern  void  incverbosity(void);
extern  void  verbosenf(int n, const char *fmt, ...);
extern  void  verbosef(const char *fmt, ...);
extern  void  vverbosef(const char *fmt, ...);
extern  void  vvverbosef(const char *fmt, ...);
/* AT&T-like option parser */
extern  int   eoptind, eopterr, eoptopt, eoptich;
extern  char  *eoptarg;
extern  int   egetopt(int argc, char* argv[], const char* opts);
extern  void  eoptreset(void); /* reset getopt globals */

/* common utility functions */
extern void eprintf(const char *fmt, ...);
extern void *emalloc(size_t n);
extern void *ecalloc(size_t n, size_t s);
extern void *erealloc(void *m, size_t n);
extern char *estrdup(const char *s);
extern char *estrndup(const char* s, size_t n);
extern char *ememdup(const char* s, size_t n);
extern char *strtrc(char *str, int c, int toc);
extern char *strprf(const char *str, const char *prefix);
extern char *strsuf(const char *str, const char *suffix);
extern bool streql(const char *s1, const char *s2);
extern bool strieql(const char *s1, const char *s2);
extern size_t strcnt(const char *s, int c); /* count c in s */
extern char *strtriml(const char *s); /* skips leading ws */
extern char *strtrimr(char *s); /* zeroes out trailing ws */
extern char *strtrim(char *s); /* strtrimr, then strtriml */
extern char *strnorm(char *s); /* normalize ws to single ' ', trim */
extern void memswap(void *mem1, void *mem2, size_t sz);
extern unsigned char *utf8(unsigned long c, unsigned char *s);
extern unsigned long unutf8(unsigned char **ps);
extern unsigned long strtou8c(const char *s, char **ep);
extern unsigned long strtocc32(const char *s, char **ep, bool *rp);
extern unsigned long strtou8cc32(const char *s, char **ep, bool *rp);
extern bool fget8bom(FILE *fp);
#define is8cbyte(c) (((c) & 0x80) != 0)
#define is8chead(c) (((c) & 0xC0) == 0xC0)
#define is8ctail(c) (((c) & 0xC0) == 0x80)
extern int int_cmp(const void *pi1, const void *pi2);

/* simple shell-style pattern matcher (cf. fnmatch) */
bool gmatch(const char *src, const char *pat);

/* floating-point reinterpret casts and exact hex i/o */
extern unsigned long long as_uint64(double f); /* NB: asuint64 is WCPL intrinsic */
extern double as_double(unsigned long long u); /* NB: asdouble is WCPL intrinsic */
extern unsigned as_uint32(float f); /* NB: asuint32 is WCPL intrinsic */
extern float as_float(unsigned u); /* NB: asfloat is WCPL intrinsic */
extern char *udtohex(unsigned long long uval, char *buf); /* buf needs 32 chars */
extern unsigned long long hextoud(const char *buf); /* -1 on error */
extern char *uftohex(unsigned uval, char *buf); /* buf needs 32 chars */
extern unsigned hextouf(const char *buf); /* -1 on error */

/* dynamic (heap-allocated) 0-terminated strings */
typedef char* dstr_t;
#define dsinit(pds) (*(dstr_t*)(pds) = NULL)
extern void dsicpy(dstr_t* mem, const dstr_t* pds);
extern void dsfini(dstr_t* pds); 
extern void dscpy(dstr_t* pds, const dstr_t* pdss);
extern void dssets(dstr_t* pds, const char *s);
#define dsclear(pds) (dssets(pds, NULL))
extern int dstr_cmp(const void *pds1, const void *pds2);

/* simple dynamic memory buffers */
typedef struct buf {
  size_t esz; /* element size in bytes */
  void*  buf; /* data (never NULL) */
  size_t fill; /* # of elements used */
  size_t end; /* # of elements allocated */
} buf_t;
extern buf_t* bufinit(buf_t* pb, size_t esz);
extern buf_t* buficpy(buf_t* mem, const buf_t* pb);
extern void* buffini(buf_t* pb);
extern buf_t mkbuf(size_t esz);
extern buf_t* newbuf(size_t esz);
extern void freebuf(buf_t* pb);
extern size_t buflen(const buf_t* pb);
extern void* bufdata(buf_t* pb);
extern bool bufempty(const buf_t* pb);
extern void bufclear(buf_t* pb);
extern void bufgrow(buf_t* pb, size_t n);
extern void bufresize(buf_t* pb, size_t n);
extern void* bufref(buf_t* pb, size_t i);
extern void bufrem(buf_t* pb, size_t i);
extern void bufnrem(buf_t* pb, size_t i, size_t n);
extern void* bufins(buf_t* pb, size_t i);
extern void* bufbk(buf_t* pb);
extern void* bufnewbk(buf_t* pb);
extern void* bufpopbk(buf_t* pb);
extern void* bufnewfr(buf_t* pb);
extern void  bufpopfr(buf_t* pb);
extern void* bufalloc(buf_t* pb, size_t n);
extern void bufrev(buf_t* pb);
extern void bufcpy(buf_t* pb, const buf_t* pab);
extern void bufcat(buf_t* pb, const buf_t* pab);
extern void bufqsort(buf_t* pb, int (*cmp)(const void *, const void *)); /* unstable */
extern void bufremdups(buf_t* pb, int (*cmp)(const void *, const void *), void (*fini)(void *)); /* adjacent */
extern void* bufsearch(const buf_t* pb, const void *pe, int (*cmp)(const void *, const void *)); /* linear */
extern void* bufbsearch(const buf_t* pb, const void *pe, int (*cmp)(const void *, const void *)); /* binary */
extern size_t bufoff(const buf_t* pb, const void *pe); /* element offset of non-NULL pe inside pb: [0..len] */
extern void bufswap(buf_t* pb1, buf_t* pb2);

/* dstr_t buffers */
typedef buf_t dsbuf_t;
#define dsbinit(mem) (bufinit(mem, sizeof(dstr_t)))
extern void dsbicpy(dsbuf_t* mem, const dsbuf_t* pb);
extern void dsbfini(dsbuf_t* pb);
extern void dsbclear(dsbuf_t* pb);
#define dsbempty(pb) (bufempty(pb))
#define dsblen(pb) (buflen(pb))
#define dsbref(pb, i) ((dstr_t*)bufref(pb, i))
#define dsbnewbk(pb) ((dstr_t*)(bufnewbk(pb)))
#define dsbpushbk(pb, pds) (dsicpy(bufnewbk(pb), pds))
#define dsbrem(pb, i) do { dsbuf_t *_pb = pb; size_t _i = i; dsfini(bufref(_pb, _i)); bufrem(_pb, _i); } while(0)
#define dsbqsort(pb) (bufqsort(pb, dstr_cmp))
#define dsbremdups(pb) (bufremdups(pb, dstr_cmp, (dsfini)))
#define dsbsearch(pb, pe) (bufsearch(pb, pe, dstr_cmp))
#define dsbbsearch(pb, pe) (bufbsearch(pb, pe, dstr_cmp))

/* unicode charsets */
typedef buf_t ucset_t;
#define ucsinit(mem) (bufinit(mem, sizeof(unsigned)*2))
#define ucsfini(ps) (buffini(ps))
#define mkucs() (mkbuf(sizeof(unsigned)*2))
#define ucsempty(ps) (bufempty(ps))
extern bool ucsin(unsigned uc, const ucset_t *ps);
extern void ucspushi(ucset_t *ps, unsigned fc, unsigned lc);

/* regular char buffers */
typedef buf_t cbuf_t;
#define cbinit(mem) (bufinit(mem, sizeof(char)))
#define cbicpy(mem, pb) (buficpy(mem, pb))
#define cbfini(pb) (buffini(pb))
#define mkcb() (mkbuf(sizeof(char)))
#define newcb() (newbuf(sizeof(char)))
#define freecb(pb) (freebuf(pb))
#define cblen(pb) (buflen(pb))
#define cbclear(pb) (bufclear(pb))
#define cbempty(pb) (buflen(pb) == 0)
#define cballoc(pb, n) ((char*)bufalloc(pb, n))
extern void cbputc(int c, cbuf_t* pcb);
#define cbputc(c, pb) (*(char*)bufnewbk(pb) = (char)(c))
extern void cbput(const char *s, size_t n, cbuf_t* pcb);
extern void cbputs(const char *s, cbuf_t* pcb);
extern size_t cbwrite(const char *s, size_t sz, size_t c, cbuf_t* pcb);
extern void cbputlc(unsigned long uc, cbuf_t* pcb);
extern void cbputwc(wchar_t wc, cbuf_t* pcb);
extern void cbputd(int v, cbuf_t* pcb);
extern void cbputld(long v, cbuf_t* pcb);
extern void cbputt(ptrdiff_t v, cbuf_t* pcb);
extern void cbputu(unsigned v, cbuf_t* pcb);
extern void cbputx(unsigned v, cbuf_t* pcb);
extern void cbputlu(unsigned long v, cbuf_t* pcb);
extern void cbputllu(unsigned long long v, cbuf_t* pcb);
extern void cbputll(long long v, cbuf_t* pcb);
extern void cbputz(size_t v, cbuf_t* pcb);
extern void cbputg(double v, cbuf_t* pcb);
extern void cbputvf(cbuf_t* pcb, const char *fmt, va_list ap);
extern void cbputf(cbuf_t* pcb, const char *fmt, ...);
extern void cbput4le(unsigned v, cbuf_t* pcb);
extern void cbput8le(unsigned long long v, cbuf_t* pcb);
extern void cbputtime(const char *fmt, const struct tm *tp, cbuf_t* pcb);
extern void cbinsc(cbuf_t* pcb, size_t n, int c);
extern void cbinss(cbuf_t* pcb, size_t n, const char *s);
extern char* cbset(cbuf_t* pcb, const char *s, size_t n);
extern char* cbsets(cbuf_t* pcb, const char *s);
extern char* cbsetf(cbuf_t* pcb, const char *fmt, ...);
extern char* cbdata(cbuf_t* pcb);
extern void cbcpy(cbuf_t* pdcb, const cbuf_t* pscb);
extern void cbcat(cbuf_t* pdcb, const cbuf_t* pscb);
extern dstr_t cbclose(cbuf_t* pcb);
extern int cbuf_cmp(const void *p1, const void *p2);
extern char* fgetlb(cbuf_t *pcb, FILE *fp);
extern char *wcsto8cb(const wchar_t *wstr, int rc, cbuf_t *pcb);

/* wide char buffers */
extern wchar_t *s8ctowcb(const char *str, wchar_t rc, buf_t *pb);

/* unicode char (unsigned long) buffers */
extern unsigned long *s8ctoucb(const char *str, unsigned long rc, buf_t *pb);

/* grow pcb to get to the required alignment */
extern void binalign(cbuf_t* pcb, size_t align);
/* lay out numbers as little-endian binary into cbuf */
extern void binchar(int c, cbuf_t* pcb);  /* align=1 */
extern void binshort(int s, cbuf_t* pcb); /* align=2 */
extern void binint(int i, cbuf_t* pcb);   /* align=4 */
extern void binllong(long long ll, cbuf_t* pcb); /* align=8 */
extern void binuchar(unsigned uc, cbuf_t* pcb);  /* align=1 */
extern void binushort(unsigned us, cbuf_t* pcb); /* align=2 */
extern void binuint(unsigned ui, cbuf_t* pcb);   /* align=4 */
extern void binullong(unsigned long long ull, cbuf_t* pcb); /* align=8 */
extern void binfloat(float f, cbuf_t* pcb);   /* align=4 */
extern void bindouble(double d, cbuf_t* pcb); /* align=8 */

/* strtok replacement */
/* usage: while ((tok = strtoken(str, sep, &str, pcb) != NULL) ...;  */
extern char *strtoken(const char *str, const char *sep, char** ep, cbuf_t *pcb);

/* symbols */
typedef int sym_t;
#define sym_cmp int_cmp
/* NULL => 0, otherwise sym is positive */
extern sym_t intern(const char *name);
/* 0 => NULL, otherwise returns stored string */
extern const char *symname(sym_t s);
/* uses limited formatter (cbputvf) internally */
extern sym_t internf(const char *fmt, ...);
/* reset symbol table */
extern void clearsyms(void);

/* simple char input abstraction */
typedef struct ii_tag {
  int (*getc)(void*);
  int (*ungetc)(int, void*);
  char *(*gets)(char*, int, void*);
  size_t (*read)(void*, size_t, size_t, void*);
  /* ctls return -1 and set errno to EINVAL if not supported */
  int (*ctl)(const char *cmd, void *arg, void *dp);
} ii_t, *pii_t;

/* common i interfaces */
extern pii_t null_pii; /* no data; data ptr ignored */
extern pii_t FILE_pii; /* data ptr is FILE* */
extern pii_t strptr_pii; /* data ptr is char** (zero-terminated) */

/* common ops working via i interfaces */
#define iigetc(pii, dp) ((pii->getc)(dp))
#define iiungetc(pii, c, dp) ((pii->ungetc)(c, dp))
#define iigets(pii, b, n, dp) ((pii->gets)(b, n, dp))
#define iiread(pii, b, s, n, dp) ((pii->read)(b, s, n, dp))
#define iiget(pii, b, n, dp) ((pii->read)(b, 1, n, dp))
#define iictl(pii, c, a, dp) ((pii->ctl)(c, a, dp))

/* simple char output abstraction */
typedef struct oi_tag {
  int (*putc)(int, void*);
  int (*puts)(const char*, void*);
  size_t (*write)(const void*, size_t, size_t, void*);
  int (*flush)(void*);
  /* ctls return -1 and set errno to EINVAL if not supported */
  int (*ctl)(const char *cmd, void *arg, void *dp);
} oi_t, *poi_t;

/* common o interfaces */
extern poi_t null_poi; /* data / data ptr are ignored */
extern poi_t FILE_poi; /* data ptr is FILE* */
extern poi_t cbuf_poi; /* data ptr is cbuf_t* (see above) */

/* common ops working via o interfaces */
#define oiputc(poi, c, dp) ((poi->putc)(c, dp))
#define oiputs(poi, s, dp) ((poi->puts)(s, dp))
#define oiwrite(poi, b, s, n, dp) ((poi->write)(b, s, n, dp))
#define oiput(poi, b, n, dp) ((poi->write)(b, 1, n, dp))
#define oiflush(poi, dp) ((poi->flush)(dp))
#define oictl(poi, c, a, dp) ((poi->ctl)(c, a, dp))

/* json i/o "file" */
typedef struct JFILE_tag {
  /* base (internal) */
  struct jfile_tag* pjf;
  bool ownsfile;
  /* context */
  bool loading;
  /* parser/unparser FSA state */
  enum {
    S_AT_OBRK, S_AT_OBRC, 
    S_AT_KEY, S_AT_VALUE, 
    S_AFTER_VALUE,
    S_AT_CBRK, S_AT_CBRC 
  } state;
} JFILE;

/* constructors/destructors */
extern JFILE* newjfii(pii_t pii, void *dp);
extern JFILE* newjfoi(poi_t poi, void *dp);
extern void freejf(JFILE* pf);
extern void jferror(JFILE* pf, const char* fmt, ...);

/* type of json value */
typedef enum { 
  JVT_ARR, 
  JVT_OBJ, 
  JVT_NULL, 
  JVT_BOOL, 
  JVT_INT, 
  JVT_UINT, 
  JVT_FLOAT, 
  JVT_STR 
} jvtype_t;

/* input operations */
extern bool jfateof(JFILE* pf); /* end of file? */
extern void jfgetobrk(JFILE* pf); /* [ */
extern bool jfatcbrk(JFILE* pf);  /* ...]? */
extern void jfgetcbrk(JFILE* pf); /* ] */
extern void jfgetobrc(JFILE* pf); /* { */
extern char* jfgetkey(JFILE* pf, cbuf_t* pcb); /* "key": */
extern bool jfatcbrc(JFILE* pf);  /* ...}? */
extern void jfgetcbrc(JFILE* pf); /* } */
extern jvtype_t jfpeek(JFILE* pf); /* type of value ahead */
extern void jfgetnull(JFILE* pf); /* null */
extern bool jfgetbool(JFILE* pf); /* true/false */
extern long long jfgetnumll(JFILE* pf); /* num as long long */
extern unsigned long long jfgetnumull(JFILE* pf); /* num as unsigned long long */
extern double jfgetnumd(JFILE* pf); /* num as double */
extern char* jfgetstr(JFILE* pf, cbuf_t* pcb); /* "str" */
extern char* jfgetbin(JFILE* pf, cbuf_t* pcb); /* "hexbin" as bytes */

/* output operations */
extern void jfputobrk(JFILE* pf); /* [ */
extern void jfputcbrk(JFILE* pf); /* ] */
extern void jfputobrc(JFILE* pf); /* { */
extern void jfputkey(JFILE* pf, const char *key); /* "key": */
extern void jfputkeyn(JFILE* pf, const char *key, size_t n); /* "key": */
extern void jfputcbrc(JFILE* pf); /* } */
extern void jfputnull(JFILE* pf); /* null */
extern void jfputbool(JFILE* pf, bool b); /* true/false */
extern void jfputnum(JFILE* pf, int num); /* num as int */
extern void jfputnumu(JFILE* pf, unsigned num); /* num as unsigned */
extern void jfputnumll(JFILE* pf, long long num); /* num as long long */
extern void jfputnumull(JFILE* pf, unsigned long long num); /* num as unsigned long long */
extern void jfputnumd(JFILE* pf, double num); /* num as double */
extern void jfputstr(JFILE* pf, const char *str); /* "str" */
extern void jfputstrn(JFILE* pf, const char *str, size_t n); /* "str" */
extern void jfputbin(JFILE* pf, const void *mem, size_t n); /* "hexbin" */
extern void jfflush(JFILE* pf);

/* bson i/o "file" */
typedef struct BFILE_tag {
  /* base (internal) */
  struct bfile_tag* pbf;
  bool ownsfile;
  /* context */
  bool loading;
} BFILE;

/* constructors/destructors */
extern BFILE* newbfii(pii_t pii, void *dp);
extern BFILE* newbfoi(poi_t poi, void *dp);
extern void freebf(BFILE* pf);
extern void bferror(BFILE* pf, const char* fmt, ...);

/* type of bson value */
typedef enum { 
  BVT_FLOAT = 0x01,
  BVT_STR   = 0x02,
  BVT_OBJ   = 0x03,
  BVT_ARR   = 0x04,
  BVT_BIN   = 0x05,
  BVT_BOOL  = 0x08,
  BVT_NULL  = 0x0A,
  BVT_INT32 = 0x10, 
  BVT_INT64 = 0x12 
} bvtype_t;

/* input operations */
extern void bfgetobrk(BFILE* pf); /* [ */
extern bool bfatcbrk(BFILE* pf);  /* ...]? */
extern void bfgetcbrk(BFILE* pf); /* ] */
extern void bfgetobrc(BFILE* pf); /* { */
extern char* bfgetkey(BFILE* pf, cbuf_t* pcb); /* "key": */
extern bool bfatcbrc(BFILE* pf);  /* ...}? */
extern void bfgetcbrc(BFILE* pf); /* } */
extern bvtype_t bfpeek(BFILE* pf); /* type of value ahead */
extern void bfgetnull(BFILE* pf); /* null */
extern bool bfgetbool(BFILE* pf); /* true/false */
extern int bfgetnum(BFILE* pf); /* num as int */
extern unsigned bfgetnumu(BFILE* pf); /* num as unsigned */
extern long long bfgetnumll(BFILE* pf); /* num as long long */
extern unsigned long long bfgetnumull(BFILE* pf); /* num as unsigned long long */
extern double bfgetnumd(BFILE* pf); /* num as double */
extern char* bfgetstr(BFILE* pf, cbuf_t* pcb); /* "str" */
extern char* bfgetbin(BFILE* pf, cbuf_t* pcb); /* binary */

/* output operations */
extern void bfputobrk(BFILE* pf); /* open array */
extern void bfputcbrk(BFILE* pf); /* close array */
extern void bfputobrc(BFILE* pf); /* open object */
extern void bfputkey(BFILE* pf, const char *key); /* "key": */
extern void bfputkeyn(BFILE* pf, const char *key, size_t n); /* "key": */
extern void bfputcbrc(BFILE* pf); /* close object */
extern void bfputnull(BFILE* pf); /* null */
extern void bfputbool(BFILE* pf, bool b); /* true/false */
extern void bfputnum(BFILE* pf, int num); /* num as int */
extern void bfputnumu(BFILE* pf, unsigned num); /* num as unsigned int */
extern void bfputnumll(BFILE* pf, long long num); /* num as long long */
extern void bfputnumull(BFILE* pf, unsigned long long num); /* num as unsigned long long */
extern void bfputnumd(BFILE* pf, double num); /* num as double */
extern void bfputstr(BFILE* pf, const char *str); /* "str" */
extern void bfputstrn(BFILE* pf, const char *str, size_t n); /* "str" */
extern void bfputbin(BFILE* pf, const char *str, size_t n); /* binary */

/* hex string converters */
extern char *hexencode(const char *s, cbuf_t* pcb); /* -> [0-9a-f]* */
extern char *hexnencode(const char *s, size_t n, cbuf_t* pcb); /* -> [0-9a-f]* */
/* returns NULL on err, whitespace and - ignored, use cblen(pcb) for binary data */
extern char *hexdecode(const char *s, cbuf_t* pcb);

/* sha256 digests */
typedef struct sha256ctx_tag {
  uint32_t h[8];
  uint8_t x[64];
  size_t x_len;
  uint64_t len;
} sha256ctx_t;
/* incremental calculation of sha256 digest */
#define SHA256DG_SIZE (32)
#define SHA256DG_HEXCHARS (64)
#define SHA256DG_B64CHARS (44)
extern void sha256init(sha256ctx_t *ctx);
extern void sha256update(sha256ctx_t *ctx, const void *mem, size_t len);
extern void sha256fini(sha256ctx_t *ctx, uint8_t digest[SHA256DG_SIZE]);
extern char *memsha256(const void *mem, size_t len, cbuf_t *pcb);
