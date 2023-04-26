/* b.c (base) -- esl */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <wchar.h>
#include <time.h>
#include <math.h>
#include "b.h"

/* globals */
static const char *g_progname = NULL;  /* program name for messages */
static const char *g_usage = NULL;  /* usage string for messages */
int g_wlevel = 0; /* warnings below this level are ignored */
int g_verbosity = 0; /* how verbose are we? */
int g_quietness = 0; /* how quiet are we? */
/* AT&T-like option parser */
int eoptind = 1; /* start*/
int eopterr = 1; /* throw errors by default */
int eoptopt = 0;
char* eoptarg = NULL;
int eoptich = 0;


/* common utility functions */

void exprintf(const char *fmt, ...)
{
  va_list args;

  fflush(stdout);
  if (progname() != NULL)
    fprintf(stderr, "%s: ", progname());

  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);

  if (fmt[0] != '\0' && fmt[strlen(fmt)-1] == ':')
    fprintf(stderr, " %s", strerror(errno));
  fprintf(stderr, "\naborting execution...\n");

  exit(2); /* conventional value for failed execution */
}

void *exmalloc(size_t n)
{
  void *p = malloc(n);
  if (p == NULL) exprintf("malloc() failed:");
  return p;
}

void *excalloc(size_t n, size_t s)
{
  void *p = calloc(n, s);
  if (p == NULL) exprintf("calloc() failed:");
  return p;
}

void *exrealloc(void *m, size_t n)
{
  void *p = realloc(m, n);
  if (p == NULL) exprintf("realloc() failed:");
  return p;
}

char *exstrdup(const char *s)
{
  char *t = (char *)exmalloc(strlen(s)+1);
  strcpy(t, s);
  return t;
}

char *exstrndup(const char* s, size_t n)
{
  char *t = (char *)exmalloc(n+1);
  strncpy(t, s, n); t[n] = '\0';
  return t;
}

char *strtrc(char* str, int c, int toc)
{
  char *s;
  for (s = str; *s; ++s) if (*s == c) *s = toc;
  return str;
}

char *strprf(const char *str, const char *prefix)
{
  assert(str); assert(prefix);
  while (*str && *str == *prefix) ++str, ++prefix;
  if (*prefix) return NULL;
  return (char *)str; 
}

char *strsuf(const char *str, const char *suffix)
{
  size_t l, sl;
  assert(str); assert(suffix);
  l = strlen(str), sl = strlen(suffix);
  if (l >= sl) { 
    str += (l - sl);
    if (strcmp(str, suffix) == 0) return (char *)str;
  }
  return NULL;
}

bool streql(const char *s1, const char *s2)
{
  if (s1 == NULL && s2 == NULL) return true;
  if (s1 == NULL || s2 == NULL) return false;
  return strcmp(s1, s2) == 0;
}

bool strieql(const char *s1, const char *s2)
{
  if (s1 == NULL && s2 == NULL) return true;
  if (s1 == NULL || s2 == NULL) return false;
  while (*s1 != 0 && *s2 != 0) {
    int c1 = *s1++ & 0xff, c2 = *s2++ & 0xff;
    if (c1 == c2) continue;
    if (c1 < 0xff && c2 < 0xff && tolower(c1) == tolower(c2)) continue;
    break; 
  }
  return *s1 == 0 && *s2 == 0;
}

size_t strcnt(const char *str, int c)
{
  int c1; size_t cnt = 0; assert(str);
  while ((c1 = *str++)) if (c1 == c) ++cnt;
  return cnt;
}

void memswap(void *mem1, void *mem2, size_t sz)
{
  char c, *p1, *p2;
  assert(mem1); assert(mem2);
  p1 = (char*)mem1; p2 = (char*)mem2;
  while (sz--) c = *p1, *p1++ = *p2, *p2++ = c;
}

/* encodes legal unicode as well as other code points up to 21 bits long (0 to U+001FFFFF) */
unsigned char *utf8(unsigned long c, unsigned char *s) 
{ /* if c has more than 21 bits (> U+1FFFFF), *s is set to 0 and s does not advance; accepts any other c w/o error */
  int t = (int)!!(c & ~0x7fL) + (int)!!(c & ~0x7ffL) + (int)!!(c & ~0xffffL) + (int)!!(c & ~0x1fffffL);
  *s = (unsigned char)(((c >> t["\0\0\0\x12\0"]) & t["\0\0\0\x07\0"]) | t["\0\0\0\xf0\0"]);
  s += (unsigned char)(t["\0\0\0\1\0"]);
  *s = (unsigned char)(((c >> t["\0\0\x0c\x0c\0"]) & t["\0\0\x0f\x3f\0"]) | t["\0\0\xe0\x80\0"]);
  s += (unsigned char)(t["\0\0\1\1\0"]);
  *s = (unsigned char)(((c >> t["\0\x06\x06\x06\0"]) & t["\0\x1f\x3f\x3f\0"]) | t["\0\xc0\x80\x80\0"]);
  s += (unsigned char)(t["\0\1\1\1\0"]);
  *s = (unsigned char)(((c & t["\x7f\x3f\x3f\x3f\0"])) | t["\0\x80\x80\x80\0"]);
  s += (unsigned char)(t["\1\1\1\1\0"]);
  return s; 
}

/* decodes legal utf-8 as well as any other encoded sequences for code points up to 21 bits (0 to U+001FFFFF) */
/* CAVEAT: in broken encoding can step over \0 byte if it is a (bad) payload byte and thus run past end of line!! */
unsigned long unutf8(unsigned char **ps) 
{ /* NB: unutf8 never advances less than 1 and more than 4 bytes; gobbles up arbitrary bytes w/o error */
  unsigned char *s = *ps; unsigned long c; unsigned t = *s >> 4; 
  c =  (unsigned long)(*s & t["\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\0\0\0\0\x1f\x1f\x0f\x07"]) << t["\0\0\0\0\0\0\0\0\0\0\0\0\x06\x06\x0c\x12"];
  s += t["\1\1\1\1\1\1\1\1\0\0\0\0\1\1\1\1"];
  c |= (unsigned long)(*s & t["\0\0\0\0\0\0\0\0\0\0\0\0\x3f\x3f\x3f\x3f"]) << t["\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x06\x0c"];
  s += t["\0\0\0\0\0\0\0\0\0\0\0\0\1\1\1\1"];
  c |= (unsigned long)(*s & t["\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x3f\x3f"]) << t["\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x06"];
  s += t["\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1\1"];
  c |= (unsigned long)(*s & t["\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x3f"]);
  s += t["\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1"];
  *ps = s; return c;
}

unsigned long strtou8c(const char *s, char **ep)
{
  unsigned long c = unutf8((unsigned char **)&s);
  if (ep) *ep = (char *)s; return c;
}

/* size of buffer large enough to hold char escapes */
#define SBSIZE 32
/* convert a single C99-like char/escape sequence (-1 on error) */
unsigned long strtocc32(const char *s, char** ep, bool *rp)
{
  char buf[SBSIZE+1]; 
  int c;
  assert(s);
  if (rp) *rp = true;
  if (*s) {
    c = *s++;
    if (c == '\\') {
      switch (c = *s++) {
        case 'a':   c = '\a'; break;
        case 'b':   c = '\b'; break;
        case 'f':   c = '\f'; break;
        case 'n':   c = '\n'; break;
        case 'r':   c = '\r'; break;
        case 't':   c = '\t'; break;
        case 'v':   c = '\v'; break;
        case '\\':  break;
        case '\'':  break;
        case '\"':  break;
        case '\?':  break;
        case 'x': {
          int i = 0; long l;
          while (i < SBSIZE && (c = *s++) && isxdigit(c))
            buf[i++] = c;
          if (i == SBSIZE) goto err;
          --s;
          buf[i] = 0; 
          l = strtol(buf, NULL, 16);
          c = (int)l & 0xff;
          if ((long)c != l) goto err; 
        } break;
        case 'u': {
          int i = 0; long l;
          c = *s++; if (isxdigit(c)) buf[i++] = c; else goto err;
          c = *s++; if (isxdigit(c)) buf[i++] = c; else goto err;
          c = *s++; if (isxdigit(c)) buf[i++] = c; else goto err;
          c = *s++; if (isxdigit(c)) buf[i++] = c; else goto err;
          buf[i] = 0;
          l = strtol(buf, NULL, 16);
          c = (int)l & 0xffff;
          if ((long)c != l) goto err;
          if (rp) *rp = false; 
        } break;
        case 'U': {
          int i = 0; long l;
          c = *s++; if (isxdigit(c)) buf[i++] = c; else goto err;
          c = *s++; if (isxdigit(c)) buf[i++] = c; else goto err;
          c = *s++; if (isxdigit(c)) buf[i++] = c; else goto err;
          c = *s++; if (isxdigit(c)) buf[i++] = c; else goto err;
          c = *s++; if (isxdigit(c)) buf[i++] = c; else goto err;
          c = *s++; if (isxdigit(c)) buf[i++] = c; else goto err;
          c = *s++; if (isxdigit(c)) buf[i++] = c; else goto err;
          c = *s++; if (isxdigit(c)) buf[i++] = c; else goto err;
          buf[i] = 0;
          l = strtol(buf, NULL, 16);
          c = (int)l & 0x7fffffff;
          if ((long)c != l) goto err; 
          if (rp) *rp = false; 
        } break;
        case '0': case '1': case '2': case '3':
        case '4': case '5': case '6': case '7': {
          int i = 0;
          buf[i++] = c; c = *s++;
          if (c >= '0' && c <= '7') {
            buf[i++] = c; c = *s++;
            if (c >= '0' && c <= '7')
              buf[i++] = c;
            else --s;
          } else --s;
          buf[i] = 0; 
          c = (int)strtol(buf, NULL, 8);
        } break;
        case 0:
          goto err;
        default:
          /* warn? return as is */
          break;
      }
    }
    if (ep) *ep = (char*)s; 
    return (unsigned long)c;
  err:;
  }
  if (ep) *ep = (char*)s;
  errno = EINVAL;
  return (unsigned long)(-1);
}

unsigned long strtou8cc32(const char *s, char **ep, bool *rp)
{
  if (is8chead(*s)) { if (rp) *rp = false;  return strtou8c(s, ep); }  
  return strtocc32(s, ep, rp);
}


bool fget8bom(FILE *fp)
{
  int c = fgetc(fp);
  if (c == EOF) return false;
  /* not comitted yet - just looking ahead... */
  if ((c & 0xFF) != 0xEF) { ungetc(c, fp); return false; }
  /* now we are comitted to read all 3 bytes - partial reads can happen */
  if ((c = fgetc(fp)) == EOF || (c & 0xFF) != 0xBB) return false;
  if ((c = fgetc(fp)) == EOF || (c & 0xFF) != 0xBF) return false;
  /* all three bytes are there */
  return true;
}

int int_cmp(const void *pi1, const void *pi2)
{
  assert(pi1); assert(pi2);
  return *(int*)pi1 - *(int*)pi2;
}


/* floating-point reinterpret casts and exact hex i/o */

unsigned long long as_uint64(double f) /* NB: asuint64 is WCPL intrinsic */
{
  union { unsigned long long u; double f; } uf;
  uf.f = f;
  return uf.u;
}

double as_double(unsigned long long u) /* NB: asdouble is WCPL intrinsic */
{
  union { unsigned long long u; double f; } uf;
  uf.u = u;
  return uf.f;
}

unsigned as_uint32(float f) /* NB: asuint32 is WCPL intrinsic */
{
  union { unsigned u; float f; } uf;
  uf.f = f;
  return uf.u;
}

float as_float(unsigned u) /* NB: asfloat is WCPL intrinsic */
{
  union { unsigned u; float f; } uf;
  uf.u = u;
  return uf.f;
}

/* print uint64 representation of double exactly in WASM-compatible hex format */
char *udtohex(unsigned long long uval, char *buf) /* needs 32 chars (25 chars, rounded up) */
{
  bool dneg = (bool)(uval >> 63ULL);
  int exp2 = (int)((uval >> 52ULL) & 0x07FFULL);
  unsigned long long mant = (uval & 0xFFFFFFFFFFFFFULL);
  if (exp2 == 0x7FF) {
    /* print as canonical NaN; todo: WASM allows :0xHHHHHHHHHH suffix! */
    if (mant != 0ULL) strcpy(buf, dneg ? "-nan" : "+nan");
    else strcpy(buf, dneg ? "-inf" : "+inf");
  } else {
    size_t i = 0, j; int val, vneg = false, dig, mdigs;
    if (exp2 == 0) val = mant == 0 ? 0 : -1022; else val = exp2 - 1023;
    if (val < 0) val = -val, vneg = true;
    do { dig = val % 10; buf[i++] = '0' + dig; val /= 10; } while (val);
    buf[i++] = vneg ? '-' : '+'; buf[i++] = 'p';
    for (mdigs = 13; mdigs > 0; --mdigs, mant >>= 4ULL) {
      dig = (int)(mant % 16); buf[i++] = dig < 10 ? '0' + dig : 'a' + dig - 10; 
    }
    buf[i++] = '.'; buf[i++] = '0' + ((exp2 == 0) ? 0 : 1);
    buf[i++] = 'x'; buf[i++] = '0';
    if (dneg) buf[i++] = '-'; buf[i] = 0;
    for (j = 0, i -= 1; j < i; ++j, --i) { 
      dig = buf[j]; buf[j] = buf[i]; buf[i] = dig;
    }
  }
  return buf;
}

/* read back uint64 representation of double as printed via udtohex; -1 on error */
unsigned long long hextoud(const char *buf)
{
  bool dneg = false;
  if (*buf == '-') ++buf, dneg = true;
  else if (*buf == '+') ++buf;
  if (strcmp(buf, "inf") == 0) {
    return dneg ? 0xFFF0000000000000ULL : 0x7FF0000000000000ULL;
  } else if (strcmp(buf, "nan") == 0) {
    /* read canonical NaN; todo: WASM allows :0xHHHHHHHHHH suffix! */
    return dneg ? 0xFFF8000000000000ULL : 0x7FF8000000000000ULL;
  } else {
    int exp2 = 0; unsigned long long mant = 0ULL;
    int ldig, val, vneg, dig, mdigs;
    if (*buf++ != '0') goto err;
    if (*buf++ != 'x') goto err;
    if (*buf != '0' && *buf != '1') goto err;
    ldig = *buf++ - '0';
    if (*buf++ != '.') goto err;
    for (mdigs = 13; mdigs > 0; --mdigs) {
      if (!*buf || !isxdigit(*buf)) goto err; 
      val = *buf++;
      dig = val <= '9' ? val - '0'
          : val <= 'F' ? val - 'A' + 10
          : val - 'a' + 10;
      mant = (mant << 4ULL) | dig;
    }
    if (*buf++ != 'p') goto err;
    if (*buf != '+' && *buf != '-') goto err;
    vneg = *buf++ == '-';
    for (val = 0; *buf; ++buf) {
      if (!isdigit(*buf)) goto err;
      val = val * 10 + *buf - '0';
    }
    if (vneg) val = -val;
    exp2 = ldig == 1 ? val + 1023 : 0;
    if (0 <= exp2 && exp2 <= 2046)
      return (unsigned long long)dneg << 63ULL | (unsigned long long)exp2 << 52ULL | mant;
 err:;
  }
  return 0xFFFFFFFFFFFFFFFFULL; 
}

/* print uint32 representation of double exactly in WASM-compatible hex format */
char *uftohex(unsigned uval, char *buf) /* needs 32 chars (17 chars, rounded up) */
{
  bool dneg = (bool)(uval >> 31U);
  int exp2 = (int)((uval >> 23U) & 0x0FFU);
  unsigned mant = (uval & 0x7FFFFFU);
  if (exp2 == 0xFF) {
    /* print as canonical NaN; todo: WASM allows :0xHHHHHH suffix! */
    if (mant != 0UL) strcpy(buf, dneg ? "-nan" : "+nan");
    else strcpy(buf, dneg ? "-inf" : "+inf");
  } else {
    size_t i = 0, j; int val, vneg = false, dig, mdigs;
    if (exp2 == 0) val = mant == 0 ? 0 : -126; else val = exp2 - 127;
    if (val < 0) val = -val, vneg = true;
    do { dig = val % 10; buf[i++] = '0' + dig; val /= 10; } while (val);
    buf[i++] = vneg ? '-' : '+'; buf[i++] = 'p';
    for (mdigs = 6, mant <<= 1; mdigs > 0; --mdigs, mant >>= 4) {
      dig = (int)(mant % 16); buf[i++] = dig < 10 ? '0' + dig : 'a' + dig - 10;
    }
    buf[i++] = '.'; buf[i++] = '0' + ((exp2 == 0) ? 0 : 1);
    buf[i++] = 'x'; buf[i++] = '0';
    if (dneg) buf[i++] = '-'; buf[i] = 0;
    for (j = 0, i -= 1; j < i; ++j, --i) {
      dig = buf[j]; buf[j] = buf[i]; buf[i] = dig;
    }
  }
  return buf;
}

/* read back uint32 representation of float as printed via uftohex; -1 on error */
unsigned hextouf(const char *buf)
{
  bool dneg = false;
  if (*buf == '-') ++buf, dneg = true;
  else if (*buf == '+') ++buf;
  if (strcmp(buf, "inf") == 0) {
    /* read canonical NaN; todo: WASM allows :0xHHHHHH suffix! */
    return dneg ? 0xFF800000U : 0x7F800000U;
  } else if (strcmp(buf, "nan") == 0) {
    return dneg ? 0xFFC00000U : 0x7FC00000U;
  } else {
    int exp2 = 0; unsigned mant = 0UL;
    int ldig, val, vneg, dig, mdigs;
    if (*buf++ != '0') goto err;
    if (*buf++ != 'x') goto err;
    if (*buf != '0' && *buf != '1') goto err;
    ldig = *buf++ - '0';
    if (*buf++ != '.') goto err;
    for (mdigs = 6; mdigs > 0; --mdigs) {
      if (!*buf || !isxdigit(*buf)) goto err;
      val = *buf++;
      dig = val <= '9' ? val - '0'
          : val <= 'F' ? val - 'A' + 10
          : val - 'a' + 10;
      mant = (mant << 4) | dig;
    }
    if (*buf++ != 'p') goto err;
    if (*buf != '+' && *buf != '-') goto err;
    vneg = *buf++ == '-';
    for (val = 0; *buf; ++buf) {
      if (!isdigit(*buf)) goto err;
      val = val * 10 + *buf - '0';
    }
    if (vneg) val = -val;
    exp2 = ldig == 1 ? val + 127 : 0;
    if (0 <= exp2 && exp2 <= 254)
      return (unsigned)dneg << 31U | (unsigned)exp2 << 23U | mant >> 1;
  err:;
  }
  return 0xFFFFFFFFU;
}


/* dynamic (heap-allocated) 0-terminated strings */

void dsicpy(dstr_t* mem, const dstr_t* pds)
{
  dstr_t ds = NULL;
  assert(mem); assert(pds);
  if (*pds) strcpy((ds = exmalloc(strlen(*pds)+1)), *pds);
  *mem = ds;
}

void dsfini(dstr_t* pds)
{
  if (pds) free(*pds);
}

void dscpy(dstr_t* pds, const dstr_t* pdss)
{ 
  dstr_t ds = NULL;
  assert(pds); assert(pdss);
  if (*pdss) strcpy((ds = exmalloc(strlen(*pdss)+1)), *pdss);
  free(*pds); *pds = ds;
}

void dssets(dstr_t* pds, const char *s)
{
  dstr_t ds = NULL;
  assert(pds);
  if (s) strcpy((ds = exmalloc(strlen(s)+1)), s);
  free(*pds); *pds = ds;
}

int dstr_cmp(const void *pds1, const void *pds2)
{
  assert(pds1); assert(pds2);
  return strcmp(*(dstr_t*)pds1, *(dstr_t*)pds2);
}


/* simple dynamic memory buffers */

buf_t* bufinit(buf_t* pb, size_t esz)
{
  assert(pb); assert(esz);
  pb->esz = esz;
  pb->end = 0;
  pb->buf = NULL;
  pb->fill = 0;
  return pb;
}

buf_t* buficpy(buf_t* mem, const buf_t* pb) /* over non-inited */
{
  assert(mem); assert(pb);
  assert(mem != pb);
  mem->esz = pb->esz;
  mem->end = pb->end; 
  mem->fill = pb->fill;
  mem->buf = NULL;
  if (pb->end > 0) {
    mem->buf = excalloc(pb->end, pb->esz);
    memcpy(mem->buf, pb->buf, pb->esz*pb->fill);
  }
  return mem;
}

void *buffini(buf_t* pb)
{
  assert(pb);
  if (pb->buf) free(pb->buf);
  pb->buf = NULL;
  return pb;
}

buf_t mkbuf(size_t esz)
{
  buf_t b;
  assert(esz);
  bufinit(&b, esz);
  return b;
}

buf_t* newbuf(size_t esz)
{
  buf_t* pb = (buf_t*)exmalloc(sizeof(buf_t));
  bufinit(pb, esz);
  return pb;
}

void freebuf(buf_t* pb)
{
  if (pb) {
    buffini(pb);
    free(pb);
  }
}

size_t buflen(const buf_t* pb)
{
  assert(pb);
  return pb->fill;
}

void* bufdata(buf_t* pb)
{
  assert(pb);
  return pb->buf;
}

bool bufempty(const buf_t* pb)
{
  assert(pb);
  return pb->fill == 0;
}

void bufclear(buf_t* pb)
{
  assert(pb);
  pb->fill = 0;
}

void bufgrow(buf_t* pb, size_t n)
{
  assert(pb);
  if (n > 0) { 
    size_t oldsz = pb->end;
    size_t newsz = oldsz*2;
    if (oldsz + n > newsz) newsz += n;
    pb->buf = exrealloc(pb->buf, newsz*pb->esz);
    pb->end = newsz;
  }
}

void bufresize(buf_t* pb, size_t n)
{
  assert(pb);
  if (n > pb->end) bufgrow(pb, n - pb->end);
  if (n > pb->fill) {
    assert(pb->buf != NULL);
    memset((char*)pb->buf + pb->fill*pb->esz, 0, (n - pb->fill)*pb->esz);
  }
  pb->fill = n;
}

void* bufref(buf_t* pb, size_t i)
{
  assert(pb);
  assert(i < pb->fill);
  assert(pb->buf != NULL);
  return (char*)pb->buf + i*pb->esz;
}

void bufrem(buf_t* pb, size_t i)
{
  size_t esz;
  assert(pb); assert(i < pb->fill);
  assert(pb->buf != NULL);
  esz = pb->esz;
  if (i < pb->fill - 1)
    memmove((char*)pb->buf + i*esz,
            (char*)pb->buf + (i+1)*esz,
            (pb->fill - 1 - i)*esz);
  --pb->fill;
}

void bufnrem(buf_t* pb, size_t i, size_t cnt)
{
  if (cnt > 0) {
    size_t esz;
    assert(pb); assert(i + cnt <= pb->fill);
    assert(pb->buf != NULL);
    esz = pb->esz;
    if (i < pb->fill - cnt)
      memmove((char*)pb->buf + i*esz,
              (char*)pb->buf + (i+cnt)*esz,
              (pb->fill - cnt - i)*esz);
    pb->fill -= cnt;
  }
}

void* bufins(buf_t* pb, size_t i)
{
  size_t esz; char *pnewe;
  assert(pb); assert(i <= pb->fill);
  esz = pb->esz;
  if (pb->fill == pb->end) bufgrow(pb, 1);
  assert(pb->buf != NULL);
  pnewe = (char*)pb->buf + i*esz;
  if (i < pb->fill)
    memmove(pnewe + esz, pnewe,
            (pb->fill - i)*esz);
  memset(pnewe, 0, esz);
  ++pb->fill;
  return pnewe;
}

void *bufbk(buf_t* pb)
{
  char* pbk;
  assert(pb); assert(pb->fill > 0);
  assert(pb->buf != NULL);
  pbk = (char*)pb->buf + (pb->fill-1)*pb->esz;
  return pbk;
}

void *bufnewbk(buf_t* pb)
{
  char* pbk; size_t esz;
  assert(pb);
  if (pb->fill == pb->end) bufgrow(pb, 1);
  assert(pb->buf != NULL);
  esz = pb->esz;
  pbk = (char*)pb->buf + pb->fill*esz;
  memset(pbk, 0, esz);
  ++pb->fill;
  return pbk;
}

void *bufpopbk(buf_t* pb)
{
  char* pbk;
  assert(pb); assert(pb->fill > 0);
  assert(pb->buf != NULL);
  pbk = (char*)pb->buf + (pb->fill-1)*pb->esz;
  pb->fill -= 1;
  return pbk; /* outside but untouched */
}

void *bufnewfr(buf_t* pb)
{
  return bufins(pb, 0);
}

void bufpopfr(buf_t* pb)
{
  bufrem(pb, 0);
}

void *bufalloc(buf_t* pb, size_t n)
{
  size_t esz; char* pbk;
  assert(pb);
  if (pb->fill + n > pb->end) bufgrow(pb, pb->fill + n - pb->end);
  else if (!pb->buf && n == 0) bufgrow(pb, 1); /* ensure buf != NULL */ 
  esz = pb->esz;
  assert(pb->buf != NULL);
  pbk = (char*)pb->buf + pb->fill*esz;
  memset(pbk, 0, esz*n);
  pb->fill += n;
  return pbk;
}

void bufrev(buf_t* pb)
{
  char *pdata; 
  size_t i, j, len, esz;
  assert(pb);
  len = pb->fill;
  if (len < 2) return;
  esz = pb->esz;
  i = 0; j = len-1;  
  pdata = (char*)pb->buf;
  assert(pb->buf != NULL);
  while (i < j) {
    memswap(pdata+i*esz, pdata+j*esz, esz);
    ++i, --j;
  }
}

void bufcpy(buf_t* pb, const buf_t* pab)
{
  size_t an = buflen(pab);
  assert(pb->esz == pab->esz);
  bufclear(pb);
  if (pab->buf) memcpy(bufalloc(pb, an), pab->buf, an*pab->esz);
}

void bufcat(buf_t* pb, const buf_t* pab)
{
  size_t an = buflen(pab);
  assert(pb->esz == pab->esz);
  if (pab->buf) memcpy(bufalloc(pb, an), pab->buf, an*pab->esz);
}

/* unstable sort */
void bufqsort(buf_t* pb, int (*cmp)(const void *, const void *))
{
  assert(pb); assert(cmp);
  if (pb->buf) qsort(pb->buf, pb->fill, pb->esz, cmp);
}

/* removes adjacent */
void bufremdups(buf_t* pb, int (*cmp)(const void *, const void *), void (*fini)(void *))
{
  char *pdata; size_t i, j, len, esz;
  assert(pb); assert(cmp);
  len = pb->fill;
  esz = pb->esz;
  if (len < 2) return;
  i = 0; j = 1;  
  pdata = (char*)pb->buf;
  assert(pb->buf != NULL);
  while (j < len) {
    /* invariant: elements [0..i] are unique, [i+1,j[ is a gap */
    assert(i < j);
    if (0 == (*cmp)(pdata+i*esz, pdata+j*esz)) {
      /* duplicate: drop it */
      if (fini) (*fini)(pdata+j*esz);
    } else {
      /* unique: move it */
      ++i; if (i < j) memcpy(pdata+i*esz, pdata+j*esz, esz);
    }  
    ++j;
  }
  pb->fill = i+1;
}

/* linear search */
void* bufsearch(const buf_t* pb, const void *pe, int (*cmp)(const void *, const void *))
{
  size_t esz; char *pdata, *pend; 
  assert(pb); assert(pe); assert(cmp);
  if (pb->fill == 0) return NULL;
  esz = pb->esz;
  pdata = (char*)pb->buf;
  assert(pb->buf != NULL);
  pend = pdata + esz*pb->fill;
  while (pdata < pend) {
    if (0 == (*cmp)(pdata, pe))
      return pdata;
    pdata += esz;
  }
  return NULL;
}

/* binary search */
void* bufbsearch(const buf_t* pb, const void *pe, int (*cmp)(const void *, const void *))
{
  assert(pb); assert(pe); assert(cmp);
  return pb->buf ? bsearch(pe, pb->buf, pb->fill, pb->esz, cmp) : NULL;
}

size_t bufoff(const buf_t* pb, const void *pe)
{
  char *p0, *p; size_t off;
  assert(pb); assert(pe);
  assert(pb->buf != NULL);
  p0 = (char*)pb->buf, p = (char*)pe;
  assert(p >= p0);
  off = (p - p0) / pb->esz;
  assert(off <= pb->fill); /* internal pointers and pointer past last elt are legal */
  return off;
}

void bufswap(buf_t* pb1, buf_t* pb2)
{
  assert(pb1); assert(pb2);
  assert(pb1->esz == pb2->esz);
  memswap(pb1, pb2, sizeof(buf_t));
}

/* unicode charsets */

bool ucsin(unsigned c, const ucset_t *ps)
{
  unsigned e = c;
  const unsigned *pbase = ps->buf; /* int partition base */
  size_t psize = ps->fill; /* partition size in int pairs */
  while (psize) { /* still have int pairs in partition */
    /* pick central pair, rounding offset to a pair */
    const unsigned *ci = pbase + (psize & ~1);
    if (e < ci[0]) { /* FIRST */
      /* search from pbase to pair before ci */
      psize >>= 1;
    } else if (e > ci[1]) { /* LAST */ 
      /* search from pair after ci */
      pbase = ci + 2;
      psize = (psize-1) >> 1;
    } else {
      return true;
    }
  }
  return false;
}

void ucspushi(ucset_t *ps, unsigned fc, unsigned lc)
{
  unsigned *nl = bufnewbk(ps);
  /* ps spacing/ordering preconds must hold! */
  assert(fc <= lc);
  assert(nl == bufdata(ps) || fc > nl[-1]);
  nl[0] = fc, nl[1] = lc; 
}



/* dstr_t buffers */

void dsbicpy(dsbuf_t* mem, const dsbuf_t* pb)
{
  dstr_t *pdsm, *pds; size_t i;
  assert(mem); assert(pb); assert(pb->esz == sizeof(dstr_t));
  buficpy(mem, pb);
  pdsm = (dstr_t*)(mem->buf), pds = (dstr_t*)(pb->buf);
  for (i = 0; i < pb->fill; ++i) dsicpy(pdsm+i, pds+i);
}

void dsbclear(dsbuf_t* pb)
{
  dstr_t *pds; size_t i;
  assert(pb); assert(pb->esz == sizeof(dstr_t));
  pds = (dstr_t*)(pb->buf);
  for (i = 0; i < pb->fill; ++i) dsfini(pds+i);
  bufclear(pb);
}

void dsbfini(dsbuf_t* pb)
{
  dsbclear(pb);
  buffini(pb);
}


/* char buffers */

void (chbputc)(int c, chbuf_t* pcb)
{
  *(char*)bufnewbk(pcb) = (char)c;
}

void chbput(const char *s, size_t n, chbuf_t* pb)
{
  size_t l = buflen(pb);
  bufresize(pb, l+n);
  memcpy(l+(char*)pb->buf, s, n);
}

void chbputs(const char *s, chbuf_t* pb)
{
  size_t n = strlen(s);
  chbput(s, n, pb);
}

size_t chbwrite(const char *s, size_t sz, size_t c, chbuf_t* pb)
{
  size_t n = sz * c;
  if (pb->fill + n > pb->end) bufgrow(pb, n);
  memcpy((char*)pb->buf+pb->fill, s, n);
  pb->fill += n; 
  return c;
}

void chbputlc(unsigned long uc, chbuf_t* pb)
{
  if (uc < 128) chbputc((unsigned char)uc, pb);
  else {
    char buf[5], *pc = (char *)utf8(uc, (unsigned char *)&buf[0]);
    chbput(&buf[0], pc-&buf[0], pb);
  }
}

void chbputwc(wchar_t wc, chbuf_t* pb)
{
  assert(WCHAR_MIN <= wc && wc <= WCHAR_MAX);
  if (wc < 128) chbputc((unsigned char)wc, pb);
  else {
    char buf[5], *pc = (char *)utf8(wc, (unsigned char *)&buf[0]);
    chbput(&buf[0], pc-&buf[0], pb);
  }
}

void chbputd(int val, chbuf_t* pb)
{
  char buf[39+1]; /* enough up to 128 bits (w/sign) */
  char *e = &buf[40], *p = e;
  if (val) {
    unsigned m; 
    if (val == INT_MIN) m = INT_MAX + (unsigned)1;
    else if (val < 0) m = -val;
    else m = val;
    do *--p = (int)(m%10) + '0';
      while ((m /= 10) > 0);
    if (val < 0) *--p = '-';
  } else *--p = '0';
  chbput(p, e-p, pb);
}

void chbputld(long val, chbuf_t* pb)
{
  char buf[39+1]; /* enough up to 128 bits (w/sign) */
  char *e = &buf[40], *p = e;
  if (val) {
    unsigned long m; 
    if (val == LONG_MIN) m = LONG_MAX + (unsigned long)1;
    else if (val < 0) m = -val;
    else m = val;
    do *--p = (int)(m%10) + '0';
      while ((m /= 10) > 0);
    if (val < 0) *--p = '-';
  } else *--p = '0';
  chbput(p, e-p, pb);
}

void chbputt(ptrdiff_t val, chbuf_t* pb)
{
  char buf[39+1]; /* enough up to 128 bits (w/sign) */
  char *e = &buf[40], *p = e;
  if (val) {
    size_t m; assert(sizeof(ptrdiff_t) == sizeof(size_t));
    if (val < 0 && val-1 > 0) m = (val-1) + (size_t)1;
    else if (val < 0) m = -val;
    else m = val;
    do *--p = (int)(m%10) + '0';
      while ((m /= 10) > 0);
    if (val < 0) *--p = '-';
  } else *--p = '0';
  chbput(p, e-p, pb);
}

void chbputu(unsigned val, chbuf_t* pb)
{
  char buf[39+1]; /* enough up to 128 bits */
  char *e = &buf[40], *p = e;
  if (val) {
    unsigned m = val; 
    do *--p = (int)(m%10) + '0';
      while ((m /= 10) > 0);
  } else *--p = '0';
  chbput(p, e-p, pb);
}

void chbputx(unsigned val, chbuf_t* pb)
{
  char buf[39+1]; /* enough up to 128 bits */
  char *e = &buf[40], *p = e;
  if (val) {
    unsigned m = val, d; 
    do *--p = (int)(d = (m%16), d < 10 ? d + '0' : d-10 + 'a');
      while ((m /= 16) > 0);
  } else *--p = '0';
  chbput(p, e-p, pb);
}

void chbputlu(unsigned long val, chbuf_t* pb)
{
  char buf[39+1]; /* enough up to 128 bits */
  char *e = &buf[40], *p = e;
  if (val) {
    unsigned long m = val; 
    do *--p = (int)(m%10) + '0';
      while ((m /= 10) > 0);
  } else *--p = '0';
  chbput(p, e-p, pb);
}

void chbputllu(unsigned long long val, chbuf_t* pb)
{
  char buf[39+1]; /* enough up to 128 bits */
  char *e = &buf[40], *p = e;
  if (val) {
    unsigned long long m = val; 
    do *--p = (int)(m%10) + '0';
      while ((m /= 10) > 0);
  } else *--p = '0';
  chbput(p, e-p, pb);
}

void chbputz(size_t val, chbuf_t* pb)
{
  char buf[39+1]; /* enough up to 128 bits */
  char *e = &buf[40], *p = e;
  if (val) {
    size_t m = val; 
    do *--p = (int)(m%10) + '0';
      while ((m /= 10) > 0);
  } else *--p = '0';
  chbput(p, e-p, pb);
}

void chbputll(long long val, chbuf_t* pb)
{
  char buf[39+1]; /* enough up to 128 bits (w/sign) */
  char *e = &buf[40], *p = e;
  if (val) {
    unsigned long long m;
    if (val == LLONG_MIN) m = LLONG_MAX + (unsigned long long)1;
    else if (val < 0) m = -val;
    else m = val;
    do *--p = (int)(m%10) + '0';
      while ((m /= 10) > 0);
    if (val < 0) *--p = '-';
  } else *--p = '0';
  chbput(p, e-p, pb);
}

void chbputg(double v, chbuf_t* pb)
{
  char buf[100];
  if (v != v) strcpy(buf, "+nan"); 
  else if (v <= -HUGE_VAL) strcpy(buf, "-inf");
  else if (v >= HUGE_VAL)  strcpy(buf, "+inf");
  else sprintf(buf, "%.17g", v); /* see WCSSKAFPA paper */
  chbputs(buf, pb);
}

/* minimalistic printf to char bufer */
void chbputvf(chbuf_t* pb, const char *fmt, va_list ap)
{
  assert(pb); assert(fmt);
  while (*fmt) {
    if (*fmt != '%' || *++fmt == '%') {
      chbputc(*fmt++, pb);
    } else if (fmt[0] == 's') {
      char *s = va_arg(ap, char*);
      chbputs(s, pb); fmt += 1;
    } else if (fmt[0] == 'c') {
      int c = va_arg(ap, int);
      chbputc(c, pb); fmt += 1;
    } else if (fmt[0] == 'l' && fmt[1] == 'c') {
      unsigned c = va_arg(ap, unsigned);
      chbputlc(c, pb); fmt += 2;
    } else if (fmt[0] == 'w' && fmt[1] == 'c') {
      wchar_t c = va_arg(ap, int); /* wchar_t promoted to int */
      chbputwc(c, pb); fmt += 2;
    } else if (fmt[0] == 'd') {
      int d = va_arg(ap, int);
      chbputd(d, pb); fmt += 1;
    } else if (fmt[0] == 'x') {
      unsigned d = va_arg(ap, unsigned);
      chbputx(d, pb); fmt += 1;
    } else if (fmt[0] == 'l' && fmt[1] == 'd') {
      long ld = va_arg(ap, long);
      chbputld(ld, pb); fmt += 2;
    } else if (fmt[0] == 'l' && fmt[1] == 'l' && fmt[2] == 'd') {
      long long lld = va_arg(ap, long long);
      chbputll(lld, pb); fmt += 3;
    } else if (fmt[0] == 't') {
      ptrdiff_t t = va_arg(ap, ptrdiff_t);
      chbputt(t, pb); fmt += 1;
    } else if (fmt[0] == 'u') {
      unsigned u = va_arg(ap, unsigned);
      chbputu(u, pb); fmt += 1;
    } else if (fmt[0] == 'l' && fmt[1] == 'u') {
      unsigned long lu = va_arg(ap, unsigned long);
      chbputlu(lu, pb); fmt += 2;
    } else if (fmt[0] == 'l' && fmt[1] == 'l' && fmt[2] == 'u') {
      unsigned long long llu = va_arg(ap, unsigned long long);
      chbputllu(llu, pb); fmt += 3;
    } else if (fmt[0] == 'z') {
      size_t z = va_arg(ap, size_t);
      chbputz(z, pb); fmt += 1;
    } else if (fmt[0] == 'g') {
      double g = va_arg(ap, double);
      chbputg(g, pb); fmt += 1;
    } else {
      assert(0 && !!"unsupported chbputvf format directive");
      break;
    } 
  }
}

void chbputf(chbuf_t* pb, const char *fmt, ...)
{
  va_list args;
  assert(pb); assert(fmt);
  va_start(args, fmt);
  chbputvf(pb, fmt, args);
  va_end(args);
}

void chbput4le(unsigned v, chbuf_t* pb)
{
  chbputc((int)(v & 0xFF), pb); v >>= 8;
  chbputc((int)(v & 0xFF), pb); v >>= 8;
  chbputc((int)(v & 0xFF), pb); v >>= 8;
  chbputc((int)(v & 0xFF), pb);
}

void chbput8le(unsigned long long v, chbuf_t* pb)
{
  chbputc((int)(v & 0xFF), pb); v >>= 8;
  chbputc((int)(v & 0xFF), pb); v >>= 8;
  chbputc((int)(v & 0xFF), pb); v >>= 8;
  chbputc((int)(v & 0xFF), pb); v >>= 8;
  chbputc((int)(v & 0xFF), pb); v >>= 8;
  chbputc((int)(v & 0xFF), pb); v >>= 8;
  chbputc((int)(v & 0xFF), pb); v >>= 8;
  chbputc((int)(v & 0xFF), pb);
}


void chbputtime(const char *fmt, const struct tm *tp, chbuf_t* pcb)
{
  char buf[201]; /* always enough? */
  assert(fmt); assert(pcb);
  if (tp != NULL && strftime(buf, 200, fmt, tp)) chbputs(buf, pcb);
}

void chbinsc(chbuf_t* pcb, size_t n, int c)
{
  char *pc = bufins(pcb, n); *pc = c;
}

void chbinss(chbuf_t* pcb, size_t n, const char *s)
{
  while (*s) {
    char *pc = bufins(pcb, n); *pc = *s;
    ++n; ++s;  
  }
}

char* chbset(chbuf_t* pb, const char *s, size_t n)
{
  bufclear(pb);
  chbput(s, n, pb);
  return chbdata(pb);
}

char* chbsets(chbuf_t* pb, const char *s)
{
  bufclear(pb);
  chbputs(s, pb);
  return chbdata(pb);
}

char *chbsetf(chbuf_t* pb, const char *fmt, ...)
{
  va_list args;
  assert(pb); assert(fmt);
  bufclear(pb);
  va_start(args, fmt);
  chbputvf(pb, fmt, args);
  va_end(args);
  return chbdata(pb);
}

char* chbdata(chbuf_t* pb)
{
  *(char*)bufnewbk(pb) = 0;
  pb->fill -= 1;
  return pb->buf; 
}

void chbcpy(chbuf_t* pb, const chbuf_t* pcb)
{
  size_t n = chblen(pcb);
  bufresize(pb, n);
  memcpy((char*)pb->buf, (char*)pcb->buf, n);
}

void chbcat(chbuf_t* pb, const chbuf_t* pcb)
{
  size_t i = chblen(pb), n = chblen(pcb);
  bufresize(pb, i+n);
  memcpy((char*)pb->buf+i, (char*)pcb->buf, n);
}

dstr_t chbclose(chbuf_t* pb)
{
  dstr_t s;
  *(char*)bufnewbk(pb) = 0;
  s = pb->buf; pb->buf = NULL; /* pb is finalized */
  return s; 
}

int chbuf_cmp(const void *p1, const void *p2)
{
  chbuf_t *pcb1 = (chbuf_t *)p1, *pcb2 = (chbuf_t *)p2; 
  const unsigned char *pc1, *pc2;
  size_t n1, n2, i = 0;
  assert(pcb1); assert(pcb2);
  n1 = chblen(pcb1), n2 = chblen(pcb2);
  pc1 = pcb1->buf, pc2 = pcb2->buf;
  while (i < n1 && i < n2) {
    int d = (int)*pc1++ - (int)*pc2++;
    if (d < 0) return -1; if (d > 0) return 1;
    ++i; 
  }
  if (n1 < n2) return -1; if (n1 > n2) return 1;
  return 0;
}

char *fgetlb(chbuf_t *pcb, FILE *fp)
{
  char buf[256], *line; size_t len;
  assert(fp); assert(pcb);
  chbclear(pcb);
  line = fgets(buf, 256, fp); /* sizeof(buf) */
  if (!line) return NULL;
  len = strlen(line);
  if (len > 0 && line[len-1] == '\n') {
    line[len-1] = 0;
    if (len > 1 && line[len-2] == '\r') line[len-2] = 0;
    return chbsets(pcb, line);
  } else for (;;) {
    if (len > 0 && line[len-1] == '\r') line[len-1] = 0;
    chbputs(line, pcb);
    line = fgets(buf, 256, fp); /* sizeof(buf) */
    if (!line) break;
    len = strlen(line);
    if (len > 0 && line[len-1] == '\n') {
      line[len-1] = 0;
      if (len > 1 && line[len-2] == '\r') line[len-2] = 0;
      chbputs(line, pcb);
      break;
    }
  } 
  return chbdata(pcb);
}

/* convert wchar_t string to utf-8 string
 * if rc = 0, return NULL on errors, else subst rc */
char *wcsto8cb(const wchar_t *wstr, int rc, chbuf_t *pcb)
{
  bool convok = true;
  chbclear(pcb);
  while (*wstr) {
    unsigned c = (unsigned)*wstr++;
    if (c > 0x1FFFFF) {
      if (rc) chbputc(rc, pcb);
      else { convok = false; break; }
    }
    chbputlc(c, pcb);
  }
  if (!convok) return NULL;
  return chbdata(pcb);
}


/* wide char buffers */

/* convert utf-8 string to wide chars in wchar_t buffer */
wchar_t *s8ctowcb(const char *str, wchar_t rc, buf_t *pb)
{
  char *s8c = (char *)str;
  bool convok = true;
  wchar_t wc;
  assert(s8c); assert(pb); 
  assert(pb->esz == sizeof(wchar_t));
  bufclear(pb);
  while (*s8c) {
    unsigned long c = unutf8((unsigned char **)&s8c);
    if (c == (unsigned long)-1 || c < WCHAR_MIN || c > WCHAR_MAX) {
      if (rc) wc = rc;
      else { convok = false; break; }
    } else {
      wc = (wchar_t)c;
    }
    *(wchar_t*)bufnewbk(pb) = wc; 
  }
  *(wchar_t*)bufnewbk(pb) = 0; 
  if (!convok) return NULL;
  return (wchar_t *)bufdata(pb);
}

/* unicode char (unsigned long) buffers */

/* convert utf-8 string to unicode chars in unsigned long buffer */
unsigned long *s8ctoucb(const char *str, unsigned long rc, buf_t *pb)
{
  char *s8c = (char *)str;
  bool convok = true;
  unsigned long uc;
  assert(s8c); assert(pb); 
  assert(pb->esz == sizeof(unsigned long));
  bufclear(pb);
  while (*s8c) {
    unsigned long c = unutf8((unsigned char **)&s8c);
    if (c == (unsigned)-1) {
      if (rc) uc = rc;
      else { convok = false; break; }
    } else {
      uc = c;
    }
    *(unsigned long*)bufnewbk(pb) = uc; 
  }
  *(unsigned long*)bufnewbk(pb) = 0; 
  if (!convok) return NULL;
  return (unsigned long *)bufdata(pb);
}

/* grow pcb to get to the required alignment */
void binalign(chbuf_t* pcb, size_t align)
{
  size_t addr = buflen(pcb), n;
  assert(align == 1 || align == 2 || align == 4 || align == 8 || align == 16);
  n = addr % align;
  if (n > 0) bufresize(pcb, addr+(align-n));
}

/* lay out numbers as little-endian binary into cbuf */
void binchar(int c, chbuf_t* pcb) /* align=1 */
{
  chbputc(c, pcb);
}

void binshort(int s, chbuf_t* pcb) /* align=2 */
{
  binalign(pcb, 2);
  chbputc((s >> 0) & 0xFF, pcb);
  chbputc((s >> 8) & 0xFF, pcb);
}

void binint(int i, chbuf_t* pcb) /* align=4 */
{
  binalign(pcb, 4);
  chbputc((i >> 0)  & 0xFF, pcb);
  chbputc((i >> 8)  & 0xFF, pcb);
  chbputc((i >> 16) & 0xFF, pcb);
  chbputc((i >> 24) & 0xFF, pcb);
}

void binllong(long long ll, chbuf_t* pcb) /* align=8 */
{
  binalign(pcb, 8);
  chbputc((ll >> 0)  & 0xFF, pcb);
  chbputc((ll >> 8)  & 0xFF, pcb);
  chbputc((ll >> 16) & 0xFF, pcb);
  chbputc((ll >> 24) & 0xFF, pcb);
  chbputc((ll >> 32) & 0xFF, pcb);
  chbputc((ll >> 40) & 0xFF, pcb);
  chbputc((ll >> 48) & 0xFF, pcb);
  chbputc((ll >> 56) & 0xFF, pcb);
}

void binuchar(unsigned uc, chbuf_t* pcb) /* align=1 */
{
  chbputc((int)uc, pcb);
}

void binushort(unsigned us, chbuf_t* pcb) /* align=2 */
{
  binshort((int)us, pcb);
}

void binuint(unsigned ui, chbuf_t* pcb) /* align=4 */
{
  binint((int)ui, pcb);
}

void binullong(unsigned long long ull, chbuf_t* pcb) /* align=8 */
{
  binllong((long long)ull, pcb);
}

void binfloat(float f, chbuf_t* pcb) /* align=4 */
{
  union { int i; float f; } inf; inf.f = f;
  binint(inf.i, pcb); 
}

void bindouble(double d, chbuf_t* pcb) /* align=8 */
{
  union { long long ll; double d; } ind; ind.d = d;
  binllong(ind.ll, pcb); 
}


/* symbols */

static struct { char **a; char ***v; size_t sz; size_t u; size_t maxu; } g_symt;

static unsigned long hashs(const char *s) {
  unsigned long i = 0, l = (unsigned long)strlen(s), h = l;
  while (i < l) h = (h << 4) ^ (h >> 28) ^ s[i++];
  return h ^ (h  >> 10) ^ (h >> 20);
}

const char *symname(sym_t s) 
{
  int sym = (int)s; const char *name = NULL;
  assert(sym >= 0); assert(sym-1 < (int)g_symt.u);
  if (sym > 0) { name = g_symt.a[sym-1]; assert(name); }
  return name;
}

sym_t intern(const char *name) 
{
  size_t i, j; int sym;
  if (name == NULL) return (sym_t)0;
  if (g_symt.sz == 0) { /* init */
    g_symt.a = excalloc(64, sizeof(char*));
    g_symt.v = excalloc(64, sizeof(char**));
    g_symt.sz = 64, g_symt.maxu = 64 / 2;
    i = hashs(name) & (g_symt.sz-1);
  } else {
    unsigned long h = hashs(name);
    for (i = h & (g_symt.sz-1); g_symt.v[i]; i = (i-1) & (g_symt.sz-1))
      if (strcmp(name, *g_symt.v[i]) == 0) return (sym_t)(g_symt.v[i]-g_symt.a+1);
    if (g_symt.u == g_symt.maxu) { /* rehash */
      size_t nsz = g_symt.sz * 2;
      char **na = excalloc(nsz, sizeof(char*));
      char ***nv = excalloc(nsz, sizeof(char**));
      for (i = 0; i < g_symt.sz; i++)
        if (g_symt.v[i]) {
          for (j = hashs(*g_symt.v[i]) & (nsz-1); nv[j]; j = (j-1) & (nsz-1)) ;
          nv[j] = g_symt.v[i] - g_symt.a + na;
        }
      free(g_symt.v); g_symt.v = nv; g_symt.sz = nsz; g_symt.maxu = nsz / 2;
      memcpy(na, g_symt.a, g_symt.u * sizeof(char*)); free(g_symt.a); g_symt.a = na; 
      for (i = h & (g_symt.sz-1); g_symt.v[i]; i = (i-1) & (g_symt.sz-1)) ;
    }
  }
  *(g_symt.v[i] = g_symt.a + g_symt.u) = 
    strcpy(exmalloc(strlen(name)+1), name);
  sym = (int)((g_symt.u)++);
  return (sym_t)(sym+1);
}

sym_t internf(const char *fmt, ...)
{
  va_list args; sym_t s; chbuf_t cb; 
  assert(fmt); chbinit(&cb);
  va_start(args, fmt);
  chbputvf(&cb, fmt, args);
  va_end(args);
  s = intern(chbdata(&cb));
  chbfini(&cb);
  return s;
}

void clearsyms(void)
{
  if (g_symt.sz != 0) {
    size_t i;
    for (i = 0; i < g_symt.sz; ++i) {
      char **p = g_symt.v[i];
      if (p) free(*p);
    }
    free(g_symt.v); g_symt.v = NULL;
    free(g_symt.a); g_symt.a = NULL;
    g_symt.sz = g_symt.u = g_symt.maxu = 0;
  }
}


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

/* skips leading whitespace */
char *strtriml(const char* str)
{
  assert(str);
  while (isspace(*str)) ++str;
  return (char *)str;
}

/* zeroes out trailing whitespace */
char *strtrimr(char* str)
{
  size_t i;
  assert(str);
  i = strlen(str);
  while (i > 0 && str[i-1] && isspace(str[i-1]))
    str[i-1] = 0, --i;
  return str;
} 

/* strtrimr, then strtriml */
char *strtrim(char* str)
{
  size_t i;
  assert(str);
  i = strlen(str);
  while (i > 0 && str[i-1] && isspace(str[i-1]))
    str[i-1] = 0, --i;
  while (*str && *(unsigned char *)str <= ' ')
    ++str;
  return str;
}

/* normalize whitespace to single ' ', trim */
char *strnorm(char* str)
{
  char *to = str, *from = str;
  /* don't use isspace - it may fail on utf-8 */
  for (;;) {
    int c = *(unsigned char *)from++;
    if (!c) { 
      *to = 0; 
      break; 
    } else if (c <= ' ') {
      /* copy space only if it separates */
      if (to > str && *(unsigned char *)from > ' ')
        *to++ = ' ';
    } else {
      *to++ = c;
    }
  }
  return str;
}

/* simple shell-style pattern matcher
 *
 *	*	     matches zero or more of any character
 *	?	     matches any single character
 *	[^xxx]	matches any single character not in the set given
 *	[!xxx]	matches any single character not in the set given
 *	[xxx]	 matches any single character in the set given
 *	The - character is understood to be a range indicator as in a-z
 *	If the ] character is the first of the set it is considered
 *	as part of the set, not the terminator.
 */
bool gmatch(const char *src, const char *pat)
{
  assert(src); assert(pat);
  while (*src) {
    switch (*pat) {
      case 0: /* src is not empty, but pat is */
        return false;
      case '?': /* match any single char */
        ++src; ++pat;
        continue;
      case '*': /* match 0 or more chars */
        /* basic optimization: skip '*'s */
        while (*pat == '*') ++pat;
        /* check if something follows the '*' */
        if (*pat == 0) return true;
        /* try to locate tail of src that matches pat */
        while (*src) if (gmatch(src++, pat)) return true;
        /* no tail of src matches pat */
        return false;
      case '[': { /* char class */
        int c = *src++; /* src is pos-d for the next iteration */
        bool in = false; /* c is in the (non-inverted) class */
        bool in_means_match = true; /* meaning of being in cc */
        bool esc = true; /* escape state at the beginning of cc */
        ++pat;
        /* check for inversion of meaning */
        if (*pat == '!' || *pat == '^') { 
          ++pat; in_means_match = false; 
        }
        /* c is in if it is in at least one of the ranges */
        while (*pat) {
          int cfrom, cto;
          cfrom = *pat;
          if (esc) { /* cfrom is just a char */
            esc = false;
          } else { /* check for special chars */
            if (cfrom == ']') break;
            if (cfrom == '\\') { esc = true; continue; }
          }
          ++pat;
          if (*pat == '-' && *(pat+1) != ']') { /* range spec */
            ++pat; cto = *pat++;
            if (cto == '\\') cto = *pat++;
          } else { /* single char spec */
            cto = cfrom;
          }
          if (c >= cfrom && c <= cto) { /* in range! */
            in = true; break;
          }
        } 
        /* see if we need to stop the matching here */
        if (in && !in_means_match) return false;
        if (!in && in_means_match) return false;
        /* skip the rest of the char class */
        while (*pat) {
          if (esc) esc = false;
          else if (*pat == ']') break;
          else if (*pat == '\\') esc = true;
          ++pat;
        }
        /* leave pat pointing to the char after [xxx] */
        ++pat;
        continue;
      } 
      case '\\': /* escape next pat char */
        ++pat;
        /* fall thru */
      default: /* char/char match */
        if (*src != *pat) return false;
        ++src; ++pat;
        continue;
    }
  }
  /* src is empty: check if pat matches it */
  while (*pat == '*') ++pat;
  return *pat == 0;
}


/* warnings and -w */

void setwlevel(int level)
{
  g_wlevel = level;
}

int getwlevel(void)
{
  int n;
  n = g_wlevel;
  return n;
}

/* verbose output and -v */
void setverbosity(int v)
{
  g_verbosity = v;
}

int getverbosity(void)
{
  int v;
  v = g_verbosity;
  return v;
}

void incverbosity(void)
{
  ++g_verbosity;
}

static void verbosenfa(int n, const char *fmt, va_list args)
{
  int v;
  v = g_verbosity;
  if (n > v) return;
  fflush(stdout);
  vfprintf(stderr, fmt, args);
}

void verbosenf(int n, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  verbosenfa(n, fmt, args);
  va_end(args);
}

void verbosef(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  verbosenfa(1, fmt, args);
  va_end(args);
}

void vverbosef(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  verbosenfa(2, fmt, args);
  va_end(args);
}

void vvverbosef(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  verbosenfa(3, fmt, args);
  va_end(args);
}


/* logger and -q */

void setquietness(int q)
{
  g_quietness = q;
}

int getquietness(void)
{
  int q;
  q = g_quietness;
  return q;
}

void incquietness(void)
{
  ++g_quietness;
}

static void lognfa(int n, const char *fmt, va_list args)
{
  if (n <= g_quietness) return;
  fflush(stdout);
  vfprintf(stderr, fmt, args);
  fflush(stderr);
}

void logenf(int n, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  lognfa(n, fmt, args);
  va_end(args);
}

/* ordinary stderr log: shut up by -q */
void logef(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  lognfa(1, fmt, args);
  va_end(args);
}

/* loud stderr log: shut up by -qq */
void llogef(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  lognfa(2, fmt, args);
  va_end(args);
}

/* very loud stderr log: shut up by -qqq */
void lllogef(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  lognfa(3, fmt, args);
  va_end(args);
}

/* progname: return stored name of program */
const char *progname(void)
{
  const char *str;
  str = g_progname;
  return str;
}

/* setprogname: set stored name of program */
void setprogname(const char *str)
{
  char *pname;
  assert(str);
  str = getfname(str);
  pname = exstrndup(str, spanfbase(str));
  g_progname = pname;
}

/* usage: return stored usage string */
const char *usage(void)
{
  const char *s;
  s = g_usage;
  return s;
}

/* setusage: set stored usage string */
void setusage(const char *str)
{
  g_usage = exstrdup(str);
}

/* eusage: report wrong usage */
void eusage(const char *fmt, ...)
{
  va_list args;

  fflush(stdout);
  if (progname() != NULL)
    fprintf(stderr, "%s: ", progname());

  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);

  if (fmt[0] != '\0' && fmt[strlen(fmt)-1] == ':')
    fprintf(stderr, " %s", strerror(errno));
  fprintf(stderr, "\n");

  if (progname() != NULL && usage() != NULL)
    fprintf(stderr, "usage: %s %s\n", progname(), usage());

  exit(1);
}

void eoptreset(void)
{
  eoptind = 1;
  eopterr = 1;
  eoptopt = 0;
  eoptarg = NULL;
  eoptich = 0;
}

int egetopt(int argc, char* argv[], const char* opts)
{
  int c; char *popt;

  /* set the name of the program if it isn't done already */
  if (progname() == NULL) setprogname(argv[0]);

  /* check if it's time to stop */
  if (eoptich == 0) { 
    if (eoptind >= argc) 
      return EOF; 
    if (argv[eoptind][0] != '-' ||
        argv[eoptind][1] == '\0')
      return EOF;
    if (strcmp(argv[eoptind], "--") == 0) {
      ++eoptind;
      return EOF;
    }
  }

  /* get next option char */
  c = argv[eoptind][++eoptich];

  /* check if it's legal */
  if (c == ':' || (popt = strchr(opts, c)) == NULL) {
    if (eopterr) {
      eusage("illegal option: -%c", c);
    }
    if (argv[eoptind][++eoptich] == '\0') {
      ++eoptind; 
      eoptich = 0;
    }
    eoptopt = c;
    return '?';
  }

  /* check if it should be accompanied by arg */
  if (popt[1] == ':') {
    if (argv[eoptind][++eoptich] != '\0') {
      eoptarg  = argv[eoptind++] + eoptich;
    } else if (++eoptind >= argc) {
      if (eopterr) {
        eusage("option -%c requires an argument", c);
      }
      eoptich = 0;
      eoptopt = c;
      return '?';
    } else {
      eoptarg = argv[eoptind++];
    }
    eoptich = 0;
  } else {
    if (argv[eoptind][eoptich + 1] == '\0') {
      ++eoptind;
      eoptich = 0;
    }
    eoptarg  = NULL;
  }

  /* eoptopt, eoptind and eoptarg are updated */
  return c;
}


/* simple char input abstraction */

static int null_getc(void *ds) { return EOF; }
static int null_ungetc(int c, void *ds) { return EOF; }
static char *null_gets(char *s, int n, void *ds) { return NULL; }
static size_t null_read(void *s, size_t sz, size_t c, void *ds) { return 0; }
static int null_ctl(const char *cmd, void *arg, void *ds) 
{ 
  errno = EINVAL;
  return -1; 
}
static ii_t null_ii = {
  null_getc,
  null_ungetc,
  null_gets,
  null_read,
  null_ctl
};
pii_t null_pii = &null_ii; 

static int file_ctl(const char *cmd, void *arg, FILE *fp) 
{ 
  assert(cmd);
  if (streql(cmd, "eof")) return feof(fp);
  if (streql(cmd, "error")) return ferror(fp);
  if (streql(cmd, "clearerr")) { clearerr(fp); return 0; }
  if (streql(cmd, "getpos")) return fgetpos(fp, arg);
  if (streql(cmd, "setpos")) return fsetpos(fp, arg);
  if (streql(cmd, "rewind")) { rewind(fp); return 0; }
  errno = EINVAL;
  return -1; 
}

static ii_t FILE_ii = {
  (int (*)(void*))fgetc,
  (int (*)(int, void*))ungetc,
  (char *(*)(char*, int, void*))fgets,
  (size_t (*)(void*, size_t, size_t, void*))fread,
  (int (*)(const char*, void*, void*))file_ctl
};
pii_t FILE_pii = &FILE_ii; 

static int str_getc(const char **ppc)
{
  int c;
  assert(ppc && *ppc);
  if (!(c = **ppc)) return EOF;
  ++*ppc;
  return c;
}
static int str_ungetc(int c, const char **ppc)
{
  assert(ppc && *ppc);
  --*ppc;
  assert(c == **ppc);
  return c;
}
static char *str_gets(char *buf, int n, const char **ppc)
{
  char *pc = buf;
  assert(buf);
  assert(ppc && *ppc);
  if (n <= 0) return NULL;
  while (--n) {
    int c = **ppc;
    if (!c) {
      if (pc == buf) return NULL;
      else break;
    }
    ++*ppc;
    if ((*pc++ = c) == '\n') break;
  }
  *pc = '\0';
  return buf;
}
static size_t str_read(void *buf, size_t sz, size_t cnt, const char **ppc)
{
  size_t i, n = cnt * sz;
  char *pc = (char*)buf;
  assert(buf);
  assert(ppc && *ppc);
  for (i = 0; i < n; ++i) {
    int c = **ppc;
    if (!c) break;
    ++*ppc;
    *pc++ = c;
  }
  return i/sz;
  /* small problem: does not guarantee that no partial object 
   * is written into buf (in case of sz > 1) */
}
static ii_t strptr_ii = {
  (int (*)(void*))str_getc,
  (int (*)(int, void*))str_ungetc,
  (char *(*)(char*, int, void*))str_gets,
  (size_t (*)(void*, size_t, size_t, void*))str_read,
  (int (*)(const char*, void*, void*))null_ctl
};
pii_t strptr_pii = &strptr_ii; 


/* simple char output abstraction */

static int null_putc(int c, void *ds) { return c; }
static int null_puts(const char *s, void *ds) { return 1; }
static size_t null_write(const void *s, size_t sz, size_t c, void *ds) { return c; }
static int null_flush(void *ds) { return 0; }
static oi_t null_oi = {
  null_putc,
  null_puts,
  null_write,
  null_flush,
  null_ctl
};
poi_t null_poi = &null_oi; 

static oi_t FILE_oi = {
  (int (*)(int, void*))fputc,
  (int (*)(const char*, void*))fputs,
  (size_t (*)(const void*, size_t, size_t, void*))fwrite,
  (int (*)(void*))fflush,
  (int (*)(const char*, void*, void*))file_ctl
};
poi_t FILE_poi = &FILE_oi; 

static oi_t cbuf_oi = {
  (int (*)(int, void*))chbputc,
  (int (*)(const char*, void*))chbputs,
  (size_t (*)(const void*, size_t, size_t, void*))chbwrite,
  null_flush,
  null_ctl
};
poi_t cbuf_poi = &cbuf_oi; 


/* json i/o "file" */

typedef struct jfile_tag {
  /* i/o stream */
  size_t (*read)(void*, size_t, size_t, void*);
  size_t (*write)(const void*, size_t, size_t, void*);
  int (*getc)(void*);
  int (*ungetc)(int, void*);
  int (*putc)(int, void*);
  int (*puts)(const char*, void*);
  int (*flush)(void*);
  void* pfile;
  dstr_t fname;
  int lineno;
  int indent;
  int tt; /* lookahead token type or -1 */
  bool autoflush;
  /* tmp bufs */
  chbuf_t tbuf; /* token */
} jfile_t;

static void jfile_init_ii(jfile_t* pjf, pii_t pii, void* dp, bool bbuf)
{
  assert(pjf); assert(pii);
  memset(pjf, 0, sizeof(jfile_t));
  pjf->pfile = dp;
  pjf->read = pii->read;
  pjf->getc = pii->getc;
  pjf->ungetc = pii->ungetc;
  pjf->write = null_poi->write;
  pjf->putc = null_poi->putc;
  pjf->puts = null_poi->puts;
  pjf->flush = null_poi->flush;
  pjf->lineno = 1;
  pjf->indent = 0;
  pjf->tt = -1;
  pjf->autoflush = !bbuf;
  chbinit(&pjf->tbuf);
}

static void jfile_init_oi(jfile_t* pjf, poi_t poi, void* dp, bool bbuf)
{
  assert(pjf); assert(poi);
  memset(pjf, 0, sizeof(jfile_t));
  pjf->pfile = dp;
  pjf->read = null_pii->read;
  pjf->getc = null_pii->getc;
  pjf->ungetc = null_pii->ungetc;
  pjf->write = poi->write;
  pjf->putc = poi->putc;
  pjf->puts = poi->puts;
  pjf->flush = poi->flush;
  pjf->lineno = 1;
  pjf->indent = 0;
  pjf->tt = -1;
  pjf->autoflush = !bbuf;
  chbinit(&pjf->tbuf);
}

static void jfile_fini(jfile_t* pjf) 
{
  free(pjf->fname); 
  chbfini(&pjf->tbuf);
}

static void jfile_close(jfile_t* pjf) 
{
  if (pjf) {
    if (pjf->read == (size_t (*)(void*, size_t, size_t, void*))&fread ||
        pjf->write == (size_t (*)(const void*, size_t, size_t, void*))&fwrite) {
      fclose(pjf->pfile);
    }
    jfile_fini(pjf);
  }
}

static void jfile_verr(bool in, jfile_t* pjf, const char *fmt, va_list args)
{
  assert(pjf);
  assert(fmt);
  chbclear(&pjf->tbuf);
  chbputvf(&pjf->tbuf, fmt, args);
  /* for now, just print error and exit; todo: longjmp */
  fprintf(stderr, "JSON error: %s\naborting execution...", chbdata(&pjf->tbuf));
  exit(EXIT_FAILURE);
}

static void jfile_ierr(jfile_t* pjf, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  jfile_verr(true, pjf, fmt, args);
  va_end(args);
}

static void jfile_oerr(jfile_t* pjf, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  jfile_verr(false, pjf, fmt, args);
  va_end(args);
}

/* json token types */
typedef enum jtoken_tag {
  JTK_WHITESPACE,
  JTK_NULL,
  JTK_TRUE,
  JTK_FALSE,
  JTK_INT,
  JTK_UINT,
  JTK_FLOAT,
  JTK_STRING,
  JTK_OBRK,
  JTK_CBRK,
  JTK_OBRC,
  JTK_CBRC,
  JTK_COMMA,
  JTK_COLON,
  JTK_EOF
} jtoken_t;

/* jlex: splits input into tokens delivered via char buf [from jsonlex.ss, patched!] */
static jtoken_t jlex(int (*in_getc)(void*), int (*in_ungetc)(int, void*), void *in, chbuf_t *pcb)
{
  int c; 
  bool gotminus = false;
  assert(pcb);

  chbclear(pcb);
  goto state_0;
  state_0:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if (c == ':') {
      chbputc(c, pcb);
      goto state_14;
    } else if (c == ',') {
      chbputc(c, pcb);
      goto state_13;
    } else if (c == '}') {
      chbputc(c, pcb);
      goto state_12;
    } else if (c == '{') {
      chbputc(c, pcb);
      goto state_11;
    } else if (c == ']') {
      chbputc(c, pcb);
      goto state_10;
    } else if (c == '[') {
      chbputc(c, pcb);
      goto state_9;
    } else if (c == '\"') {
      chbputc(c, pcb);
      goto state_8;
    } else if (c == '-') {
      chbputc(c, pcb);
      gotminus = true;
      goto state_7;
    } else if (c == '0') {
      chbputc(c, pcb);
      goto state_6;
    } else if ((c >= '1' && c <= '9')) {
      chbputc(c, pcb);
      goto state_5;
    } else if (c == 'f') {
      chbputc(c, pcb);
      goto state_4;
    } else if (c == 't') {
      chbputc(c, pcb);
      goto state_3;
    } else if (c == 'n') {
      chbputc(c, pcb);
      goto state_2;
    } else if (c == '\t' || c == '\n' || c == '\r' || c == ' ') {
      chbputc(c, pcb);
      goto state_1;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_1:
    c = in_getc(in);
    if (c == EOF) {
      return JTK_WHITESPACE;
    } else if (c == '\t' || c == '\n' || c == '\r' || c == ' ') {
      chbputc(c, pcb);
      goto state_1;
    } else {
      in_ungetc(c, in);
      return JTK_WHITESPACE;
    }
  state_2:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if (c == 'u') {
      chbputc(c, pcb);
      goto state_33;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_3:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if (c == 'r') {
      chbputc(c, pcb);
      goto state_30;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_4:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if (c == 'a') {
      chbputc(c, pcb);
      goto state_26;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_5:
    c = in_getc(in);
    if (c == EOF) {
      return gotminus ? JTK_INT : JTK_UINT;
    } else if (c == '.') {
      chbputc(c, pcb);
      goto state_22;
    } else if (c == 'E' || c == 'e') {
      chbputc(c, pcb);
      goto state_21;
    } else if ((c >= '0' && c <= '9')) {
      chbputc(c, pcb);
      goto state_5;
    } else {
      in_ungetc(c, in);
      return gotminus ? JTK_INT : JTK_UINT;
    }
  state_6:
    c = in_getc(in);
    if (c == EOF) {
      return gotminus ? JTK_INT : JTK_UINT;
    } else if (c == '.') {
      chbputc(c, pcb);
      goto state_22;
    } else if (c == 'E' || c == 'e') {
      chbputc(c, pcb);
      goto state_21;
    } else {
      in_ungetc(c, in);
      return gotminus ? JTK_INT : JTK_UINT;
    }
  state_7:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if (c == '0') {
      chbputc(c, pcb);
      goto state_6;
    } else if ((c >= '1' && c <= '9')) {
      chbputc(c, pcb);
      goto state_5;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_8:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if (c == '\\') {
      chbputc(c, pcb);
      goto state_16;
    } else if (c == '\"') {
      chbputc(c, pcb);
      goto state_15;
    } else if (!((c >= 0x00 && c <= 0x1F) /* this place is patched! */
                 || c == '\"' || c == '\\')) {
      chbputc(c, pcb);
      goto state_8;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_9:
    return JTK_OBRK;
  state_10:
    return JTK_CBRK;
  state_11:
    return JTK_OBRC;
  state_12:
    return JTK_CBRC;
  state_13:
    return JTK_COMMA;
  state_14:
    return JTK_COLON;
  state_15:
    return JTK_STRING;
  state_16:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if (c == 'u') {
      chbputc(c, pcb);
      goto state_17;
    } else if (c == '\"' || c == '/' || c == '\\' || c == 'b' || c == 'f' || c == 'n' || c == 'r' || c == 't') {
      chbputc(c, pcb);
      goto state_8;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_17:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
      chbputc(c, pcb);
      goto state_18;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_18:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
      chbputc(c, pcb);
      goto state_19;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_19:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
      chbputc(c, pcb);
      goto state_20;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_20:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
      chbputc(c, pcb);
      goto state_8;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_21:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if (c == '+' || c == '-') {
      chbputc(c, pcb);
      goto state_25;
    } else if ((c >= '0' && c <= '9')) {
      chbputc(c, pcb);
      goto state_24;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_22:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if ((c >= '0' && c <= '9')) {
      chbputc(c, pcb);
      goto state_23;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_23:
    c = in_getc(in);
    if (c == EOF) {
      return JTK_FLOAT;
    } else if ((c >= '0' && c <= '9')) {
      chbputc(c, pcb);
      goto state_23;
    } else if (c == 'E' || c == 'e') {
      chbputc(c, pcb);
      goto state_21;
    } else {
      in_ungetc(c, in);
      return JTK_FLOAT;
    }
  state_24:
    c = in_getc(in);
    if (c == EOF) {
      return JTK_FLOAT;
    } else if ((c >= '0' && c <= '9')) {
      chbputc(c, pcb);
      goto state_24;
    } else {
      in_ungetc(c, in);
      return JTK_FLOAT;
    }
  state_25:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if ((c >= '0' && c <= '9')) {
      chbputc(c, pcb);
      goto state_24;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_26:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if (c == 'l') {
      chbputc(c, pcb);
      goto state_27;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_27:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if (c == 's') {
      chbputc(c, pcb);
      goto state_28;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_28:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if (c == 'e') {
      chbputc(c, pcb);
      goto state_29;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_29:
    return JTK_FALSE;
  state_30:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if (c == 'u') {
      chbputc(c, pcb);
      goto state_31;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_31:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if (c == 'e') {
      chbputc(c, pcb);
      goto state_32;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_32:
    return JTK_TRUE;
  state_33:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if (c == 'l') {
      chbputc(c, pcb);
      goto state_34;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_34:
    c = in_getc(in);
    if (c == EOF) {
      goto err;
    } else if (c == 'l') {
      chbputc(c, pcb);
      goto state_35;
    } else {
      in_ungetc(c, in);
      goto err;
    }
  state_35:
    return JTK_NULL;

  err:
    return JTK_EOF;
}

/* peek at the next non-whitespace token in the stream */
static jtoken_t jfile_peekt(jfile_t* pjf)
{
  if (pjf->tt >= 0) {
    /* lookahead token is in tbuf already */
    assert(pjf->tt > JTK_WHITESPACE && pjf->tt <= JTK_EOF);
    return (jtoken_t)pjf->tt; 
  } 
  assert(chbempty(&pjf->tbuf));
  for (;;) {
    jtoken_t tk = jlex(pjf->getc, pjf->ungetc, pjf->pfile, &pjf->tbuf);
    if (tk == JTK_EOF) {
      int c = (pjf->getc)(pjf->pfile);
      if (c == EOF) { 
        /* real EOF */
        pjf->tt = JTK_EOF;
        chbclear(&pjf->tbuf);
        return JTK_EOF;
      } else {
        /* lex error */
        (pjf->ungetc)(c, pjf->pfile);
        jfile_ierr(pjf, "unexpected character: %c", c);
      }
    } else if (tk == JTK_WHITESPACE) {
      pjf->lineno += (int)strcnt(chbdata(&pjf->tbuf), '\n');
      chbclear(&pjf->tbuf);
      continue;
    } else {
      pjf->tt = tk;
      return tk;
    }
  } 
}

/* drop next token in the stream */
static void jfile_dropt(jfile_t* pjf)
{
  /* clear lookehead unless it is real EOF */
  if (pjf->tt >= 0 && pjf->tt != JTK_EOF) {
    pjf->tt = -1;
    chbclear(&pjf->tbuf);
  }
}

/* decode lookahead string token as utf-8 into pcb */
static char* jfile_tstring(jfile_t* pjf, chbuf_t* pcb)
{
  char *ts; int32_t c32h = 0;
  assert(pjf->tt == JTK_STRING);
  chbclear(pcb);
  ts = chbdata(&pjf->tbuf);
  /* convert surrogate pairs to normal unicode chars */
  assert(*ts == '\"');
  for (ts += 1; *ts != '\"'; ) {
    int32_t c32;
    if (*ts == '\\') {
      if (ts[1] == '/') c32 = '/', ts+= 2; /* JSON-specific escape */
      else c32 = strtocc32(ts, &ts, NULL); /* other JSON escapes are subset of C99 */
    } else {
      c32 = (int32_t)strtou8c(ts, &ts);
    }
    if (c32 == -1) jfile_ierr(pjf, "invalid chars in string: %s", ts);
    /* TODO: check c32 for valid UNICODE char ranges */
    if (c32 >= 0xD800 && c32 <= 0xDBFF) {
      /* first char of a surrogate pair */
      if (c32h != 0) jfile_ierr(pjf, "surrogate char sequence error");
      c32h = c32;
      continue;
    } else if (c32 >= 0xDC00 && c32 <= 0xDFFF) {
      /* second char of a surrogate pair */
      if (c32h == 0) jfile_ierr(pjf, "surrogate char sequence error");
      /* note: UTF-16 rfc2781 allows high part to be zero (c32h == 0xD800)! */
      c32 = ((c32h - 0xD800) << 10) + (c32 - 0xDC00);
      c32h = 0;
    }
    chbputlc(c32, pcb);
  }
  /* check for incomplete surrogates */
  if (c32h != 0) jfile_ierr(pjf, "surrogate char sequence error");
  /* note: pcb may legally contain zeroes! */
  return chbdata(pcb);
}


/* encode utf-8 string of length n into token buf */
static void jfile_tunstring(jfile_t* pjf, const char *str, size_t n)
{
  chbuf_t *pcb = &pjf->tbuf; char buf[40];
  chbclear(pcb);
  chbputc('\"', pcb);
  while (n > 0) {
    int32_t c32; char *end;
    int c = *str & 0xFF;
    /* check for control chars manually */
    if (c <= 0x1F) {
      switch (c) {
        case '\b' : chbputs("\\b", pcb); break;
        case '\f' : chbputs("\\f", pcb); break;
        case '\n' : chbputs("\\n", pcb); break;
        case '\r' : chbputs("\\r", pcb); break;
        case '\t' : chbputs("\\t", pcb); break;
        default   : sprintf(buf, "\\u%.4X", c); chbputs(buf, pcb); break;
      }
      ++str; --n;
      continue;
    } else if (c == '\"' || c == '\\') {
      /* note: / can be left unescaped */
      switch (c) {
        case '\"' : chbputs("\\\"", pcb); break;
        case '\\' : chbputs("\\\\", pcb); break;
        case '/' :  chbputs("\\/", pcb); break;
      }
      ++str; --n;
      continue;
    }
    /* get next unicode char */
    c32 = (int32_t)strtou8c(str, &end);
    if (c32 == -1) jfile_ierr(pjf, "broken utf-8 encoding: %s", str);
    if (end > str+n) jfile_ierr(pjf, "cut-off utf-8 encoding: %s", str);
    if (c32 <= 0x1F) {
      /* should have been taken care of above! */
      jfile_ierr(pjf, "invalid utf-8 encoding: %s", str);
    } else if (c32 <= 0x80) {
      /* put ascii chars as-is */
      assert(c32 == c && end == str+1);
      chbputc(c, pcb);
    } else if (c32 <= 0xFFFF) {
      /* BMP (TODO: check for non-chars such as U+FFFF and surrogates!) */
      /* if ??? jfile_ierr(pjf, "invalid utf-8 encoding: %.10s...", str); */
      /* was: cbput8c(c32, pcb); */
      sprintf(buf, "\\u%.4X", (int)c32); chbputs(buf, pcb);
    } else if (c32 <= 0x10FFFF) {
      /* legal space above bmp; encode as two surrogates */
      int32_t v = c32 - 0x10000, c1 = 0xD800 + ((v >> 10) & 0x3FF), c2 = 0xDC00 + (v & 0x3FF);
      sprintf(buf, "\\u%.4X\\u%.4X", c1, c2); chbputs(buf, pcb);
    } else {
      /* char outside Unicode range? */
      jfile_ierr(pjf, "nonstandard utf-8 encoding: %s", str);
    }
    n -= (size_t)(end-str); str = end;
  }
  chbputc('\"', pcb);
}

/* decode lookahead number token */
static double jfile_tnumberd(jfile_t* pjf)
{
  char *ts; double d;
  assert(pjf->tt >= JTK_INT && pjf->tt <= JTK_FLOAT);
  ts = chbdata(&pjf->tbuf);
  d = strtod(ts, &ts);
  assert(ts && !*ts);
  return d;
}

/* encode number into token buf */
static void jfile_tunnumberd(jfile_t* pjf, double num)
{
  char buf[30], *pc = buf;
  chbuf_t *pcb = &pjf->tbuf;
  sprintf(buf, "%.15g", num);
  /* the format above may produce [-]{inf...|nan...} */
  if (*pc == '-') ++pc;
  if (!isdigit(*pc)) jfile_ierr(pjf, "not a number: %s", buf);
  chbsets(pcb, buf);
}

/* decode lookahead number token as long long */
static long long jfile_tnumberll(jfile_t* pjf)
{
  char *ts, *end, *dd; long long ll;
  assert(pjf->tt == JTK_INT || pjf->tt == JTK_UINT);
  ts = chbdata(&pjf->tbuf);
  dd = *ts == '-' ? ts+1 : ts;
  if (strspn(dd, STR_09) != strlen(dd)) jfile_ierr(pjf, "not an integer number: %s", ts);
  errno = 0;
  ll = strtoll(ts, &end, 10); /* yes, it may overflow */
  if (errno) jfile_ierr(pjf, "signed integer number overflow: %s", ts);
  assert(end && !*end);
  return ll;
}

/* encode number into token buf as long long */
static void jfile_tunnumberll(jfile_t* pjf, long long num)
{
  chbuf_t *pcb = &pjf->tbuf;
  chbclear(pcb);
  chbputll(num, pcb);
}

/* decode lookahead number token as unsigned long long */
static unsigned long long jfile_tnumberull(jfile_t* pjf)
{
  char *ts, *end; unsigned long long ull;
  assert(pjf->tt == JTK_UINT);
  ts = chbdata(&pjf->tbuf);
  if (strspn(ts, STR_09) != strlen(ts)) jfile_ierr(pjf, "not an unsigned integer number: %s", ts);
  errno = 0;
  ull = strtoull(ts, &end, 10); /* yes, it may overflow */
  if (errno) jfile_ierr(pjf, "unsigned integer number overflow: %s", ts);
  assert(end && !*end);
  return ull;
}

/* encode number into token buf as unsigned long long */
static void jfile_tunnumberull(jfile_t* pjf, unsigned long long num)
{
  chbuf_t *pcb = &pjf->tbuf;
  chbclear(pcb);
  chbputllu(num, pcb);
}

/* output a single char to pjf */
static void jfile_putc(int c, jfile_t* pjf) 
{
  (pjf->putc)(c, pjf->pfile);
}

/* output a string to pjf */
static void jfile_puts(const char *s, jfile_t* pjf) 
{
  (pjf->puts)(s, pjf->pfile);
}

/* output contents of token buf to pjf */
static void jfile_putt(jfile_t* pjf) 
{
  (pjf->puts)(chbdata(&pjf->tbuf), pjf->pfile);
}

/* indent output by pjf->indent positions */
static void jfile_putindent(jfile_t* pjf) 
{
  const char* pc = "          "; 
  int i = pjf->indent / 10; 
  while (i-- > 0) (pjf->write)(pc, 1, 10, pjf->pfile); 
  (pjf->write)(pc, 1, pjf->indent % 10, pjf->pfile);
}

/* put separator (if given) and indent to current level */
static void jfile_indent(jfile_t* pjf, int sep) 
{
  if (sep) (pjf->putc)(sep, pjf->pfile);
  (pjf->putc)('\n', pjf->pfile); 
  jfile_putindent(pjf);
}

/* flush pending output to destination */
static void jfile_flush(jfile_t* pjf) 
{ 
  (pjf->flush)(pjf->pfile);
}

static void jfinit_ii(JFILE* pf, pii_t pii, void *dp, bool bbuf) 
{
  memset(pf, 0, sizeof(JFILE));
  pf->pjf = exmalloc(sizeof(jfile_t));
  jfile_init_ii(pf->pjf, pii, dp, bbuf);
  pf->ownsfile = false;
  pf->loading = true;
  pf->state = S_AT_VALUE;
}

static void jfinit_oi(JFILE* pf, poi_t poi, void *dp, bool bbuf) 
{
  memset(pf, 0, sizeof(JFILE));
  pf->pjf = exmalloc(sizeof(jfile_t));
  jfile_init_oi(pf->pjf, poi, dp, bbuf);
  pf->ownsfile = false;
  pf->loading = false;
  pf->state = S_AT_VALUE;
}

JFILE* newjfii(pii_t pii, void *dp)
{
  JFILE* pf;
  assert(pii);
  pf = exmalloc(sizeof(JFILE));
  jfinit_ii(pf, pii, dp, true); 
  return pf;
}

JFILE* newjfoi(poi_t poi, void *dp)
{
  JFILE* pf;
  assert(poi);
  pf = exmalloc(sizeof(JFILE));
  jfinit_oi(pf, poi, dp, true); 
  return pf;
}

void freejf(JFILE* pf) /* closes the file if not stdin/stdout/stderr */
{
  if (pf) {
    if (!pf->loading) jfile_flush(pf->pjf);
    if (pf->ownsfile) jfile_close(pf->pjf);
    else jfile_fini(pf->pjf);
    free(pf->pjf);
    free(pf);
  }
}

void jferror(JFILE* pf, const char* fmt, ...)
{
  va_list args;
  assert(pf); assert(fmt);
  va_start(args, fmt);
  jfile_verr(pf->loading, pf->pjf, fmt, args);
  va_end(args);
}

bool jfateof(JFILE* pf) /* end of file? */
{
  /* legal in states: S_AFTER_VALUE S_AT_VALUE (not checked) */
  jtoken_t t;
  assert(pf); assert(pf->loading);
  t = jfile_peekt(pf->pjf);
  return (t == JTK_EOF);
}

void jfgetobrk(JFILE* pf) /* [ */
{
  /* legal in states: S_AT_VALUE S_AFTER_VALUE */
  jtoken_t t;
  assert(pf); assert(pf->loading);
  if (pf->state == S_AFTER_VALUE) {
    t = jfile_peekt(pf->pjf);
    if (t == JTK_COMMA) {
      jfile_dropt(pf->pjf);
      pf->state = S_AT_VALUE;
    }
  }
  if (pf->state != S_AT_VALUE) jferror(pf, "no value ahead");
  t = jfile_peekt(pf->pjf);
  if (t != JTK_OBRK) jferror(pf, "[ expected");
  jfile_dropt(pf->pjf);
  t = jfile_peekt(pf->pjf);
  if (t == JTK_CBRK) pf->state = S_AT_CBRK;
  else pf->state = S_AT_VALUE;
  /* out states: S_AT_VALUE S_AT_CBRK */
}

bool jfatcbrk(JFILE* pf)  /* ...]? */
{
  /* legal in states: S_AFTER_VALUE S_AT_VALUE S_AT_CBRK */
  jtoken_t t;
  assert(pf); assert(pf->loading);
  if (pf->state == S_AFTER_VALUE) {
    t = jfile_peekt(pf->pjf);
    if (t == JTK_CBRK) {
      pf->state = S_AT_CBRK;
    } else if (t == JTK_COMMA) {
      jfile_dropt(pf->pjf);
      pf->state = S_AT_VALUE;
    }
  }
  if (pf->state == S_AT_CBRK) return true;
  if (pf->state == S_AT_VALUE) return false;
  if (pf->state == S_AFTER_VALUE) jferror(pf, ", or ] expected");
  jferror(pf, "] or value expected");
  return false; 
  /* out states: S_AT_VALUE S_AT_CBRK */
}

void jfgetcbrk(JFILE* pf) /* ] */
{
  /* legal in states: S_AFTER_VALUE S_AT_CBRK */
  jtoken_t t;
  assert(pf); assert(pf->loading);
  if (pf->state == S_AFTER_VALUE) {
    t = jfile_peekt(pf->pjf);
    if (t == JTK_CBRK) {
      pf->state = S_AT_CBRK;
    }
  }
  if (pf->state != S_AT_CBRK) jferror(pf, "] expected");
  t = jfile_peekt(pf->pjf);
  assert(t == JTK_CBRK);
  jfile_dropt(pf->pjf);
  pf->state = S_AFTER_VALUE;
  /* out states: S_AFTER_VALUE */
}

void jfgetobrc(JFILE* pf) /* { */
{
  /* legal in states: S_AT_VALUE S_AFTER_VALUE */
  jtoken_t t;
  assert(pf); assert(pf->loading);
  if (pf->state == S_AFTER_VALUE) {
    t = jfile_peekt(pf->pjf);
    if (t == JTK_COMMA) {
      jfile_dropt(pf->pjf);
      pf->state = S_AT_VALUE;
    }
  }
  if (pf->state != S_AT_VALUE) jferror(pf, "no value ahead");
  t = jfile_peekt(pf->pjf);
  if (t != JTK_OBRC) jferror(pf, "{ expected");
  jfile_dropt(pf->pjf);
  t = jfile_peekt(pf->pjf);
  if (t == JTK_CBRC) pf->state = S_AT_CBRC;
  else pf->state = S_AT_KEY;
  /* out states: S_AT_KEY S_AT_CBRK */
}

bool jfatcbrc(JFILE* pf)  /* ...]? */
{
  /* legal in states: S_AFTER_VALUE S_AT_KEY S_AT_CBRC */
  jtoken_t t;
  assert(pf); assert(pf->loading);
  if (pf->state == S_AFTER_VALUE) {
    t = jfile_peekt(pf->pjf);
    if (t == JTK_CBRC) {
      pf->state = S_AT_CBRC;
    } else if (t == JTK_COMMA) {
      jfile_dropt(pf->pjf);
      pf->state = S_AT_KEY;
    }
  }
  if (pf->state == S_AT_CBRC) return true;
  if (pf->state == S_AT_KEY) return false;
  if (pf->state == S_AFTER_VALUE) jferror(pf, ", or } expected");
  jferror(pf, "} or key-value pair expected");
  return false; 
  /* out states: S_AT_KEY S_AT_CBRC */
}

char* jfgetkey(JFILE* pf, chbuf_t* pcb) /* "key": */
{
  /* legal in states: S_AFTER_VALUE S_AT_KEY */
  jtoken_t t; char *key;
  assert(pf); assert(pcb);
  assert(pf->loading);
  if (pf->state == S_AFTER_VALUE) {
    t = jfile_peekt(pf->pjf);
    if (t == JTK_COMMA) {
      jfile_dropt(pf->pjf);
      pf->state = S_AT_KEY;
    }
  }
  if (pf->state != S_AT_KEY) jferror(pf, "key-value pair expected");
  t = jfile_peekt(pf->pjf);
  if (t != JTK_STRING) jferror(pf, "key-value pair expected");
  key = jfile_tstring(pf->pjf, pcb);
  jfile_dropt(pf->pjf);
  t = jfile_peekt(pf->pjf);  
  if (t != JTK_COLON) jferror(pf, "colon expected");
  jfile_dropt(pf->pjf);
  pf->state = S_AT_VALUE;
  return key;
  /* out states: S_AT_VALUE */
}

void jfgetcbrc(JFILE* pf) /* } */
{
  /* legal in states: S_AFTER_VALUE S_AT_CBRC */
  jtoken_t t;
  assert(pf); assert(pf->loading);
  if (pf->state == S_AFTER_VALUE) {
    t = jfile_peekt(pf->pjf);
    if (t == JTK_CBRC) {
      pf->state = S_AT_CBRC;
    }
  }
  if (pf->state != S_AT_CBRC) jferror(pf, "} expected");
  t = jfile_peekt(pf->pjf);
  assert(t == JTK_CBRC);
  jfile_dropt(pf->pjf);
  pf->state = S_AFTER_VALUE;
  /* out states: S_AFTER_VALUE */
}

jvtype_t jfpeek(JFILE* pf) /* type of value ahead */
{
  /* legal in states: S_AFTER_VALUE S_AT_VALUE */
  jtoken_t t;
  assert(pf); assert(pf->loading);
  if (pf->state == S_AFTER_VALUE) {
    t = jfile_peekt(pf->pjf);
    if (t == JTK_COMMA) {
      jfile_dropt(pf->pjf);
      pf->state = S_AT_VALUE;
    }
  }
  if (pf->state != S_AT_VALUE) jferror(pf, "no value ahead");
  t = jfile_peekt(pf->pjf);
  if (t == JTK_OBRK) return JVT_ARR;
  if (t == JTK_OBRC) return JVT_OBJ;
  if (t == JTK_NULL) return JVT_NULL;
  if (t == JTK_TRUE || t == JTK_FALSE) return JVT_BOOL;
  if (t == JTK_INT) return JVT_INT;
  if (t == JTK_UINT) return JVT_UINT;
  if (t == JTK_FLOAT) return JVT_FLOAT;
  if (t == JTK_STRING) return JVT_STR;
  if (t == JTK_OBRC) return JVT_OBJ;
  jferror(pf, "no value ahead");
  return (jvtype_t)-1;
  /* out states: S_AT_VALUE */
}

void jfgetnull(JFILE* pf) /* null */
{
  /* legal in states: S_AFTER_VALUE S_AT_VALUE */
  jtoken_t t;
  assert(pf); assert(pf->loading);
  if (pf->state == S_AFTER_VALUE) {
    t = jfile_peekt(pf->pjf);
    if (t == JTK_COMMA) {
      jfile_dropt(pf->pjf);
      pf->state = S_AT_VALUE;
    }
  }
  if (pf->state != S_AT_VALUE) jferror(pf, "no value ahead");
  t = jfile_peekt(pf->pjf);
  if (t != JTK_NULL) jferror(pf, "null expected");
  jfile_dropt(pf->pjf);
  pf->state = S_AFTER_VALUE;
  /* out states: S_AFTER_VALUE */
}

bool jfgetbool(JFILE* pf) /* true/false */
{
  /* legal in states: S_AFTER_VALUE S_AT_VALUE */
  jtoken_t t;
  assert(pf); assert(pf->loading);
  if (pf->state == S_AFTER_VALUE) {
    t = jfile_peekt(pf->pjf);
    if (t == JTK_COMMA) {
      jfile_dropt(pf->pjf);
      pf->state = S_AT_VALUE;
    }
  }
  if (pf->state != S_AT_VALUE) jferror(pf, "no value ahead");
  t = jfile_peekt(pf->pjf);
  if (t != JTK_TRUE && t != JTK_FALSE) jferror(pf, "true/false expected");
  jfile_dropt(pf->pjf);
  pf->state = S_AFTER_VALUE;
  return t == JTK_TRUE;
  /* out states: S_AFTER_VALUE */
}

double jfgetnumd(JFILE* pf) /* num as double */
{
  /* legal in states: S_AFTER_VALUE S_AT_VALUE */
  jtoken_t t; double d;
  assert(pf); assert(pf->loading);
  if (pf->state == S_AFTER_VALUE) {
    t = jfile_peekt(pf->pjf);
    if (t == JTK_COMMA) {
      jfile_dropt(pf->pjf);
      pf->state = S_AT_VALUE;
    }
  }
  if (pf->state != S_AT_VALUE) jferror(pf, "no value ahead");
  t = jfile_peekt(pf->pjf);
  if (t < JTK_INT || t > JTK_FLOAT) jferror(pf, "number expected");
  d = jfile_tnumberd(pf->pjf);
  jfile_dropt(pf->pjf);
  pf->state = S_AFTER_VALUE;
  return d;
  /* out states: S_AFTER_VALUE */
}

long long jfgetnumll(JFILE* pf) /* num as long long */
{
  /* legal in states: S_AFTER_VALUE S_AT_VALUE */
  jtoken_t t; long long ll;
  assert(pf); assert(pf->loading);
  if (pf->state == S_AFTER_VALUE) {
    t = jfile_peekt(pf->pjf);
    if (t == JTK_COMMA) {
      jfile_dropt(pf->pjf);
      pf->state = S_AT_VALUE;
    }
  }
  if (pf->state != S_AT_VALUE) jferror(pf, "no value ahead");
  t = jfile_peekt(pf->pjf);
  if (t != JTK_INT && t != JTK_UINT) jferror(pf, "integer number expected");
  ll = jfile_tnumberll(pf->pjf);
  jfile_dropt(pf->pjf);
  pf->state = S_AFTER_VALUE;
  return ll;
  /* out states: S_AFTER_VALUE */
}

unsigned long long jfgetnumull(JFILE* pf) /* num as unsigned long long */
{
  /* legal in states: S_AFTER_VALUE S_AT_VALUE */
  jtoken_t t; unsigned long long ull;
  assert(pf); assert(pf->loading);
  if (pf->state == S_AFTER_VALUE) {
    t = jfile_peekt(pf->pjf);
    if (t == JTK_COMMA) {
      jfile_dropt(pf->pjf);
      pf->state = S_AT_VALUE;
    }
  }
  if (pf->state != S_AT_VALUE) jferror(pf, "no value ahead");
  t = jfile_peekt(pf->pjf);
  if (t != JTK_UINT) jferror(pf, "unsigned integer expected");
  ull = jfile_tnumberull(pf->pjf);
  jfile_dropt(pf->pjf);
  pf->state = S_AFTER_VALUE;
  return ull;
  /* out states: S_AFTER_VALUE */
}

char* jfgetstr(JFILE* pf, chbuf_t* pcb)
{
  /* legal in states: S_AFTER_VALUE S_AT_VALUE */
  jtoken_t t; char *s;
  assert(pf); assert(pcb);
  assert(pf->loading);
  if (pf->state == S_AFTER_VALUE) {
    t = jfile_peekt(pf->pjf);
    if (t == JTK_COMMA) {
      jfile_dropt(pf->pjf);
      pf->state = S_AT_VALUE;
    }
  }
  if (pf->state != S_AT_VALUE) jferror(pf, "no value ahead");
  t = jfile_peekt(pf->pjf);
  if (t != JTK_STRING) jferror(pf, "string expected");
  s = jfile_tstring(pf->pjf, pcb);
  jfile_dropt(pf->pjf);
  pf->state = S_AFTER_VALUE;
  return s;
  /* out states: S_AFTER_VALUE */
}

void jfputobrk(JFILE* pf) /* [ */
{
  jfile_t* pjf;
  assert(pf); assert(!pf->loading);
  pjf = pf->pjf;
  if (pf->state == S_AT_OBRK) jfile_indent(pjf, 0);
  else if (pf->state == S_AFTER_VALUE) jfile_indent(pjf, ',');
  jfile_putc('[', pjf);
  ++(pjf->indent);
  pf->state = S_AT_OBRK;
}

void jfputcbrk(JFILE* pf) /* ] */
{
  jfile_t* pjf;
  assert(pf); assert(!pf->loading);
  pjf = pf->pjf;
  --(pjf->indent);
  if (pf->state == S_AFTER_VALUE) jfile_indent(pjf, 0);
  jfile_putc(']', pjf);
  pf->state = S_AFTER_VALUE;
}

void jfputobrc(JFILE* pf) /* { */
{
  jfile_t* pjf;
  assert(pf); assert(!pf->loading);
  pjf = pf->pjf;
  if (pf->state == S_AT_OBRK) jfile_indent(pjf, 0);
  else if (pf->state == S_AFTER_VALUE) jfile_indent(pjf, ',');
  jfile_putc('{', pjf);
  ++(pjf->indent);
  pf->state = S_AT_OBRC;
}

void jfputkeyn(JFILE* pf, const char *key, size_t n) /* "key": */
{
  jfile_t* pjf;
  assert(pf); assert(!pf->loading);
  assert(key);
  pjf = pf->pjf;
  if (pf->state == S_AT_OBRC) jfile_indent(pjf, 0); 
  else if (pf->state == S_AFTER_VALUE) jfile_indent(pjf, ',');
  jfile_tunstring(pjf, key, n);
  jfile_putt(pjf);
  jfile_putc(':', pjf);
  jfile_putc(' ', pjf);
  pf->state = S_AT_VALUE;
}

void jfputkey(JFILE* pf, const char *key) /* "key": */
{
  assert(pf); assert(key);
  jfputkeyn(pf, key, strlen(key));
}

void jfputcbrc(JFILE* pf) /* } */
{
  jfile_t* pjf;
  assert(pf); assert(!pf->loading);
  pjf = pf->pjf;
  --(pjf->indent);
  if (pf->state == S_AFTER_VALUE) jfile_indent(pjf, 0);
  jfile_putc('}', pjf);
  pf->state = S_AFTER_VALUE;
}

void jfputnull(JFILE* pf) /* null */
{
  jfile_t* pjf;
  assert(pf); assert(!pf->loading);
  pjf = pf->pjf;
  if (pf->state == S_AT_OBRK) jfile_indent(pjf, 0); 
  else if (pf->state == S_AFTER_VALUE) jfile_indent(pjf, ',');
  jfile_puts("null", pjf);
  pf->state = S_AFTER_VALUE;
}

void jfputbool(JFILE* pf, bool b) /* true/false */
{
  jfile_t* pjf;
  assert(pf); assert(!pf->loading);
  pjf = pf->pjf;
  if (pf->state == S_AT_OBRK) jfile_indent(pjf, 0); 
  else if (pf->state == S_AFTER_VALUE) jfile_indent(pjf, ',');
  jfile_puts(b ? "true" : "false", pjf);
  pf->state = S_AFTER_VALUE;
}

void jfputnumd(JFILE* pf, double num) /* num as double */
{
  jfile_t* pjf;
  assert(pf); assert(!pf->loading);
  pjf = pf->pjf;
  if (pf->state == S_AT_OBRK) jfile_indent(pjf, 0); 
  else if (pf->state == S_AFTER_VALUE) jfile_indent(pjf, ',');
  jfile_tunnumberd(pjf, num);
  jfile_putt(pjf);
  pf->state = S_AFTER_VALUE;
}

void jfputnum(JFILE* pf, int num) /* num as int */
{
  jfputnumll(pf, num);
}

void jfputnumll(JFILE* pf, long long num) /* num as long long */
{
  jfile_t* pjf;
  assert(pf); assert(!pf->loading);
  pjf = pf->pjf;
  if (pf->state == S_AT_OBRK) jfile_indent(pjf, 0); 
  else if (pf->state == S_AFTER_VALUE) jfile_indent(pjf, ',');
  jfile_tunnumberll(pjf, num);
  jfile_putt(pjf);
  pf->state = S_AFTER_VALUE;
}

void jfputnumu(JFILE* pf, unsigned num) /* num as unsigned */
{
  jfputnumull(pf, num);
}

void jfputnumull(JFILE* pf, unsigned long long num) /* num as unsigned long long */
{
  jfile_t* pjf;
  assert(pf); assert(!pf->loading);
  pjf = pf->pjf;
  if (pf->state == S_AT_OBRK) jfile_indent(pjf, 0); 
  else if (pf->state == S_AFTER_VALUE) jfile_indent(pjf, ',');
  jfile_tunnumberull(pjf, num);
  jfile_putt(pjf);
  pf->state = S_AFTER_VALUE;
}

void jfputstrn(JFILE* pf, const char *str, size_t n) /* "str" */
{
  jfile_t* pjf;
  assert(pf); assert(!pf->loading);
  assert(str);
  pjf = pf->pjf;
  if (pf->state == S_AT_OBRK) jfile_indent(pjf, 0); 
  else if (pf->state == S_AFTER_VALUE) jfile_indent(pjf, ',');
  jfile_tunstring(pjf, str, n);
  jfile_putt(pjf);
  pf->state = S_AFTER_VALUE;
}

void jfputstr(JFILE* pf, const char *str) /* "str" */
{
  assert(pf); assert(str);
  jfputstrn(pf, str, strlen(str));
}

void jfflush(JFILE* pf)
{
  assert(pf);
  assert(!pf->loading);
  jfile_flush(pf->pjf);  
}


/* bson i/o "file" */

typedef struct bfile_tag {
  /* i/o stream */
  size_t (*read)(void*, size_t, size_t, void*);
  size_t (*write)(const void*, size_t, size_t, void*);
  int (*getc)(void*);
  int (*ungetc)(int, void*);
  int (*putc)(int, void*);
  int (*puts)(const char*, void*);
  int (*flush)(void*);
  void* pfile;
  dstr_t fname;
  bvtype_t dvt; /* doc val type (in) */  
  bvtype_t kvt; /* key val type (in) */  
  chbuf_t kbuf; /* key buf (i/o) */
  buf_t parvts; /* stack of parent vts (in) */
  buf_t chbufs; /* stack of tmp bufs (out) */
  buf_t counts; /* stack of counts (out) */
} bfile_t;

static void bfile_init_ii(bfile_t* pbf, pii_t pii, void* dp, bool bbuf)
{
  assert(pbf); assert(pii);
  memset(pbf, 0, sizeof(bfile_t));
  pbf->pfile = dp;
  pbf->read = pii->read;
  pbf->getc = pii->getc;
  pbf->ungetc = pii->ungetc;
  pbf->write = null_poi->write;
  pbf->putc = null_poi->putc;
  pbf->puts = null_poi->puts;
  pbf->flush = null_poi->flush;
  pbf->dvt = BVT_OBJ;
  pbf->kvt = 0;
  chbinit(&pbf->kbuf);
  bufinit(&pbf->parvts, sizeof(bvtype_t));
  bufinit(&pbf->chbufs, sizeof(chbuf_t));
  bufinit(&pbf->counts, sizeof(int));
}

static void bfile_init_oi(bfile_t* pbf, poi_t poi, void* dp, bool bbuf)
{
  assert(pbf); assert(poi);
  memset(pbf, 0, sizeof(bfile_t));
  pbf->pfile = dp;
  pbf->read = null_pii->read;
  pbf->getc = null_pii->getc;
  pbf->ungetc = null_pii->ungetc;
  pbf->write = poi->write;
  pbf->putc = poi->putc;
  pbf->puts = poi->puts;
  pbf->flush = poi->flush;
  pbf->dvt = BVT_OBJ;
  pbf->kvt = 0;
  chbinit(&pbf->kbuf);
  bufinit(&pbf->parvts, sizeof(bvtype_t));
  bufinit(&pbf->chbufs, sizeof(chbuf_t));
  bufinit(&pbf->counts, sizeof(int));
}

static void bfile_fini(bfile_t* pbf) 
{
  size_t i;
  free(pbf->fname); 
  chbfini(&pbf->kbuf);
  buffini(&pbf->parvts);
  for (i = 0; i < buflen(&pbf->chbufs); ++i) chbfini(bufref(&pbf->chbufs, i)); 
  buffini(&pbf->chbufs);
  buffini(&pbf->counts);
}

static void bfile_close(bfile_t* pbf) 
{
  if (pbf) {
    if (pbf->read == (size_t (*)(void*, size_t, size_t, void*))&fread ||
        pbf->write == (size_t (*)(const void*, size_t, size_t, void*))&fwrite) {
      fclose(pbf->pfile);
    }
    bfile_fini(pbf);
  }
}

static void bfile_verr(bool in, bfile_t* pbf, const char *fmt, va_list args)
{
  assert(pbf);
  assert(fmt);
  chbclear(&pbf->kbuf);
  chbputvf(&pbf->kbuf, fmt, args);
  /* for now, just print error and exit; todo: longjmp */
  fprintf(stderr, "BSON error: %s\naborting execution...", chbdata(&pbf->kbuf));
  exit(EXIT_FAILURE);
}

static void bfile_ierr(bfile_t* pbf, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  bfile_verr(true, pbf, fmt, args);
  va_end(args);
}

static void bfile_oerr(bfile_t* pbf, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  bfile_verr(false, pbf, fmt, args);
  va_end(args);
}

static bool supported_vt(bvtype_t vt)
{
  switch (vt) {
    case BVT_FLOAT: case BVT_STR:  case BVT_OBJ:   case BVT_ARR:   case BVT_BIN:
    case BVT_BOOL:  case BVT_NULL: case BVT_INT32: case BVT_INT64: return true;
  }
  return false;
}

static const char* bfile_getkey(bfile_t* pbf)
{
  if (pbf->kvt == 0) {
    pbf->kvt = pbf->getc(pbf->pfile);
    if (pbf->kvt == 0) bfile_ierr(pbf, "peek at end of obj/array");
    if (!supported_vt(pbf->kvt)) bfile_ierr(pbf, "unsupported type code: %d", pbf->kvt);
    chbclear(&pbf->kbuf);
    while (true) { 
      int c = pbf->getc(pbf->pfile); 
      if (c == EOF) bfile_ierr(pbf, "unexpected end-of-file");
      if (c == 0) break;
      chbputc(c, &pbf->kbuf);
    }
  }
  return chbdata(&pbf->kbuf);
}

static bvtype_t bfile_peekvt(bfile_t* pbf)
{
  bfile_getkey(pbf);
  return pbf->kvt;  
}

static bool bfile_atzero(bfile_t* pbf, bvtype_t vt)
{
  int c;
  assert(pbf->dvt == vt);
  c = pbf->getc(pbf->pfile);
  if (c == EOF) bfile_ierr(pbf, "unexpected end-of-file");
  pbf->ungetc(c, pbf->pfile);
  return c == 0;
}

static void bfile_opendoc(bfile_t* pbf, bvtype_t vt)
{
  char buf[4];
  bvtype_t *pvt;
  if (pbf->dvt == BVT_ARR) bfile_getkey(pbf);
  pvt = bufnewbk(&pbf->parvts);
  assert((!pbf->kvt && vt == BVT_OBJ) || pbf->kvt == vt);
  *pvt = pbf->dvt; pbf->dvt = vt;
  pbf->read(buf, 4, 1, pbf->pfile); 
  /* size is ignored: we can rely on 0 terminators */
  pbf->kvt = 0; /* ready to read keys */
} 

static void bfile_closedoc(bfile_t* pbf, bvtype_t vt)
{
  int c = pbf->getc(pbf->pfile);
  if (c != 0) bfile_ierr(pbf, "missing end of obj/array");
  if (!bufempty(&pbf->parvts)) {
    bvtype_t *pvt = bufpopbk(&pbf->parvts);
    pbf->dvt = *pvt;
  } else { /* must be on top */
    assert(vt == BVT_OBJ);
    pbf->dvt = 0;
  }
  pbf->kvt = 0;
}

static void bfile_getnull(bfile_t* pbf)
{
  if (pbf->dvt == BVT_ARR) bfile_getkey(pbf);
  if (pbf->kvt != BVT_NULL) bfile_ierr(pbf, "null expected");
  pbf->kvt = 0;
}

static bool bfile_getbool(bfile_t* pbf)
{
  int c;
  if (pbf->dvt == BVT_ARR) bfile_getkey(pbf);
  c = pbf->getc(pbf->pfile);
  if (pbf->kvt != BVT_BOOL || (c != 0 && c != 1)) bfile_ierr(pbf, "bool expected");
  pbf->kvt = 0;
  return c;
}

static uint32_t bfile_geti32(bfile_t* pbf)
{
  uint8_t b[4]; unsigned n; uint32_t v;
  if (pbf->dvt == BVT_ARR) bfile_getkey(pbf);
  n = pbf->read(b, 1, 4, pbf->pfile);
  if (pbf->kvt != BVT_INT32 || n != 4) bfile_ierr(pbf, "int32 expected");
  v = ((uint32_t)b[3] << 24) | ((uint32_t)b[2] << 16) 
    | ((uint32_t)b[1] << 8)  |  (uint32_t)b[0];
  pbf->kvt = 0;
  return v;
}

static uint64_t bfile_geti64(bfile_t* pbf)
{
  uint8_t b[8]; unsigned n; uint64_t v;
  if (pbf->dvt == BVT_ARR) bfile_getkey(pbf);
  n = pbf->read(b, 1, 8, pbf->pfile);
  if (pbf->kvt != BVT_INT32 || n != 8) bfile_ierr(pbf, "int64 expected");
  v = ((uint64_t)b[7] << 56) | ((uint64_t)b[6] << 48) 
    | ((uint64_t)b[5] << 40) | ((uint64_t)b[4] << 32) 
    | ((uint64_t)b[3] << 24) | ((uint64_t)b[2] << 16) 
    | ((uint64_t)b[1] << 8)  |  (uint64_t)b[0];
  pbf->kvt = 0;
  return v;
}

static double bfile_getfloat(bfile_t* pbf)
{
  uint8_t b[8]; unsigned n; union { uint64_t u; double f; } v;
  if (pbf->dvt == BVT_ARR) bfile_getkey(pbf);
  n = pbf->read(b, 1, 8, pbf->pfile);
  if (pbf->kvt != BVT_FLOAT || n != 8) bfile_ierr(pbf, "float expected");
  v.u = ((uint64_t)b[7] << 56) | ((uint64_t)b[6] << 48) 
      | ((uint64_t)b[5] << 40) | ((uint64_t)b[4] << 32) 
      | ((uint64_t)b[3] << 24) | ((uint64_t)b[2] << 16) 
      | ((uint64_t)b[1] << 8)  |  (uint64_t)b[0];
  pbf->kvt = 0;
  return v.f;
}

static char* bfile_getstr(bfile_t* pbf, chbuf_t* pcb)
{
  uint8_t b[4]; unsigned n; uint32_t v;
  if (pbf->dvt == BVT_ARR) bfile_getkey(pbf);
  n = pbf->read(b, 1, 4, pbf->pfile);
  v = ((uint32_t)b[3] << 24) | ((uint32_t)b[2] << 16) 
    | ((uint32_t)b[1] << 8)  |  (uint32_t)b[0];
  if (pbf->kvt != BVT_STR || n != 4 || !v) bfile_ierr(pbf, "string expected");
  chbclear(pcb); 
  n = pbf->read(chballoc(pcb, v-1), 1, v-1, pbf->pfile);
  if (n != v-1 || pbf->getc(pbf->pfile) != 0) bfile_ierr(pbf, "missing end of string");
  pbf->kvt = 0;
  return chbdata(pcb);
}

static void bfile_getbin(bfile_t* pbf, chbuf_t* pcb)
{
  uint8_t b[4]; unsigned n; int st; uint32_t v;
  if (pbf->dvt == BVT_ARR) bfile_getkey(pbf);
  n = pbf->read(b, 1, 4, pbf->pfile);
  v = ((uint32_t)b[3] << 24) | ((uint32_t)b[2] << 16) 
    | ((uint32_t)b[1] << 8)  |  (uint32_t)b[0];
  st = pbf->getc(pbf->pfile); /* subtype is ignored */
  if (pbf->kvt != BVT_BIN || n != 4 || st == EOF) bfile_ierr(pbf, "binary block expected");
  chbclear(pcb); 
  n = pbf->read(chballoc(pcb, v), 1, v, pbf->pfile);
  if (n != v) bfile_ierr(pbf, "unexpected end of binary block");
  pbf->kvt = 0;
}

static void bfile_setkeyn(bfile_t* pbf, const char *key, size_t n)
{
  int *pcnt;
  assert(!bufempty(&pbf->counts));
  pcnt = bufbk(&pbf->counts);
  assert(*pcnt % 2 == 0); /* even number of keys+elts */
  *pcnt += 1; /* key is in tbuf */
  chbset(&pbf->kbuf, key, n);
}

static void bfile_putkey(bfile_t* pbf, bvtype_t vt)
{
  if (!bufempty(&pbf->counts)) {
    int *pcnt = bufbk(&pbf->counts);
    chbuf_t *pcb = bufbk(&pbf->chbufs);
    if (*pcnt % 2 == 0) { /* no key, generate */
      chbsetf(&pbf->kbuf, "%d", *pcnt/2);
      *pcnt += 1; /* key is in tbuf */
    }
    chbputc(0, &pbf->kbuf);
    chbputc((int)vt, pcb);
    chbcat(pcb, &pbf->kbuf);
    chbclear(&pbf->kbuf); 
  }  
}

static void bfile_startdoc(bfile_t* pbf)
{
  chbinit(bufnewbk(&pbf->chbufs));
  bufnewbk(&pbf->counts);
}

static void bfile_enddoc(bfile_t* pbf)
{
  chbuf_t *pcb = bufpopbk(&pbf->chbufs), *pccb;
  int *pcnt = bufpopbk(&pbf->counts);
  assert(*pcnt % 2 == 0); /* even number of keys+elts */
  if (bufempty(&pbf->chbufs)) { 
    pccb = &pbf->kbuf; 
    bufclear(pccb);
  } else { 
    pccb = bufbk(&pbf->chbufs);
  }
  chbputc(0, pcb);
  chbput4le(chblen(pcb)+4, pccb);
  chbcat(pccb, pcb);
  chbfini(pcb);
  if (bufempty(&pbf->chbufs)) {
    pbf->write(chbdata(pccb), 1, chblen(pccb), pbf->pfile);
    pbf->flush(pbf->pfile);
    bufclear(pccb);
  } else {
    pcnt = bufbk(&pbf->counts);
    assert(*pcnt % 2 == 1);
    *pcnt += 1;
  }
}

static void bfile_putnull(bfile_t* pbf)
{
  int *pcnt = bufbk(&pbf->counts);
  assert(*pcnt % 2 == 1);
  *pcnt += 1;
}

static void bfile_putbool(bfile_t* pbf, bool b)
{
  int *pcnt = bufbk(&pbf->counts);
  chbuf_t *pcb = bufbk(&pbf->chbufs);
  assert(*pcnt % 2 == 1);
  chbputc(b ? 1 : 0, pcb);
  *pcnt += 1;
}

static void bfile_puti32(bfile_t* pbf, int32_t v)
{
  int *pcnt = bufbk(&pbf->counts);
  chbuf_t *pcb = bufbk(&pbf->chbufs);
  assert(*pcnt % 2 == 1);
  chbput4le((unsigned)v, pcb);
  *pcnt += 1;
}

static void bfile_puti64(bfile_t* pbf, int64_t v)
{
  int *pcnt = bufbk(&pbf->counts);
  chbuf_t *pcb = bufbk(&pbf->chbufs);
  assert(*pcnt % 2 == 1);
  chbput8le((unsigned long long)v, pcb);
  *pcnt += 1;
}

static void bfile_putstr(bfile_t* pbf, const char *p, size_t n)
{
  int *pcnt = bufbk(&pbf->counts);
  chbuf_t *pcb = bufbk(&pbf->chbufs);
  assert(*pcnt % 2 == 1);
  chbput4le(n+1, pcb);
  chbput(p, n, pcb);
  chbputc(0, pcb);
  *pcnt += 1;
}

static void bfile_putbin(bfile_t* pbf, const char *p, size_t n)
{
  int *pcnt = bufbk(&pbf->counts);
  chbuf_t *pcb = bufbk(&pbf->chbufs);
  assert(*pcnt % 2 == 1);
  chbput4le(n, pcb);
  chbputc(0, pcb); /* generic binary */
  chbput(p, n, pcb);  
  *pcnt += 1;
}

static void bfinit_ii(BFILE* pf, pii_t pii, void *dp, bool bbuf) 
{
  memset(pf, 0, sizeof(BFILE));
  pf->pbf = exmalloc(sizeof(bfile_t));
  bfile_init_ii(pf->pbf, pii, dp, bbuf);
  pf->ownsfile = false;
  pf->loading = true;
}

static void bfinit_oi(BFILE* pf, poi_t poi, void *dp, bool bbuf) 
{
  memset(pf, 0, sizeof(BFILE));
  pf->pbf = exmalloc(sizeof(bfile_t));
  bfile_init_oi(pf->pbf, poi, dp, bbuf);
  pf->ownsfile = false;
  pf->loading = false;
}

BFILE* newbfii(pii_t pii, void *dp)
{
  BFILE* pf;
  assert(pii);
  pf = exmalloc(sizeof(BFILE));
  bfinit_ii(pf, pii, dp, true); 
  return pf;
}

BFILE* newbfoi(poi_t poi, void *dp)
{
  BFILE* pf;
  assert(poi);
  pf = exmalloc(sizeof(BFILE));
  bfinit_oi(pf, poi, dp, true); 
  return pf;
}

void freebf(BFILE* pf) /* closes the file if not stdin/stdout/stderr */
{
  if (pf) {
    if (pf->ownsfile) bfile_close(pf->pbf);
    else bfile_fini(pf->pbf);
    free(pf->pbf);
    free(pf);
  }
}

void bferror(BFILE* pf, const char* fmt, ...)
{
  va_list args;
  assert(pf); assert(fmt);
  va_start(args, fmt);
  bfile_verr(pf->loading, pf->pbf, fmt, args);
  va_end(args);
}


void bfgetobrk(BFILE* pf)
{
  assert(pf); assert(pf->loading);
  bfile_opendoc(pf->pbf, BVT_ARR); 
}

bool bfatcbrk(BFILE* pf)
{
  return bfile_atzero(pf->pbf, BVT_ARR);
}

void bfgetcbrk(BFILE* pf)
{
  assert(pf); assert(pf->loading);
  bfile_closedoc(pf->pbf, BVT_ARR); 
}

void bfgetobrc(BFILE* pf)
{
  assert(pf); assert(pf->loading);
  bfile_opendoc(pf->pbf, BVT_OBJ); 
}

char* bfgetkey(BFILE* pf, chbuf_t* pcb)
{
  const char *key;
  assert(pf); assert(pf->loading);
  key = bfile_getkey(pf->pbf);
  return pcb ? chbsets(pcb, key) : (char* )key;
}

bool bfatcbrc(BFILE* pf)
{
  return bfile_atzero(pf->pbf, BVT_OBJ);
}

void bfgetcbrc(BFILE* pf)
{
  assert(pf); assert(pf->loading);
  bfile_closedoc(pf->pbf, BVT_OBJ); 
}

bvtype_t bfpeek(BFILE* pf)
{
  assert(pf); assert(pf->loading);
  return bfile_peekvt(pf->pbf); 
}

void bfgetnull(BFILE* pf)
{
  assert(pf); assert(pf->loading);
  bfile_getnull(pf->pbf);
}

bool bfgetbool(BFILE* pf)
{
  assert(pf); assert(pf->loading);
  return bfile_getbool(pf->pbf);
}

int bfgetnum(BFILE* pf)
{
  assert(pf); assert(pf->loading);
  return (int)bfile_geti32(pf->pbf);
}

unsigned bfgetnumu(BFILE* pf)
{
  assert(pf); assert(pf->loading);
  return (unsigned)bfile_geti32(pf->pbf);
}

long long bfgetnumll(BFILE* pf)
{
  assert(pf); assert(pf->loading);
  return (long long)bfile_geti64(pf->pbf);
}

unsigned long long bfgetnumull(BFILE* pf)
{
  assert(pf); assert(pf->loading);
  return (unsigned long long)bfile_geti64(pf->pbf);
}

double bfgetnumd(BFILE* pf)
{
  assert(pf); assert(pf->loading);
  return bfile_getfloat(pf->pbf);
}

char* bfgetstr(BFILE* pf, chbuf_t* pcb)
{
  assert(pf); assert(pf->loading);
  return bfile_getstr(pf->pbf, pcb);
}

char* bfgetbin(BFILE* pf, chbuf_t* pcb)
{
  assert(pf); assert(pf->loading);
  return bfile_getstr(pf->pbf, pcb);
}

void bfputobrk(BFILE* pf)
{
  assert(pf); assert(!pf->loading);
  bfile_putkey(pf->pbf, BVT_ARR);
  bfile_startdoc(pf->pbf);  
}

void bfputcbrk(BFILE* pf)
{
  assert(pf); assert(!pf->loading);
  bfile_enddoc(pf->pbf);
}

void bfputobrc(BFILE* pf)
{
  assert(pf); assert(!pf->loading);
  bfile_putkey(pf->pbf, BVT_OBJ);
  bfile_startdoc(pf->pbf);
}

void bfputcbrc(BFILE* pf)
{
  assert(pf); assert(!pf->loading);
  bfile_enddoc(pf->pbf);
}

void bfputkey(BFILE* pf, const char *key)
{
  assert(pf); assert(!pf->loading);
  assert(key);
  bfile_setkeyn(pf->pbf, key, strlen(key));
}

void bfputkeyn(BFILE* pf, const char *key, size_t n)
{
  assert(pf); assert(!pf->loading);
  assert(key);
  bfile_setkeyn(pf->pbf, key, n);
}

void bfputnull(BFILE* pf)
{
  assert(pf); assert(!pf->loading);
  bfile_putkey(pf->pbf, BVT_NULL);
  bfile_putnull(pf->pbf);
}

void bfputbool(BFILE* pf, bool b)
{
  assert(pf); assert(!pf->loading);
  bfile_putkey(pf->pbf, BVT_BOOL);
  bfile_putbool(pf->pbf, b);
}

void bfputnum(BFILE* pf, int num)
{
  assert(pf); assert(!pf->loading);
  bfile_putkey(pf->pbf, BVT_INT32);
  bfile_puti32(pf->pbf, (int32_t)num);
}

void bfputnumu(BFILE* pf, unsigned num)
{
  assert(pf); assert(!pf->loading);
  bfile_putkey(pf->pbf, BVT_INT32);
  bfile_puti64(pf->pbf, (int32_t)num);
}

void bfputnumll(BFILE* pf, long long num)
{
  assert(pf); assert(!pf->loading);
  bfile_putkey(pf->pbf, BVT_INT64);
  bfile_puti64(pf->pbf, (int64_t)num);
}

void bfputnumull(BFILE* pf, unsigned long long num)
{
  assert(pf); assert(!pf->loading);
  bfile_putkey(pf->pbf, BVT_INT64);
  bfile_puti64(pf->pbf, (int64_t)num);
}

void bfputnumd(BFILE* pf, double num)
{
  union { int64_t i; double f; } ud;
  assert(pf); assert(!pf->loading);
  bfile_putkey(pf->pbf, BVT_FLOAT);
  ud.f = num;
  bfile_puti64(pf->pbf, ud.i);
}

void bfputstr(BFILE* pf, const char *str)
{
  assert(pf); assert(!pf->loading);
  bfile_putkey(pf->pbf, BVT_STR);
  bfile_putstr(pf->pbf, str, strlen(str));
}

void bfputstrn(BFILE* pf, const char *str, size_t n)
{
  assert(pf); assert(!pf->loading);
  bfile_putkey(pf->pbf, BVT_STR);
  bfile_putstr(pf->pbf, str, n);
}

void bfputbin(BFILE* pf, const char *str, size_t n)
{
  assert(pf); assert(!pf->loading);
  bfile_putkey(pf->pbf, BVT_BIN);
  bfile_putbin(pf->pbf, str, n);
}


/* platform-specific stuff */

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

