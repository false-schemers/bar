/* a.c (archiver) -- esl */

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
#include <wchar.h>
#include "b.h"
#include "a.h"


/* bar globals */
char g_cmd = 'h'; /* 't', 'x', 'c', or 'h' */
const char *g_arfile = NULL; /* archive file name */
const char *g_dstdir = NULL;  /* destination dir or - for stdout */
const char *g_exfile = NULL; /* excluded glob patterns file name */
bool g_keepold = false; /* do not owerwrite existing files (-k) */
int g_integrity = 0; /* check/calc integrity hashes; 1=SHA256 */
char g_format = 0; /* 'b': BAR, 't': ASAR, 0: check extension */
dsbuf_t g_expats; /* list of excluded patterns */

void init_archiver(void)
{
  dsbinit(&g_expats);
} 

void fini_archiver(void)
{
  dsbfini(&g_expats);
}

void loadex(void)
{
  FILE *fp = fopen(g_exfile, "r");
  chbuf_t cb = mkchb(); char *line;
  if (!fp) exprintf("can't open excluded patterns file %s:", g_exfile);
  while ((line = fgetlb(&cb, fp)) != NULL) {
    line = strtrim(line);
    if (*line == 0 || *line == '#') continue;
    dsbpushbk(&g_expats, &line);
  }
  fclose(fp);
  chbfini(&cb);
}

bool excluded(const char *fname)
{
  size_t i;
  for (i = 0; i < dsblen(&g_expats); ++i) {
    dstr_t *pds = dsbref(&g_expats, i);
    if (gmatch(fname, *pds)) return true;
  }
  return false;
}

/* file/directory entry */

fdent_t* fdeinit(fdent_t* mem)
{
  memset(mem, 0, sizeof(fdent_t));
  fdebinit(&mem->files);
  dsinit(&mem->name);
  dsinit(&mem->integrity_hash);
  dsbinit(&mem->integrity_blocks);
  return mem;
}

void fdefini(fdent_t* pe)
{
  fdebfini(&pe->files);
  dsfini(&pe->name);
  dsfini(&pe->integrity_hash);
  dsbfini(&pe->integrity_blocks);
}

fdebuf_t* fdebinit(fdebuf_t* mem)
{
  bufinit(mem, sizeof(fdent_t));
  return mem;
}

void fdebfini(fdebuf_t* pb)
{
  size_t i;
  for (i = 0; i < buflen(pb); ++i) fdefini(bufref(pb, i));
  buffini(pb); 
}


uint32_t unpack_uint32_le(uint8_t buf[4])
{
  return buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
}

uint32_t read_header(FILE *fp, chbuf_t *pcb)
{
  uint8_t hbuf[16]; uint32_t psz, off, asz, ssz, x;
  if (fread(hbuf, 16, 1, fp) != 1) exprintf("%s: can't read archive header", g_arfile);
  psz = unpack_uint32_le(hbuf);
  off = unpack_uint32_le(hbuf+4);  
  asz = unpack_uint32_le(hbuf+8);  
  ssz = unpack_uint32_le(hbuf+12);
  verbosef("psz = 0x%.8x, off = 0x%.8x, asz = 0x%.8x, ssz = 0x%.8x\n", psz, off, asz, ssz);
  if (ssz < 12) exprintf("%s: invalid archive header [3]", g_arfile);
  x = ssz + 4; if (x % 4 > 0) x += 4 - (x % 4); /* align to 32 bit */
  if (x != asz) exprintf("%s: invalid archive header [2]", g_arfile);
  x += 4;
  if (x != off) exprintf("%s: invalid archive header [1]", g_arfile); 
  if (psz != 4) exprintf("%s: invalid archive header [0]", g_arfile);
  bufresize(pcb, ssz);
  if (fread(pcb->buf, 1, ssz, fp) != ssz) exprintf("%s: invalid archive header data", g_arfile);
  return off;
}

void parse_header_files_json(JFILE *jfp, const char *base, fdebuf_t *pfdb)
{
  chbuf_t kcb = mkchb(), ncb = mkchb();
  jfgetobrc(jfp);
  while (!jfatcbrc(jfp)) {
    fdent_t *pfde = fdebnewbk(pfdb);
    jfgetkey(jfp, &ncb); /* name: */
    fprintf(stdout, "%s/%s\n", base, chbdata(&ncb));
    pfde->name = exstrdup(chbdata(&ncb));
    jfgetobrc(jfp);
    while (!jfatcbrc(jfp)) {
      char *key = jfgetkey(jfp, &kcb);
      if (streql(key, "files")) {
        char *nbase = chbsetf(&kcb, "%s/%s", base, chbdata(&ncb));
        pfde->isdir = true;
        parse_header_files_json(jfp, nbase, &pfde->files);
      } else if (streql(key, "offset")) { 
        /* NB: asar string (js exact num range is 53 bits) */
        char *soff = jfgetstr(jfp, &kcb);
        pfde->offset = strtoull(soff, NULL, 10);
      } else if (streql(key, "size")) { 
        pfde->size = jfgetnumull(jfp);
      } else if (streql(key, "executable")) { 
        pfde->executable = jfgetbool(jfp);
      } else if (streql(key, "unpacked")) { 
        pfde->unpacked = jfgetbool(jfp);
      } else if (streql(key, "integrity")) {
        jfgetobrc(jfp);
        while (!jfatcbrc(jfp)) {
          key = jfgetkey(jfp, &kcb);
          if (streql(key, "algorithm")) {
            char *ia = jfgetstr(jfp, &kcb);
            pfde->integrity_algorithm = streql(ia, "SHA256");
          } else if (streql(key, "hash")) {
            char *hash = jfgetbin(jfp, &kcb);
            if (pfde->integrity_algorithm == 1 && chblen(&kcb) == 32)
              pfde->integrity_hash = exmemdup(hash, 32);
          } else if (streql(key, "blockSize")) {
            pfde->integrity_block_size = (unsigned long)jfgetnumull(jfp); 
          } else if (streql(key, "blocks")) {
            jfgetobrk(jfp);
            while (!jfatcbrk(jfp)) {
              char *block = jfgetstr(jfp, &kcb);
              if (pfde->integrity_algorithm == 1 && chblen(&kcb) == 32) {
                *dsbnewbk(&pfde->integrity_blocks) = exmemdup(block, 32);
              }  
            }
            jfgetcbrk(jfp);
          }
        }
        jfgetcbrc(jfp);
      } else { 
        exprintf("%s: invalid entry: %s", g_arfile, chbdata(&kcb));
      }
    }
    if (!pfde->isdir) {
      fprintf(stdout, "  offset = 0x%.8lx (%ld)\n", 
        (unsigned long)pfde->offset, (unsigned long)pfde->offset);
      fprintf(stdout, "  size = 0x%.8lx (%ld)\n", 
        (unsigned long)pfde->size, (unsigned long)pfde->size);
      fprintf(stdout, "  executable = %d\n", (int)pfde->executable);
      fprintf(stdout, "  unpacked = %d\n", (int)pfde->unpacked);
    }
    jfgetcbrc(jfp);
  }
  jfgetcbrc(jfp);
  chbfini(&kcb), chbfini(&ncb);
}

void unparse_header_files_json(JFILE *jfp, fdebuf_t *pfdb)
{
  size_t i; chbuf_t cb = mkchb();
  jfputobrc(jfp);
  for (i = 0; i < fdeblen(pfdb); ++i) {
    fdent_t *pfde = fdebref(pfdb, i);
    if (pfde->name) jfputkey(jfp, pfde->name);
    jfputobrc(jfp);
    if (pfde->isdir) {
      if (pfde->unpacked) { 
        jfputkey(jfp, "unpacked"); 
        jfputbool(jfp, true); 
      }
      jfputkey(jfp, "files");
      unparse_header_files_json(jfp, &pfde->files);
    } else {
      jfputkey(jfp, "size");
      jfputnumull(jfp, pfde->size);
      if (pfde->unpacked) {
        jfputkey(jfp, "unpacked"); 
        jfputbool(jfp, true); 
      } else {      
        jfputkey(jfp, "offset");
        /* NB: asar string (js exact num range is 53 bits) */
        jfputstr(jfp, chbsetf(&cb, "%llu", pfde->offset)); 
      }
      if (pfde->executable) { 
        jfputkey(jfp, "executable"); 
        jfputbool(jfp, true); 
      }
      if (pfde->integrity_algorithm == 1/*SHA256*/) {
        jfputkey(jfp, "integrity"); 
        jfputobrc(jfp);
        jfputkey(jfp, "algorithm"); 
        jfputstr(jfp, "SHA256");
        if (pfde->integrity_hash) {
          jfputkey(jfp, "hash"); 
          jfputbin(jfp, pfde->integrity_hash, 32);
        }
        if (pfde->integrity_block_size) {
          size_t k;
          jfputkey(jfp, "blockSize"); 
          jfputnumull(jfp, pfde->integrity_block_size);
          jfputkey(jfp, "blocks");
          jfputobrk(jfp);
          for (k = 0; k < dsblen(&pfde->integrity_blocks); ++k) {
            dstr_t *pds = dsbref(&pfde->integrity_blocks, k);
            jfputbin(jfp, *pds, 32);
          }
          jfputcbrk(jfp);
        }
        jfputcbrc(jfp);
      }
    }
    jfputcbrc(jfp);
  }
  jfputcbrc(jfp);
  chbfini(&cb);  
}

void unparse_header_files_bson(BFILE *bfp, fdebuf_t *pfdb)
{
  size_t i; chbuf_t cb = mkchb();
  bfputobrc(bfp);
  for (i = 0; i < fdeblen(pfdb); ++i) {
    fdent_t *pfde = fdebref(pfdb, i);
    if (pfde->name) bfputkey(bfp, pfde->name);
    bfputobrc(bfp);
    if (pfde->isdir) {
      if (pfde->unpacked) { 
        bfputkey(bfp, "unpacked"); 
        bfputbool(bfp, true); 
      }
      bfputkey(bfp, "files");
      unparse_header_files_bson(bfp, &pfde->files);
    } else {
      bfputkey(bfp, "size");
      bfputnumull(bfp, pfde->size);
      if (pfde->unpacked) {
        bfputkey(bfp, "unpacked"); 
        bfputbool(bfp, true); 
      } else {      
        bfputkey(bfp, "offset");
        bfputnumull(bfp, pfde->offset);
      }
      if (pfde->executable) { 
        bfputkey(bfp, "executable"); 
        bfputbool(bfp, true); 
      }
      if (pfde->integrity_algorithm == 1/*SHA256*/) {
        bfputkey(bfp, "integrity"); 
        bfputobrc(bfp);
        bfputkey(bfp, "algorithm"); 
        bfputnum(bfp, pfde->integrity_algorithm);
        if (pfde->integrity_hash) {
          bfputkey(bfp, "hash"); 
          bfputbin(bfp, pfde->integrity_hash, 32);
        }
        if (pfde->integrity_block_size) {
          size_t k;
          bfputkey(bfp, "blockSize"); 
          bfputnumull(bfp, pfde->integrity_block_size);
          bfputkey(bfp, "blocks");
          bfputobrk(bfp);
          for (k = 0; k < dsblen(&pfde->integrity_blocks); ++k) {
            dstr_t *pds = dsbref(&pfde->integrity_blocks, k);
            bfputbin(bfp, *pds, 32);
          }
          bfputcbrk(bfp);
        }
        bfputcbrc(bfp);
      }
    }
    bfputcbrc(bfp);
  }
  bfputcbrc(bfp);
  chbfini(&cb);  
}

void parse_header(chbuf_t *pcb, fdebuf_t *pfdb)
{
  char *pc = pcb->buf; 
  JFILE *jfpi = newjfii(strptr_pii, &pc);
  JFILE *jfpo = newjfoi(FILE_poi, stdout);
  chbuf_t kcb = mkchb(); 
  jfgetobrc(jfpi);
  jfgetkey(jfpi, &kcb); /* "files": */
  if (!streql(chbdata(&kcb), "files")) exprintf("%s: invalid file list", g_arfile);
  parse_header_files_json(jfpi, "", pfdb);
  jfgetcbrc(jfpi);
  freejf(jfpi);
  jfputobrc(jfpo);
  jfputkey(jfpo, "files");
  unparse_header_files_json(jfpo, pfdb);
  jfputcbrc(jfpo);
  freejf(jfpo); fputc('\n', stdout);
  chbfini(&kcb);
}

void list_fdebuf(const char *base, fdebuf_t *pfdb, FILE *pf, bool full)
{
  size_t i; chbuf_t cb = mkchb();
  for (i = 0; i < fdeblen(pfdb); ++i) {
    fdent_t *pfde = fdebref(pfdb, i);
    if (pfde->isdir) {
      const char *sbase;
      if (full) {
        fprintf(pf, "d-%c ", pfde->unpacked ? 'u' : '-');
        fprintf(pf, "                           ");
      }
      if (!base) fprintf(pf, "%s/\n", pfde->name);
      else fprintf(pf, "%s/%s/\n", base, pfde->name);
      if (!base) sbase = pfde->name;
      else sbase = chbsetf(&cb, "%s/%s", base, pfde->name);
      list_fdebuf(sbase, &pfde->files, pf, full);
    } else {
      if (full) {
        fprintf(pf, "-%c%c ", pfde->executable ? 'x' : '-', pfde->unpacked ? 'u' : '-');
        if (pfde->unpacked) fprintf(pf, "              %12lu ", (unsigned long)pfde->size);
        else fprintf(pf, "@%-12lu %12lu ", (unsigned long)pfde->offset, (unsigned long)pfde->size);
      }
      if (!base) fprintf(pf, "%s\n", pfde->name);
      else fprintf(pf, "%s/%s\n", base, pfde->name);
    }
  }
  chbfini(&cb);
}

void list(void)
{
  FILE *fp; uint32_t off; chbuf_t cb = mkchb();
  fdebuf_t fdeb; fdebinit(&fdeb);
  if (!(fp = fopen(g_arfile, "rb"))) exprintf("can't open archive file %s:", g_arfile);
  off = read_header(fp, &cb);
  verbosef("header = \'%s\'\n", chbdata(&cb));
  parse_header(&cb, &fdeb);
  list_fdebuf(NULL, &fdeb, stdout, getverbosity() > 0);
  chbfini(&cb); fdebfini(&fdeb);
  fclose(fp);
}


/* copy file via fread/fwrite */
size_t fcopy(FILE *ifp, FILE *ofp)
{
  char buf[BUFSIZ];
  size_t bc = 0;
  assert(ifp); assert(ofp);
  for (;;) {
    size_t n = fread(buf, 1, BUFSIZ, ifp);
    if (!n) break;
    fwrite(buf, 1, n, ofp);
    bc += n;
    if (n < BUFSIZ) break;
  }
  return bc;
}

uint64_t addfde(uint64_t off, const char *path, fdebuf_t *pfdeb)
{
  fsstat_t st;
  if (fsstat(path, &st) && (st.isdir || st.isreg)) {
    char *fname = getfname(path);
    fdent_t *pfde = fdebnewbk(pfdeb);
    pfde->name = exstrdup(fname);
    pfde->isdir = st.isdir;
    pfde->size = st.size;
    if (excluded(path)) {
      pfde->unpacked = true;
    } else {
      if (pfde->isdir) {
        chbuf_t cb = mkchb();
        dsbuf_t dsb; dsbinit(&dsb);
        if (dir(path, &dsb)) {
          size_t i;
          for (i = 0; i < dsblen(&dsb); ++i) {
            dstr_t *pds = dsbref(&dsb, i);
            if (streql(*pds, ".") || streql(*pds, "..")) continue;
            off = addfde(off, chbsetf(&cb, "%s/%s", path, *pds), &pfde->files);
          }
        } else {
          exprintf("can't open directory: %s", path);
        }
        dsbfini(&dsb);
        chbfini(&cb);
      } else {
        pfde->offset = off;
        off += pfde->size;
        if (g_integrity) {
          //...
        }
      }
    }
  } else {
    exprintf("can't stat file or directory: %s", path);
  }
  return off;
}

void create(int argc, char **argv)
{
  FILE *fp; JFILE *jfp; BFILE *bfp; fdebuf_t fdeb;
  chbuf_t hcb = mkchb(); int i;
  if (!(fp = fopen(g_arfile, "wb"))) exprintf("can't open archive file %s:", g_arfile);
  fdebinit(&fdeb);
  for (i = 0; i < argc; ++i) {
    /* NB: we don't care where file/dir arg is located */
    addfde(0, argv[i], &fdeb);
  }
  list_fdebuf(NULL, &fdeb, stdout, getverbosity() > 0);
  jfp = newjfoi(FILE_poi, stdout);
  unparse_header_files_json(jfp, &fdeb);
  freejf(jfp);
  fputc('\n', stdout);
  bfp = newbfoi(FILE_poi, fp);
  unparse_header_files_bson(bfp, &fdeb);
  freebf(bfp);
  fclose(fp);
  chbfini(&hcb); fdebfini(&fdeb);
}

void b2jcopyfield(BFILE *bfp, JFILE *jfp, bool inobj)
{
  chbuf_t cb = mkchb();
  bvtype_t vt;
  if (inobj) {
    char *key = bfgetkey(bfp, &cb);
    jfputkey(jfp, key);
  }
  vt = bfpeek(bfp);
  switch (vt) {
   case BVT_OBJ: {
     bfgetobrc(bfp); 
     jfputobrc(jfp);
     while (!bfatcbrc(bfp)) b2jcopyfield(bfp, jfp, true);
     bfgetcbrc(bfp); 
     jfputcbrc(jfp);
   } break;
   case BVT_ARR: {
     bfgetobrk(bfp); 
     jfputobrk(jfp);
     while (!bfatcbrk(bfp)) b2jcopyfield(bfp, jfp, false);
     bfgetcbrk(bfp); 
     jfputcbrk(jfp);
   } break;
   case BVT_NULL: {
     bfgetnull(bfp);
     jfputnull(jfp);
   } break;
   case BVT_BOOL: {
     bool x = bfgetbool(bfp);
     jfputbool(jfp, x);
   } break;
   case BVT_INT32: {
     int x = bfgetnum(bfp);
     jfputnum(jfp, x);
   } break; 
   case BVT_INT64: {
     long long x = bfgetnumll(bfp);
     jfputnumll(jfp, x);
   } break; 
   case BVT_FLOAT: {
     double x = bfgetnumd(bfp);
     jfputnumd(jfp, x);
   } break; 
   case BVT_STR: {
     char *x = bfgetstr(bfp, &cb);
     jfputstr(jfp, x);
   } break; 
   case BVT_BIN: {
     bfgetbin(bfp, &cb);
     jfputbin(jfp, chbdata(&cb), chblen(&cb));
   } break; 
   default:
     exprintf("unsupported type code: \\x%.2X", vt);
     assert(false);
  }
  chbfini(&cb);
}

void extract(int argc, char **argv)
{
#if 1 /* bson->json test */
  FILE *fp; JFILE *jfp; BFILE *bfp;
  if (!(fp = fopen(g_arfile, "rb"))) exprintf("can't open archive file %s:", g_arfile);
  jfp = newjfoi(FILE_poi, stdout);
  bfp = newbfii(FILE_pii, fp);
  bfgetobrc(bfp); 
  jfputobrc(jfp);
  while (!bfatcbrc(bfp)) b2jcopyfield(bfp, jfp, true);
  bfgetcbrc(bfp); 
  jfputcbrc(jfp);
  freebf(bfp); freejf(jfp);
  fclose(fp);
#else /* just a test */  
  FILE *fp; JFILE *jfp; BFILE *bfp;
  chbuf_t cb = mkchb(); char *r; int ir; double dr; bool br;
  if (!(fp = fopen(g_arfile, "wb"))) exprintf("can't open archive file %s:", g_arfile);
  jfp = newjfoi(FILE_poi, stdout);
  jfputobrc(jfp);
    jfputkey(jfp, "tags");
      jfputobrk(jfp);
      jfputcbrk(jfp);
    jfputkey(jfp, "tz");
      jfputnumll(jfp, -25200);
    jfputkey(jfp, "days");
      jfputobrk(jfp);
        jfputnumll(jfp, 1);
        jfputnumll(jfp, 1);
        jfputnumll(jfp, 2);
        jfputnumll(jfp, 1);
      jfputcbrk(jfp);
    jfputkey(jfp, "coord");
      jfputobrk(jfp);
        jfputnumd(jfp, -90.0715);
        jfputnumd(jfp, 29.9510);
      jfputcbrk(jfp);
    jfputkey(jfp, "data");
      jfputobrk(jfp);
        jfputobrc(jfp);
          jfputkey(jfp, "name");
            jfputstr(jfp, "ox03");
          jfputkey(jfp, "staff");
            jfputbool(jfp, true);
        jfputcbrc(jfp);
        jfputobrc(jfp);
          jfputkey(jfp, "name");
            jfputnull(jfp);
          jfputkey(jfp, "staff");
            jfputbool(jfp, false);
          jfputkey(jfp, "extra");
            jfputobrc(jfp);
              jfputkey(jfp, "info");
              jfputstr(jfp, "");
            jfputcbrc(jfp);
        jfputcbrc(jfp);
        jfputobrc(jfp);
          jfputkey(jfp, "name");
            jfputstr(jfp, "ox03");
          jfputkey(jfp, "staff");
            jfputbool(jfp, true);
        jfputcbrc(jfp);
        jfputobrc(jfp);
        jfputcbrc(jfp);
      jfputcbrk(jfp);
  jfputcbrc(jfp);
  freejf(jfp);
  fputc('\n', stdout);
  bfp = newbfoi(FILE_poi, fp);
  bfputobrc(bfp);
    bfputkey(bfp, "tags");
      bfputobrk(bfp);
      bfputcbrk(bfp);
    bfputkey(bfp, "tz");
      bfputnum(bfp, -25200);
    bfputkey(bfp, "days");
      bfputobrk(bfp);
        bfputnum(bfp, 1);
        bfputnum(bfp, 1);
        bfputnum(bfp, 2);
        bfputnum(bfp, 1);
      bfputcbrk(bfp);
    bfputkey(bfp, "coord");
      bfputobrk(bfp);
        bfputnumd(bfp, -90.0715);
        bfputnumd(bfp, 29.9510);
      bfputcbrk(bfp);
    bfputkey(bfp, "data");
      bfputobrk(bfp);
        bfputobrc(bfp);
          bfputkey(bfp, "name");
            bfputstr(bfp, "ox03");
          bfputkey(bfp, "staff");
            bfputbool(bfp, true);
        bfputcbrc(bfp);
        bfputobrc(bfp);
          bfputkey(bfp, "name");
            bfputnull(bfp);
          bfputkey(bfp, "staff");
            bfputbool(bfp, false);
          bfputkey(bfp, "extra");
            bfputobrc(bfp);
              bfputkey(bfp, "info");
              bfputstr(bfp, "");
            bfputcbrc(bfp);
        bfputcbrc(bfp);
        bfputobrc(bfp);
          bfputkey(bfp, "name");
            bfputstr(bfp, "ox03");
          bfputkey(bfp, "staff");
            bfputbool(bfp, true);
        bfputcbrc(bfp);
        bfputobrc(bfp);
        bfputcbrc(bfp);
      bfputcbrk(bfp);
  bfputcbrc(bfp);
  freebf(bfp);
  fclose(fp);
  if (!(fp = fopen(g_arfile, "rb"))) exprintf("can't open archive file (r) %s:", g_arfile);
  bfp = newbfii(FILE_pii, fp);
  bfgetobrc(bfp);
    r=bfgetkey(bfp, &cb); assert(streql(r, "tags"));
      bfgetobrk(bfp);
      bfgetcbrk(bfp);
    r=bfgetkey(bfp, &cb); assert(streql(r, "tz"));
      ir=bfgetnum(bfp); assert(ir==-25200);
    r=bfgetkey(bfp, &cb); assert(streql(r, "days"));
      bfgetobrk(bfp);
        ir=bfgetnum(bfp); assert(ir==1);
        ir=bfgetnum(bfp); assert(ir==1);
        ir=bfgetnum(bfp); assert(ir==2);
        ir=bfgetnum(bfp); assert(ir==1);
      bfgetcbrk(bfp);
    r=bfgetkey(bfp, &cb); assert(streql(r, "coord"));
      bfgetobrk(bfp);
        dr=bfgetnumd(bfp); assert(dr==-90.0715);
        dr=bfgetnumd(bfp); assert(dr==29.9510);
      bfgetcbrk(bfp);
    r=bfgetkey(bfp, &cb); assert(streql(r, "data"));
      bfgetobrk(bfp);
        bfgetobrc(bfp);
          r=bfgetkey(bfp, &cb); assert(streql(r, "name"));
            r=bfgetstr(bfp, &cb); assert(streql(r, "ox03"));
          r=bfgetkey(bfp, &cb); assert(streql(r, "staff"));
            br=bfgetbool(bfp); assert(br==true);
        bfgetcbrc(bfp);
        bfgetobrc(bfp);
          r=bfgetkey(bfp, &cb); assert(streql(r, "name"));
            bfgetnull(bfp);
          r=bfgetkey(bfp, &cb); assert(streql(r, "staff"));
            br=bfgetbool(bfp); assert(br==false);
          r=bfgetkey(bfp, &cb); assert(streql(r, "extra"));
            bfgetobrc(bfp);
              r=bfgetkey(bfp, &cb); assert(streql(r, "info"));
              r=bfgetstr(bfp, &cb); assert(streql(r, ""));
            bfgetcbrc(bfp);
        bfgetcbrc(bfp);
        bfgetobrc(bfp);
          r=bfgetkey(bfp, &cb); assert(streql(r, "name"));
            r=bfgetstr(bfp, &cb); assert(streql(r, "ox03"));
          r=bfgetkey(bfp, &cb); assert(streql(r, "staff"));
            br=bfgetbool(bfp); assert(br==true);
        bfgetcbrc(bfp);
        bfgetobrc(bfp);
        bfgetcbrc(bfp);
      bfgetcbrk(bfp);
  bfgetcbrc(bfp);
  freebf(bfp);
  fclose(fp);
  chbfini(&cb);
#endif
}

int main(int argc, char **argv)
{
  int opt;

  setprogname(argv[0]);
  setusage
    ("[OPTION]... [FILE/DIR]...\n"
     "The archiver works with .asar (json header) and .bar (bson header) archives.\n"
     "\n"
     "Examples:\n"
     "  bar -cf archive.bar foo bar  # Create archive.bar from files foo and bar\n"
     "  bar -tvf archive.bar         # List all files in archive.bar verbosely\n"
     "  bar -xf archive.bar foo bar  # Extract files foo and bar from archive.bar\n"
     "  bar -xf archive.bar          # Extract all files from archive.bar\n"
     "\n"
     "If a long option shows an argument as mandatory, then it is mandatory\n"
     "for the equivalent short option also.  Similarly for optional arguments.\n"     
     "\n"
     "Main operation mode:\n"
     "  -c, --create                 Create a new archive\n"
     "  -t, --list                   List the contents of an archive\n"
     "  -x, --extract                Extract files from an archive\n"
     "\n"
     "Operation modifiers:\n"
     "  -f, --file=FILE              Use archive FILE (required in all modes)\n"
     "  -k, --keep-old-files         Don't overwrite existing files when extracting\n"
     "  -C, --directory=DIR          Use directory DIR for extracted files\n"
     "  -O, --to-stdout              Extract files to standard output\n"
     "  -X, --exclude-from=FILE      Exclude files via globbing patterns in FILE\n"
     "  --exclude=\"PATTERN\"          Exclude files, given as a globbing PATTERN\n"
     "  --integrity=SHA256           Calculate or check file integrity info\n"
     "\n"
     "Archive format selection:\n"
     "  -o, --format=asar            Create asar archive even if extension is not .asar\n"
     "  --format=bar                 Create bar archive even if extension is .asar\n"
     "\n"
     "Informative output:\n"
     "  -v, --verbose                Increase output verbosity\n"
     "  -q, --quiet                  Suppress logging\n"
     "  -h, --help                   Print this help, then exit\n");
     
  while ((opt = egetopt(argc, argv, "ctxf:kC:OX:owvqh-:")) != EOF) {
    switch (opt) {
      case 'c': g_cmd = 'c'; break;
      case 't': g_cmd = 't'; break;
      case 'x': g_cmd = 'x'; break;
      case 'f': g_arfile = eoptarg; break;
      case 'k': g_keepold = true; break;
      case 'C': g_dstdir = eoptarg; break;
      case 'O': g_dstdir = "-"; break;
      case 'X': g_exfile = eoptarg; break;
      case 'o': g_format = 't'; break;
      case 'w': setwlevel(3); break;
      case 'v': incverbosity(); break;
      case 'q': incquietness(); break;
      case 'h': g_cmd = 'h'; break;
      case '-': {
        char *arg;
        if (streql(eoptarg, "create")) g_cmd = 'c';
        else if (streql(eoptarg, "list")) g_cmd = 't';
        else if (streql(eoptarg, "extract")) g_cmd = 'x';
        else if ((arg = strprf(eoptarg, "file=")) != NULL) g_arfile = arg;
        else if (streql(eoptarg, "keep-old-files")) g_keepold = true;
        else if ((arg = strprf(eoptarg, "directory=")) != NULL) g_dstdir = arg;
        else if ((arg = strprf(eoptarg, "exclude-from=")) != NULL) g_exfile = arg;
        else if ((arg = strprf(eoptarg, "exclude=")) != NULL) dsbpushbk(&g_expats, &arg);
        else if (streql(eoptarg, "verbose")) incverbosity();
        else if (streql(eoptarg, "quiet")) incquietness();
        else if (streql(eoptarg, "help")) g_cmd = 'h';
        else if (streql(eoptarg, "integrity=SHA256")) g_integrity = 1;
        else if (streql(eoptarg, "old-archive")) g_format = 't';
        else if (streql(eoptarg, "format=asar")) g_format = 't';
        else if (streql(eoptarg, "format=bar")) g_format = 'b';
        else eusage("illegal option: --%s", eoptarg);  
      } break;
    }
  }

  init_archiver();
  
  switch (g_cmd) {
    case 't': {
      if (!g_arfile) eusage("-f FILE argument is missing");
      if (g_dstdir) eusage("unexpected -C/-O options in create mode");
      if (g_exfile) eusage("unexpected -X option in listing mode");
      if (eoptind < argc) eusage("too many arguments for list command");
      list();
    } break;
    case 'c': {
      if (!g_arfile) eusage("-f FILE argument is missing");
      if (g_dstdir) eusage("unexpected -C/-O options in create mode");
      if (g_exfile) loadex();
      create(argc-eoptind, argv+eoptind);
    } break;
    case 'x': {
      if (!g_arfile) eusage("-f FILE argument is missing");
      if (g_exfile) loadex();
      extract(argc-eoptind, argv+eoptind);
    } break;
    case 'h': {
      eusage("BAR (Basic Archiver) 1.00 built on " __DATE__); 
    } break;
  }  

  fini_archiver();

  return EXIT_SUCCESS;
}

