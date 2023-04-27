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
int g_integrity = 0; /* check/calc integrity hashes; 1: SHA256 */
int g_format = 0; /* 'b': BAR, 't': ASAR, 0: check extension */
dsbuf_t g_expats; /* list of excluded patterns */
dsbuf_t g_unpats; /* list of unpacked patterns */
size_t g_bufsize = 0x400000;
char *g_buffer = NULL;

void init_archiver(void)
{
  dsbinit(&g_expats);
  dsbinit(&g_unpats);
  g_buffer = exmalloc(g_bufsize);
} 

void fini_archiver(void)
{
  dsbfini(&g_expats);
  dsbfini(&g_unpats);
  free(g_buffer);
}

void addex(dsbuf_t *pdsb, const char *arg)
{
  chbuf_t cb = mkchb(); char *pat; 
  size_t len = strlen(arg);
  if (len > 0 && arg[len-1] == '/') --len;
  pat = chbset(&cb, arg, len); 
  dsbpushbk(&g_expats, &pat);
  chbfini(&cb);
}

void loadex(void)
{
  FILE *fp = fopen(g_exfile, "r");
  chbuf_t cb = mkchb(); char *line;
  if (!fp) exprintf("can't open excluded patterns file %s:", g_exfile);
  while ((line = fgetlb(&cb, fp)) != NULL) {
    line = strtrim(line);
    if (*line == 0 || *line == '#') continue;
    addex(&g_expats, line);
  }
  fclose(fp);
  chbfini(&cb);
}

bool excluded(const char *base, const char *fname, dsbuf_t *pdsb)
{
  size_t i;
  for (i = 0; i < dsblen(pdsb); ++i) {
    dstr_t *pds = dsbref(pdsb, i), pat = *pds;
    bool res;
    if (strprf(pat, "./")) res = gmatch(base, pat+2);
    else if (strchr(pat, '/')) res = gmatch(base, pat);
    else res = gmatch(fname, pat);
    if (res) return true;
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

void pack_uint32_le(uint32_t v, uint8_t buf[4])
{
  buf[0] = v & 0xff; v >>= 8;
  buf[1] = v & 0xff; v >>= 8;
  buf[2] = v & 0xff; v >>= 8;
  buf[3] = v & 0xff;
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
  if (ssz < 12) exprintf("%s: invalid asar archive header [3]", g_arfile);
  x = ssz + 4; if (x % 4 > 0) x += 4 - (x % 4); /* align to 32 bit */
  if (x != asz) exprintf("%s: invalid asar archive header [2]", g_arfile);
  x += 4;
  if (x != off) exprintf("%s: invalid asar archive header [1]", g_arfile); 
  if (psz != 4) exprintf("%s: invalid asar archive header [0]", g_arfile);
  bufresize(pcb, ssz);
  if (fread(pcb->buf, 1, ssz, fp) != ssz) exprintf("%s: invalid archive header data", g_arfile);
  return off + 8; /* from the start of the file */
}

void write_header(int format, FILE *fp, chbuf_t *pcb)
{
  uint8_t hbuf[16]; uint32_t psz, off, asz, ssz;
  ssz = (uint32_t)chblen(pcb);
  asz = ssz + 4; if (asz % 4 > 0) asz += 4 - (asz % 4); /* align to 32 bit */
  if (format == 't') { /* asar */
    psz = 4; 
    off = sizeof(ssz) + asz; /* offset from the end of asz */
    pack_uint32_le(psz, hbuf);
    pack_uint32_le(off, hbuf+4);  
    pack_uint32_le(asz, hbuf+8);  
    pack_uint32_le(ssz, hbuf+12);
  } else { /* bsar */
    psz = 3;
    off = asz; /* offset from the end of asz */
    pack_uint32_le(psz, hbuf);
    pack_uint32_le(off, hbuf+4);  
    pack_uint32_le(asz, hbuf+8);  
  }
  if (fwrite(hbuf, psz*4, 1, fp) != 1) goto err;
  if (fwrite(chbdata(pcb), ssz, 1, fp) != 1) goto err;
  if (asz > ssz) {
    memset(hbuf, 0, 16);
    if (fwrite(hbuf, asz-ssz, 1, fp) != 1) goto err;
  }
  return;
err: 
  exprintf("%s: can't write archive header", g_arfile);
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
            if (pfde->integrity_algorithm == 1 && chblen(&kcb) == SHA256DG_SIZE)
              pfde->integrity_hash = exmemdup(hash, SHA256DG_SIZE);
          } else if (streql(key, "blockSize")) {
            pfde->integrity_block_size = (unsigned long)jfgetnumull(jfp); 
          } else if (streql(key, "blocks")) {
            jfgetobrk(jfp);
            while (!jfatcbrk(jfp)) {
              char *block = jfgetstr(jfp, &kcb);
              if (pfde->integrity_algorithm == 1 && chblen(&kcb) == SHA256DG_SIZE) {
                *dsbnewbk(&pfde->integrity_blocks) = exmemdup(block, SHA256DG_SIZE);
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
          jfputbin(jfp, pfde->integrity_hash, SHA256DG_SIZE);
        }
        if (pfde->integrity_block_size) {
          size_t k;
          jfputkey(jfp, "blockSize"); 
          jfputnumull(jfp, pfde->integrity_block_size);
          jfputkey(jfp, "blocks");
          jfputobrk(jfp);
          for (k = 0; k < dsblen(&pfde->integrity_blocks); ++k) {
            dstr_t *pds = dsbref(&pfde->integrity_blocks, k);
            jfputbin(jfp, *pds, SHA256DG_SIZE);
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
          bfputbin(bfp, pfde->integrity_hash, SHA256DG_SIZE);
        }
        if (pfde->integrity_block_size) {
          size_t k;
          bfputkey(bfp, "blockSize"); 
          bfputnumull(bfp, pfde->integrity_block_size);
          bfputkey(bfp, "blocks");
          bfputobrk(bfp);
          for (k = 0; k < dsblen(&pfde->integrity_blocks); ++k) {
            dstr_t *pds = dsbref(&pfde->integrity_blocks, k);
            bfputbin(bfp, *pds, SHA256DG_SIZE);
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

void unparse_header(int format, chbuf_t *pcb, fdebuf_t *pfdb)
{
  if (format == 't') {
    JFILE *jfp = newjfoi(cbuf_poi, pcb);
    jfputobrc(jfp);
    jfputkey(jfp, "files");
    unparse_header_files_json(jfp, pfdb);
    jfputcbrc(jfp);
    freejf(jfp);
  } else {
    BFILE *bfp = newbfoi(cbuf_poi, pcb);
    bfputobrc(bfp);
    bfputkey(bfp, "files");
    unparse_header_files_bson(bfp, pfdb);
    bfputcbrc(bfp);
    freebf(bfp);
  }
}

void list_fdebuf(const char *base, fdebuf_t *pfdb, FILE *pf, bool full)
{
  size_t i; chbuf_t cb = mkchb();
  for (i = 0; i < fdeblen(pfdb); ++i) {
    fdent_t *pfde = fdebref(pfdb, i);
    if (pfde->isdir) {
      const char *sbase;
      if (full) {
        fprintf(pf, "d--%c ", pfde->unpacked ? 'u' : '-');
        fprintf(pf, "                           ");
      }
      if (!base) fprintf(pf, "%s/\n", pfde->name);
      else fprintf(pf, "%s/%s/\n", base, pfde->name);
      if (!base) sbase = pfde->name;
      else sbase = chbsetf(&cb, "%s/%s", base, pfde->name);
      list_fdebuf(sbase, &pfde->files, pf, full);
    } else {
      if (full) {
        fprintf(pf, "-%c%c%c ", pfde->integrity_hash ? 'i' : '-',
          pfde->executable ? 'x' : '-', pfde->unpacked ? 'u' : '-');
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

void writef(const char *path, fdent_t *pfde, FILE *ofp)
{
  chbuf_t cb = mkchb(); FILE *ifp;  
  sha256ctx_t fhash, bhash;
  uint8_t digest[SHA256DG_SIZE];
  size_t bc = 0;
  if ((ifp = fopen(path, "rb")) == NULL) {
    exprintf("%s: cannot open file:", path);
  }
  if (g_integrity == 1) {
    pfde->integrity_algorithm = g_integrity;
    pfde->integrity_block_size = g_bufsize;
    sha256init(&fhash);
  }
  for (;;) {
    size_t n = fread(g_buffer, 1, g_bufsize, ifp);
    if (g_integrity == 1) {
      sha256init(&bhash);
      sha256update(&bhash, g_buffer, n);
      sha256fini(&bhash, &digest[0]);
      *dsbnewbk(&pfde->integrity_blocks) = exmemdup(&digest[0], SHA256DG_SIZE);
      sha256update(&fhash, g_buffer, n);
    }
    if (!n) break;
    fwrite(g_buffer, 1, n, ofp);
    bc += n;
    if (n < g_bufsize) break;
  }
  if (bc != pfde->size) {
    exprintf("%s: actual file size (%llu) is different from stat file size (%llu)",
      (unsigned long long)bc, (unsigned long long)pfde->size);
  }
  if (g_integrity == 1) {
    sha256fini(&fhash, &digest[0]);
    pfde->integrity_hash = exmemdup(&digest[0], SHA256DG_SIZE);
  }
  fclose(ifp);
  chbfini(&cb);
}

uint64_t addfde(uint64_t off, const char *base, const char *path, fdebuf_t *pfdeb, FILE *ofp)
{
  fsstat_t st;
  if (fsstat(path, &st) && (st.isdir || st.isreg)) {
    char *fname; fdent_t *pfde;
    fname = getfname(path);
    if (excluded(base, fname, &g_expats)) return off;
    pfde = fdebnewbk(pfdeb);
    pfde->name = exstrdup(fname);
    pfde->isdir = st.isdir;
    pfde->size = st.size;
    if (excluded(base, fname, &g_unpats)) {
      pfde->unpacked = true;
    } else {
      if (pfde->isdir) {
        chbuf_t cbb = mkchb(), cbp = mkchb();
        dsbuf_t dsb; dsbinit(&dsb);
        if (dir(path, &dsb)) {
          size_t i;
          for (i = 0; i < dsblen(&dsb); ++i) {
            dstr_t *pds = dsbref(&dsb, i); char *nb, *np;
            if (streql(*pds, ".") || streql(*pds, "..")) continue;
            nb = *base ? chbsetf(&cbb, "%s/%s", base, *pds) : *pds;
            np = chbsetf(&cbp, "%s/%s", path, *pds);
            off = addfde(off, nb, np, &pfde->files, ofp);
          }
        } else {
          exprintf("can't open directory: %s", path);
        }
        dsbfini(&dsb);
        chbfini(&cbb), chbfini(&cbp);
      } else {
        pfde->offset = off;
        off += pfde->size;
        writef(path, pfde, ofp);
      }
    }
  } else {
    exprintf("can't stat file or directory: %s", path);
  }
  return off;
}

void create(int argc, char **argv)
{
  FILE *fp, *tfp; fdebuf_t fdeb;
  chbuf_t hcb = mkchb(); int i, format;
  if (!(fp = fopen(g_arfile, "wb"))) exprintf("can't open archive file %s:", g_arfile);
  format = g_format ? g_format : strsuf(g_arfile, ".asar") ? 't' : 'b';
  tfp = etmpopen("w+b");
  fdebinit(&fdeb);
  for (i = 0; i < argc; ++i) {
    /* NB: we don't care where file/dir arg is located */
    addfde(0, getfname(argv[i]), argv[i], &fdeb, tfp);
  }
  list_fdebuf(NULL, &fdeb, stdout, getverbosity() > 0);
  unparse_header(format, &hcb, &fdeb);
  write_header(format, fp, &hcb);
  rewind(tfp);
  fcopy(tfp, fp);
  fclose(tfp);
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
#if 1 /* ... */
  /* for now, look at g_format, not at header */
  FILE *fp; uint32_t off; chbuf_t cb = mkchb();
  fdebuf_t fdeb; fdebinit(&fdeb);
  if (!(fp = fopen(g_arfile, "rb"))) exprintf("can't open archive file %s:", g_arfile);
  off = read_header(fp, &cb);
  verbosef("header = \'%s\'\n", chbdata(&cb));
  parse_header(&cb, &fdeb);
  list_fdebuf(NULL, &fdeb, stdout, getverbosity() > 0);
  chbfini(&cb); fdebfini(&fdeb);
  fclose(fp);
#else /* just a dump of bson */
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
#endif  
}

int main(int argc, char **argv)
{
  int opt;

  init_archiver();

  setprogname(argv[0]);
  setusage
    ("[OPTION]... [FILE/DIR]...\n"
     "The archiver works with .asar (json header) and .bsar (bson header) archives.\n"
     "\n"
     "Examples:\n"
     "  bar -cf arch.bsar foo bar    # Create bsar archive from files foo and bar\n"
     "  bar -cf arch.asar foo bar    # Create asar archive from files foo and bar\n"
     "  bar -tvf arch.bsar           # List all files in arch.bsar verbosely\n"
     "  bar -xf arch.bsar foo bar    # Extract files foo and bar from arch.bsar\n"
     "  bar -xf arch.bsar            # Extract all files from arch.bsar\n"
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
     "  --unpack=\"PATTERN\"           Exclude files, but keep their info in archive\n"
     "  --integrity=SHA256           Calculate or check file integrity info\n"
     "\n"
     "Archive format selection:\n"
     "  -o, --format=asar            Create asar archive even if extension is not .asar\n"
     "  --format=bsar                Create bsar archive even if extension is .asar\n"
     "\n"
     "Informative output:\n"
     "  -v, --verbose                Increase output verbosity\n"
     "  -q, --quiet                  Suppress logging\n"
     "  -h, --help                   Print this help, then exit\n"
     "\n"
     "Note: when creating archives (-c), only the name of each argument file/dir\n"
     "is stored in the archive, not a complete path to the argument file/dir.\n");
     
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
        else if ((arg = strprf(eoptarg, "exclude=")) != NULL) addex(&g_expats, arg);
        else if ((arg = strprf(eoptarg, "unpack=")) != NULL) addex(&g_unpats, arg);
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

