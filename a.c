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
#include "r.h"

/* bar globals */
char g_cmd = 'h'; /* 't', 'x', 'c', or 'h' */
const char *g_arfile = NULL; /* archive file name */
const char *g_dstdir = NULL; /* destination dir or - for stdout */
const char *g_infile = NULL; /* included glob patterns file name */
const char *g_exfile = NULL; /* excluded glob patterns file name */
bool g_keepold = false; /* do not owerwrite existing files (-k) */
int g_integrity = 0; /* check/calc integrity hashes; 1: SHA256 */
int g_integerrc = 0; /* extraction integrity error count */
int g_format = 0; /* 'b': BSAR, 'a': ASAR, 0: check extension */
dsbuf_t g_inpats; /* list of included patterns */
dsbuf_t g_expats; /* list of excluded patterns */
dsbuf_t g_unpats; /* list of unpacked patterns */
size_t g_bufsize = 0x400000;
char *g_buffer = NULL;

void init_archiver(void)
{
  dsbinit(&g_inpats);
  dsbinit(&g_expats);
  dsbinit(&g_unpats);
  g_buffer = exmalloc(g_bufsize);
} 

void fini_archiver(void)
{
  dsbfini(&g_inpats);
  dsbfini(&g_expats);
  dsbfini(&g_unpats);
  free(g_buffer);
}

#define PAT_LITERAL 1
#define PAT_ANCHORED 2
#define PAT_WCMATCHSLASH 4

void addpat(dsbuf_t *pdsb, const char *arg, int flags)
{
  chbuf_t cb = mkchb(); char *pat; 
  size_t len = strlen(arg);
  if (len > 0 && arg[len-1] == '/') --len;
  chbset(&cb, arg, len);
  chbinsc(&cb, 0, '0'+flags);
  pat = chbdata(&cb); 
  dsbpushbk(pdsb, &pat);
  chbfini(&cb);
}

void loadpats(dsbuf_t *pdsb, const char *fname, int flags)
{
  FILE *fp = fopen(fname, "r");
  chbuf_t cb = mkchb(); char *line;
  if (!fp) exprintf("can't open excluded patterns file %s:", g_exfile);
  while ((line = fgetlb(&cb, fp)) != NULL) {
    line = strtrim(line);
    if (*line == 0 || *line == '#') continue;
    addpat(&g_expats, line, flags);
  }
  fclose(fp);
  chbfini(&cb);
}

bool matchpats(const char *path, const char *fname, dsbuf_t *pdsb)
{
  size_t i;
  for (i = 0; i < dsblen(pdsb); ++i) {
    dstr_t *pds = dsbref(pdsb, i), pat = *pds;
    int flags = *pat++ - '0'; bool res;
    if (flags & PAT_LITERAL) res = streql(path, pat);
    else if (flags & PAT_ANCHORED) res = gmatch(path, pat);
    else if (strprf(pat, "./")) res = gmatch(path, pat+2);
    else if (strchr(pat, '/')) res = gmatch(path, pat);
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

void parse_header_files_json(JFILE *jfp, const char *base, fdebuf_t *pfdb)
{
  chbuf_t kcb = mkchb(), ncb = mkchb();
  jfgetobrc(jfp);
  while (!jfatcbrc(jfp)) {
    fdent_t *pfde = fdebnewbk(pfdb);
    jfgetkey(jfp, &ncb); /* name: */
    vverbosef("%s/%s\n", base, chbdata(&ncb));
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
      vverbosef("  offset = 0x%.8lx (%ld)\n", 
        (unsigned long)pfde->offset, (unsigned long)pfde->offset);
      vverbosef("  size = 0x%.8lx (%ld)\n", 
        (unsigned long)pfde->size, (unsigned long)pfde->size);
      vverbosef("  executable = %d\n", (int)pfde->executable);
      vverbosef("  unpacked = %d\n", (int)pfde->unpacked);
    }
    jfgetcbrc(jfp);
  }
  jfgetcbrc(jfp);
  chbfini(&kcb), chbfini(&ncb);
}

void parse_header_files_bson(BFILE *bfp, const char *base, fdebuf_t *pfdb)
{
  chbuf_t kcb = mkchb(), ncb = mkchb();
  bfgetobrc(bfp);
  while (!bfatcbrc(bfp)) {
    fdent_t *pfde = fdebnewbk(pfdb);
    bfgetkey(bfp, &ncb); /* name: */
    vverbosef("%s/%s\n", base, chbdata(&ncb));
    pfde->name = exstrdup(chbdata(&ncb));
    bfgetobrc(bfp);
    while (!bfatcbrc(bfp)) {
      char *key = bfgetkey(bfp, &kcb);
      if (streql(key, "files")) {
        char *nbase = chbsetf(&kcb, "%s/%s", base, chbdata(&ncb));
        pfde->isdir = true;
        parse_header_files_bson(bfp, nbase, &pfde->files);
      } else if (streql(key, "offset")) { 
        pfde->offset = bfgetnumull(bfp);
      } else if (streql(key, "size")) { 
        pfde->size = bfgetnumull(bfp);
      } else if (streql(key, "executable")) { 
        pfde->executable = bfgetbool(bfp);
      } else if (streql(key, "unpacked")) { 
        pfde->unpacked = bfgetbool(bfp);
      } else if (streql(key, "integrity")) {
        int integrity = 0; 
        bfgetobrc(bfp);
        while (!bfatcbrc(bfp)) {
          key = bfgetkey(bfp, &kcb);
          if (streql(key, "algorithm")) {
            integrity = bfgetnum(bfp);
            if (integrity == 1) pfde->integrity_algorithm = 1; /* SHA256 */
          } else if (streql(key, "hash")) {
            char *hash = bfgetbin(bfp, &kcb);
            if (integrity == 1 && chblen(&kcb) == SHA256DG_SIZE)
              pfde->integrity_hash = exmemdup(hash, SHA256DG_SIZE);
          } else if (streql(key, "blockSize")) {
            unsigned long n = (unsigned long)bfgetnumull(bfp);
            if (integrity == 1) pfde->integrity_block_size = n; 
          } else if (streql(key, "blocks")) {
            bfgetobrk(bfp);
            while (!bfatcbrk(bfp)) {
              char *block = bfgetbin(bfp, &kcb);
              if (integrity == 1 && chblen(&kcb) == SHA256DG_SIZE) {
                *dsbnewbk(&pfde->integrity_blocks) = exmemdup(block, SHA256DG_SIZE);
              }  
            }
            bfgetcbrk(bfp);
          }
        }
        bfgetcbrc(bfp);
      } else { 
        exprintf("%s: invalid entry: %s", g_arfile, chbdata(&kcb));
      }
    }
    if (!pfde->isdir) {
      vverbosef("  offset = 0x%.8lx (%ld)\n", 
        (unsigned long)pfde->offset, (unsigned long)pfde->offset);
      vverbosef("  size = 0x%.8lx (%ld)\n", 
        (unsigned long)pfde->size, (unsigned long)pfde->size);
      vverbosef("  executable = %d\n", (int)pfde->executable);
      vverbosef("  unpacked = %d\n", (int)pfde->unpacked);
    }
    bfgetcbrc(bfp);
  }
  bfgetcbrc(bfp);
  chbfini(&kcb), chbfini(&ncb);
}

uint32_t read_header(FILE *fp, fdebuf_t *pfdb)
{
  uint8_t hbuf[16]; uint32_t psz, off, asz, ssz;
  int format; /* 'a': asar, 'b': bsar */ 
  /* read header data from fp */
  if (fread(hbuf, 4, 1, fp) != 1) goto err;
  psz = unpack_uint32_le(hbuf);
  if (psz == 3) format = 'b';
  else if (psz == 4) format = 'a';
  else exprintf("%s: invalid archive header", g_arfile);
  if (format == 'a') { /* asar, 4-word signature */ 
    JFILE *jfp; uint32_t x;
    chbuf_t kcb = mkchb();
    if (fread(hbuf+4, 12, 1, fp) != 1) goto err;
    off = unpack_uint32_le(hbuf+4);  
    asz = unpack_uint32_le(hbuf+8);  
    ssz = unpack_uint32_le(hbuf+12);
    if (ssz < 12) exprintf("%s: invalid asar archive header [3]", g_arfile);
    x = ssz + 4; if (x % 4 > 0) x += 4 - (x % 4); /* align to 32 bit */
    if (x != asz) exprintf("%s: invalid asar archive header [2]", g_arfile);
    x += 4;
    if (x != off) exprintf("%s: invalid asar archive header [1]", g_arfile); 
    off += 12; /* from the start of the file */
    /* header starts right after 4-word signature */
    jfp = newjfii(FILE_pii, fp);
    jfgetobrc(jfp);
    jfgetkey(jfp, &kcb); /* "files": */
    if (!streql(chbdata(&kcb), "files")) exprintf("%s: invalid asar file list", g_arfile);
    parse_header_files_json(jfp, "", pfdb);
    jfgetcbrc(jfp);
    freejf(jfp);
    chbfini(&kcb);
  } else { /* bsar, 3-word signature */
    BFILE *bfp; chbuf_t kcb = mkchb();
    if (fread(hbuf+4, 8, 1, fp) != 1) goto err;
    off = unpack_uint32_le(hbuf+4);  
    asz = unpack_uint32_le(hbuf+8);  
    ssz = 0;
    if (asz != off) exprintf("%s: invalid bsar archive header [1]", g_arfile);
    off += 12; /* from the start of the file */
    /* header starts right after 3-word signature */
    bfp = newbfii(FILE_pii, fp);
    bfgetobrc(bfp);
    bfgetkey(bfp, &kcb); /* "files": */
    if (!streql(chbdata(&kcb), "files")) exprintf("%s: invalid bsar file list", g_arfile);
    parse_header_files_bson(bfp, "", pfdb);
    bfgetcbrc(bfp);
    freebf(bfp);
    chbfini(&kcb);
  }
  return off;
err:
  exprintf("%s: can't read archive header", g_arfile);
  return 0;
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

void write_header(int format, fdebuf_t *pfdb, FILE *fp)
{
  uint8_t hbuf[16]; uint32_t psz, off, asz, ssz;
  chbuf_t hcb = mkchb();
  /* serialize header data to hcb */
  if (format == 'a') {
    JFILE *jfp = newjfoi(cbuf_poi, &hcb);
    jfputobrc(jfp);
    jfputkey(jfp, "files");
    unparse_header_files_json(jfp, pfdb);
    jfputcbrc(jfp);
    freejf(jfp);
  } else {
    BFILE *bfp = newbfoi(cbuf_poi, &hcb);
    bfputobrc(bfp);
    bfputkey(bfp, "files");
    unparse_header_files_bson(bfp, pfdb);
    bfputcbrc(bfp);
    freebf(bfp);
  }
  /* write header data to fp */
  ssz = (uint32_t)chblen(&hcb);
  if (format == 'a') { /* asar, 4-word signature */
    psz = 4; 
    asz = ssz + 4; /* add at least 4 bytes */ 
    if (asz % 4 > 0) asz += 4 - (asz % 4); /* align to 32 bit */
    off = sizeof(ssz) + asz; /* offset from the end of asz */
    pack_uint32_le(psz, hbuf);
    pack_uint32_le(off, hbuf+4);  
    pack_uint32_le(asz, hbuf+8);  
    pack_uint32_le(ssz, hbuf+12);
  } else { /* bsar, 3-word signature */
    psz = 3;
    asz = ssz; /* no extra padding */ 
    if (asz % 4 > 0) asz += 4 - (asz % 4); /* align to 32 bit */
    off = asz; /* offset from the end of asz */
    pack_uint32_le(psz, hbuf);
    pack_uint32_le(off, hbuf+4);  
    pack_uint32_le(asz, hbuf+8);  
  }
  if (fwrite(hbuf, psz*4, 1, fp) != 1) goto err;
  if (fwrite(chbdata(&hcb), ssz, 1, fp) != 1) goto err;
  if (asz > ssz) {
    memset(hbuf, 0, 16);
    if (fwrite(hbuf, asz-ssz, 1, fp) != 1) goto err;
  }
  chbfini(&hcb);
  return;
err: 
  exprintf("%s: can't write archive header", g_arfile);
}


void list_files(const char *base, fdebuf_t *pfdb, dsbuf_t *ppats, bool full, FILE *pf)
{
  size_t i; chbuf_t cb = mkchb();
  for (i = 0; i < fdeblen(pfdb); ++i) {
    fdent_t *pfde = fdebref(pfdb, i); 
    dsbuf_t *ppatsi = ppats; const char *sbase;
    if (!base) sbase = pfde->name;
    else sbase = chbsetf(&cb, "%s/%s", base, pfde->name);
    if (matchpats(sbase, pfde->name, &g_expats)) continue;
    /* ppats == NULL means list this one and everything below */
    if (ppatsi && matchpats(sbase, pfde->name, ppatsi)) ppatsi = NULL;
    if (pfde->isdir) {
      if (!ppatsi) {
        if (full) {
          fprintf(pf, "d--%c ", pfde->unpacked ? 'u' : '-');
          fprintf(pf, "                           ");
        }
        if (!base) fprintf(pf, "%s/\n", pfde->name);
        else fprintf(pf, "%s/%s/\n", base, pfde->name);
      }
      list_files(sbase, &pfde->files, ppatsi, full, pf);
    } else {
      if (!ppatsi) {
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
  }
  chbfini(&cb);
}

void list(int argc, char **argv)
{
  FILE *fp; uint32_t hsz; 
  fdebuf_t fdeb; fdebinit(&fdeb);
  while (argc-- > 0) addpat(&g_inpats, *argv++, PAT_LITERAL);
  if (!(fp = fopen(g_arfile, "rb"))) exprintf("can't open archive file %s:", g_arfile);
  hsz = read_header(fp, &fdeb);
  list_files(NULL, &fdeb, dsbempty(&g_inpats) ? NULL : &g_inpats, getverbosity()>0, stdout);
  fdebfini(&fdeb);
  fclose(fp);
}


/* copy file via fread/fwrite */
size_t copy_file(FILE *ifp, FILE *ofp)
{
  size_t bc = 0;
  assert(ifp); assert(ofp);
  for (;;) {
    size_t n = fread(g_buffer, 1, g_bufsize, ifp);
    if (!n) break;
    fwrite(g_buffer, 1, n, ofp);
    bc += n;
    if (n < g_bufsize) break;
  }
  return bc;
}

void write_file(const char *path, fdent_t *pfde, FILE *ofp)
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
    pfde->integrity_block_size = (uint32_t)g_bufsize;
    sha256init(&fhash);
  }
  for (;;) {
    size_t n = fread(g_buffer, 1, g_bufsize, ifp);
    if (g_integrity == 1) {
      sha256init(&bhash);
      sha256update(&bhash, g_buffer, n);
      sha256fini(&bhash, digest);
      *dsbnewbk(&pfde->integrity_blocks) = exmemdup((char*)&digest[0], SHA256DG_SIZE);
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
    sha256fini(&fhash, digest);
    pfde->integrity_hash = exmemdup((char*)&digest[0], SHA256DG_SIZE);
  }
  fclose(ifp);
  chbfini(&cb);
}

uint64_t create_files(uint64_t off, const char *base, const char *path, fdebuf_t *pfdeb, FILE *ofp)
{
  fsstat_t st;
  if (fsstat(path, &st) && (st.isdir || st.isreg)) {
    char *fname; fdent_t *pfde;
    fname = getfname(path);
    if (matchpats(base, fname, &g_expats)) return off;
    pfde = fdebnewbk(pfdeb);
    pfde->name = exstrdup(fname);
    pfde->isdir = st.isdir;
    pfde->size = st.size;
    if (matchpats(base, fname, &g_unpats)) {
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
            off = create_files(off, nb, np, &pfde->files, ofp);
          }
        } else {
          exprintf("can't open directory: %s", path);
        }
        dsbfini(&dsb);
        chbfini(&cbb), chbfini(&cbp);
      } else {
        pfde->offset = off;
        off += pfde->size;
        write_file(path, pfde, ofp);
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
  int i, format; uint64_t off = 0;
  if (!(fp = fopen(g_arfile, "wb"))) exprintf("can't open archive file %s:", g_arfile);
  format = g_format ? g_format : strsuf(g_arfile, ".asar") ? 'a' : 'b';
  tfp = etmpopen("w+b");
  fdebinit(&fdeb);
  for (i = 0; i < argc; ++i) {
    /* NB: we don't care where file/dir arg is located */
    off = create_files(off, getfname(argv[i]), argv[i], &fdeb, tfp);
  }
  list_files(NULL, &fdeb, NULL, getverbosity()>0, stdout);
  write_header(format, &fdeb, fp);
  rewind(tfp);
  copy_file(tfp, fp);
  fclose(tfp);
  fclose(fp);
  fdebfini(&fdeb);
}


/* copy file via fread/fwrite */
size_t copy_file_n(FILE *ifp, FILE *ofp, size_t bytec, fdent_t *pfde)
{
  sha256ctx_t fhash, bhash;
  uint8_t digest[SHA256DG_SIZE];
  size_t bc = 0, ibidx = 0; 
  bool ckint = false;
  assert(ifp); assert(ofp);
  if (g_integrity == 1 && pfde->integrity_algorithm == 1) {
    sha256init(&fhash);
    ckint = true;
  }
  while (bytec > 0) {
    size_t c = (bytec < g_bufsize) ? bytec : g_bufsize;
    size_t n = fread(g_buffer, 1, c, ifp);
    if (!n) break;
    if (ckint) {
      sha256init(&bhash);
      sha256update(&bhash, g_buffer, n);
      sha256fini(&bhash, digest);
      if (ibidx < dsblen(&pfde->integrity_blocks)) {
        if (memcmp(*dsbref(&pfde->integrity_blocks, ibidx), &digest[0], SHA256DG_SIZE) != 0) {
          logef("Warning: %s: integrity info does not match member block: %s [%d]\n", g_arfile, pfde->name, (int)ibidx);
        }
      }
      ++ibidx;
      sha256update(&fhash, g_buffer, n);
    }
    fwrite(g_buffer, 1, n, ofp);
    bc += n;
    bytec -= c;
  }
  if (ckint) {
    sha256fini(&fhash, digest);
    if (memcmp(pfde->integrity_hash, &digest[0], SHA256DG_SIZE) != 0) {
      logef("Warning: %s: integrity info does not match member contents: %s\n", g_arfile, pfde->name);
      g_integerrc += 1;
    } else {
      if (getverbosity() > 1) logef("**** integrity checks passed\n");
    }
  }
  return bc;
}

void extract_files(const char *base, uint32_t hsz, fdebuf_t *pfdb, dsbuf_t *ppats, FILE *fp)
{
  size_t i; chbuf_t cb = mkchb();
  for (i = 0; i < fdeblen(pfdb); ++i) {
    fdent_t *pfde = fdebref(pfdb, i);
    dsbuf_t *ppatsi = ppats; const char *sbase;
    if (!base) sbase = pfde->name;
    else sbase = chbsetf(&cb, "%s/%s", base, pfde->name);
    if (matchpats(sbase, pfde->name, &g_expats)) continue;
    /* ppats == NULL means extract this one and everything below */
    if (ppatsi && matchpats(sbase, pfde->name, ppatsi)) ppatsi = NULL;
    if (pfde->isdir) {
      extract_files(sbase, hsz, &pfde->files, ppatsi, fp);
    } else if (!ppatsi && !pfde->unpacked) {
      size_t n, fsz = (size_t)pfde->size; 
      long long pos = (long long)hsz + (long long)pfde->offset;
      if (getverbosity() > 0) {
        logef("-%c%c%c ", pfde->integrity_hash ? 'i' : '-',
          pfde->executable ? 'x' : '-', pfde->unpacked ? 'u' : '-');
        if (pfde->unpacked) logef("              %12lu ", (unsigned long)pfde->size);
        else logef("@%-12lu %12lu ", (unsigned long)pfde->offset, (unsigned long)pfde->size);
      }
      logef("%s\n", sbase);
      if (fseekll(fp, pos, SEEK_SET) != 0) exprintf("%s: seek failed", g_arfile);
      if (streql(g_dstdir, "-")) {
        n = copy_file_n(fp, stdout, fsz, pfde);
      } else {
        chbuf_t fcb = mkchb(), dcb = mkchb();
        char *dstdir = trimdirsep(chbsets(&dcb, g_dstdir));
        char *dpath = (streql(dstdir, ".")) ?
          chbsets(&fcb, sbase) : chbsetf(&fcb, "%s%c%s", dstdir, dirsep, sbase);
        char *ddir = chbset(&dcb, dpath, spanfdir(dpath));
        FILE *ofp;
        if (!direxists(ddir)) {
          vverbosef("%s: creating missing directories on path: %s\n", progname(), ddir);
          emkdirp(ddir);
        }
        if (fexists(dpath) && g_keepold) {
          logef("%s: keeping existing file in -k mode: %s\n", progname(), dpath);
          continue;
        }
        ofp = fopen(dpath, "wb");
        if (!ofp) {
          exprintf("%s: can't open file for writing:", dpath);
        } else { 
          n = copy_file_n(fp, ofp, fsz, pfde); 
          fclose(ofp); 
        }
        chbfini(&fcb), chbfini(&dcb);
      }
      if (n != fsz) exprintf("%s: unexpected end of archive", g_arfile);
    }
  }
  chbfini(&cb);
}

void extract(int argc, char **argv)
{
  FILE *fp; uint32_t hsz; 
  fdebuf_t fdeb; fdebinit(&fdeb);
  while (argc-- > 0) addpat(&g_inpats, *argv++, PAT_LITERAL);
  if (!(fp = fopen(g_arfile, "rb"))) exprintf("can't open archive file %s:", g_arfile);
  hsz = read_header(fp, &fdeb);
  extract_files(NULL, hsz, &fdeb, dsbempty(&g_inpats) ? NULL : &g_inpats, fp);
  fdebfini(&fdeb);
  fclose(fp);
  if (g_integerrc > 0) {
    logef("%s: %d member(s) had integrity problems\n", g_arfile, (int)g_integerrc);
    exit(1);
  }
}


int main(int argc, char **argv)
{
  int opt;
  int patflags = 0;

  setu8cp();
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
     "  --include-from=FILE          List/extract files via globbing patterns in FILE\n"
     "  --include=\"PATTERN\"          List/extract files, given as a globbing PATTERN\n"
     "  --integrity=SHA256           Calculate or check file integrity info\n"
     "\n"
     "Archive format selection:\n"
     "  -o, --format=asar            Create asar archive even if extension is not .asar\n"
     "  --format=bsar                Create bsar archive even if extension is .asar\n"
     "\n"
     "File name matching options:\n"
     "   --anchored                  Patterns match path\n"
     "   --no-anchored               Patterns match file/directory name\n"
     "   --wildcards                 Patterns are wildcards\n"
     "   --no-wildcards              Patterns match verbatim\n"
     "\n"
     "Informative output:\n"
     "  -v, --verbose                Increase output verbosity\n"
     "  -q, --quiet                  Suppress logging\n"
     "  -h, --help                   Print this help, then exit\n"
     "\n"
     "Note: when creating archives (-c), only the name of each argument file/dir\n"
     "is stored in the archive, not a complete path to the argument file/dir.\n");
  
  if (argc >= 3 && *argv[1] != '-') {
    /* traditional tar-like usage: cmd archive ... */
    char *cmd = argv[1];
    bool gotf = false, gotmode = false; 
    while (*cmd) switch (*cmd++) {
      case 'c': g_cmd = 'c'; gotmode = true; break;
      case 't': g_cmd = 't'; gotmode = true; break;
      case 'x': g_cmd = 'x'; gotmode = true; break;
      case 'f': gotf = true; break;
      case 'o': g_format = 'a'; break;
      case 'k': g_keepold = true; break;
      case 'v': incverbosity(); break;
      default: eusage("unexpected flag in command combo: %c", *--cmd);
    }
    if (!gotf || !gotmode) eusage("invalid command combo: %s", argv[1]);
    /* next argument is archive name */
    g_arfile = argv[2];
    /* continue parsing options/args from argv[3] */
    eoptind = 3;
  }
     
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
      case 'o': g_format = 'a'; break;
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
        else if ((arg = strprf(eoptarg, "exclude=")) != NULL) addpat(&g_expats, arg, patflags);
        else if ((arg = strprf(eoptarg, "unpack=")) != NULL) addpat(&g_unpats, arg, patflags);
        else if ((arg = strprf(eoptarg, "include-from=")) != NULL) g_infile = arg;
        else if ((arg = strprf(eoptarg, "include=")) != NULL) addpat(&g_inpats, arg, patflags);
        else if (streql(eoptarg, "anchored")) patflags |= PAT_ANCHORED;
        else if (streql(eoptarg, "no-anchored")) patflags &= ~PAT_ANCHORED;
        else if (streql(eoptarg, "wildcards")) patflags &= ~PAT_LITERAL;
        else if (streql(eoptarg, "no-wildcards")) patflags |= PAT_LITERAL;
        else if (streql(eoptarg, "verbose")) incverbosity();
        else if (streql(eoptarg, "quiet")) incquietness();
        else if (streql(eoptarg, "help")) g_cmd = 'h';
        else if (streql(eoptarg, "integrity=SHA256")) g_integrity = 1;
        else if (streql(eoptarg, "integrity")) g_integrity = 1;
        else if (streql(eoptarg, "old-archive")) g_format = 'a';
        else if (streql(eoptarg, "format=asar")) g_format = 'a';
        else if (streql(eoptarg, "format=bsar")) g_format = 'b';
        else eusage("illegal option: --%s", eoptarg);  
      } break;
    }
  }
  
  if (streql(g_dstdir, "-")) fbinary(stdout);
  if (g_exfile) loadpats(&g_expats, g_exfile, patflags);
  if (g_infile) loadpats(&g_inpats, g_infile, patflags);
  
  switch (g_cmd) {
    case 't': {
      if (!g_arfile) eusage("-f FILE argument is missing");
      if (g_dstdir) eusage("unexpected -C/-O options in list mode");
      list(argc-eoptind, argv+eoptind);
    } break;
    case 'c': {
      if (!g_arfile) eusage("-f FILE argument is missing");
      if (g_dstdir) eusage("unexpected -C/-O options in create mode");
      if (!dsbempty(&g_inpats)) eusage("unexpected include options in create mode");
      create(argc-eoptind, argv+eoptind);
    } break;
    case 'x': {
      if (!g_arfile) eusage("-f FILE argument is missing");
      if (!g_dstdir) g_dstdir = ".";
      extract(argc-eoptind, argv+eoptind);
    } break;
    case 'h': {
      eusage("BAR (Basic Archiver) 1.00 built on " __DATE__); 
    } break;
  }  

  fini_archiver();

  return EXIT_SUCCESS;
}

