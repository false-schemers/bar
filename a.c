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
const char *g_ar = NULL;
/* long options for 'pack' command */
const char *g_ordering = NULL;
const char *g_unpack = NULL;
const char *g_unpack_dir = NULL;
bool g_exclude_hidden = false;
/* long options for 'list' command */
bool g_is_pack = false;

void init_archiver(void)
{
} 

void fini_archiver(void)
{
}

/* file/directory entry */

fdent_t* fdeinit(fdent_t* mem)
{
  memset(mem, 0, sizeof(fdent_t));
  fdebinit(&mem->files);
  dsinit(&mem->name);
  dsinit(&mem->integrity_algorithm);
  dsinit(&mem->integrity_hash);
  dsbinit(&mem->integrity_blocks);
  return mem;
}

void fdefini(fdent_t* pe)
{
  fdebfini(&pe->files);
  dsfini(&pe->name);
  dsfini(&pe->integrity_algorithm);
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
  if (fread(hbuf, 16, 1, fp) != 1) exprintf("%s: can't read archive header", g_ar);
  psz = unpack_uint32_le(hbuf);
  off = unpack_uint32_le(hbuf+4);  
  asz = unpack_uint32_le(hbuf+8);  
  ssz = unpack_uint32_le(hbuf+12);
  verbosef("psz = 0x%.8x, off = 0x%.8x, asz = 0x%.8x, ssz = 0x%.8x\n", psz, off, asz, ssz);
  if (ssz < 12) exprintf("%s: invalid archive header [3]", g_ar);
  x = ssz + 4; if (x % 4 > 0) x += 4 - (x % 4); /* align to 32 bit */
  if (x != asz) exprintf("%s: invalid archive header [2]", g_ar);
  x += 4;
  if (x != off) exprintf("%s: invalid archive header [1]", g_ar); 
  if (psz != 4) exprintf("%s: invalid archive header [0]", g_ar);
  bufresize(pcb, ssz);
  if (fread(pcb->buf, 1, ssz, fp) != ssz) exprintf("%s: invalid archive header data", g_ar);
  return off;
}

void parse_header_files(JFILE *jfp, const char *base, fdebuf_t *pfdb)
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
        parse_header_files(jfp, nbase, &pfde->files);
      } else if (streql(key, "offset")) { 
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
            pfde->integrity_algorithm = exstrdup(jfgetstr(jfp, &kcb));
          } else if (streql(key, "hash")) {
            pfde->integrity_hash = exstrdup(jfgetstr(jfp, &kcb));
          } else if (streql(key, "blockSize")) {
            pfde->integrity_block_size = (unsigned long)jfgetnumull(jfp); 
          } else if (streql(key, "blocks")) {
            jfgetobrk(jfp);
            while (!jfatcbrk(jfp)) {
              char *block = jfgetstr(jfp, &kcb);
              dsbpushbk(&pfde->integrity_blocks, &block);
            }
            jfgetcbrk(jfp);
          }
        }
        jfgetcbrc(jfp);
      } else { 
        exprintf("%s: invalid entry: %s", g_ar, chbdata(&kcb));
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

void unparse_header_files(JFILE *jfp, fdebuf_t *pfdb)
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
      unparse_header_files(jfp, &pfde->files);
    } else {
      jfputkey(jfp, "size");
      jfputnumull(jfp, pfde->size);
      if (pfde->unpacked) {
        jfputkey(jfp, "unpacked"); 
        jfputbool(jfp, true); 
      } else {      
        jfputkey(jfp, "offset");
        jfputstr(jfp, chbsetf(&cb, "%llu", pfde->offset)); 
      }
      if (pfde->executable) { 
        jfputkey(jfp, "executable"); 
        jfputbool(jfp, true); 
      }
      if (pfde->integrity_algorithm) {
        jfputkey(jfp, "integrity"); 
        jfputobrc(jfp);
        jfputkey(jfp, "algorithm"); 
        jfputstr(jfp, pfde->integrity_algorithm);
        if (pfde->integrity_hash) {
          jfputkey(jfp, "hash"); 
          jfputstr(jfp, pfde->integrity_hash);
        }
        if (pfde->integrity_block_size) {
          size_t k;
          jfputkey(jfp, "blockSize"); 
          jfputnumull(jfp, pfde->integrity_block_size);
          jfputkey(jfp, "blocks");
          jfputobrk(jfp);
          for (k = 0; k < dsblen(&pfde->integrity_blocks); ++k) {
            dstr_t *pds = dsbref(&pfde->integrity_blocks, k);
            jfputstr(jfp, *pds);
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

void parse_header(chbuf_t *pcb, fdebuf_t *pfdb)
{
  char *pc = pcb->buf; 
  JFILE *jfpi = newjfii(strptr_pii, &pc);
  JFILE *jfpo = newjfoi(FILE_poi, stdout);
  chbuf_t kcb = mkchb(); 
  jfgetobrc(jfpi);
  jfgetkey(jfpi, &kcb); /* "files": */
  if (!streql(chbdata(&kcb), "files")) exprintf("%s: invalid file list", g_ar);
  parse_header_files(jfpi, "", pfdb);
  jfgetcbrc(jfpi);
  freejf(jfpi);
  jfputobrc(jfpo);
  jfputkey(jfpo, "files");
  unparse_header_files(jfpo, pfdb);
  jfputcbrc(jfpo);
  freejf(jfpo); fputc('\n', stdout);
  chbfini(&kcb);
}

void pack(const char *dir, const char *ar)
{
  eusage("NYI: pack");
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

void list(const char *ar)
{
  FILE *fp; uint32_t off; chbuf_t cb = mkchb();
  fdebuf_t fdeb; fdebinit(&fdeb);
  g_ar = ar;
  if (!(fp = fopen(ar, "rb"))) exprintf("can't open archive file %s:", ar);
  off = read_header(fp, &cb);
  verbosef("header = \'%s\'\n", chbdata(&cb));
  parse_header(&cb, &fdeb);
  list_fdebuf(NULL, &fdeb, stdout, true);
  chbfini(&cb); fdebfini(&fdeb);
  fclose(fp);
}

void extractf(const char *ar, const char *f)
{
  eusage("NYI: extract-file");
}

void extract(const char *ar, const char *dir)
{
  eusage("NYI: extract");
}

/* interpret long options */
static void longopt(const char *longopt, int *peoptind, int argc, char **argv)
{
  if (streql(longopt, "ordering") && *peoptind < argc)
    g_ordering = argv[(*peoptind)++];
  else if (streql(longopt, "unpack") && *peoptind < argc)
    g_unpack = argv[(*peoptind)++];
  else if (streql(longopt, "unpack-dir") && *peoptind < argc)
    g_unpack_dir = argv[(*peoptind)++];
  else if (streql(longopt, "exclude-hidden"))
    g_exclude_hidden = true;
  else if (streql(longopt, "is-pack"))
    g_is_pack = true;
  else eusage("illegal option: --%s", longopt);  
}

int main(int argc, char **argv)
{
  int opt;
  const char *cmd = NULL;
  const char *dir = NULL;
  const char *ar  = NULL;
  const char *f   = NULL;

  setprogname(argv[0]);
  setusage
    ("[OPTIONS] [COMMAND]\n"
     "commands are:\n"
     "   c  dir ar  Pack dir as archive ar\n"
     "   l  ar      List ar contents\n"
     "   ef ar f    Extract file f from archive ar\n"
     "   e  ar dir  Extract archive ar as dir\n"
     "command-specific options are:\n"
     "  --is-pack   List: each file in the asar is pack or unpack\n"
     "options are:\n"
     "  -w          Suppress warnings\n"
     "  -v          Increase verbosity\n"
     "  -q          Suppress logging ('quiet')\n"
     "  -i          Same as --is-pack\n"
     "  -h          This help");
  while ((opt = egetopt(argc, argv, "wvq-:h")) != EOF) {
    switch (opt) {
      case 'w':  setwlevel(3); break;
      case 'v':  incverbosity(); break;
      case 'q':  incquietness(); break;
      case '-':  longopt(eoptarg, &eoptind, argc, argv); break;
      case 'h':  eusage("BAR 1.00 built on " __DATE__);
    }
  }

  init_archiver();

  if (eoptind == argc) eusage("command argument is missing");
  cmd = argv[eoptind++];
  if (streql(cmd, "p") || streql(cmd, "pack")) {
    if (eoptind == argc) eusage("dir argument of pack command is missing");
    dir = argv[eoptind++];
    if (eoptind == argc) eusage("ar argument of pack command is missing");
    ar = argv[eoptind++];
    if (eoptind != argc) eusage("too many arguments of pack command");
    pack(dir, ar);
  } else if (streql(cmd, "l") || streql(cmd, "list")) { 
    if (eoptind == argc) eusage("ar argument of list command is missing");
    ar = argv[eoptind++];
    if (eoptind != argc) eusage("too many arguments of list command");
    list(ar);
  } else if (streql(cmd, "ef") || streql(cmd, "extract-file")) { 
    if (eoptind == argc) eusage("ar argument of extract-file command is missing");
    ar = argv[eoptind++];
    if (eoptind == argc) eusage("file argument of extract-file command is missing");
    f = argv[eoptind++];
    if (eoptind != argc) eusage("too many arguments of extract-file command");
    extractf(ar, f);
  } else if (streql(cmd, "e") || streql(cmd, "extract")) { 
    if (eoptind == argc) eusage("ar argument of extract command is missing");
    ar = argv[eoptind++];
    if (eoptind == argc) eusage("dir argument of extract command is missing");
    dir = argv[eoptind++];
    if (eoptind != argc) eusage("too many arguments of extract command");
    extract(ar, dir);
  } else {
    eusage("unknown command");
  }

  fini_archiver();

  return EXIT_SUCCESS;
}

