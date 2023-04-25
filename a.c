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
const char *g_dstdir = ".";  /* destination directory */
const char *g_exfile = NULL; /* excluded glob patterns file name */
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
  if (!streql(chbdata(&kcb), "files")) exprintf("%s: invalid file list", g_arfile);
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

void create(int argc, char **argv)
{
  chbuf_t hcb = mkchb(); int i;
  fdebuf_t fdeb; fdebinit(&fdeb);
  
  for (i = 0; i < argc; ++i) {
    /* NB: we don't care where file/dir arg is located */
    char *path = argv[i]; fsstat_t st; 
    if (fsstat(path, &st) && (st.isdir || st.isreg)) {
      char *fname = getfname(path);
      fdent_t *pfde = fdebnewbk(&fdeb);
      pfde->name = exstrdup(fname);
      pfde->isdir = st.isdir;
      pfde->size = st.size;  
      if (excluded(path)) {
        pfde->unpacked = true;
      } else {
        //if (pfde->isdir)
      }
    } else {
      exprintf("can't find file or directory: %s", path);
    }
  }
  
  list_fdebuf(NULL, &fdeb, stdout, getverbosity() > 0);
  chbfini(&hcb); fdebfini(&fdeb);
}

void extract(int argc, char **argv)
{
  eusage("NYI: extract");
}

int main(int argc, char **argv)
{
  int opt;

  setprogname(argv[0]);
  setusage
    ("[OPTION]... [FILE]...\n"
     "The archiver works with .asar (json header) and .bar (bson header) archives.\n"
     "\n"
     "Examples:\n"
     "  bar -cf archive.bar foo bar  # Create archive.bar from files foo and bar\n"
     "  bar -tvf archive.bar         # List all files in archive.bar verbosely\n"
     "  bar -xf archive.bar          # Extract all files from archive.bar\n"
     "\n"
     "Main operation mode:\n"
     "  -c, --create                 Create a new archive\n"
     "  -t, --list                   List the contents of an archive\n"
     "  -x, --extract                Extract files from an archive\n"
     "\n"
     "Operation modifiers:\n"
     "  -f, --file=FILE              Use archive FILE\n"
     "  -C, --directory=DIR          Use directory DIR for extracted files\n"
     "  -X, --exclude-from=FILE      Exclude files via globbing patterns in FILE\n"
     "\n"
     "Informative output:\n"
     "  -v, --verbose                Increase output verbosity\n"
     "  -q, --quiet                  Suppress logging\n"
     "  -h, --help                   Print this help, then exit\n");
     
  while ((opt = egetopt(argc, argv, "ctxf:X:C:wvqh-:")) != EOF) {
    switch (opt) {
      case 'c': g_cmd = 'c'; break;
      case 't': g_cmd = 't'; break;
      case 'x': g_cmd = 'x'; break;
      case 'f': g_arfile = eoptarg; break;
      case 'C': g_dstdir = eoptarg; break;
      case 'X': g_exfile = eoptarg; break;
      case 'w': setwlevel(3); break;
      case 'v': incverbosity(); break;
      case 'q': incquietness(); break;
      case 'h': g_cmd = 'h'; break;
      case '-': {
        const char *arg;
        if (streql(eoptarg, "create")) g_cmd = 'c';
        else if (streql(eoptarg, "list")) g_cmd = 't';
        else if (streql(eoptarg, "extract")) g_cmd = 'x';
        else if ((arg = strprf(eoptarg, "file=")) != NULL) g_arfile = arg;
        else if ((arg = strprf(eoptarg, "directory=")) != NULL) g_dstdir = arg;
        else if ((arg = strprf(eoptarg, "exclude-from=")) != NULL) g_exfile = arg;
        else if (streql(eoptarg, "verbose")) incverbosity();
        else if (streql(eoptarg, "quiet")) incquietness();
        else if (streql(eoptarg, "help")) g_cmd = 'h';
        else eusage("illegal option: --%s", eoptarg);  
      } break;
    }
  }

  init_archiver();
  
  switch (g_cmd) {
    case 't': {
      if (!g_arfile) eusage("-f FILE argument is missing");
      if (!streql(g_dstdir, ".")) eusage("-C option is ignored in listing mode");
      if (g_exfile) eusage("-X option is ignored in listing mode");
      if (eoptind < argc) eusage("too many arguments for list command");
      list();
    } break;
    case 'c': {
      if (!g_arfile) eusage("-f FILE argument is missing");
      if (!streql(g_dstdir, ".")) eusage("-C option is ignored in create mode");
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

