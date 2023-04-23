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


/* wcpl globals */
const char * g_ar = NULL;

void init_archiver(void)
{
} 

void fini_archiver(void)
{
}

uint32_t unpack_uint32_le(uint8_t buf[4])
{
  return buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
}

uint32_t read_header(FILE *fp, chbuf_t *pcb)
{
  uint8_t hbuf[16]; uint32_t psz, off, x, ssz;
  if (fread(hbuf, 16, 1, fp) != 1) exprintf("%s: can't read archive header", g_ar);
  psz = unpack_uint32_le(hbuf);
  off = unpack_uint32_le(hbuf+4);  
  x = unpack_uint32_le(hbuf+8);  
  ssz = unpack_uint32_le(hbuf+12);
  verbosef("psz = 0x%.8x, off = 0x%.8x, x = 0x%.8x, ssz = 0x%.8x\n", psz, off, x, ssz);
  if (psz != 4 || x > off || ssz > off) exprintf("%s: invalid archive header", g_ar);
  bufresize(pcb, ssz);
  if (fread(pcb->buf, 1, ssz, fp) != ssz) exprintf("%s: invalid archive header data", g_ar);
  return off;
}

void parse_header_files(JFILE *jfp, const char *base)
{
  chbuf_t kcb = mkchb(), ncb = mkchb();
  jfgetobrc(jfp);
  while (!jfatcbrc(jfp)) {
    unsigned long long off = 0, size = 0;
    bool executable = false, unpacked = false;
    bool isdir = false;
    jfgetkey(jfp, &ncb); /* name: */
    fprintf(stdout, "%s/%s\n", base, chbdata(&ncb));
    jfgetobrc(jfp);
    while (!jfatcbrc(jfp)) {
      char *key = jfgetkey(jfp, &kcb);
      if (streql(key, "files")) {
        char *nbase = chbsetf(&kcb, "%s/%s", base, chbdata(&ncb));
        fprintf(stdout, "  unpacked = %d\n", (int)unpacked);
        parse_header_files(jfp, nbase);
        isdir = true;
      } else if (streql(key, "offset")) { 
        char *soff = jfgetstr(jfp, &kcb);
        off = strtoull(soff, NULL, 10);
      } else if (streql(key, "size")) { 
        size = jfgetnumull(jfp);
      } else if (streql(key, "executable")) { 
        executable = jfgetbool(jfp);
      } else if (streql(key, "unpacked")) { 
        unpacked = jfgetbool(jfp);
      } else if (streql(key, "integrity")) {
        jfgetobrc(jfp);
        while (!jfatcbrc(jfp)) {
          key = jfgetkey(jfp, &kcb);
          if (streql(key, "algorithm")) {
            char *alg = jfgetstr(jfp, &kcb);
          } else if (streql(key, "hash")) {
            char *hash = jfgetstr(jfp, &kcb);
          } else if (streql(key, "blockSize")) {
            unsigned long long bsz = jfgetnumull(jfp); 
          } else if (streql(key, "blocks")) {
            jfgetobrk(jfp);
            while (!jfatcbrk(jfp)) {
              char *block = jfgetstr(jfp, &kcb);
            }
            jfgetcbrk(jfp);
          }
        }
        jfgetcbrc(jfp);
      } else { 
        exprintf("%s: invalid entry: %s", g_ar, chbdata(&kcb));
      }
    }
    if (!isdir) {
      fprintf(stdout, "  offset = 0x%.8lx (%ld)\n", (unsigned long)off, (unsigned long)off);
      fprintf(stdout, "  size = 0x%.8lx (%ld)\n", (unsigned long)size, (unsigned long)size);
      fprintf(stdout, "  executable = %d\n", (int)executable);
      fprintf(stdout, "  unpacked = %d\n", (int)unpacked);
    }
    jfgetcbrc(jfp);
  }
  jfgetcbrc(jfp);
  chbfini(&kcb), chbfini(&ncb);
}

void parse_header(chbuf_t *pcb)
{
  char *pc = pcb->buf; JFILE *jfp = newjfii(strptr_pii, &pc);
  chbuf_t kcb = mkchb(); 
  jfgetobrc(jfp);
  jfgetkey(jfp, &kcb); /* "files": */
  if (!streql(chbdata(&kcb), "files")) exprintf("%s: invalid file list", g_ar);
  parse_header_files(jfp, "");  
  jfgetcbrc(jfp);
  freejf(jfp);
  chbfini(&kcb);
}

void pack(const char *dir, const char *ar)
{
  eusage("NYI: pack");
}

void list(const char *ar)
{
  FILE *fp; uint32_t off; chbuf_t cb = mkchb();
  g_ar = ar;
  if (!(fp = fopen(ar, "rb"))) exprintf("can't open archive file %s:", ar);
  off = read_header(fp, &cb);
  verbosef("header = \'%s\'\n", chbdata(&cb));
  parse_header(&cb);
  chbfini(&cb);
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
     "   p  dir ar  Pack dir as archive ar\n"
     "   l  ar      List ar contents\n"
     "   ef ar f    Extract file f from archive ar\n"
     "   e  ar dir  Extract archive ar as dir\n"
     "options are:\n"
     "  -w          Suppress warnings\n"
     "  -v          Increase verbosity\n"
     "  -q          Suppress logging ('quiet')\n"
     "  -h          This help");
  while ((opt = egetopt(argc, argv, "wvqh")) != EOF) {
    switch (opt) {
      case 'w':  setwlevel(3); break;
      case 'v':  incverbosity(); break;
      case 'q':  incquietness(); break;
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

