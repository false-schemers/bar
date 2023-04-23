/* c.c (wcpl compiler) -- esl */

#include <stdbool.h>
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
long    g_optlvl;   /* -O arg */

void init_archiver(void)
{
} 

void fini_archiver(void)
{
}

void pack(const char *dir, const char *ar)
{
  eusage("NYI: pack");
}

void list(const char *ar)
{
  eusage("NYI: list");
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

