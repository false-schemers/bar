/* a.h (archiver) -- esl */

#pragma once

/* file/directory entry */
typedef struct fdent {
  bool isdir;
  dstr_t name;
  /* dir fields */
  buf_t files;
  /* file fields */
  unsigned long long offset;
  unsigned long long size;
  bool executable;
  bool unpacked;
  dstr_t integrity_algorithm;
  dstr_t integrity_hash;
  unsigned long integrity_block_size;
  dsbuf_t integrity_blocks;
} fdent_t;

extern fdent_t* fdeinit(fdent_t* mem);
extern void fdefini(fdent_t* pe);

typedef buf_t fdebuf_t;
extern fdebuf_t* fdebinit(fdebuf_t* mem);
extern void fdebfini(fdebuf_t* pb);
#define fdeblen(pb) (buflen(pb))
#define fdebref(pb, i) ((fdent_t*)bufref(pb, i))
#define fdebnewbk(pb) (fdeinit(bufnewbk(pb)))


