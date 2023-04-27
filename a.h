/* a.h (archiver) -- esl */

#pragma once

/* file/directory entry */
typedef struct fdent {
  bool isdir;
  dstr_t name;
  /* dir fields */
  buf_t files;
  /* file fields */
  uint64_t offset;
  uint64_t size;
  bool executable;
  bool unpacked;
  int integrity_algorithm; /* 0=none, 1=SHA256 */
  dstr_t integrity_hash; /* 32 bytes for SHA256 */
  uint32_t integrity_block_size; /* 0x400000 */
  dsbuf_t integrity_blocks; /* 32 bytes x N */
} fdent_t;

extern fdent_t* fdeinit(fdent_t* mem);
extern void fdefini(fdent_t* pe);

typedef buf_t fdebuf_t;
extern fdebuf_t* fdebinit(fdebuf_t* mem);
extern void fdebfini(fdebuf_t* pb);
#define fdeblen(pb) (buflen(pb))
#define fdebref(pb, i) ((fdent_t*)bufref(pb, i))
#define fdebnewbk(pb) (fdeinit(bufnewbk(pb)))


