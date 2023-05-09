# BAR - Basic Archiver
                         
BAR is a very basic archiver with TAR-like command line interface and Electron's ASAR-inspired header format.
It supports both ASAR format (directory is stored in ASCII JSON), and a related BSAR format (directory is 
stored in binary JSON). Both formats describe the same data, but BSON is a bit more compact and can be easily
traversed in memory, e.g. if just one file needs to be extracted.

BAR is very easy to install; it only needs a C compiler and has no dependency on platform-specific building tools. 
There is no distributives or packages: just compile the source file with your favorite C compiler, link it with 
the standard C runtime libraries and be done with it. For some platforms, precompiled binaries are available 
(please see [releases](https://github.com/false-schemers/bar/releases)).

## Installation

Here's how you can compile BAR on a unix box using GCC:

```
gcc -o bar [bar].c
```

Instructions for other compilers are similar (you may use Clang on Linux/Mac or CL on Windows). 
Please note that CL may issue warnings; we recommend to add `-D_CRT_SECURE_NO_WARNINGS` for Windows 
headers (unless you want to hear that `fopen` is no longer a reasonable way to open files).

The resulting executable has no dependencies (except C runtime) and can be run from any location.
If compiled statically, it can be easily moved between systems with the same ABI.

## Commmand line interface

BAR adheres to TAR's command line conventions:

```
bar: BAR (Basic Archiver) 1.00 built on May  9 2023
usage: bar [OPTION]... [FILE/DIR]...
The archiver works with .asar (json header) and .bsar (bson header) archives.

Examples:
  bar -cf arch.bsar foo bar    # Create bsar archive from files foo and bar
  bar -cf arch.asar foo bar    # Create asar archive from files foo and bar
  bar -tvf arch.bsar           # List all files in arch.bsar verbosely
  bar -xf arch.bsar foo bar    # Extract files foo and bar from arch.bsar
  bar -xf arch.bsar            # Extract all files from arch.bsar

If a long option shows an argument as mandatory, then it is mandatory
for the equivalent short option also.  Similarly for optional arguments.

Main operation mode:
  -c, --create                 Create a new archive
  -t, --list                   List the contents of an archive
  -x, --extract                Extract files from an archive

Operation modifiers:
  -f, --file=FILE              Use archive FILE (required in all modes)
  -k, --keep-old-files         Don't overwrite existing files when extracting
  -C, --directory=DIR          Use directory DIR for extracted files
  -O, --to-stdout              Extract files to standard output
  -X, --exclude-from=FILE      Exclude files via globbing patterns in FILE
  --exclude="PATTERN"          Exclude files, given as a globbing PATTERN
  --unpack="PATTERN"           Exclude files, but keep their info in archive
  --include-from=FILE          List/extract files via globbing patterns in FILE
  --include="PATTERN"          List/extract files, given as a globbing PATTERN
  --integrity=SHA256           Calculate or check file integrity info

Archive format selection:
  -o, --format=asar            Create asar archive even if extension is not .asar
  --format=bsar                Create bsar archive even if extension is .asar

File name matching options:
   --anchored                  Patterns match path
   --no-anchored               Patterns match file/directory name
   --wildcards                 Patterns are wildcards
   --no-wildcards              Patterns match verbatim

Informative output:
  -v, --verbose                Increase output verbosity
  -q, --quiet                  Suppress logging
  -h, --help                   Print this help, then exit

Note: when creating archives (-c), only the name of each argument file/dir
is stored in the archive, not a complete path to the argument file/dir.
```

## Family

Please see [BAZ](https://github.com/false-schemers/baz) repository for a bigger archiver with support for compression.
