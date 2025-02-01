# bggp-tools

Tools for playing BGGP.

## bggp.py

`bggp-tool` is a tool for creating and verifying entries for BGGP.

### Requirments

- [rich](https://github.com/Textualize/rich)
- [yxdump](https://github.com/netspooky/yxd)

### Command Line Usage

```
$ python3 bggp.py --help
usage: bggp.py [-h] [-b VERIFY_BINARY] [-e VERIFY_ENTRY] [-c CREATE_ENTRY]

bggp-tool

options:
  -h, --help        show this help message and exit
  -b VERIFY_BINARY  File To Verify (ANY)
  -e VERIFY_ENTRY   BGGP Entry File To Verify (.txt)
  -c CREATE_ENTRY   Create entry from file (ANY)
```

- The `-b` option can take in any file and create a BGGP verification stub from it.
- The `-e` option takes in a BGGP entry in a text file
- The `-c` option takes in a file and walks you through the steps of creating an entry.
- Passing no arguments activates the interactive shell

### Interactive Shell

This is a simple shell to work with files and entries.

```
$ python3 bggp.py

 █▄▄▄▄▄▄▄▄▄ █▀▀▀▀▀▀ ▄▄ █▀▀▀▀▀▀ ▄▄ ▀▀▀▀▀▀▀▀▀█
 ▄▄▄▄▄▄▄▄▄█ █▄▄▄▄▄▄▄▄█ █▄▄▄▄▄▄▄▄█ █▀▀▀▀▀▀▀▀▀
 ▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄ ▄
      █     █▄▄▄▄▄▄▄▄█ █▄▄▄▄▄▄▄▄█ █▄▄▄▄▄▄▄▄▄

BGGP> h
bggp-tool help
             ╷
  Command    │ Description
╶────────────┼────────────────────────────────────────╴
  c          │ (c)reate a new entry
  c file.bin │ (c)reate a new entry from (file.bin)
  e          │ Load (e)ntry from stdin
  e file.txt │ Load (e)ntry from (file.txt)
  i          │ Print info about current entry, if any
  r          │ (r)eset entry
  s          │ (s)ave data to bggp.bin
  s file.bin │ (s)ave data to (file.bin)
  v          │ (v)erify an entry (creates stub)
  x          │ E(x)it
             ╵
```


### TODO

- [ ] Add score calculations
- [ ] Make base64 decoding in parseEntry a little less painful

