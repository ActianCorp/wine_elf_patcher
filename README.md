-*- coding: utf-8 -*-

# wine_elf_patcher

🍷🧝‍♀️ WINE ELF Patcher

## Build instruction ##

- Clone this repo, https://github.com/ActianCorp/wine_elf_patcher.git
- cd to repo, `cd wine_elf_patcher`
- Download https://github.com/lief-project/LIEF/releases/download/0.15.1/LIEF-0.15.1-Linux-x86_64.tar.gz
- Extract it via `tar -xvzf LIEF-0.15.1-Linux-x86_64.tar.gz`
- To compile run: `g++ -o modifystacksize -I./LIEF-0.15.1-Linux-x86_64/include/ modifystacksize.cpp ./LIEF-0.15.1-Linux-x86_64/lib/libLIEF.so`
- **NOTE** Library libLIEF.so is required at runtime by modifystacksize, see https://github.com/lief-project/LIEF for licensing information.

## Usage
    $ ./modifystacksize
    Usage: ./modifystacksize <Input file> [Output File] [New stack size in bytes]
