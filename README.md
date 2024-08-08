-*- coding: utf-8 -*-

# wine_elf_patcher

🍷🧝‍♀️ WINE ELF Patcher

## Build instruction ##

- Clone this repo, https://github.com/ActianCorp/wine_elf_patcher.git
- cd to repo
- Download https://github.com/lief-project/LIEF/releases/download/0.15.1/LIEF-0.15.1-Linux-x86_64.tar.gz
- Extract it via 'tar -xvzf'
- To compile run: g++ -o modifystacksize -I./LIEF-0.15.1-Linux-x86_64/include/ modifystacksize.cpp ./LIEF-0.15.1-Linux-x86_64/lib/libLIEF.so
- Library libLIEF.so is required at runtime by modifystacksize
