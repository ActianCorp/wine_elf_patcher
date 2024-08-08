
#include <iostream>
//#include <unistd.h>

#include "LIEF/ELF.hpp"
//#include "LIEF/logging.hpp"

using namespace LIEF::ELF;


// below is copied from winnt.h Wine header file
typedef unsigned char   BYTE;     // 1 byte
typedef unsigned short  WORD;     // 2 byte
typedef unsigned int    DWORD;    // 4 byte
typedef unsigned long ULONGLONG;  // 8 byte

typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD  Magic; /* 0x20b */
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    ULONGLONG ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

#define	IMAGE_FILE_MACHINE_AMD64	        0x8664
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC       0x20b
#define IMAGE_NT_SIGNATURE                  0x00004550 /* PE00 */
#define IMAGE_SIZEOF_NT_OPTIONAL64_HEADER 	240

int main(int argc, char **argv) {

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <Input file> [Output File] [New stack size in bytes] \n" ;
        return 1;
    }

    //if (argc > 4)
     //   usleep(10000000);

    //LIEF::logging::set_level(LIEF::logging::LEVEL::DEBUG);
    std::unique_ptr<Binary> binary = Parser::parse(argv[1]);
    if (binary == nullptr) {
        std::cerr << "Couldn't parse input file: " << argv[1] << '\n';
        return 2;
    }

    const Symbol *symbol = binary->get_symtab_symbol("__wine_spec_nt_header");
    if (!symbol)
    {
        std::cerr << "Couldn't fetch Wine header symbol from: " << argv[1] << '\n';
        return 3;
    } 
    uint64_t addr = symbol->value();
    auto ptr = binary->get_content_from_virtual_address(addr, sizeof(IMAGE_NT_HEADERS64), Binary::VA_TYPES::RVA);
    auto ptraddr = ptr.data();
    if (!ptraddr)
    {
        std::cerr << "Couldn't fetch virtual address of symbol: " << symbol->value() << '\n'; 
        return 4;
    } 
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)ptraddr;
    if (nt && nt->Signature == IMAGE_NT_SIGNATURE 
        && nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64
        && nt->FileHeader.SizeOfOptionalHeader == IMAGE_SIZEOF_NT_OPTIONAL64_HEADER
        && nt->FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64)
        && nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
        && sizeof(IMAGE_NT_HEADERS64) == 264
        && sizeof(IMAGE_FILE_HEADER) == 20)
    {
        std::cout << "== All checks are good. == \n";
        std::cout << "== Current stack size:  == " << std::dec << nt->OptionalHeader.SizeOfStackReserve << '\n';
    }
    else
    {
        std::cerr << "== Check failed. == \n";
        std::cout << "== Input file: == " << argv[1] << '\n';
        if (symbol)
        {
            std::cout << symbol << '\n';
            std::cout << symbol->shndx() << '\n';
            std::cout << symbol->value() << '\n';
            std::cout << symbol->size() << '\n';
            std::cout << symbol->name() << '\n';
            if (nt) {
                std::cout << "== Value of nt->Signature                         == 0x" << std::hex << nt->Signature << '\n';
                std::cout << "== Value of nt->OptionalHeader.SizeOfStackReserve == " << std::dec << nt->OptionalHeader.SizeOfStackReserve << '\n';
                std::cout << "== Value of nt->FileHeader.Machine                == 0x" << std::hex << nt->FileHeader.Machine << '\n';
                std::cout << "== Value of nt->FileHeader.SizeOfOptionalHeader   == " << std::dec << nt->FileHeader.SizeOfOptionalHeader << '\n';
                std::cout << "== Value of nt->OptionalHeader.Magic              == 0x" << std::hex << nt->OptionalHeader.Magic << '\n';
                std::cout << "== Value of sizeof(IMAGE_OPTIONAL_HEADER64)       == " << std::dec << sizeof(IMAGE_OPTIONAL_HEADER64) << '\n';
                std::cout << "== Value of sizeof(IMAGE_NT_HEADERS64)            == " << std::dec << sizeof(IMAGE_NT_HEADERS64) << '\n';
                std::cout << "== Value of sizeof(IMAGE_SECTION_HEADER)          == " << std::dec << sizeof(IMAGE_FILE_HEADER) << '\n';
            }
        }
        return 5;
    }

    if (argc == 4)
    {
        ULONGLONG stackval;
        stackval = std::stoul(argv[3]);
        // stack size is in multiple of 1024, for more information ref: wine/tools/winebuild/spec32.c
        stackval = stackval - stackval%1024;
        nt->OptionalHeader.SizeOfStackReserve = stackval;
        std::string nfile(argv[2]);
        binary->write(nfile);
        std::cout << "== New stack size: == " << stackval << '\n';
        std::cout << "== New file Created. == " << nfile << '\n';
    }
    return 0;
}

