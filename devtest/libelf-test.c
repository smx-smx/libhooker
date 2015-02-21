/*
   http://em386.blogspot.com

You may not use this code in a product,
   but feel free to study it and rewrite it
   in your own way

   This code is an example of how to use the
   libelf library for reading ELF objects.

   gcc -o libelf-howto libelf-howto.c -lelf
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>

#define ERR -1

Elf32_Ehdr *elf_header;		/* ELF header */
Elf *elf;                       /* Our Elf pointer for libelf */
Elf_Scn *scn;                   /* Section Descriptor */
Elf_Data *edata;                /* Data Descriptor */
GElf_Sym sym;			/* Symbol */
GElf_Shdr shdr;                 /* Section Header */

int main(int argc, char *argv[])
{

int fd; 		// File Descriptor
char *base_ptr;		// ptr to our object in memory
char *file = argv[1];	// filename
struct stat elf_stats;	// fstat struct

        if((fd = open(file, O_RDWR)) == ERR)
        {
		printf("couldnt open %s\n", file);
		return ERR;
        }

printf("Opened\n");
        if((fstat(fd, &elf_stats)))
        {
		printf("could not fstat %s\n", file);
                close(fd);
		return ERR;
        }

printf("Fstated\n");
        if((base_ptr = (char *) malloc(elf_stats.st_size)) == NULL)
        {
		printf("could not malloc\n");
                close(fd);
		return ERR;
        }

        if((read(fd, base_ptr, elf_stats.st_size)) < elf_stats.st_size)
        {
		printf("could not read %s\n", file);
                free(base_ptr);
                close(fd);
		return ERR;
        }

printf("Read\n");

	/* Check libelf version first */
	if(elf_version(EV_CURRENT) == EV_NONE)
	{
		printf("WARNING Elf Library is out of date!\n");
	}

elf_header = (Elf32_Ehdr *) base_ptr;	// point elf_header at our object in memory
elf = elf_begin(fd, ELF_C_READ, NULL);	// Initialize 'elf' pointer to our file descriptor

printf("elf began\n");

if(elf_kind(elf) != ELF_K_ELF) {
   printf("elf kind is not k\n");
   return ERR;
}

GElf_Ehdr ehdr_mem, * ehdr;
if((ehdr = gelf_getehdr(elf, &ehdr_mem)) == NULL) {
   printf("unable to get ehdr\n");
   return ERR;
}
/*
if(ehdr->e_type != ET_DYN){
   printf("elf is not dynamical executable\n");
   return ERR;
}
*/

printf ("ehdr e_phnum: %d\n", ehdr->e_phnum);


int i;
for (i = 0; i < ehdr->e_phnum; ++i) {
      GElf_Phdr phdr_mem;
      GElf_Phdr *phdr = gelf_getphdr (elf, i, &phdr_mem);


      if (phdr == NULL) {
          printf("skipping because phhdr is NULL\n");
          continue;
      }

      printf("phdr p_type: %d\n", phdr->p_type);
}



/* Iterate through section headers */
while((scn = elf_nextscn(elf, scn)) != 0)
{

      printf("next section: %08x\n", scn);

	// point shdr at this section header entry
	gelf_getshdr(scn, &shdr);


		// print the section header type
                printf("Type: ");

                switch(shdr.sh_type)
                {
                        case SHT_NULL: printf( "SHT_NULL\t");               break;
                        case SHT_PROGBITS: printf( "SHT_PROGBITS");       break;
                        case SHT_SYMTAB: printf( "SHT_SYMTAB");           break;
                        case SHT_STRTAB: printf( "SHT_STRTAB");           break;
                        case SHT_RELA: printf( "SHT_RELA\t");               break;
                        case SHT_HASH: printf( "SHT_HASH\t");               break;
                        case SHT_DYNAMIC: printf( "SHT_DYNAMIC");         break;
                        case SHT_NOTE: printf( "SHT_NOTE\t");               break;
                        case SHT_NOBITS: printf( "SHT_NOBITS");           break;
                        case SHT_REL: printf( "SHT_REL\t");                 break;
                        case SHT_SHLIB: printf( "SHT_SHLIB");             break;
                        case SHT_DYNSYM: printf( "SHT_DYNSYM");           break;
                        case SHT_INIT_ARRAY: printf( "SHT_INIT_ARRAY");   break;
                        case SHT_FINI_ARRAY: printf( "SHT_FINI_ARRAY");   break;
                        case SHT_PREINIT_ARRAY: printf( "SHT_PREINIT_ARRAY"); break;
                        case SHT_GROUP: printf( "SHT_GROUP");             break;
                        case SHT_SYMTAB_SHNDX: printf( "SHT_SYMTAB_SHNDX"); break;
                        case SHT_NUM: printf( "SHT_NUM\t");                 break;
                        case SHT_LOOS: printf( "SHT_LOOS\t");               break;
                        case SHT_GNU_verdef: printf( "SHT_GNU_verdef");   break;
                        case SHT_GNU_verneed: printf( "SHT_VERNEED");     break;
                        case SHT_GNU_versym: printf( "SHT_GNU_versym");   break;
                        default: printf( "(none) ");                      break;
                }

		// print the section header flags
		printf("\t(");
                if(shdr.sh_flags & SHF_WRITE) { printf("W"); }
                if(shdr.sh_flags & SHF_ALLOC) { printf("A"); }
                if(shdr.sh_flags & SHF_EXECINSTR) { printf("X"); }
                if(shdr.sh_flags & SHF_STRINGS) { printf("S"); }
		printf(")\t");

	// the shdr name is in a string table, libelf uses elf_strptr() to find it
	// using the e_shstrndx value from the elf_header
	printf("%s\n", elf_strptr(elf, elf_header->e_shstrndx, shdr.sh_name));
}


// Iterate through section headers again this time well stop when we find symbols 
elf = elf_begin(fd, ELF_C_READ, NULL);

int symbol_count;

while((scn = elf_nextscn(elf, scn)) != NULL)
{
        gelf_getshdr(scn, &shdr);

	// When we find a section header marked SHT_SYMTAB stop and get symbols
	if(shdr.sh_type == SHT_SYMTAB)
        {
		// edata points to our symbol table
		edata = elf_getdata(scn, edata);

		// how many symbols are there? this number comes from the size of
		// the section divided by the entry size
		symbol_count = shdr.sh_size / shdr.sh_entsize;

		// loop through to grab all symbols
		for(i = 0; i < symbol_count; i++)
                {			
			// libelf grabs the symbol data using gelf_getsym()
                        gelf_getsym(edata, i, &sym);

			// print out the value and size
			printf("%08x %08d ", sym.st_value, sym.st_size);
	
			// type of symbol binding
			switch(ELF32_ST_BIND(sym.st_info))
			{
				case STB_LOCAL: printf("LOCAL"); break;
				case STB_GLOBAL: printf("GLOBAL"); break;
				case STB_WEAK: printf("WEAK"); break;
				case STB_NUM: printf("NUM"); break;
				case STB_LOOS: printf("LOOS"); break;
				case STB_HIOS: printf("HIOS"); break;
				case STB_LOPROC: printf("LOPROC"); break;
				case STB_HIPROC: printf("HIPROC"); break;
				default: printf("UNKNOWN"); break;
			}

			printf("\t");

			// type of symbol
			switch(ELF32_ST_TYPE(sym.st_info))
			{
				case STT_NOTYPE: printf("NOTYPE"); break;
				case STT_OBJECT: printf("OBJECT"); break;
				case STT_FUNC:  printf("FUNC"); break;
				case STT_SECTION: printf("SECTION"); break;
				case STT_FILE: printf("FILE"); break;
				case STT_COMMON: printf("COMMON"); break;
				case STT_TLS: printf("TLS"); break;
				case STT_NUM: printf("NUM"); break;
				case STT_LOOS: printf("LOOS"); break;
				case STT_HIOS: printf("HIOS"); break;
				case STT_LOPROC: printf("LOPROC"); break;
				case STT_HIPROC: printf("HIPROC"); break;
				default: printf("UNKNOWN"); break;
			}

			printf("\t");

			// the name of the symbol is somewhere in a string table
			// we know which one using the shdr.sh_link member
			// libelf grabs the string using elf_strptr()
                        printf("%s\n", elf_strptr(elf, shdr.sh_link, sym.st_name));
                }

	}
}

return 0;
}

