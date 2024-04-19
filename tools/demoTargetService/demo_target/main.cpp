// This program is used to test afl on local host to observe path
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

extern "C" {
    #include "config.h"
    #include "types.h"
}

// #include "hash.h"


#define SHM_ENV_VAR         "__AFL_SHM_ID"
extern u8* __afl_area_ptr;



int main(int argc, char **argv)
{
    char *id_str = getenv(SHM_ENV_VAR);
    if (id_str != 0) {
        int shm_id = atoi(id_str);
        __afl_area_ptr = reinterpret_cast<uint8_t*>(mmap(nullptr, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_id, 0));
    }

   FILE *fp = NULL;
   char buff[255];
 
   fp = fopen(argv[1], "r");
   fscanf(fp, "%254s", buff);// bug here
   printf("1: %s\n", buff );

   switch (buff[0]){ // coverage increase test here
    case 'a':
    {
        printf("a\n");
        printf("32rghjiong");
        break;
    }
    case 'b':
    {
        printf("b\n");
        printf("fwtvberghbeb");
        break;
    }
    case 'c':
    {
        printf("c\n");
        printf("gnuioni349o");
        break;
    }
    case 'd':
    {
        printf("d\n");
        printf("4nio9bn4fg3u9gfo");
        break;
    }
    default:
        printf("defaults\n");
        break;
    

   }
 
   
   fclose(fp); 
}
