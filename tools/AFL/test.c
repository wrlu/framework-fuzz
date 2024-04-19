#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "fdp.h"

int main(int argc, char** argv){
    int fd;
    fd = open(argv[1], O_RDONLY);
    
}