/*
	A mmap file wrapper
	Copyright 2015 Smx
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "mfile.h"

/*
 * Creates a new mfile structure
 */
MFILE *mfile_new(){
	MFILE *mem = calloc(1, sizeof(MFILE));
	return mem;
}

/*
 * Updates size and path to a file
 */
int _mfile_update_info(MFILE *file, const char *path){
	if(path){
		if(file->path)
			free(file->path);
		file->path = strdup(path);
	}
	if(stat(file->path, &(file->statBuf)) < 0)
		return -1;
	return 0;
}

/*
 * Wrapper to mmap
 */
void *mfile_map(MFILE *file, size_t size){
	size_t mapSize;
	if(size == 0){
		mapSize = msize(file);
	} else {
		mapSize = size;
	}
	if(msize(file) < size){
		lseek(file->fd, size-1, SEEK_SET);
		uint8_t buf = 0x00;
		write(file->fd, &buf, 1);
		lseek(file->fd, 0, SEEK_SET);
		_mfile_update_info(file, NULL);
	}
	if(file->pMem){

	}
	file->pMem = mmap(0, mapSize, file->prot, MAP_SHARED, file->fd, 0);
	if(file->pMem == MAP_FAILED){
		//err_exit("mmap failed: %s\n", strerror(errno));
		return NULL;
	}
	return file->pMem;
}

/*
 * Opens and maps a file with open
 */
MFILE *mopen(const char *path, int oflags){
	MFILE *file = mfile_new();
	file->fd = open(path, oflags);
	if(file->fd < 0){
		goto e0_ret;
	}
	
	if(_mfile_update_info(file, path) < 0)
		goto e1_ret;
	
	if((oflags & O_ACCMODE) == O_RDONLY) {
		file->prot = PROT_READ;
	} else if((oflags & O_ACCMODE) == O_WRONLY) {
		file->prot = PROT_WRITE;
	} else if((oflags & O_ACCMODE) == O_RDWR) {
		file->prot = PROT_READ | PROT_WRITE;
	}

	if(msize(file) > 0){
		if(mfile_map(file, 0) == MAP_FAILED){
			goto e1_ret;
		}
	}
	return file;

	e1_ret:
		close(file->fd);
	e0_ret:
		if(file->path)
			free(file->path);
		free(file);
		return NULL;
}

/*
 * Closes an opened file and frees the structure
 */
int mclose(MFILE *mfile){
	if(!mfile || mfile->fd < 0 || !mfile->pMem || mfile->size <= 0)
		return -1;
	if(munmap(mfile->pMem, mfile->size) < 0)
		return -2;
	free(mfile->path);
	close(mfile->fd);
	free(mfile);
	mfile = NULL;
	return 0;
}

/*
 * Opens and maps a file with fopen
 */
MFILE *mfopen(const char *path, const char *mode){
	MFILE *file = mfile_new();

	file->fh = fopen(path, mode);
	if(file->fh == NULL){
		goto e0_ret;
	}
	file->fd = fileno(file->fh);
	
	if(_mfile_update_info(file, path) < 0)
		goto e1_ret;

	if(strstr(mode, "r") != NULL){
		file->prot |= PROT_READ;
	}
	if(strstr(mode, "w") != NULL){
		file->prot |= PROT_WRITE;
	}

	if(msize(file) > 0){
		if(mfile_map(file, 0) == MAP_FAILED){
			goto e1_ret;
		}
	}

	return file;

	e1_ret:
		fclose(file->fh);
	e0_ret:
		free(file);
		return NULL;
}
