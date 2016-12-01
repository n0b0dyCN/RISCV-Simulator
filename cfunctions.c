#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>

int SYS_read(int fd, char *buf, int len) {
	return read(fd, buf, len);
}

int SYS_fstat(int fd, struct stat *buf) {
	// sizeof(struct stat) = 114
	return fstat(fd, buf);
}

int SYS_gettimeofday(struct timeval *myTime)
{
	int ret_val = 0;
    ret_val = gettimeofday(myTime, NULL);
    return ret_val;
}

int SYS_write(int fd, char *buf, int len)
{
	return write(fd, buf, len);
}
