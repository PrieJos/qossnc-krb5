#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define TRACE_FILE_NAME		"sncgss_krb5.trc"
#define TRACE_FILE_FLAGS    O_CREAT|O_WRONLY|O_TRUNC
#define TRACE_FILE_PERMS    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH

static int trc_fd = -1;

void trace_init(const char *trc_filename)
{
	char *filename = trc_filename;

	if (!filename)
		filename = TRACE_FILE_NAME;
	trc_fd = open(filname, TRACE_FILE_FLAGS, TRACE_FILE_PERMS);

	return trc_fd;
}

void trace_finish(void)
{
	if (trc_fd != -1) {
		close(trc_fd);
		trc_fd = -1;
	}

	return;
}

ssize_t trace_write(const char *fname, const char *msg) 
{
	ssize_t count = -1;

	if (trc_fd == -1)
		return -1;

	if (msg)
		count = write(trc_fd, msg, sizeof(msg));
	
	return count;
}

