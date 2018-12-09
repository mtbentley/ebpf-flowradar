#define _GNU_SOURCE
#include "bpf_load.h"
#include "common.h"

#include <linux/bpf.h>

#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <sys/vfs.h>
#include <libgen.h>
#include <stdlib.h>


#ifndef BPF_FS_MAGIC
# define BPF_FS_MAGIC   0xcafe4a11
#endif

// copied from https://github.com/netoptimizer/prototype-kernel/blob/72e473c723bc8dbc389b00d2ec631729444e4998/kernel/samples/bpf/xdp_ddos01_blacklist_user.c#L103
/* Verify BPF-filesystem is mounted on given file path */
static int bpf_fs_check_path(const char *path)
{
	struct statfs st_fs;
	char *dname, *dir;
	int err = 0;

	if (path == NULL)
		return -EINVAL;

	dname = strdup(path);
	if (dname == NULL)
		return -ENOMEM;

	dir = dirname(dname);
	if (statfs(dir, &st_fs)) {
		fprintf(stderr, "ERR: failed to statfs %s: (%d)%s\n",
			dir, errno, strerror(errno));
		err = -errno;
	}
	free(dname);

	if (!err && st_fs.f_type != BPF_FS_MAGIC) {
		fprintf(stderr,
			"ERR: specified path %s is not on BPF FS\n\n"
			" You need to mount the BPF filesystem type like:\n"
			"  mount -t bpf bpf /sys/fs/bpf/\n\n",
			path);
		err = -EINVAL;
	}

	return err;
}


int main(int argc, char *argv[]) {
    char filename[256];
    int ifindex;
    char *ifname;
    char *nspath;
    int nsfd;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <ifname> <ns-path>\n", argv[0]);
        return 1;
    }

    ifname = argv[1];
    nspath = argv[2];

    snprintf(filename, sizeof(filename), "%s.o", argv[0]);

    // Load the bpf file.  The fd will end up in prog_fd[0]
    if (load_bpf_file(filename)) {
        fprintf(
            stderr,
            "ERR: failed to load file %s: %s\n",
            filename, bpf_log_buf
        );
        return 1;
    }

    if (!prog_fd[0]) {
        fprintf(
            stderr,
            "ERR: load_bpf_file(%d): %s\n",
            errno, strerror(errno)
        );
        return 1;
    }

    for (int i=0; i<NUM_MAP_PINS; i++) {
        if (map_fd[i] <= 0) {
            fprintf(
                stderr,
                "ERR: map %d(%s) failed to load: %d\n",
                i, map_pins[i].path, map_fd[i]
            );
            return 1;
        }
        if (bpf_fs_check_path(map_pins[i].path) < 0)
            return 1;

        // Try to pin the i-th map_fd to the filesystem
        if (bpf_obj_pin(map_fd[i], map_pins[i].path)) {
            fprintf(
                stderr,
                "ERR: Cannot pin map %s: err(%d):%s\n",
                map_pins[i].path, errno, strerror(errno)
            );
            return 1;
        }
    }

    nsfd = open(nspath, O_RDONLY);
    if (nsfd < 0) {
        fprintf(
            stderr,
            "ERR: failed to open nspath(%d): %s\n",
            errno, strerror(errno)
        );
        return 1;
    }

    // Set the namespace
    if (setns(nsfd, 0)) {
        fprintf(
            stderr,
            "ERR: failed to join ns(%d): %s\n",
            errno, strerror(errno)
        );
        return 1;
    }

    // Lookup the interface index
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "ERR: unknown ifname(%d): %s", errno, strerror(errno));
        return 1;
    }

    // Add the xdp program to the interface
    if (bpf_set_link_xdp_fd(ifindex, prog_fd[0], 0) < 0) {
        fprintf(stderr, "ERR: failed to set prog\n");
        return 1;
    }

    return 0;
}
