#define _GNU_SOURCE
#include "bpf_load.h"
#include "common.h"
#include "bpf_util.h"

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
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>


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

void maybe_use_old_map(struct bpf_map_data *map, int idx) {
    char *path = map_pins[idx].path_formatted;
    int existing_fd = bpf_obj_get(path);

    if (existing_fd > 0) { // There's an old map to use! yay!
        map->fd = existing_fd;
    }
}

int main(int argc, char *argv[]) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    char filename[256];
    int ifindex;
    char *ifname;
    char *nspath;
    int nsfd;
    unsigned int nr_cpus = bpf_num_possible_cpus();

    if (argc < 5) {
        fprintf(stderr, "Usage: %s <ifname> <ns-path> <host-num> <save-prefix> [reset-maps]\n",
            argv[0]);
        return 1;
    }

    ifname = argv[1];
    nspath = argv[2];
    uint16_t host_num = atoi(argv[3]);
    uint8_t save_prefix = atoi(argv[4]);

    if (format_map_paths(host_num, save_prefix))
        return 1;

    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        fprintf(stderr, "ERR: failed to set rlimit\n");
        return 1;
    }

    int reset_maps = 0;
    if (argc > 5)
        if (strcmp(argv[5], "yes") || strcmp(argv[5], "1"))
            reset_maps = 1;

    if (reset_maps) {
        printf("Resetting maps...\n");
        for (int i=0; i<NUM_MAP_PINS; i++) {
            if (unlink(map_pins[i].path_formatted)) {
                fprintf(
                    stderr,
                    "WARN: failed to unlink %s(%d): %s\n",
                    map_pins[i].path_formatted, errno, strerror(errno)
                );
            }
        }
    }

    snprintf(filename, sizeof(filename), "%s.o", argv[0]);

    // Load the bpf file.  The fd will end up in prog_fd[0]
    if (load_bpf_file_fixup_map(filename, maybe_use_old_map)) {
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

    char *dirc, *dname;
    dirc = strdup(bpf_pin_folder);
    dname = dirname(dirc);
    if (mkdir(dname, 0x700)) {
        if (errno != EEXIST) {
            fprintf(
                stderr,
                "ERR: failed to mkdir %s: %s\n",
                dname, strerror(errno)
            );
            return 1;
        }
    }
    free(dname);
    free(dirc);
    if (mkdir(bpf_pin_folder, 0x700)) {
        if (errno != EEXIST) {
            fprintf(
                stderr,
                "ERR: failed to mkdir %s: %s\n",
                bpf_pin_folder, strerror(errno)
            );
            return 1;
        }
    }
    for (int i=0; i<NUM_MAP_PINS; i++) {
        if (map_fd[i] <= 0) {
            fprintf(
                stderr,
                "ERR: map %d(%s) failed to load: %d\n",
                i, map_pins[i].path_formatted, map_fd[i]
            );
            return 1;
        }
        if (bpf_fs_check_path(map_pins[i].path_formatted) < 0)
            return 1;

        if (bpf_obj_get(map_pins[i].path_formatted) <= 0) {
            // Try to pin the i-th map_fd to the filesystem
            if (bpf_obj_pin(map_fd[i], map_pins[i].path_formatted)) {
                fprintf(
                    stderr,
                    "ERR: Cannot pin map %s: err(%d):%s\n",
                    map_pins[i].path_formatted, errno, strerror(errno)
                );
                return 1;
            }
        }
    }

    int host_info_fd = bpf_obj_get(map_pins[8].path_formatted);
    uint64_t host_nums[nr_cpus];
    memset(host_nums, 0, sizeof(host_nums));

    for (unsigned int i=0; i<nr_cpus; i++) {
        host_nums[i] = host_num;
    }

    if (host_info_fd <= 0) {
        fprintf(
            stderr,
            "WARN: Could not open host info map(%d): %s\n",
            errno, strerror(errno)
        );
    } else {
        uint32_t key = 0;
        bpf_map_update_elem(host_info_fd, &key, host_nums, 0);
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
        fprintf(stderr, "ERR: unknown ifname(%d): %s\n", errno, strerror(errno));
        return 1;
    }

    // Add the xdp program to the interface
    if (bpf_set_link_xdp_fd(ifindex, prog_fd[0], 0) < 0) {
        fprintf(stderr, "ERR: failed to set prog\n");
        return 1;
    }

    return 0;
}
