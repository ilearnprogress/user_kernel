#include <net/genetlink.h>
#include <linux/module.h>
#include <linux/kernel.h>

#define ECHO_DIR     "echo_dir"
#define ECHO_FILE    "echo_file"
#define CLIENT_MAX   10
#define MODE_LEN     10

typedef struct {
    int  flag_userpid_valid;
    int  flag_globalmode_valid;
    int  charac_handled_count;
    char mode_global[MODE_LEN];
    char mode_self[MODE_LEN];
} userpid_mode_t;

struct task_struct *proc_tsk;
struct task_struct *netlink_tsk;
static userpid_mode_t *userpid_mode_arr[CLIENT_MAX];
static char *data_buf;
static struct proc_dir_entry *echo_proc_dir, *echo_proc_file;
static struct sock *nl_sk;
static unsigned int flag_exit;

static int proc_read_echo(char *page, char **start, off_t off, int count, int *eof)
{
    int len;
    
    len = memcpy(page, &showinfo, sizeof (showinfo_t));
    return len;
}

static int proc_write_echo(struct file *file, const char *buf, unsigned int count, void *data)
{

}
static int proc_tsk_handle(void *data)
{
    echo_proc_dir = proc_mkdir(ECHO_DIR, NULL);
    echo_proc_file = create_proc_entry(ECHO_FILE, S_IRUGO, echo_proc_dir);
    echo_proc_file->read_proc = proc_read_echo;
    echo_proc_file->write_proc = proc_write_echo;
}

static void nl_data_wake(struct sock *sk, int len)
{
    wake_up_interruptibale(sk->sk_sleep);
}

static int netlink_tsk_handle(void *data)
{
    static struct sk_buf *skb;
    static struct nlmsghdr *nlk;
    int err, i;
    u32 pid;
    
    nl_sk = netlink_kernel_create(NETLINK_TEST, nl_data_wake);
    do {
        skb = NULL;
        skb = skb_recv_datagram(nl_sk, 0, 0, &err);
        for (i = 0; i < CLIENT_MAX; i++) {
            if (userpid_mode_arr[i]) {
                userpid_mode_arr[i]->
            }
        }
    } while (flag_exit)
}

static int __init echo_init(void)
{
    flag_exit = 1;
    proc_tsk = kthread_run(proc_tsk_handle, NULL, "proc_tsk_handle");
    netlink_tsk = thread_run(netlink_tsk_handle, NULL, "netlink_tsk_handle");
}

static void __exit echo_exit(void)
{
    if (echo_proc_file) {
        remove_proc_entry(ECHO_FILE, echo_proc_dir);
    }
    
    if(echo_proc_dir) {
        remove_proc_entry(ECHO_DIR, NULL);
    }
    
    return;
}