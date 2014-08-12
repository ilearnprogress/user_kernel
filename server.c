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
    u32  user_pid;
    int  mode_global;           /* 1: normal (default mode), 2: upper, 3: lower */
    int  mode_self;   /* 1: normal (default mode), 2: upper, 3: lower */
} userpid_mode_t;

struct task_struct *proc_tsk;
struct task_struct *netlink_tsk;
static userpid_mode_t *userpid_mode_arr[CLIENT_MAX];
static char *data_buf;
static struct proc_dir_entry *echo_proc_dir, *echo_proc_file;
static struct sock *nl_sk;
static unsigned int flag_exit;
static unsigned int client_count;
static unsigned int global_charac_handled;

/* show the message to user space */
static int proc_read_echo(char *page, char **start, off_t off, int count, int *eof)
{
    int len;
    
    len = memcpy(page, &showinfo, sizeof (showinfo_t));
    return len;
}

 /* get data from user data, receive the data and the check if user pid is exited */
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

static void normal_feedback()
{

}

static void upper_feedback()
{

}

static void lower_feedback()
{

}

static void create_new_userpid()
{

}

static int netlink_tsk_handle(void *data)
{
    static struct sk_buf *skb;
    static struct nlmsghdr *nlh;
    int err, i, place_idle;
    u32 pid;
    
    nl_sk = netlink_kernel_create(NETLINK_TEST, nl_data_wake);
   
//        skb = skb_recv_datagram(nl_sk, 0, 0, &err);
    nlh = (struct nlmsghdr *)skb->data;
    if (client_count < CLIENT_MAX) {
        for (i = 0; i < CLIENT_MAX; i++) {
            if (userpid_mode_arr[i]) {
                if (userpid_mode_arr[i]->user_pid == nlh->nlmsg_pid) {
                    /* the user_pid in being in the arr and global mode is valid*/
                    if (userpid_mode_arr[i]->flag_globalmode_valid) {  
                        switch (userpid_mode_arr[i]->mode_global) {
                        case 1:
                            normal_feedback();
                            break;
                        case 2:
                            upper_feedback();
                            break;
                        case 3:
                            lower_feedback();
                            break;
                        default:
                            break;
                        }
                    } else {
                        switch (userpid_mode_arr[i]->mode_self) {
                        case 1:
                            normal_feedback();
                            break;
                        case 2:
                            upper_feedback();
                            break;
                        case 3:
                            lower_feedback();
                            break;
                        default:
                            break;
                        }
                    }
                }
            } else {
                place_idle = i;
            }
            /* need to kmalloc a buf to fill up the new user process and client_count++*/
            create_new_userpid();
        }        
    } else {
        printk("the count of client reach max\n");
    }
}

static int __init echo_init(void)
{
    flag_exit = 1;
    proc_tsk = kthread_run(proc_tsk_handle, NULL, "proc_tsk_handle");
    nl_sk = netlink_kernel_create(NETLINK_TEST, nl_data_wake);
    while (flag_exit) {
        skb = NULL;
        skb = skb_dequeue(&sk->receive_queue)
        if (skb == NULL) {
            continue;
        }
        netlink_tsk = thread_run(netlink_tsk_handle, (void *)skb, "netlink_tsk_handle");
    }
    
}

static void __exit echo_exit(void)
{
    flag_exit = 0;
    if (!IS_ERR(proc_tsk)) {
        kthread_stop(proc_tsk);
    }

    if (!IS_ERR(proc_tsk)) {
        kthread_stop(netlink_tsk);
    }

    if (echo_proc_file) {
        remove_proc_entry(ECHO_FILE, echo_proc_dir);
    }
    
    if(echo_proc_dir) {
        remove_proc_entry(ECHO_DIR, NULL);
    }
    
    return;
}