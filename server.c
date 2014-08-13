#include <net/genetlink.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/string.h>

#define ECHO_DIR     "echo_dir"
#define ECHO_FILE    "echo_file"
#define CLIENT_MAX   10
#define MODE_LEN     10
#define MAX_LEN      4096

typedef struct {
    int  flag_globalmode_valid;
    int  charac_handled_count;
    int  mode_global;           /* 1: normal (default mode), 2: upper, 3: lower */
    int  mode_self;   /* 1: normal (default mode), 2: upper, 3: lower */
} userpid_mode_t;

typedef struct {
    u32 pid;
    int mode;
    struct list_head *list_control;
} mode_control_t;

typedef struct {
    int user_pid;      /* the send process id */
    int control_pid;     /* the controlled process id */
    char mode[10];    /* the controlled mode to be turn */  
} proc_control_t;

typedef struct {
    userpid_mode_t *userpid_mod_task;
    struct sk_buf *skb_task;
    struct list_head list_send;
} send_task_t;

struct task_struct *proc_tsk;
struct task_struct *netlink_tsk;
static userpid_mode_t *userpid_mode_arr[CLIENT_MAX];
static char *data_buf;
static struct proc_dir_entry *echo_proc_dir, *echo_proc_file;
static struct sock *nl_sk;
static send_task_t send_task;
static unsigned int flag_exit;
static unsigned int client_count;
static unsigned int global_charac_handled;
struct mutex mutex_flag;
static mode_control_t mode_control;
static *buf_mod;

DECLARE_COMPLETION(completion_send);
/* show the message to user space */
static int proc_read_echo(char *page, char **start, off_t off, int count, int *eof)
{
    int len;
    
    len = memcpy(page, &showinfo, sizeof (showinfo_t));
    return len;
}

 /* get data from user data, receive the data and the check if user pid is exited */
static int proc_write_echo(struct file *file, const char *buff, unsigned int count, void *data)
{
    char *argv_arr[3], *argv_tmp;
    proc_control_t *proc_control;
    struct list_head *pos, *pos_tmp;
    
    if (strlen(buf) == 0 || count == 0) {
        return 1;
    }
    
    buf_mod = (char *)kmalloc(MAX_LEN);
    if (buf_mod == NULL) {
        return;
    }

    if (copy_from_user(buf_mod, buff, count))
    {
        kfree(buf_mod);
        return 1;
    }

    (proc_control_t *)buf_mod;
    proc_control = 
    mutex_lock(&mutex_flag);
    if (list_empty(&(mode_control.list_control))){
        list_add(&(pr))
    }
    if (proc_control->control_pid == 0)
        list_for_each_safe(pos, pos_tmp, &mode_control.list_control) {
    
    }
    
    return count;
}

static int proc_tsk_handle(void *data)
{
    echo_proc_dir = proc_mkdir(ECHO_DIR, NULL);
    echo_proc_file = create_proc_entry(ECHO_FILE, S_IRUGO, echo_proc_dir);
    echo_proc_file->read_proc = proc_read_echo;
    echo_proc_file->write_proc = proc_write_echo;
}


char *str_tolower(const char * &str)
{
    int i;

    for (i = 0; str[i]; i++) {
        if ((str[i] < 'z' && str[i] > 'a') || (str[i] < 'Z' && str[i] > 'A')) {
            if (str[i] < 'Z' && str[i] > 'A') {
                str[i] = str[i] + ('a' - 'A');
            }
        }
    }
    
    return lower_str;
}

char *str_toupper(const char * &str)
{
    int len;
    for (i = 0; str[i]; i++) {
        if ((str[i] < 'z' && str[i] > 'a') || (str[i] < 'Z' && str[i] > 'A')) {
            if (str[i] < 'z' && str[i] > 'a') {
                str[i] = str[i] - ('a' - 'A');
            }
        } 
    }
    
    return upper_str;
}

static void netlink_tsk_handle(struct sock *sk, int len)
{
    static struct sk_buf *skb;
    send_task_t *task;
    int err, i, place_idle;
    char *buf_feedback;
    u32 pid;
   
    while (flag_exit) {
        skb = NULL;
        skb = skb_dequeue(&sk->receive_queue)
        if (skb == NULL) {
            continue;
        }
        
        if (client_count > CLIENT_MAX) {
            continue;
        }
        
        task = (send_task_t *)kmalloc(sizeof (send_task_t), GFP_ATOMIC);
        task->skb_task = skb_copy(skb, GFP_ATOMIC);
        task->userpid_mod_task = (userpid_mode_t *)kmalloc(sizeof (userpid_mode_t));
        if (task == NULL || task->skb_task == NULL || task->userpid_mod_task) {
            if (task != NULL) {
                kfree(task);
            }
            
            if (task->userpid_mod_task != NULL) {
                kfree(task->userpid_mod_task);
            }
            continue;
        }
     //   if (is global by /proc)
    //    task->skb_task = (struct sk_buf *)kmalloc(sizeof (struct sk_buf));
    //   memcpy(task->skb_task, skb, sizeof (struct sk_buf));
        task->userpid_mod_task->flag_globalmode_valid = 1;
        task->userpid_mod_task->mode_global = 1;
        task->userpid_mod_task->mode_self = 1;
        task->charac_handled_count = 0;
        list_add(&(task->list_send), &(send_task.list_send));
        complete(&completion_send);  
    }   
}

static void netlink_tsk_send(void *data)
{
    struct list_head *pos, *pos_tmp;
    send_task_t task_tmp;
    static struct nlmsghdr *nlh;
    
    do {
        wait_for_completion(&completion_send);
        mutex_lock(&mutex_flag);
        list_for_each_safe(pos, pos_tmp, &send_task.list_send) {
            task_tmp = list_entry(pos, send_task_t, list_send);
            nlh = (struct nlmsghdr *)task_tmp->skb_task->data;
            if (task_tmp->userpid_mod_task->flag_globalmode_valid == 1) {
                switch (task_tmp->userpid_mod_task->mode_global) {
                case 1:
                    break;
                case 2:
                    str_toupper((char *)NLMSG_DATA(nlh));
                    break;
                case 3:
                    buf_feedback = str_tolower((char *)NLMSG_DATA(nlh));
                    break;
                default:
                    break;
                }
            } else {
                switch (task_tmp->userpid_mod_task->mode_self) {
                case 1:
                    break;
                case 2:
                    buf_feedback = str_toupper((char *)NLMSG_DATA(nlh));
                    break;
                case 3:
                    buf_feedback = str_tolower((char *)NLMSG_DATA(nlh));
                    break;
                default:
                    break;
                }
            }
            netlink_unicast(nl_sk, task_tmp->skb_task, nlh->nlmsg_pid, 0);
            list_del(pos);
            if (task_tmp->userpid_mod_task) {
                free(task_tmp->userpid_mod_task);
            }
            if (task_tmp) {
                free(task_tmp);
            }
            mutex_unlock(&mutex_flag);
        }
    } while (flag_exit)
}

static int __init echo_init(void)
{
    flag_exit = 1;
    mutex_init(&mutex_flag);
    INIT_HEAD_LIST(&send_task.list_send);
    proc_tsk = kthread_run(proc_tsk_handle, NULL, "proc_tsk_handle");
    nl_sk = netlink_kernel_create(NETLINK_TEST, netlink_tsk_handle);
    netlink_tsk = thread_run(netlink_tsk_send, NULL, "netlink_tsk_send");    
}

static void __exit echo_exit(void)
{
    flag_exit = 0;
    if (!IS_ERR(proc_tsk_handle)) {
        kthread_stop(proc_tsk_handle);
    }

    if (!IS_ERR(netlink_tsk_send)) {
        kthread_stop(netlink_tsk_send);
    }

    if (echo_proc_file) {
        remove_proc_entry(ECHO_FILE, echo_proc_dir);
    }
    
    if(echo_proc_dir) {
        remove_proc_entry(ECHO_DIR, NULL);
    }
    
    if (!IS_ERR(&mutex_flag)) {
        mutex_destroy(&mutex_flag);
    }
    
    if (!IS_ERR(nl_sk->sk_socket)) {
        sock_release(nl_sk->sk_socket);
    }
     
    return;
}