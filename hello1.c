#include <net/genetlink.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>

typedef struct {
    u32 pid;
    int mode;
    struct list_head list_control;
} mode_control_t; 

typedef struct {
    int user_pid;      /* the send process id */
    int control_pid;     /* the controlled process id */
    int mode;    /* the controlled mode to be turn */  
} proc_control_t;

typedef struct {
    int mode;
    struct genl_info *info_task;
    struct list_head list_send;
} send_task_t;

//Code based on http://people.ee.ethz.ch/~arkeller/linux/multi/kernel_user_space_howto-3.html

/* attributes (variables):
 * the index in this enum is used as a reference for the type,
 * userspace application has to indicate the corresponding type
 * the policy is used for security considerations 
 */
enum {
    DOC_EXMPL_A_UNSPEC,
    DOC_EXMPL_A_MSG,
    __DOC_EXMPL_A_MAX,
};
#define DOC_EXMPL_A_MAX (__DOC_EXMPL_A_MAX - 1)

/* attribute policy: defines which attribute has which type (e.g int, char * etc)
 * possible values defined in net/netlink.h 
 */
static struct nla_policy doc_exmpl_genl_policy[DOC_EXMPL_A_MAX + 1] = {
    [DOC_EXMPL_A_MSG] = { .type = NLA_NUL_STRING },
};

#define VERSION_NR 1
//family definition
static struct genl_family doc_exmpl_gnl_family = {
    .id = GENL_ID_GENERATE,         //Genetlink should generate an id
    .hdrsize = 0,
    .name = "CONTROL_EXMPL",        //The name of this family, used by userspace application
    .version = VERSION_NR,          //Version number  
    .maxattr = DOC_EXMPL_A_MAX,
};

/* commands: enumeration of all commands (functions), 
 * used by userspace application to identify command to be executed
 */
enum {
    DOC_EXMPL_C_UNSPEC,
    DOC_EXMPL_C_ECHO,
    __DOC_EXMPL_C_MAX,
};

#define ECHO_DIR     "echo_dir"
#define ECHO_FILE    "echo_file"
#define CLIENT_MAX   10
#define MODE_LEN     10
#define MAX_LEN      4096


struct task_struct *gnetlink_tsk;
static send_task_t send_task;
static unsigned int flag_exit;
static unsigned int client_count;
static unsigned int global_charac_handled;
struct mutex mutex_flag;
static mode_control_t mode_control;
static struct proc_dir_entry *echo_proc_dir, *echo_proc_file;
struct task_struct *proc_tsk;
static int global_mode;

#define DOC_EXMPL_C_MAX (__DOC_EXMPL_C_MAX - 1)

DECLARE_COMPLETION(completion_send);

void str_tolower(char **str)
{
    int i;

    for (i = 0; (*str)[i]; i++) {
        if (((*str)[i] < 'z' && (*str)[i] > 'a') || ((*str)[i] < 'Z' && (*str)[i] > 'A')) {
            if ((*str)[i] < 'Z' && (*str)[i] > 'A') {
                (*str)[i] = (*str)[i] + ('a' - 'A');
            }
        }
    }
    
    return;
}

void str_toupper(char **str)
{
    int i;
 
    for (i = 0; (*str)[i]; i++) {
        if (((*str)[i] < 'z' && (*str)[i] > 'a') || ((*str)[i] < 'Z' && (*str)[i] > 'A')) {
            if ((*str)[i] < 'z' && (*str)[i] > 'a') {
                (*str)[i] = (*str)[i] - ('a' - 'A');
            }
        } 
    }
    
    return;
}

static int proc_read_echo(char *page, char **start, off_t off, int count, int *eof)
{
    int len;    
    char buf[100];
    char buf_mod[10];
    
    memset(buf, 0, 100);
    memset(buf_mod, 0, 10);
    switch (global_mode) {
    case 1:
        sprintf(buf_mod, "%s", "normal");
        break;
    case 2:
        sprintf(buf_mod, "%s", "upper");
        break;
    case 3:
        sprintf(buf_mod, "%s", "lower");
        break;
    default:
        break;
    }
    sprintf(buf, "global mode: %s \
        Characters: %d\n", buf_mod, global_charac_handled);
    len = memcpy(page, buf, strlen(buf) + 1);
    return len;
}

 /* get data from user data, receive the data and the check if user pid is exited */
static int proc_write_echo(struct file *file, const char *buff, unsigned int count, void *data)
{
    char *argv_arr[3], *argv_tmp;
    proc_control_t *proc_control_add;
    mode_control_t *mode_control_tmp, *mode_control_add;
    struct list_head *pos, *pos_tmp;
    int flag_exist;
    char *buf_data;
    
    if (strlen(buff) == 0 || count == 0) {
        return 1;
    }
    
    buf_data = (char *)kmalloc(MAX_LEN, GFP_ATOMIC);
    if (buf_data == NULL) {
        return;
    }

    if (copy_from_user(buf_data, buff, count))
    {
        kfree(buf_data);
        return 1;
    }

    proc_control_add = (proc_control_t *)buf_data;
    mode_control_add = (mode_control_t *)kmalloc(sizeof (mode_control_add), GFP_ATOMIC);
    if (mode_control_add == NULL) {
        if (buf_data) {
            kfree(buf_data);
        }
        return;
    }

    memset(mode_control_add, 0, sizeof (mode_control_t));
    mode_control_add->pid = proc_control_add->control_pid;
    mode_control_add->mode = proc_control_add->mode;
    
    if (buf_data) {
        kfree(buf_data);
    }
    
    mutex_lock(&mutex_flag);
    flag_exist = 0;
    if (!list_empty(&(mode_control.list_control))) {
        list_for_each_safe(pos, pos_tmp, &mode_control.list_control) {
            mode_control_tmp = list_entry(pos, mode_control_t, list_control);
            if (mode_control_add->pid == 0) {
                list_del(&(mode_control_tmp->list_control));
                if (mode_control_tmp) {
                    kfree(mode_control_tmp);
                }
                global_mode = mode_control_add->mode;
            }
            if (mode_control_tmp->pid == mode_control_add->pid) {
                mode_control_add->mode = mode_control_tmp->mode;
                flag_exist = 1;
            }
        }
    }
 
    if (flag_exist == 0) {
        list_add(&(mode_control_add->list_control), &mode_control.list_control);
    }    
    mutex_unlock(&mutex_flag);
    return count;
}

static const struct file_operations proc_fops = {
    .read = proc_read_echo,
    .write = proc_write_echo,
};

static void proc_tsk_handle()
{
    echo_proc_file = proc_create_data(ECHO_FILE, 0, NULL, &proc_fops, NULL);
}

void gnetlink_tsk_send(void *data_buf)
{
    struct list_head *pos, *pos_tmp;
    send_task_t *task_tmp;
    static struct nlmsghdr *nlh;
    char *data;
    struct nlattr *na;
    void *msg_head;
    struct sk_buff *skb;
    int rc;
    char *buf_send;
    
    do {
        wait_for_completion(&completion_send);
        printk("get a completion\n");
        mutex_lock(&mutex_flag);
        if (!list_empty(&send_task.list_send)) {
            list_for_each_safe(pos, pos_tmp, &send_task.list_send) {
                task_tmp = list_entry(pos, send_task_t, list_send);
                na = task_tmp->info_task->attrs[DOC_EXMPL_A_MSG];  
                if (na) {
                    data = (char *)nla_data(na);
                    if (data == NULL) {
                        mutex_unlock(&mutex_flag);
                        continue;
                    }           
                    switch (task_tmp->mode) {
                    case 1:
                        break;
                    case 2:
                        str_toupper(&data);
                        break;
                    case 3:
                        str_tolower(&data);
                        break;
                    default:
                        break;
                    } 
                    
                    na = task_tmp->info_task->attrs[DOC_EXMPL_A_MSG];
                    if (na == NULL) {
                         mutex_unlock(&mutex_flag);
                        continue;
                    }
                    data = (char *)nla_data(na);
                    global_charac_handled += strlen(data);
                    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
                    if (skb == NULL) {
                        mutex_unlock(&mutex_flag);
                        continue;
                    } 


                    msg_head = genlmsg_put(skb, 0, task_tmp->info_task->snd_seq+1, &doc_exmpl_gnl_family, 0, DOC_EXMPL_C_ECHO);
                    if (msg_head == NULL) {
                        rc = -ENOMEM;
                        mutex_unlock(&mutex_flag);
                        continue;
                    }
                 //Add a DOC_EXMPL_A_MSG attribute (actual value to be sent)
                    rc = nla_put_string(skb, DOC_EXMPL_A_MSG, data);
                    if (rc != 0) {
                        mutex_unlock(&mutex_flag);
                        continue;
                    }
             
                 //Finalize the message
                    genlmsg_end(skb, msg_head);

                    //Send the message back
                    rc = genlmsg_unicast(genl_info_net(task_tmp->info_task), skb,task_tmp->info_task->snd_portid );
                    if (rc != 0) {
                        mutex_unlock(&mutex_flag);
                        continue;;
                    }                                        
                }
                list_del(pos);
                if (task_tmp->info_task) {
                    kfree(task_tmp->info_task);
                }
                if (task_tmp) {
                    kfree(task_tmp);
                }
                mutex_unlock(&mutex_flag);
            }
        }
    } while (flag_exit);
    
    return;
}
//An echo command, receives a message, prints it and sends another message back
int doc_exmpl_echo(struct sk_buff *skb_2, struct genl_info *info) {
    struct genl_info *info_tmp;
 //   send_task_t *task;
    mode_control_t *mode_control_tmp;
    struct list_head *pos;
    int flag_pid;
    char *data;
    struct nlattr *na;
    struct sk_buff *skb;
    void *msg_head;
    int rc;
    send_task_t *task;
 
    if (info == NULL) {
        return 1;
    }
  
    printk("msg arrived\n");    
    task = (send_task_t *)kmalloc(sizeof (send_task_t), GFP_ATOMIC);
    if (task == NULL) {
        return 1;
    }
    task->info_task = (struct genl_info *)kmalloc(sizeof (struct genl_info), GFP_ATOMIC);
    if (task->info_task == NULL) {
        return 1;
    }
    memcpy(task->info_task, info, sizeof (struct genl_info));

//        flag_pid = 0;
        mutex_lock(&mutex_flag);
        if (!list_empty(&(mode_control.list_control))) {
            list_for_each(pos, &(mode_control.list_control)) {
                mode_control_tmp = list_entry(pos, mode_control_t, list_control);
                if (mode_control_tmp->pid == 0) {
                    task->mode = mode_control_tmp->mode;
                    flag_pid = 1;
                } else {
                    if (mode_control_tmp->pid == task->info_task->snd_portid) {
                        task->mode = mode_control_tmp->mode;
                        flag_pid = 1;
                    }
                }
            }
        }
        if (flag_pid == 0) {
            task->mode = 1; 
        }
        
        list_add(&(task->list_send), &(send_task.list_send));
        mutex_unlock(&mutex_flag); 
        complete(&completion_send);   
        return 0;
   
}

//Commands: mapping between the command enumeration and the actual function
struct genl_ops doc_exmpl_gnl_ops_echo = {
    .cmd = DOC_EXMPL_C_ECHO,
    .flags = 0,
    .policy = doc_exmpl_genl_policy,
    .doit = doc_exmpl_echo,
    .dumpit = NULL,
};


static int __init gnKernel_init(void) {
    int rc;

    INIT_LIST_HEAD(&(send_task.list_send));
    INIT_LIST_HEAD(&(mode_control.list_control));
    mutex_init(&mutex_flag);
    flag_exit = 1;
    
    rc = genl_register_family(&doc_exmpl_gnl_family);
    if (rc != 0) {
        goto failure;
    }

    rc = genl_register_ops(&doc_exmpl_gnl_family, &doc_exmpl_gnl_ops_echo);
    if (rc != 0) {
        printk("Register ops: %i\n",rc);
        genl_unregister_family(&doc_exmpl_gnl_family);
        goto failure;
    }
    proc_tsk_handle();
    gnetlink_tsk = kthread_run(gnetlink_tsk_send, NULL, "netlink_tsk_send"); 
    return 0; 
 
failure:
    printk("An error occured while inserting the generic netlink example module\n");
    return -1;
}

static void __exit gnKernel_exit(void) {
    int ret;
    printk("Generic Netlink Example Module unloaded.\n");
    flag_exit = 0;
    complete(&completion_send);
    if (!IS_ERR(gnetlink_tsk)) {
        kthread_stop(gnetlink_tsk);
    }
    
    if (echo_proc_file) {
        remove_proc_entry(ECHO_FILE, echo_proc_dir);
    }
    
    if(echo_proc_dir) {
        remove_proc_entry(ECHO_DIR, NULL);
    }
    
    ret = genl_unregister_ops(&doc_exmpl_gnl_family, &doc_exmpl_gnl_ops_echo);
    if(ret != 0) {
        printk("Unregister ops: %i\n",ret);
        return;
    }

    ret = genl_unregister_family(&doc_exmpl_gnl_family);
    if(ret !=0) {
        printk("Unregister family %i\n",ret);
    }
 //   if (!IS_ERR(&mutex_flag)) {
        mutex_destroy(&mutex_flag);
 //   }
}

module_init(gnKernel_init);
module_exit(gnKernel_exit);
MODULE_LICENSE("GPL");

     

