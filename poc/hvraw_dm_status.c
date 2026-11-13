#include <linux/delay.h>
#include <linux/hyperv.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

/* Inject only Dynamic Memory status reports on an already initialized channel.
 * The stock hv_balloon callback stays installed and handles every request and
 * response, preserving its page ownership and transaction state. */

static unsigned long channel_address;
static unsigned long send_address;
static unsigned long long available_pages;
static unsigned long long committed_pages;
static unsigned int burst = 20;
static unsigned int interval_ms = 50;

struct dm_status_wire {
	u16 type;
	u16 size;
	u32 transaction_id;
	u64 available;
	u64 committed;
	u64 page_file_size;
	u64 zero_free;
	u32 page_file_writes;
	u32 io_diff;
} __packed;

static long call6(unsigned long function, unsigned long a1, unsigned long a2,
		  unsigned long a3, unsigned long a4, unsigned long a5,
		  unsigned long a6)
{
	register unsigned long reg_di asm("rdi") = a1;
	register unsigned long reg_si asm("rsi") = a2;
	register unsigned long reg_dx asm("rdx") = a3;
	register unsigned long reg_c asm("rcx") = a4;
	register unsigned long reg_8 asm("r8") = a5;
	register unsigned long reg_9 asm("r9") = a6;
	unsigned long out = function;

	asm volatile("call *%%rax"
		     : "+a"(out), "+r"(reg_di), "+r"(reg_si), "+r"(reg_dx),
		       "+r"(reg_c), "+r"(reg_8), "+r"(reg_9)
		     :
		     : "r10", "r11", "cc", "memory");
	return (long)out;
}

static int ulong_set(const char *value, const struct kernel_param *parameter)
{
	return kstrtoull(value, 0, (unsigned long long *)parameter->arg);
}

static int inject_status(void)
{
	struct vmbus_channel *channel = (void *)channel_address;
	struct dm_status_wire message = {
		.type = cpu_to_le16(5),
		.size = cpu_to_le16(sizeof(message)),
		.available = cpu_to_le64(available_pages),
		.committed = cpu_to_le64(committed_pages),
	};
	unsigned int index;
	int error = 0;

	if (!channel || !send_address || !burst || burst > 200 ||
	    interval_ms > 1000)
		return -EINVAL;

	for (index = 0; index < burst; index++) {
		message.transaction_id = cpu_to_le32(0x4d590000u + index);
		error = (int)call6(send_address, (unsigned long)channel,
				   (unsigned long)&message, sizeof(message), 0,
				   VM_PKT_DATA_INBAND, 0);
		if (error)
			break;
		if (interval_ms)
			msleep(interval_ms);
	}

	pr_info("HVDM_STATUS avail=%llu committed=%llu sent=%u err=%d\n",
		available_pages, committed_pages, index, error);
	return error;
}

static int arm_set(const char *value, const struct kernel_param *parameter)
{
	int armed;

	if (kstrtoint(value, 0, &armed) || armed != 1)
		return -EINVAL;
	return inject_status();
}

static const struct kernel_param_ops ulong_ops = {.set = ulong_set};
static const struct kernel_param_ops arm_ops = {.set = arm_set};

module_param_cb(channel, &ulong_ops, &channel_address, 0600);
module_param_cb(send_fn, &ulong_ops, &send_address, 0600);
module_param_cb(available, &ulong_ops, &available_pages, 0600);
module_param_cb(committed, &ulong_ops, &committed_pages, 0600);
module_param(burst, uint, 0600);
module_param(interval_ms, uint, 0600);
module_param_cb(arm, &arm_ops, NULL, 0200);

static int __init hvraw_dm_status_init(void)
{
	return 0;
}

static void __exit hvraw_dm_status_exit(void)
{
}

module_init(hvraw_dm_status_init);
module_exit(hvraw_dm_status_exit);
MODULE_LICENSE("GPL");
