#include <linux/atomic.h>
#include <linux/hyperv.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

/* Preserve the stock Dynamic Memory state machine and mutate only its genuine
 * one-second status messages.  The balloon_up probe is observation-only. */

static unsigned long channel_address;
static unsigned long send_address;
static unsigned long balloon_up_address;
static unsigned int reports = 5;
static atomic_t reports_left;
static atomic_t mutations;
static atomic_t balloon_requests;
static unsigned int mutation_count;
static unsigned int receiver_count;

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

static struct kprobe send_probe;
static struct kprobe receiver_probe;

static int __kprobes mutate_stock_status(struct kprobe *probe,
					 struct pt_regs *registers)
{
	struct dm_status_wire *message;
	unsigned int left;

	if (registers->di != channel_address ||
	    registers->dx != sizeof(struct dm_status_wire))
		return 0;

	message = (struct dm_status_wire *)registers->si;
	if (!message || READ_ONCE(message->type) != cpu_to_le16(5) ||
	    READ_ONCE(message->size) != cpu_to_le16(sizeof(*message)))
		return 0;

	for (;;) {
		left = (unsigned int)atomic_read(&reports_left);
		if (!left)
			return 0;
		if (atomic_cmpxchg(&reports_left, left, left - 1) == left)
			break;
	}

	WRITE_ONCE(message->committed, cpu_to_le64(0));
	left = (unsigned int)atomic_inc_return(&mutations);
	WRITE_ONCE(mutation_count, left);
	pr_info("HVDM_GATE stock=%u trans=%u available=%llu committed=0\n",
		left, le32_to_cpu(READ_ONCE(message->transaction_id)),
		le64_to_cpu(READ_ONCE(message->available)));
	return 0;
}

static int __kprobes observe_balloon_request(struct kprobe *probe,
					     struct pt_regs *registers)
{
	unsigned int count;

	count = (unsigned int)atomic_inc_return(&balloon_requests);
	WRITE_ONCE(receiver_count, count);
	pr_info("HVDM_RECEIVER type=6 count=%u\n", count);
	return 0;
}

static int __init notrace hvraw_dm_status_init(void)
{
	int error;

	if (!channel_address || !send_address || !balloon_up_address ||
	    !reports || reports > 10)
		return -EINVAL;

	atomic_set(&reports_left, reports);
	atomic_set(&mutations, 0);
	atomic_set(&balloon_requests, 0);
	mutation_count = 0;
	receiver_count = 0;

	send_probe.addr = (kprobe_opcode_t *)send_address;
	send_probe.pre_handler = mutate_stock_status;
	error = register_kprobe(&send_probe);
	if (error)
		return error;

	receiver_probe.addr = (kprobe_opcode_t *)balloon_up_address;
	receiver_probe.pre_handler = observe_balloon_request;
	error = register_kprobe(&receiver_probe);
	if (error) {
		unregister_kprobe(&send_probe);
		return error;
	}

	pr_info("HVDM_GATE armed reports=%u\n", reports);
	return 0;
}

static void __exit notrace hvraw_dm_status_exit(void)
{
	unregister_kprobe(&receiver_probe);
	unregister_kprobe(&send_probe);
}

module_param_named(channel, channel_address, ulong, 0600);
module_param_named(send_fn, send_address, ulong, 0600);
module_param_named(balloon_up_fn, balloon_up_address, ulong, 0600);
module_param(reports, uint, 0600);
module_param_named(mutated, mutation_count, uint, 0400);
module_param_named(receiver_requests, receiver_count, uint, 0400);

module_init(hvraw_dm_status_init);
module_exit(hvraw_dm_status_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bounded observer gate for Hyper-V Dynamic Memory");
