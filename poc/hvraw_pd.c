#include <linux/delay.h>
#include <linux/hyperv.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

/* Probe the NVSP v6 PacketDirect API surface on the live NetVSP channel.
 * Control-plane requests only; NvspMessage6TypePdPostBatch is never sent. */

static unsigned long channel_address;
static unsigned int op = 1;
static unsigned long long arg_pa;
static unsigned int arg_len = 0x1000;
static unsigned int arg_sub = 1;
static unsigned int arg_a;
static unsigned int arg_b = 1;
static unsigned int arg_prov;
static unsigned int arg_q;
static unsigned int arg_region = 1;
static unsigned int wait_ms = 1500;

struct pd_grp_affinity {
	u64 mask;
	u16 grp;
	u16 reserved[3];
} __packed;

struct pd_req {
	u32 msg_type; /* 135 = NVSP_MSG6_TYPE_PD_API */
	u32 op;
	union {
		struct {
			u64 mmio_pa;
			u32 mmio_len;
			u16 num_subchn;
		} __packed config;
		struct {
			u8 host_dpath_is_pd;
			u8 guest_pd_enabled;
		} __packed sw_dpath;
		struct {
			u32 prov_id;
			u32 flag;
		} __packed open_prov;
		struct {
			u32 prov_id;
		} __packed cls_prov;
		struct {
			u32 prov_id;
			u16 q_id;
			u16 q_size;
			u8 is_recv_q;
			u8 is_rss_q;
			u32 recv_data_len;
			struct pd_grp_affinity affy;
		} __packed cr_q;
		struct {
			u32 len;
			u32 pf_node;
			u16 region_id;
		} __packed alloc_com_buf;
	} __packed;
} __packed;

static unsigned long send_fn;
static unsigned long recv_fn;

static void quiet_callback(void *context)
{
}

static int ulong_set(const char *value, const struct kernel_param *parameter)
{
	return kstrtoull(value, 0, (unsigned long long *)parameter->arg);
}

/* Call exported hv_vmbus functions by kallsyms address so the module links
 * without a modversioned dependency on hv_vmbus (depends= must stay empty). */
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

static int do_probe(void)
{
	struct vmbus_channel *channel = (struct vmbus_channel *)channel_address;
	void (*saved_callback)(void *context);
	void *saved_context;
	struct pd_req request;
	u8 response[256];
	u32 actual;
	u64 request_id;
	unsigned long deadline;
	int error;
	int packets = 0;
	u32 send_length = 8;

	if (!channel || !send_fn || !recv_fn)
		return -EINVAL;

	memset(&request, 0, sizeof(request));
	request.msg_type = 135;
	request.op = op;
	switch (op) {
	case 1:
		request.config.mmio_pa = arg_pa;
		request.config.mmio_len = arg_len;
		request.config.num_subchn = arg_sub;
		send_length = 8 + 14;
		break;
	case 2:
		request.sw_dpath.host_dpath_is_pd = arg_a;
		request.sw_dpath.guest_pd_enabled = arg_b;
		send_length = 8 + 2;
		break;
	case 3:
		request.open_prov.prov_id = arg_prov;
		request.open_prov.flag = arg_a;
		send_length = 8 + 8;
		break;
	case 4:
		request.cls_prov.prov_id = arg_prov;
		send_length = 8 + 4;
		break;
	case 5:
		request.cr_q.prov_id = arg_prov;
		request.cr_q.q_id = arg_q;
		request.cr_q.q_size = 256;
		request.cr_q.is_recv_q = arg_a;
		request.cr_q.is_rss_q = 0;
		request.cr_q.recv_data_len = arg_len;
		send_length = 8 + 30;
		break;
	case 8:
		request.alloc_com_buf.len = arg_len;
		request.alloc_com_buf.pf_node = 0;
		request.alloc_com_buf.region_id = arg_region;
		send_length = 8 + 10;
		break;
	default:
		return -EOPNOTSUPP;
	}

	saved_callback = channel->onchannel_callback;
	saved_context = channel->channel_callback_context;
	channel->onchannel_callback = quiet_callback;
	channel->channel_callback_context = NULL;

	error = (int)call6(send_fn, (unsigned long)channel,
			   (unsigned long)&request, send_length,
			   0x4d5954480000ULL + op, VM_PKT_DATA_INBAND,
			   VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	pr_info("HVPD send op=%u len=%u err=%d\n", op, send_length, error);

	deadline = jiffies + msecs_to_jiffies(wait_ms);
	while (time_before(jiffies, deadline)) {
		actual = 0;
		request_id = 0;
		error = (int)call6(recv_fn, (unsigned long)channel,
				   (unsigned long)response, sizeof(response),
				   (unsigned long)&actual,
				   (unsigned long)&request_id, 0);
		if (error || (!actual && !request_id)) {
			usleep_range(500, 1500);
			continue;
		}
		packets++;
		if (!actual) {
			pr_info("HVPD txn-complete rid=%llx\n", request_id);
			if (request_id == 0x4d5954480000ULL + op)
				break;
			continue;
		}
		pr_info("HVPD pkt len=%u rid=%llx head=%*phN\n", actual,
			request_id, (int)min(actual, 48u), response);
		if (actual >= 12 && *(u32 *)response == 135) {
			u32 *words = (u32 *)response;

			pr_info("HVPD comp op=%u status=0x%x extra=%*phN\n",
				words[1], words[2],
				(int)min(actual - 12, 20u), response + 12);
			break;
		}
	}

	channel->onchannel_callback = saved_callback;
	channel->channel_callback_context = saved_context;
	pr_info("HVPD done op=%u packets=%d\n", op, packets);
	return 0;
}

static int arm_set(const char *value, const struct kernel_param *parameter)
{
	int armed = 0;

	if (kstrtoint(value, 0, &armed) || armed != 1)
		return -EINVAL;
	return do_probe();
}

static const struct kernel_param_ops ulong_ops = { .set = ulong_set };
static const struct kernel_param_ops arm_ops = { .set = arm_set };

module_param_cb(channel, &ulong_ops, &channel_address, 0600);
module_param_cb(send_fn, &ulong_ops, &send_fn, 0600);
module_param_cb(recv_fn, &ulong_ops, &recv_fn, 0600);
module_param(op, uint, 0600);
module_param_cb(pa, &ulong_ops, &arg_pa, 0600);
module_param_named(len, arg_len, uint, 0600);
module_param_named(sub, arg_sub, uint, 0600);
module_param_named(a, arg_a, uint, 0600);
module_param_named(b, arg_b, uint, 0600);
module_param_named(prov, arg_prov, uint, 0600);
module_param_named(q, arg_q, uint, 0600);
module_param_named(region, arg_region, uint, 0600);
module_param(wait_ms, uint, 0600);
module_param_cb(arm, &arm_ops, NULL, 0200);

static int __init hvraw_pd_init(void)
{
    return 0;
}

static void __exit hvraw_pd_exit(void)
{
}

module_init(hvraw_pd_init);
module_exit(hvraw_pd_exit);
MODULE_LICENSE("GPL");
