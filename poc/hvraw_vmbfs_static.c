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
	"\\imc.hiv",
	"\\kernel",
	"\\initrd.img",
	"\\cmdline",
	"\\missing-3900000",
	"\\..\\imc.hiv",
};

static struct vmbus_channel *channel;
static struct frame tx;
static unsigned char rx[512];
static unsigned int phase;
static unsigned int path_index;
static bool prefix_read;

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

	/* Move the UTF-16 path after count+offset, copying backwards. */
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
		if (pipe_type != PIPE_DATA || pipe_length != actual - 8 ||
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
			if (status == 0 && size && !prefix_read && path_index < 4) {
				prefix_read = true;
				send_read(path_index);
			} else if (++path_index < ARRAY_SIZE(paths)) {
				send_info(path_index);
			}
		} else if (message == VMBFS_READ_RESPONSE) {
			pr_info("VMBFS_READ path=%s status=%u returned=%u data=%*phN\n",
				paths[path_index], status, actual - 20,
				(int)min(actual - 20, 16u), rx + 20);
			if (++path_index < ARRAY_SIZE(paths))
				send_info(path_index);
		}
	} while (actual);
}

static int hvraw_probe(struct hv_device *device,
		       const struct hv_vmbus_device_id *id)
{
	int error;

	if (channel)
		return -EBUSY;
	channel = device->channel;
	error = vmbus_open(channel, 16 * PAGE_SIZE, 16 * PAGE_SIZE,
			   NULL, 0, hvraw_callback, device);
	pr_info("VMBFS_OPEN relid=%u result=%d\n",
		device->channel->offermsg.child_relid, error);
	if (error) {
		channel = NULL;
		return error;
	}
	error = send_version();
	pr_info("VMBFS_TX version result=%d\n", error);
	return 0;
}

static int hvraw_remove(struct hv_device *device)
{
	if (channel == device->channel) {
		vmbus_close(channel);
		channel = NULL;
	}
	return 0;
}

static const struct hv_vmbus_device_id hvraw_ids[] = {
	{ .guid = GUID_INIT(0xc376c1c3, 0xd276, 0x48d2, 0x90, 0xa9,
			    0xc0, 0x47, 0x48, 0x07, 0x2c, 0x60) },
	{ }
};

static struct hv_driver hvraw_driver = {
	.name = "hvraw_vmbfs_static",
	.id_table = hvraw_ids,
	.probe = hvraw_probe,
	.remove = hvraw_remove,
};

static int __init hvraw_init(void)
{
	return vmbus_driver_register(&hvraw_driver);
}

static void __exit hvraw_exit(void)
{
	vmbus_driver_unregister(&hvraw_driver);
}

module_init(hvraw_init);
module_exit(hvraw_exit);
MODULE_LICENSE("GPL");

