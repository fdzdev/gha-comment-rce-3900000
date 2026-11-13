#include <linux/fs.h>
#include <linux/hyperv.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#define HVRAW_MAX 16384

struct hvraw_pipe_header {
	__le32 packet_type;
	__le32 length;
} __packed;

static struct vmbus_channel *raw_channel;
static DEFINE_SPINLOCK(response_lock);
static DECLARE_WAIT_QUEUE_HEAD(response_wait);
static unsigned char response[HVRAW_MAX];
static u32 response_len;

static void hvraw_callback(void *context)
{
	unsigned long flags;
	u32 actual = 0;
	u64 request_id = 0;

	do {
		spin_lock_irqsave(&response_lock, flags);
		vmbus_recvpacket(raw_channel, response, sizeof(response), &actual,
				 &request_id);
		if (actual && actual <= sizeof(response))
			response_len = actual;
		spin_unlock_irqrestore(&response_lock, flags);
		if (actual)
			wake_up_interruptible(&response_wait);
	} while (actual);
}

static int hvraw_probe(struct hv_device *device,
		       const struct hv_vmbus_device_id *id)
{
	int error;

	if (raw_channel)
		return -EBUSY;
	raw_channel = device->channel;
	error = vmbus_open(raw_channel, 16 * PAGE_SIZE, 16 * PAGE_SIZE,
			   NULL, 0, hvraw_callback, device);
	if (error)
		raw_channel = NULL;
	pr_info("hvraw_vmbfs: probe relid=%u open=%d\n",
		device->channel->offermsg.child_relid, error);
	return error;
}

static int hvraw_remove(struct hv_device *device)
{
	if (raw_channel == device->channel) {
		vmbus_close(raw_channel);
		raw_channel = NULL;
		wake_up_interruptible(&response_wait);
	}
	return 0;
}

static const struct hv_vmbus_device_id hvraw_ids[] = {
	{ .guid = GUID_INIT(0xc376c1c3, 0xd276, 0x48d2, 0x90, 0xa9,
			    0xc0, 0x47, 0x48, 0x07, 0x2c, 0x60) },
	{ }
};
MODULE_DEVICE_TABLE(vmbus, hvraw_ids);

static struct hv_driver hvraw_driver = {
	.name = "hvraw_vmbfs",
	.id_table = hvraw_ids,
	.probe = hvraw_probe,
	.remove = hvraw_remove,
};

static ssize_t hvraw_write(struct file *file, const char __user *source,
			   size_t length, loff_t *offset)
{
	struct hvraw_pipe_header *pipe;
	void *frame;
	int error;

	if (!raw_channel)
		return -ENODEV;
	if (!length || length > HVRAW_MAX - sizeof(*pipe))
		return -EMSGSIZE;
	frame = kmalloc(length + sizeof(*pipe), GFP_KERNEL);
	if (!frame)
		return -ENOMEM;
	pipe = frame;
	pipe->packet_type = cpu_to_le32(1);
	pipe->length = cpu_to_le32(length);
	if (copy_from_user(pipe + 1, source, length)) {
		kfree(frame);
		return -EFAULT;
	}
	spin_lock_irq(&response_lock);
	response_len = 0;
	spin_unlock_irq(&response_lock);
	error = vmbus_sendpacket(raw_channel, frame, length + sizeof(*pipe), 0,
				 VM_PKT_DATA_INBAND, 0);
	kfree(frame);
	return error ? error : length;
}

static ssize_t hvraw_read(struct file *file, char __user *destination,
			  size_t length, loff_t *offset)
{
	unsigned long flags;
	unsigned char *copy;
	u32 available;
	int error;

	if (!raw_channel)
		return -ENODEV;
	error = wait_event_interruptible_timeout(response_wait,
		READ_ONCE(response_len) || !READ_ONCE(raw_channel), 2 * HZ);
	if (error < 0)
		return error;
	if (!error)
		return -ETIMEDOUT;
	copy = kmalloc(min_t(size_t, length, HVRAW_MAX), GFP_KERNEL);
	if (!copy)
		return -ENOMEM;
	spin_lock_irqsave(&response_lock, flags);
	available = min_t(u32, length, response_len);
	memcpy(copy, response, available);
	response_len = 0;
	spin_unlock_irqrestore(&response_lock, flags);
	if (available && copy_to_user(destination, copy, available)) {
		kfree(copy);
		return -EFAULT;
	}
	kfree(copy);
	return available;
}

static const struct file_operations hvraw_operations = {
	.owner = THIS_MODULE,
	.read = hvraw_read,
	.write = hvraw_write,
};

static struct miscdevice hvraw_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "hvrawvmbfs",
	.fops = &hvraw_operations,
	.mode = 0600,
};

static int __init hvraw_init(void)
{
	int error;

	error = misc_register(&hvraw_misc);
	if (error)
		return error;
	error = vmbus_driver_register(&hvraw_driver);
	if (error)
		misc_deregister(&hvraw_misc);
	return error;
}

static void __exit hvraw_exit(void)
{
	vmbus_driver_unregister(&hvraw_driver);
	misc_deregister(&hvraw_misc);
}

module_init(hvraw_init);
module_exit(hvraw_exit);
MODULE_LICENSE("GPL");

