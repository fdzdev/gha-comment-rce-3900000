#undef CONFIG_FORTIFY_SOURCE

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/string.h>
#include <linux/types.h>

#define RNDIS_MAX_INPUT 4000

static unsigned long get_address;
static unsigned long send_address;
static unsigned long put_address;
static unsigned long rndis_device;
static unsigned int request_type = 5;
static unsigned int oid = 0x0001010e;
static unsigned int input_length = 4;
static unsigned int count = 1;
static unsigned int timeout_ms = 3000;
static unsigned int delay_us;
static unsigned int hold;
static char data_hex[RNDIS_MAX_INPUT * 2 + 1];
static int arm;

static int ulong_set(const char *value, const struct kernel_param *parameter)
{
    return kstrtoull(value, 0, (unsigned long long *)parameter->arg);
}

static int uint_set(const char *value, const struct kernel_param *parameter)
{
    return kstrtouint(value, 0, parameter->arg);
}

static const struct kernel_param_ops ulong_ops = { .set = ulong_set };
static const struct kernel_param_ops uint_ops = { .set = uint_set };

static int decode_nibble(char value)
{
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    if (value >= 'A' && value <= 'F')
        return value - 'A' + 10;
    return -EINVAL;
}

static int decode_hex(u8 *output, const char *input, size_t input_length)
{
    size_t index;

    for (index = 0; index < input_length; index += 2) {
        int high = decode_nibble(input[index]);
        int low = decode_nibble(input[index + 1]);

        if (high < 0 || low < 0)
            return -EINVAL;
        output[index / 2] = (high << 4) | low;
    }
    return 0;
}

static void *call_get(unsigned long device, u32 type, u32 length)
{
    unsigned long function = get_address;

    asm volatile("call *%%rax"
                 : "+a"(function)
                 : "D"(device), "S"((unsigned long)type), "d"((unsigned long)length)
                 : "rcx", "r8", "r9", "r10", "r11", "cc", "memory");
    return (void *)function;
}

static int call_send(unsigned long device, void *request)
{
    unsigned long function = send_address;

    asm volatile("call *%%rax"
                 : "+a"(function)
                 : "D"(device), "S"(request)
                 : "rdx", "rcx", "r8", "r9", "r10", "r11", "cc", "memory");
    return (int)function;
}

static void call_put(unsigned long device, void *request)
{
    unsigned long function = put_address;

    asm volatile("call *%%rax"
                 : "+a"(function)
                 : "D"(device), "S"(request)
                 : "rdx", "rcx", "r8", "r9", "r10", "r11", "cc", "memory");
}

static void execute(void)
{
    const u32 request_length = input_length + 28;
    size_t hex_length = strlen(data_hex);
    unsigned int iteration;

    if ((request_type != 4 && request_type != 5) ||
        input_length > RNDIS_MAX_INPUT || count > 256 || (hex_length & 1)) {
        pr_info("rndis_oid_set invalid input_length=%u hex_length=%zu count=%u\n",
                input_length, hex_length, count);
        return;
    }

    for (iteration = 0; iteration < count; iteration++) {
        void *request = call_get(rndis_device, request_type, request_length);
        u8 *wire = NULL;
        u8 *response;
        u32 offset;
        u32 waited;
        int error;

        if (!request) {
            pr_info("rndis_oid_set iteration=%u allocation_failed\n", iteration);
            return;
        }
        for (offset = 0x1000; offset < 0x1800; offset += 4) {
            u8 *candidate = (u8 *)request + offset;

            if (*(u32 *)candidate == request_type &&
                *(u32 *)(candidate + 4) == request_length &&
                *(u32 *)(candidate + 8) > 0 &&
                *(u32 *)(candidate + 8) < 0x100000) {
                wire = candidate;
                break;
            }
        }
        if (!wire) {
            pr_info("rndis_oid_set iteration=%u request_message_not_found\n", iteration);
            call_put(rndis_device, request);
            return;
        }

        *(u32 *)(wire + 0x0c) = oid;
        *(u32 *)(wire + 0x10) = input_length;
        *(u32 *)(wire + 0x14) = 20;
        *(u32 *)(wire + 0x18) = 0;
        if (input_length && hex_length &&
            decode_hex(wire + 0x1c, data_hex,
                       min_t(size_t, hex_length, input_length * 2))) {
            pr_info("rndis_oid_set iteration=%u invalid_hex\n", iteration);
            call_put(rndis_device, request);
            return;
        }

        error = call_send(rndis_device, request);
        if (error) {
            pr_info("rndis_oid_set iteration=%u oid=%#x input_length=%u send=%d\n",
                    iteration, oid, input_length, error);
            call_put(rndis_device, request);
            return;
        }
        if (hold) {
            pr_info("rndis_oid_set iteration=%u oid=%#x input_length=%u queued reqid=%u\n",
                    iteration, oid, input_length, *(u32 *)(wire + 8));
            continue;
        }
        for (waited = 0; waited < timeout_ms; waited++) {
            if (READ_ONCE(*(u32 *)((u8 *)request + 0x10)))
                break;
            msleep(1);
        }
        if (waited == timeout_ms) {
            pr_info("rndis_oid_set iteration=%u oid=%#x input_length=%u timeout reqid=%u\n",
                    iteration, oid, input_length, *(u32 *)(wire + 8));
            return;
        }

        smp_rmb();
        response = (u8 *)request + 0x30;
        pr_info("rndis_oid_set iteration=%u oid=%#x input_length=%u type=%#x len=%u reqid=%u status=%#x waited=%u\n",
                iteration, oid, input_length, *(u32 *)response,
                *(u32 *)(response + 4), *(u32 *)(response + 8),
                *(u32 *)(response + 0x0c), waited);
        if (request_type == 5)
            pr_info("rndis_oid_set_data oid=%#x head=%*phN\n", oid,
                    min_t(u32, input_length, 64), wire + 0x1c);
        if (request_type == 4) {
            u32 result_length = *(u32 *)(response + 0x10);
            u32 result_offset = *(u32 *)(response + 0x14);

            if (result_length <= RNDIS_MAX_INPUT && result_offset <= RNDIS_MAX_INPUT &&
                result_length + result_offset <= RNDIS_MAX_INPUT)
                pr_info("rndis_oid_query oid=%#x result_length=%u result_offset=%u head=%*phN\n",
                        oid, result_length, result_offset,
                        min_t(u32, result_length, 192), response + 8 + result_offset);
        }
        call_put(rndis_device, request);
        if (delay_us)
            usleep_range(delay_us, delay_us + 20);
    }
}

static int arm_set(const char *value, const struct kernel_param *parameter)
{
    unsigned int requested;

    if (kstrtouint(value, 0, &requested) || !requested)
        return -EINVAL;
    if (!get_address || !send_address || !put_address || !rndis_device)
        return -EINVAL;
    arm = requested;
    execute();
    return 0;
}

static const struct kernel_param_ops arm_ops = {
    .set = arm_set,
    .get = param_get_int,
};

module_param_cb(get_address, &ulong_ops, &get_address, 0000);
module_param_cb(send_address, &ulong_ops, &send_address, 0000);
module_param_cb(put_address, &ulong_ops, &put_address, 0000);
module_param_cb(rndis_device, &ulong_ops, &rndis_device, 0000);
module_param_cb(request_type, &uint_ops, &request_type, 0600);
module_param_cb(oid, &uint_ops, &oid, 0600);
module_param_cb(input_length, &uint_ops, &input_length, 0600);
module_param_cb(count, &uint_ops, &count, 0600);
module_param_cb(timeout_ms, &uint_ops, &timeout_ms, 0600);
module_param_cb(delay_us, &uint_ops, &delay_us, 0600);
module_param_cb(hold, &uint_ops, &hold, 0600);
module_param_string(data_hex, data_hex, sizeof(data_hex), 0600);
module_param_cb(arm, &arm_ops, &arm, 0600);

static int __init rndis_oid_set_init(void)
{
    return 0;
}

static void __exit rndis_oid_set_exit(void)
{
}

module_init(rndis_oid_set_init);
module_exit(rndis_oid_set_exit);
MODULE_LICENSE("GPL");
