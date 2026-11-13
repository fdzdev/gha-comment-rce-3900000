#include <linux/delay.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>

static unsigned long query_address;
static unsigned long rndis_device;
static unsigned long netvsc_device;
static unsigned int oid = 0x00010101;
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

static int call_query(unsigned char *result, u32 *result_size)
{
    unsigned long function = query_address;
    register unsigned long argument5 asm("r8") = (unsigned long)result_size;

    asm volatile("call *%%rax"
                 : "+a"(function)
                 : "D"(rndis_device), "S"(netvsc_device), "d"(oid),
                   "c"(result), "r"(argument5)
                 : "r9", "r10", "r11", "cc", "memory");
    return (int)function;
}

static int arm_set(const char *value, const struct kernel_param *parameter)
{
    static unsigned char result[4096];
    unsigned int requested;
    u32 result_size = sizeof(result);
    unsigned int index;
    int error;

    if (kstrtouint(value, 0, &requested) || !requested)
        return -EINVAL;
    if (!query_address || !rndis_device || !netvsc_device)
        return -EINVAL;
    arm = requested;
    error = call_query(result, &result_size);
    pr_info("rndis_oid_census oid=%#x ret=%d size=%u count=%u\n",
            oid, error, result_size, result_size / sizeof(u32));
    if (!error && oid == 0x00010101) {
        for (index = 0; index < result_size / sizeof(u32); index++)
            pr_info("rndis_oid value=%#010x\n", ((u32 *)result)[index]);
    } else {
        pr_info("rndis_oid_result head=%*phN\n", min_t(u32, result_size, 64), result);
    }
    return 0;
}

static const struct kernel_param_ops arm_ops = {
    .set = arm_set,
    .get = param_get_int,
};

module_param_cb(query_address, &ulong_ops, &query_address, 0000);
module_param_cb(rndis_device, &ulong_ops, &rndis_device, 0000);
module_param_cb(netvsc_device, &ulong_ops, &netvsc_device, 0000);
module_param_cb(oid, &uint_ops, &oid, 0000);
module_param_cb(arm, &arm_ops, &arm, 0600);

static int __init rndis_oid_census_init(void)
{
    return 0;
}

static void __exit rndis_oid_census_exit(void)
{
}

module_init(rndis_oid_census_init);
module_exit(rndis_oid_census_exit);
MODULE_LICENSE("GPL");
