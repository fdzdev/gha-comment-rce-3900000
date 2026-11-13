#include <linux/gfp.h>
#include <linux/hyperv.h>
#include <linux/module.h>
#include <asm/hyperv-tlfs.h>
#include <asm/mshyperv.h>

struct get_vp_input_one {
	struct {
		u64 partition_id;
		u32 vp_index;
		u8 input_vtl;
		u8 padding[3];
	} header;
	struct {
		u32 name;
		u32 reserved;
	} element;
} __packed;

static u64 read_vp_register(void *input_page, void *output_page, u64 partition_id,
			    u32 vp_index, u32 register_name)
{
	struct get_vp_input_one *input = input_page;

	memset(input_page, 0, PAGE_SIZE);
	memset(output_page, 0, PAGE_SIZE);
	input->header.partition_id = partition_id;
	input->header.vp_index = vp_index;
	input->element.name = register_name;
	return hv_do_hypercall(HVCALL_GET_VP_REGISTERS |
			       HV_HYPERCALL_REP_COMP_1, input_page, output_page);
}

static void print_probe(void *input_page, void *output_page, const char *label,
			u64 partition_id, u32 vp_index)
{
	u64 status = read_vp_register(input_page, output_page, partition_id,
				      vp_index, HV_REGISTER_VP_INDEX);
	u64 low = *(u64 *)output_page;
	u64 high = *(u64 *)(output_page + sizeof(u64));

	pr_info("HV_PARTITION_PROBE target=%s partition=%#llx vp=%#x status=%#llx code=%llu rep=%llu low=%#llx high=%#llx\n",
		label, partition_id, vp_index, status,
		status & HV_HYPERCALL_RESULT_MASK,
		(status & HV_HYPERCALL_REP_COMP_MASK) >> HV_HYPERCALL_REP_COMP_OFFSET,
		low, high);
}

static int __init hv_partition_probe_init(void)
{
	void *input_page = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	void *output_page = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	u64 status;
	u64 self;

	if (!input_page || !output_page)
		return -ENOMEM;
	status = hv_do_hypercall(HVCALL_GET_PARTITION_ID, NULL, output_page);
	self = *(u64 *)output_page;
	pr_info("HV_PARTITION_PROBE get_partition_id status=%#llx code=%llu self=%#llx\n",
		status, status & HV_HYPERCALL_RESULT_MASK, self);
	print_probe(input_page, output_page, "self-sentinel", HV_PARTITION_ID_SELF,
		    HV_VP_INDEX_SELF);
	print_probe(input_page, output_page, "self-explicit", self, 0);
	print_probe(input_page, output_page, "partition-zero", 0, 0);
	print_probe(input_page, output_page, "partition-one", 1, 0);
	print_probe(input_page, output_page, "neighbor", self ^ 1, 0);
	print_probe(input_page, output_page, "random", 0x3900000, 0);
	free_page((unsigned long)input_page);
	free_page((unsigned long)output_page);
	return 0;
}

static void __exit hv_partition_probe_exit(void) {}

module_init(hv_partition_probe_init);
module_exit(hv_partition_probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bounded Hyper-V partition-authority discriminator");
