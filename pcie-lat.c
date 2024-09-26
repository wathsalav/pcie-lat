/*
 * Copyright (C) 2014 by the author(s)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * =============================================================================
 *
 * Author(s):
 *   Andre Richter, andre.o.richter @t gmail_com
 *
 * Credits:
 *   Chris Wright: Linux pci-stub driver.
 *
 *   Gabriele Paoloni: "How to Benchmark Code Execution Times on
 *                     Intel IA-32 and IA-64 Instruction Set Architectures"
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/smp.h>
#include <linux/cpufreq.h>

#ifdef __aarch64__
#include <linux/perf/arm_pmu.h>
#endif //__aarach64__

#define DRIVER_NAME "pcie-lat"
#define LOOPS_UPPER_LIMIT	10000000
#define LOOPS_DEFAULT		100000
#define OVERHEAD_MEASURE_LOOPS	1000000

static char ids[1024] __initdata;
static u32 xtsc_khz;

module_param_string(ids, ids, sizeof(ids), 0);
MODULE_PARM_DESC(ids, "Initial PCI IDs to add to the driver, format is "
                 "\"vendor:device[:subvendor[:subdevice[:class[:class_mask]]]]\""
		 " and multiple comma separated entries can be specified");

static unsigned int tsc_overhead;

struct result_data_t {
	u64 tsc_start;
	u64 tsc_diff;
};

/* BAR info*/
struct bar_t {
	int len;
	void __iomem *addr;
};

struct options_t {
	unsigned int loops;
	unsigned char target_bar;
	u32 cpu_id;
	u32 bar_offset;
};

struct pcielat_priv {
	struct pci_dev *pdev;
	struct bar_t bar[6];
	dev_t dev_num;
	struct cdev cdev;
	struct result_data_t *result_data;
	unsigned int cur_resdata_size_in_bytes;
	struct options_t options;
};

/*
 * Character device data and callbacks
 */
static struct class *pcielat_class;

static int dev_open(struct inode *inode, struct file *file)
{
	struct pcielat_priv *priv = container_of(inode->i_cdev,
						 struct pcielat_priv, cdev);
	file->private_data = priv;

	return 0;
};

static ssize_t dev_read(struct file *file, char __user *buf,
			size_t count, loff_t *ppos)
{
	struct pcielat_priv *priv = file->private_data;

	/* If offset is behind string length, return nothing */
	if (*ppos >= priv->cur_resdata_size_in_bytes)
		return 0;

	/* If user wants to read more than is available, return what's there */
	if (*ppos + count > priv->cur_resdata_size_in_bytes)
		count = priv->cur_resdata_size_in_bytes - *ppos;

	if (copy_to_user(buf, (void *)priv->result_data + *ppos, count) != 0)
		return -EFAULT;

	*ppos += count;
	return count;
}

static const struct file_operations fops = {
	.owner	 = THIS_MODULE,
	.open	 = dev_open,
	.read	 = dev_read
};

/*
 * PCI device callbacks
 */
static int pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int err = 0, i;
	int mem_bars;
	struct pcielat_priv *priv;
	struct device *dev;

	priv = kzalloc(sizeof(struct pcielat_priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	err = pci_enable_device_mem(pdev);
	if (err)
		goto failure_pci_enable;

	/* Request only the BARs that contain memory regions */
	mem_bars = pci_select_bars(pdev, IORESOURCE_MEM);
	err = pci_request_selected_regions(pdev, mem_bars, DRIVER_NAME);
	if (err)
		goto failure_pci_regions;

	/* Memory Map BARs for MMIO */
	for (i = 0; i < 6; i++) {
		if (mem_bars & (1 << i)) {
			priv->bar[i].addr = ioremap(pci_resource_start(pdev, i),
						    pci_resource_len(pdev, i));

			if (IS_ERR(priv->bar[i].addr)) {
				err = PTR_ERR(priv->bar[i].addr);
				break;
			} else
				priv->bar[i].len = (int)pci_resource_len(pdev, i);
		} else {
			priv->bar[i].addr = NULL;
			priv->bar[i].len = -1;
		}
	}

	if (err) {
		for (i--; i >= 0; i--)
			if (priv->bar[i].len)
				iounmap(priv->bar[i].addr);
		goto failure_ioremap;
	}

	/* Get device number range */
	err = alloc_chrdev_region(&priv->dev_num, 0, 1, DRIVER_NAME);
	if (err)
		goto failure_alloc_chrdev_region;

	/* connect cdev with file operations */
	cdev_init(&priv->cdev, &fops);
	priv->cdev.owner = THIS_MODULE;

	/* add major/min range to cdev */
	err = cdev_add(&priv->cdev, priv->dev_num, 1);
	if (err)
		goto failure_cdev_add;

	dev = device_create(pcielat_class, &pdev->dev, priv->dev_num, NULL,
			    "%02x:%02x.%x", pdev->bus->number,
			    PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));

	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto failure_device_create;
	}

	dev_set_drvdata(dev, priv);
	pci_set_drvdata(pdev, priv);
	dev_info(&pdev->dev, "claimed by " DRIVER_NAME "\n");

	return 0;

failure_device_create:
	cdev_del(&priv->cdev);

failure_cdev_add:
	unregister_chrdev_region(priv->dev_num, 0);

failure_alloc_chrdev_region:
	for (i = 0; i < 6; i++)
		if (priv->bar[i].len)
			iounmap(priv->bar[i].addr);

failure_ioremap:
	pci_release_selected_regions(pdev,
				     pci_select_bars(pdev, IORESOURCE_MEM));

failure_pci_regions:
	pci_disable_device(pdev);

failure_pci_enable:
	kfree(priv);

	return err;
}

static void pci_remove(struct pci_dev *pdev)
{
	int i;
	struct pcielat_priv *priv = pci_get_drvdata(pdev);

	device_destroy(pcielat_class, priv->dev_num);

	cdev_del(&priv->cdev);

	unregister_chrdev_region(priv->dev_num, 0);

	for (i = 0; i < 6; i++)
		if (priv->bar[i].len)
			iounmap(priv->bar[i].addr);

	pci_release_selected_regions(pdev,
				     pci_select_bars(pdev, IORESOURCE_MEM));
	pci_disable_device(pdev);

	if (!priv->result_data)
		vfree(priv->result_data);

	kfree(priv);
}

static struct pci_driver pcielat_driver = {
	.name		= DRIVER_NAME,
	.id_table	= NULL,	/* only dynamic id's */
	.probe		= pci_probe,
	.remove         = pci_remove,
};

/*
 * The following codeimplements PCIe latency measurement by
 * benchmarking the time it takes to complete a readl() to a user
 * specified BAR and offset within this BAR.
 *
 * Time is measured via the TSC and implemented according to
 * "G. Paoloni, How to benchmark code execution times on
 * intel ia-32 and ia-64 instruction set architectures,
 * White paper, Intel Corporation." for x86 architecture.
 *
 * Time is measured via the PMU cycle counter for aarch64
 * architecture.
 */

#ifdef __aarch64__
#define get_pmc_tsc(tsc)				\
	asm volatile("isb" : : : "memory"); 		\
        asm volatile("mrs %0, pmccntr_el0" : "=r" (tsc));
#define get_tsc(tsc)					\
	asm volatile("isb" : : : "memory"); 		\
        asm volatile("mrs %0, cntvct_el0" : "=r" (tsc));
#define get_tsc_freq(freq)				\
	asm volatile("mrs %0, cntfrq_el0" : "=r" (freq));
#else
#define get_tsc_top(high, low)				\
	asm volatile ("cpuid         \n\t"		\
		      "rdtsc         \n\t"		\
		      "mov %%edx, %0 \n\t"		\
		      "mov %%eax, %1 \n\t"		\
		      :"=r" (high), "=r"(low)		\
		      :					\
		      :"rax", "rbx", "rcx", "rdx");
#define get_tsc_bottom(high, low)			\
	asm volatile ("rdtscp \n\t"			\
		      "mov %%edx, %0 \n\t"		\
		      "mov %%eax, %1 \n\t"		\
		      "cpuid \n\t"			\
		      :"=r" (high), "=r"(low)		\
		      :					\
		      :"rax", "rbx", "rcx", "rdx");
#endif

#ifdef __aarch64__
static void start_pmu_cycle_counter(void)
{
	u64 cval;
	cval = read_sysreg(pmcr_el0);
	pr_info("pmcr_el0: %llx\n", cval);
	cval |= 0x01;
	write_sysreg(cval, pmcr_el0);
	cval = read_sysreg(pmcntenset_el0);
	pr_info("pmcntenset_el0: %llx\n", cval);
	cval |= 0x01 << 31;
	write_sysreg(cval, pmcntenset_el0);
}

static void stop_pmu_cycle_counter(void *arg)
{
	u64 cval;
	cval = read_sysreg(pmcr_el0);
	cval &= ~0x01;
	write_sysreg(cval, pmcr_el0);
	cval = read_sysreg(pmcntenset_el0);
	cval &= ~(0x01 << 31);
	write_sysreg(cval, pmcntenset_el0);
}
#endif //__aarch64__

static unsigned int __init get_tsc_overhead(void)
{
	u64 sum;
	unsigned int i;

#if defined(__x86_64__) || defined(__i386__)
	u32 cpu_id;
	u32 tsc_high_before, tsc_high_after;
	u32 tsc_low_before, tsc_low_after;
	cpu_id = get_cpu();
#elif defined(__aarch64__)
	u64 tsc_start, tsc_end;
#else
#error Unsupported architecture
#endif //__x86_64__ || __i386__


#if defined(__x86_64__) || defined(__i386__)
	get_tsc_top(tsc_high_before, tsc_low_before);
	get_tsc_bottom(tsc_high_after, tsc_low_after);
	get_tsc_top(tsc_high_before, tsc_low_before);
	get_tsc_bottom(tsc_high_after, tsc_low_after);
#elif defined(__aarch64__)
        get_pmc_tsc(tsc_start);
        get_pmc_tsc(tsc_end);
        get_pmc_tsc(tsc_start);
        get_pmc_tsc(tsc_end);
#else
#error Unsupported architecture
#endif //__x86_64__ || __i386__

	sum = 0;
	for (i = 0; i < OVERHEAD_MEASURE_LOOPS; i++) {
#if defined(__x86_64__) || defined(__i386__)
		get_tsc_top(tsc_high_before, tsc_low_before);
		get_tsc_bottom(tsc_high_after, tsc_low_after);
		/* Calculate delta; lower 32 Bit should be enough here */
	        sum += tsc_low_after - tsc_low_before;
#elif defined(__aarch64__)
	        get_pmc_tsc(tsc_start);
	        get_pmc_tsc(tsc_end);
	        sum += tsc_end - tsc_start;
#else
#error Unsupported architecture
#endif //__x86_64__ || __i386__
	}

#if defined(__x86_64__) || defined(__i386__)
	put_cpu();
#endif //__x86_64__ || __i386__

#ifdef __aarch64__
#endif //__aarch64__
	return sum / OVERHEAD_MEASURE_LOOPS;
}


static void do_benchmark(void *arg)
{
	unsigned long flags;
	u64 tsc_start, tsc_end, tsc_diff;
	unsigned int i;
	struct pcielat_priv *priv = (struct pcielat_priv*)arg;
	void __iomem *pcie_addr = priv->bar[priv->options.target_bar].addr + priv->options.bar_offset;
	
#if defined(__x86_64__) || defined(__i386__)
	u32 tsc_high_before, tsc_high_after;
	u32 tsc_low_before, tsc_low_after;
#elif defined(__aarch64__)
	start_pmu_cycle_counter();
	preempt_disable();
	raw_local_irq_save(flags);
	tsc_overhead = get_tsc_overhead();
	raw_local_irq_restore(flags);
	preempt_enable();
#else
#error Unsupported architecture
#endif //__x86_64__ || __i386__
	/*
	 * "Warmup" of the benchmarking code.
	 * This will put instructions into cache.
	 */
#if defined(__x86_64__) || defined(__i386__)
	get_tsc_top(tsc_high_before, tsc_low_before);
	get_tsc_bottom(tsc_high_after, tsc_low_after);
	get_tsc_top(tsc_high_before, tsc_low_before);
	get_tsc_bottom(tsc_high_after, tsc_low_after);
#elif defined(__aarch64__)
	get_pmc_tsc(tsc_start);
	get_pmc_tsc(tsc_end);
	get_pmc_tsc(tsc_start);
	get_pmc_tsc(tsc_end);
#else
#error Unsupported architecture
#endif //__x86_64__ || __i386__

        /* Main latency measurement loop */
	for (i = 0; i < priv->options.loops; i++) {

		preempt_disable();
		raw_local_irq_save(flags);
#if defined(__x86_64__) || defined(__i386__)
		get_tsc_top(tsc_high_before, tsc_low_before);
#elif defined(__aarch64__)
		get_pmc_tsc(tsc_start);
#else
#error Unsupported architecture
#endif //__x86_64__ || __i386__

		/*** Function to measure execution time for ***/
		//readl(priv->bar[priv->options.target_bar].addr + priv->options.bar_offset);
		readl(pcie_addr);
		/***************************************/

#if defined(__x86_64__) || defined(__i386__)
		get_tsc_bottom(tsc_high_after, tsc_low_after);
#elif defined(__aarch64__)
		get_pmc_tsc(tsc_end);
#else
#error Unsupported architecture
#endif //__x86_64__ || __i386__

		raw_local_irq_restore(flags);
		preempt_enable();

		/* Calculate delta */
#if defined(__x86_64__) || defined(__i386__)
		tsc_start = ((u64) tsc_high_before << 32) | tsc_low_before;
		tsc_end = ((u64) tsc_high_after << 32) | tsc_low_after;
#endif //__x86_64__ || __i386__
	        tsc_diff = tsc_end - tsc_start;

		priv->result_data[i].tsc_start  = tsc_start;
		priv->result_data[i].tsc_diff   = tsc_diff;

		/* Short delay to ensure we don't DoS the device */
		ndelay(800);
	}
#ifdef __aarch64__
	stop_pmu_cycle_counter(&(priv->options.cpu_id));
#endif //__aarch64__
}

/*
 * sysfs attributes
 */
static ssize_t pcielat_tsc_freq_show(struct device *dev,
				     struct device_attribute *attr,
				     char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%llu\n", xtsc_khz * 1000LLU);
}

static ssize_t pcielat_tsc_overhead_show(struct device *dev,
					 struct device_attribute *attr,
					 char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", tsc_overhead);
}

static ssize_t pcielat_loops_show(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	struct pcielat_priv *priv = dev_get_drvdata(dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 priv->options.loops);
}

static ssize_t pcielat_loops_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct pcielat_priv *priv = dev_get_drvdata(dev);
	unsigned int loops;
	int err;

	sscanf(buf, "%u", &loops);

	/* sanity check */
	if ((loops == 0) || (loops > LOOPS_UPPER_LIMIT))
		return -EINVAL;

	/* alloc new mem only if loop count changed */
	if (loops != priv->options.loops) {
		if (!priv->result_data) {
			vfree(priv->result_data);
			priv->cur_resdata_size_in_bytes = 0;
		}

		priv->options.loops = loops;
		priv->result_data = vmalloc(priv->options.loops * sizeof(struct result_data_t));

		if (IS_ERR(priv->result_data))
		{
			err = PTR_ERR(priv->result_data);
			return -ENOMEM;
		}

		priv->cur_resdata_size_in_bytes = priv->options.loops * sizeof(struct result_data_t);
	}

	return count;
}

static ssize_t pcielat_target_bar_show(struct device *dev,
				       struct device_attribute *attr, char *buf)
{
	struct pcielat_priv *priv = dev_get_drvdata(dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n", priv->options.target_bar);
}

static ssize_t pcielat_target_bar_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct pcielat_priv *priv = dev_get_drvdata(dev);
	unsigned short bar;

	sscanf(buf, "%hx", &bar);

	if (bar <= 5)
		priv->options.target_bar = bar;

	return count;
}

static ssize_t pcielat_bar_offset_show(struct device *dev,
				       struct device_attribute *attr, char *buf)
{
	struct pcielat_priv *priv = dev_get_drvdata(dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n", priv->options.bar_offset);
}

static ssize_t pcielat_bar_offset_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct pcielat_priv *priv = dev_get_drvdata(dev);
	unsigned int offset;

	sscanf(buf, "%u", &offset);

	if (!(offset % 4)) /* 32bit aligned */
		priv->options.bar_offset = offset;

	return count;
}

static ssize_t pcielat_core_show(struct device *dev,
				       struct device_attribute *attr, char *buf)
{
	struct pcielat_priv *priv = dev_get_drvdata(dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n", priv->options.cpu_id);
}

static ssize_t pcielat_core_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct pcielat_priv *priv = dev_get_drvdata(dev);

	sscanf(buf, "%u", &priv->options.cpu_id);

	return count;
}

static ssize_t pcielat_measure_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct pcielat_priv *priv = dev_get_drvdata(dev);
	int target_bar_len;
	u32 _xtsc_khz;

	if (priv->options.loops == 0) {
		dev_info(dev, "Loop count for measurements not set!\n");
		return -EINVAL;
	}

	target_bar_len = priv->bar[priv->options.target_bar].len;

	if (target_bar_len < 0) {
		dev_info(dev, "Target BAR not mmaped!\n");
		return -EINVAL;
	}

	/* cancel if offset is to high */
	if (priv->options.bar_offset > (target_bar_len - 4)) {
		dev_info(dev, "target_bar_len: %d, offset: %d; range failure!\n",
			 target_bar_len,
			 priv->options.bar_offset);
		return -EINVAL;
	}

	_xtsc_khz = cpufreq_get(priv->options.cpu_id);
	/* there is no observer for xtsc_khz below this point, we don't want
	 * run do_benchmark on the target core before we set xtsc_khz.
	 */
	xtsc_khz = smp_load_acquire(&_xtsc_khz);

	if ((smp_call_function_single(priv->options.cpu_id, do_benchmark, priv, true)) < 0) {
		pr_err("Failed launching do_benchmark() on core %u\n", priv->options.cpu_id);
		return -EINVAL;
	}

	dev_info(dev, "Benchmark done with %d measure_loops for BAR%d, offset 0x%08x on CPU %d\n",
		 priv->options.loops,
		 priv->options.target_bar,
		 priv->options.bar_offset,
		 priv->options.cpu_id);

	return count;
}

static DEVICE_ATTR_RO(pcielat_tsc_freq);
static DEVICE_ATTR_RO(pcielat_tsc_overhead);
static DEVICE_ATTR_RW(pcielat_loops);
static DEVICE_ATTR_RW(pcielat_target_bar);
static DEVICE_ATTR_RW(pcielat_bar_offset);
static DEVICE_ATTR_WO(pcielat_measure);
static DEVICE_ATTR_RW(pcielat_core);

static struct attribute *pcielat_attrs[] = {
	&dev_attr_pcielat_tsc_freq.attr,
	&dev_attr_pcielat_tsc_overhead.attr,
	&dev_attr_pcielat_loops.attr,
	&dev_attr_pcielat_target_bar.attr,
	&dev_attr_pcielat_bar_offset.attr,
	&dev_attr_pcielat_measure.attr,
	&dev_attr_pcielat_core.attr,
	NULL,
};

ATTRIBUTE_GROUPS(pcielat);

/*
 * Module init functions
 */
static char *pci_char_devnode(struct device *dev, umode_t *mode)
{
	struct pci_dev *pdev = to_pci_dev(dev->parent);
	return kasprintf(GFP_KERNEL, DRIVER_NAME "/%02x:%02x.%x",
			 pdev->bus->number,
			 PCI_SLOT(pdev->devfn),
			 PCI_FUNC(pdev->devfn));
}

#ifndef __aarch64__
static int check_tsc_invariant(void)
{
	uint32_t edx;

	/* Check for RDTSCP instruction */
	asm volatile("cpuid"
		     : "=d" (edx)
		     : "a" (0x80000001)
		     : "rbx", "rcx"
		);

	if (edx | 0x8000000) {
		pr_info(DRIVER_NAME ": CPUID.80000001:EDX[bit 27] == 1, "
			"RDTSCP instruction available\n");
	}
	else {
		pr_info(DRIVER_NAME ": CPUID.80000001:EDX[bit 27] == 0, "
			"RDTSCP instruction not available\n"
			"Exiting here\n");
		return 0;
	}

	/* Check for TSC invariant bit */
	asm volatile("cpuid"
		     : "=d" (edx)
		     : "a" (0x80000007)
		     : "rbx", "rcx"
		);

	if (edx | 0x100) {
		pr_info(DRIVER_NAME ": CPUID.80000007:EDX[bit 8] == 1, "
			"TSC is invariant\n");
		return 1;
	}
	else {
		pr_info(DRIVER_NAME ": CPUID.80000007:EDX[bit 8] == 0, "
			"TSC is not invariant\n"
			"Exiting here\n");
		return 0;
	}
}
#endif //__aarch64__

static int __init pci_init(void)
{
	int err;
	char *p, *id;
	/* Initialize xtsc_khz in an arch specific manner */
#if defined(__x86_64__) || defined(__i386__)
	xtsc_khz = tsc_khz;
	/* Check if host is capable of benchmarking with TSC */
	if (!check_tsc_invariant())
		return  -EPERM;
	/* Print TSC frequency as measured from the kernel boot routines */
	pr_info(DRIVER_NAME ": TSC frequency: %d kHz\n", xtsc_khz);
	tsc_overhead = get_tsc_overhead();
	/* calculate TSC overhead of the system */
	pr_info(DRIVER_NAME ": Overhead of TSC measurement: %d cycles\n", tsc_overhead);
#endif ///__x86_64__ || __i386__



	pcielat_class = class_create(THIS_MODULE, DRIVER_NAME);
	if (IS_ERR(pcielat_class)) {
		err = PTR_ERR(pcielat_class);
		return err;
	}
	pcielat_class->devnode = pci_char_devnode;
	pcielat_class->dev_groups = pcielat_groups;

	err = pci_register_driver(&pcielat_driver);
	if (err)
		goto failure_register_driver;

	/* no ids passed actually */
	if (ids[0] == '\0')
		return 0;

	/* add ids specified in the module parameter */
	p = ids;
	while ((id = strsep(&p, ","))) {
		unsigned int vendor, device, subvendor = PCI_ANY_ID,
			subdevice = PCI_ANY_ID, class=0, class_mask=0;
		int fields;

		if (!strlen(id))
			continue;

		fields = sscanf(id, "%x:%x:%x:%x:%x:%x",
				&vendor, &device, &subvendor, &subdevice,
				&class, &class_mask);

		if (fields < 2) {
			pr_warn(DRIVER_NAME ": invalid id string \"%s\"\n", id);
			continue;
		}

		pr_info(DRIVER_NAME ": add %04X:%04X sub=%04X:%04X cls=%08X/%08X\n",
			vendor, device, subvendor, subdevice, class, class_mask);

		err = pci_add_dynid(&pcielat_driver, vendor, device,
				    subvendor, subdevice, class, class_mask, 0);
		if (err)
			pr_warn(DRIVER_NAME ": failed to add dynamic id (%d)\n", err);
	}

	return 0;

failure_register_driver:
	pr_err("FAILED\n");
	class_destroy(pcielat_class);

	return err;
}

static void __exit pci_exit(void)
{
	pci_unregister_driver(&pcielat_driver);
	class_destroy(pcielat_class);
}

module_init(pci_init);
module_exit(pci_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Generic x86_64 PCIe latency measurement module");
MODULE_AUTHOR("Andre Richter <andre.o.richter@gmail.com>,"
	      "Institute for Integrated Systems,"
	      "Technische Universität München");
