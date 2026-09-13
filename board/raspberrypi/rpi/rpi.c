// SPDX-License-Identifier: GPL-2.0
/*
 * (C) Copyright 2012-2016 Stephen Warren
 */

#include <common.h>
#include <config.h>
#include <dm.h>
#include <env.h>
#include <efi_loader.h>
#include <fdt_support.h>
#include <fdt_simplefb.h>
#include <hang.h>
#include <init.h>
#include <memalign.h>
#include <mmc.h>
#include <asm/gpio.h>
#include <asm/arch/mbox.h>
#include <asm/arch/msg.h>
#include <asm/arch/sdhci.h>
#include <asm/global_data.h>
#include <dm/platform_data/serial_bcm283x_mu.h>
#include <broadcom/bcm_board_types.h>

#ifdef CONFIG_ARM64
#include <asm/armv8/mmu.h>
#endif
#include <watchdog.h>
#include <dm/pinctrl.h>

DECLARE_GLOBAL_DATA_PTR;

/* Assigned in lowlevel_init.S
 * Push the variable into the .data section so that it
 * does not get cleared later.
 */
unsigned long __section(".data") fw_dtb_pointer;

/* TODO(sjg@chromium.org): Move these to the msg.c file */
struct msg_get_arm_mem {
	struct bcm2835_mbox_hdr hdr;
	struct bcm2835_mbox_tag_get_arm_mem get_arm_mem;
	u32 end_tag;
};

struct msg_get_board_rev {
	struct bcm2835_mbox_hdr hdr;
	struct bcm2835_mbox_tag_get_board_rev get_board_rev;
	u32 end_tag;
};

struct msg_get_board_serial {
	struct bcm2835_mbox_hdr hdr;
	struct bcm2835_mbox_tag_get_board_serial get_board_serial;
	u32 end_tag;
};

struct msg_get_mac_address {
	struct bcm2835_mbox_hdr hdr;
	struct bcm2835_mbox_tag_get_mac_address get_mac_address;
	u32 end_tag;
};

struct msg_get_clock_rate {
	struct bcm2835_mbox_hdr hdr;
	struct bcm2835_mbox_tag_get_clock_rate get_clock_rate;
	u32 end_tag;
};

#ifdef CONFIG_ARM64
#define DTB_DIR "broadcom/"
#else
#define DTB_DIR ""
#endif

/*
 * https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#raspberry-pi-revision-codes
 */
struct rpi_model {
	const char *name;
	const char *fdtfile;
	bool has_onboard_eth;
};

static const struct rpi_model rpi_model_unknown = {
	"Unknown model",
	DTB_DIR "bcm283x-rpi-other.dtb",
	false,
};

static const struct rpi_model rpi_models_new_scheme[] = {
	[0x0] = {
		"Model A",
		DTB_DIR "bcm2835-rpi-a.dtb",
		false,
	},
	[0x1] = {
		"Model B",
		DTB_DIR "bcm2835-rpi-b.dtb",
		true,
	},
	[0x2] = {
		"Model A+",
		DTB_DIR "bcm2835-rpi-a-plus.dtb",
		false,
	},
	[0x3] = {
		"Model B+",
		DTB_DIR "bcm2835-rpi-b-plus.dtb",
		true,
	},
	[0x4] = {
		"2 Model B",
		DTB_DIR "bcm2836-rpi-2-b.dtb",
		true,
	},
	[0x6] = {
		"Compute Module",
		DTB_DIR "bcm2835-rpi-cm.dtb",
		false,
	},
	[0x8] = {
		"3 Model B",
		DTB_DIR "bcm2837-rpi-3-b.dtb",
		true,
	},
	[0x9] = {
		"Zero",
		DTB_DIR "bcm2835-rpi-zero.dtb",
		false,
	},
	[0xA] = {
		"Compute Module 3",
		DTB_DIR "bcm2837-rpi-cm3.dtb",
		false,
	},
	[0xC] = {
		"Zero W",
		DTB_DIR "bcm2835-rpi-zero-w.dtb",
		false,
	},
	[0xD] = {
		"3 Model B+",
		DTB_DIR "bcm2837-rpi-3-b-plus.dtb",
		true,
	},
	[0xE] = {
		"3 Model A+",
		DTB_DIR "bcm2837-rpi-3-a-plus.dtb",
		false,
	},
	[0x10] = {
		"Compute Module 3+",
		DTB_DIR "bcm2837-rpi-cm3.dtb",
		false,
	},
	[0x11] = {
		"4 Model B",
		DTB_DIR "bcm2711-rpi-4-b.dtb",
		true,
	},
	[0x12] = {
		"Zero 2 W",
		DTB_DIR "bcm2837-rpi-zero-2-w.dtb",
		false,
	},
	[0x13] = {
		"400",
		DTB_DIR "bcm2711-rpi-400.dtb",
		true,
	},
	[0x14] = {
		"Compute Module 4",
		DTB_DIR "bcm2711-rpi-cm4.dtb",
		true,
	},
	[0x17] = {
		"5 Model B",
		DTB_DIR "bcm2712-rpi-5-b.dtb",
		true,
	},
};

static const struct rpi_model rpi_models_old_scheme[] = {
	[0x2] = {
		"Model B",
		DTB_DIR "bcm2835-rpi-b.dtb",
		true,
	},
	[0x3] = {
		"Model B",
		DTB_DIR "bcm2835-rpi-b.dtb",
		true,
	},
	[0x4] = {
		"Model B rev2",
		DTB_DIR "bcm2835-rpi-b-rev2.dtb",
		true,
	},
	[0x5] = {
		"Model B rev2",
		DTB_DIR "bcm2835-rpi-b-rev2.dtb",
		true,
	},
	[0x6] = {
		"Model B rev2",
		DTB_DIR "bcm2835-rpi-b-rev2.dtb",
		true,
	},
	[0x7] = {
		"Model A",
		DTB_DIR "bcm2835-rpi-a.dtb",
		false,
	},
	[0x8] = {
		"Model A",
		DTB_DIR "bcm2835-rpi-a.dtb",
		false,
	},
	[0x9] = {
		"Model A",
		DTB_DIR "bcm2835-rpi-a.dtb",
		false,
	},
	[0xd] = {
		"Model B rev2",
		DTB_DIR "bcm2835-rpi-b-rev2.dtb",
		true,
	},
	[0xe] = {
		"Model B rev2",
		DTB_DIR "bcm2835-rpi-b-rev2.dtb",
		true,
	},
	[0xf] = {
		"Model B rev2",
		DTB_DIR "bcm2835-rpi-b-rev2.dtb",
		true,
	},
	[0x10] = {
		"Model B+",
		DTB_DIR "bcm2835-rpi-b-plus.dtb",
		true,
	},
	[0x11] = {
		"Compute Module",
		DTB_DIR "bcm2835-rpi-cm.dtb",
		false,
	},
	[0x12] = {
		"Model A+",
		DTB_DIR "bcm2835-rpi-a-plus.dtb",
		false,
	},
	[0x13] = {
		"Model B+",
		DTB_DIR "bcm2835-rpi-b-plus.dtb",
		true,
	},
	[0x14] = {
		"Compute Module",
		DTB_DIR "bcm2835-rpi-cm.dtb",
		false,
	},
	[0x15] = {
		"Model A+",
		DTB_DIR "bcm2835-rpi-a-plus.dtb",
		false,
	},
};

static uint32_t revision;
static uint32_t rev_scheme;
static uint32_t rev_type;
static const struct rpi_model *model;

int dram_init(void)
{
	ALLOC_CACHE_ALIGN_BUFFER(struct msg_get_arm_mem, msg, 1);
	int ret;

	BCM2835_MBOX_INIT_HDR(msg);
	BCM2835_MBOX_INIT_TAG(&msg->get_arm_mem, GET_ARM_MEMORY);

	ret = bcm2835_mbox_call_prop(BCM2835_MBOX_PROP_CHAN, &msg->hdr);
	if (ret) {
		printf("bcm2835: Could not query ARM memory size\n");
		return -1;
	}

	gd->ram_size = msg->get_arm_mem.body.resp.mem_size;

	/*
	 * In some configurations the memory size returned by VideoCore
	 * is not aligned to the section size, what is mandatory for
	 * the u-boot's memory setup.
	 */
	gd->ram_size &= ~MMU_SECTION_SIZE;

	return 0;
}

#ifdef CONFIG_OF_BOARD
int dram_init_banksize(void)
{
	int ret;

	ret = fdtdec_setup_memory_banksize();
	if (ret)
		return ret;

	return fdtdec_setup_mem_size_base();
}
#endif

static void set_fdtfile(void)
{
	const char *fdtfile;

	if (env_get("fdtfile"))
		return;

	fdtfile = model->fdtfile;
	env_set("fdtfile", fdtfile);
}

/*
 * If the firmware provided a valid FDT at boot time, let's expose it in
 * ${fdt_addr} so it may be passed unmodified to the kernel.
 */
static void set_fdt_addr(void)
{
	if (env_get("fdt_addr"))
		return;

	if (fdt_magic(fw_dtb_pointer) != FDT_MAGIC)
		return;

	env_set_hex("fdt_addr", fw_dtb_pointer);
}

/*
 * Prevent relocation from stomping on a firmware provided FDT blob.
 */
phys_addr_t board_get_usable_ram_top(phys_size_t total_size)
{
	if ((gd->ram_top - fw_dtb_pointer) > SZ_64M)
		return gd->ram_top;
	return fw_dtb_pointer & ~0xffff;
}

static void set_usbethaddr(void)
{
	ALLOC_CACHE_ALIGN_BUFFER(struct msg_get_mac_address, msg, 1);
	int ret;

	if (!model->has_onboard_eth)
		return;

	if (env_get("usbethaddr"))
		return;

	BCM2835_MBOX_INIT_HDR(msg);
	BCM2835_MBOX_INIT_TAG(&msg->get_mac_address, GET_MAC_ADDRESS);

	ret = bcm2835_mbox_call_prop(BCM2835_MBOX_PROP_CHAN, &msg->hdr);
	if (ret) {
		printf("bcm2835: Could not query MAC address\n");
		/* Ignore error; not critical */
		return;
	}

	eth_env_set_enetaddr("usbethaddr", msg->get_mac_address.body.resp.mac);

	if (!env_get("ethaddr"))
		env_set("ethaddr", env_get("usbethaddr"));

	return;
}

#ifdef CONFIG_ENV_VARS_UBOOT_RUNTIME_CONFIG
static void set_board_info(void)
{
	char s[11];

	snprintf(s, sizeof(s), "0x%X", revision);
	env_set("board_revision", s);
	snprintf(s, sizeof(s), "%d", rev_scheme);
	env_set("board_rev_scheme", s);
	/* Can't rename this to board_rev_type since it's an ABI for scripts */
	snprintf(s, sizeof(s), "0x%X", rev_type);
	env_set("board_rev", s);
	env_set("board_name", model->name);
}
#endif /* CONFIG_ENV_VARS_UBOOT_RUNTIME_CONFIG */

static void set_serial_number(void)
{
	ALLOC_CACHE_ALIGN_BUFFER(struct msg_get_board_serial, msg, 1);
	int ret;
	char serial_string[17] = { 0 };

	if (env_get("serial#"))
		return;

	BCM2835_MBOX_INIT_HDR(msg);
	BCM2835_MBOX_INIT_TAG_NO_REQ(&msg->get_board_serial, GET_BOARD_SERIAL);

	ret = bcm2835_mbox_call_prop(BCM2835_MBOX_PROP_CHAN, &msg->hdr);
	if (ret) {
		printf("bcm2835: Could not query board serial\n");
		/* Ignore error; not critical */
		return;
	}

	snprintf(serial_string, sizeof(serial_string), "%016llx",
		 msg->get_board_serial.body.resp.serial);
	env_set("serial#", serial_string);
}

int misc_init_r(void)
{
	set_fdt_addr();
	set_fdtfile();
	set_usbethaddr();
#ifdef CONFIG_ENV_VARS_UBOOT_RUNTIME_CONFIG
	set_board_info();
#endif
	set_serial_number();

	return 0;
}

static void get_board_revision(void)
{
	ALLOC_CACHE_ALIGN_BUFFER(struct msg_get_board_rev, msg, 1);
	int ret;
	const struct rpi_model *models;
	uint32_t models_count;
	ofnode node;

	BCM2835_MBOX_INIT_HDR(msg);
	BCM2835_MBOX_INIT_TAG(&msg->get_board_rev, GET_BOARD_REV);

	ret = bcm2835_mbox_call_prop(BCM2835_MBOX_PROP_CHAN, &msg->hdr);
	if (ret) {
		/* Ignore error; not critical */
		node = ofnode_path("/system");
		if (!ofnode_valid(node)) {
			printf("bcm2835: Could not find /system node\n");
			return;
		}

		ret = ofnode_read_u32(node, "linux,revision", &revision);
		if (ret) {
			printf("bcm2835: Could not find linux,revision\n");
			return;
		}
	} else {
		revision = msg->get_board_rev.body.resp.rev;
	}

	/*
	 * For details of old-vs-new scheme, see:
	 * https://github.com/pimoroni/RPi.version/blob/master/RPi/version.py
	 * http://www.raspberrypi.org/forums/viewtopic.php?f=63&t=99293&p=690282
	 * (a few posts down)
	 *
	 * For the RPi 1, bit 24 is the "warranty bit", so we mask off just the
	 * lower byte to use as the board rev:
	 * http://www.raspberrypi.org/forums/viewtopic.php?f=63&t=98367&start=250
	 * http://www.raspberrypi.org/forums/viewtopic.php?f=31&t=20594
	 */
	if (revision & 0x800000) {
		rev_scheme = 1;
		rev_type = (revision >> 4) & 0xff;
		models = rpi_models_new_scheme;
		models_count = ARRAY_SIZE(rpi_models_new_scheme);
	} else {
		rev_scheme = 0;
		rev_type = revision & 0xff;
		models = rpi_models_old_scheme;
		models_count = ARRAY_SIZE(rpi_models_old_scheme);
	}
	if (rev_type >= models_count) {
		printf("RPI: Board rev 0x%x outside known range\n", rev_type);
		model = &rpi_model_unknown;
	} else if (!models[rev_type].name) {
		printf("RPI: Board rev 0x%x unknown\n", rev_type);
		model = &rpi_model_unknown;
	} else {
		model = &models[rev_type];
	}

	if (IS_ENABLED(CONFIG_BOARD_TYPES)) {
		gd->board_type = rev_type;
	}

	printf("RPI %s (0x%x)\n", model->name, revision);
}

int board_init(void)
{
#ifdef CONFIG_HW_WATCHDOG
	hw_watchdog_init();
#endif

	get_board_revision();

	gd->bd->bi_boot_params = 0x100;

	return bcm2835_power_on_module(BCM2835_MBOX_POWER_DEVID_USB_HCD);
}

/*
 * If the firmware passed a device tree use it for U-Boot.
 */
void *board_fdt_blob_setup(int *err)
{
	*err = 0;
	if (fdt_magic(fw_dtb_pointer) != FDT_MAGIC) {
		*err = -ENXIO;
		return NULL;
	}

	return (void *)fw_dtb_pointer;
}

int copy_property(void *dst, void *src, char *path, char *property)
{
	int dst_offset, src_offset;
	const fdt32_t *prop;
	int len;

	src_offset = fdt_path_offset(src, path);
	dst_offset = fdt_path_offset(dst, path);

	if (src_offset < 0 || dst_offset < 0)
		return -1;

	prop = fdt_getprop(src, src_offset, property, &len);
	if (!prop)
		return -1;

	return fdt_setprop(dst, dst_offset, property, prop, len);
}

/* Copy tweaks from the firmware dtb to the loaded dtb */
void  update_fdt_from_fw(void *fdt, void *fw_fdt)
{
	/* Using dtb from firmware directly; leave it alone */
	if (fdt == fw_fdt)
		return;

	/* The firmware provides a more precie model; so copy that */
	copy_property(fdt, fw_fdt, "/", "model");

	/* memory reserve as suggested by the firmware */
	copy_property(fdt, fw_fdt, "/", "memreserve");

	/* Adjust dma-ranges for the SD card and PCI bus as they can depend on
	 * the SoC revision
	 */
	copy_property(fdt, fw_fdt, "emmc2bus", "dma-ranges");
	copy_property(fdt, fw_fdt, "pcie0", "dma-ranges");

	/* Bootloader configuration template exposes as nvmem */
	if (copy_property(fdt, fw_fdt, "blconfig", "reg") == 0)
		copy_property(fdt, fw_fdt, "blconfig", "status");

	/* kernel address randomisation seed as provided by the firmware */
	copy_property(fdt, fw_fdt, "/chosen", "kaslr-seed");

	/* address of the PHY device as provided by the firmware  */
	copy_property(fdt, fw_fdt, "ethernet0/mdio@e14/ethernet-phy@1", "reg");
}

int ft_board_setup(void *blob, struct bd_info *bd)
{
	int node;

	update_fdt_from_fw(blob, (void *)fw_dtb_pointer);

	node = fdt_node_offset_by_compatible(blob, -1, "simple-framebuffer");
	if (node < 0)
		fdt_simplefb_add_node(blob);
	else
		fdt_simplefb_enable_and_mem_rsv(blob);

#ifdef CONFIG_EFI_LOADER
	/* Reserve the spin table */
	efi_add_memory_map(0, CONFIG_RPI_EFI_NR_SPIN_PAGES << EFI_PAGE_SHIFT,
			   EFI_RESERVED_MEMORY_TYPE);
#endif

	return 0;
}

/* TODO: Using late_init to initialize pci device with ID_RP1.
 * RP1 pci device should be initialized by the PCI subsystem because
 * it is under develop right now and depends from the final device-tree
 * format from the Linux Kernel. Current device-tree format violates
 * pci driver model. So this should be changed after upstreaming RP1
 * to the Linux Kernel source code.
 * This initialization should be done only for RPI5 board.
 */
#ifdef CONFIG_BCM2712
/*
 * A/B root selection: pair the root slot with the boot partition.
 *
 * With dm-verity the kernel command line names the root DEVICE (inside
 * dm-mod.create=...), and the command line lives in cmdline.txt inside the
 * SIGNED boot.img. Naming the partition there would force one signed image per
 * slot. Instead cmdline.txt carries a placeholder, @ROOTDEV@, and the pairing
 * is a fixed rule applied here at boot:
 *
 *     firmware loaded boot.img from partition 1  ->  root A
 *     firmware loaded boot.img from partition 5  ->  root B
 *
 * The firmware reports the partition it booted from in the device tree, at
 * /chosen/bootloader/partition. So ONE signed boot.img serves both pairs, an
 * update always writes the pair that is not running, and a failed tryboot
 * reverts to the untouched pair with nothing to swap back. The rule itself is
 * signed (it is this code); the partition number is the only runtime input,
 * and it can only choose between two roots that are each checked against the
 * single root hash the image carries.
 *
 * This is board_fdt_chosen_bootargs(), which fdt_chosen() writes into the
 * kernel's /chosen/bootargs and which bootm_measure() measures into PCR 1 --
 * so the SUBSTITUTED command line is what gets measured.
 *
 * Fail closed: an unknown partition number, or a template with an unresolved
 * placeholder, hangs rather than booting a root the rule does not vouch for.
 * A template without the placeholder is passed through unchanged (dev images).
 * An explicit "bootargs" environment variable keeps U-Boot's usual precedence.
 */
#define RPI_ROOTDEV_PLACEHOLDER	"@ROOTDEV@"

static const struct {
	u32 boot_partition;
	const char *root_dev;
} rpi_ab_pairs[] = {
	{ 1, "/dev/mmcblk0p2" },	/* boot A -> root A */
	{ 5, "/dev/mmcblk0p3" },	/* boot B -> root B */
};

char *board_fdt_chosen_bootargs(void)
{
	static char buf[2048];
	const void *fdt = (const void *)fw_dtb_pointer;
	const char *tmpl, *dev = NULL, *src, *hit;
	const u32 *part;
	int node, len, i;
	size_t out = 0, ph = strlen(RPI_ROOTDEV_PLACEHOLDER);

	/* explicit env wins, as everywhere in U-Boot */
	tmpl = env_get("bootargs");
	if (!tmpl) {
		if (fdt_magic(fdt) != FDT_MAGIC)
			return NULL;
		node = fdt_path_offset(fdt, "/chosen");
		if (node < 0)
			return NULL;
		tmpl = fdt_getprop(fdt, node, "bootargs", NULL);
		if (!tmpl)
			return NULL;
	}

	if (!strstr(tmpl, RPI_ROOTDEV_PLACEHOLDER))
		return (char *)tmpl;		/* nothing to resolve */

	node = fdt_path_offset(fdt, "/chosen/bootloader");
	part = node >= 0 ? fdt_getprop(fdt, node, "partition", &len) : NULL;
	if (part && len == sizeof(u32)) {
		u32 p = fdt32_to_cpu(*part);

		for (i = 0; i < ARRAY_SIZE(rpi_ab_pairs); i++)
			if (rpi_ab_pairs[i].boot_partition == p)
				dev = rpi_ab_pairs[i].root_dev;
		printf("[AB] firmware booted from partition %u -> root %s\n",
		       p, dev ? dev : "UNKNOWN");
	} else {
		printf("[AB] /chosen/bootloader/partition missing\n");
	}
	if (!dev) {
		printf("[AB] cannot pair a root with this boot partition; halting\n");
		hang();
	}

	/* substitute every occurrence of the placeholder */
	for (src = tmpl; (hit = strstr(src, RPI_ROOTDEV_PLACEHOLDER)); src = hit + ph) {
		size_t n = hit - src;

		if (out + n + strlen(dev) >= sizeof(buf))
			goto too_long;
		memcpy(buf + out, src, n);
		out += n;
		memcpy(buf + out, dev, strlen(dev));
		out += strlen(dev);
	}
	if (out + strlen(src) >= sizeof(buf))
		goto too_long;
	strcpy(buf + out, src);
	return buf;

too_long:
	printf("[AB] command line too long after substitution; halting\n");
	hang();
	return NULL;
}

int board_late_init(void)
{
	struct udevice *dev;
	int err;

	err = dm_pci_find_device(PCI_VENDOR_ID_RPI, PCI_DEVICE_ID_RP1_C0,
				 0, &dev);
	if (err)
		printf("RPI: RP1 device not found\n");

	return 0;
}
#endif
