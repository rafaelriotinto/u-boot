// SPDX-License-Identifier: GPL-2.0+
/*
 * (C) Copyright 2000-2009
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 */

#ifndef USE_HOSTCC
#include <common.h>
#include <bootm.h>
#include <bootstage.h>
#include <cli.h>
#include <command.h>
#include <cpu_func.h>
#include <dm.h>
#include <env.h>
#include <errno.h>
#include <fdt_support.h>
#include <irq_func.h>
#include <lmb.h>
#include <log.h>
#include <malloc.h>
#include <mapmem.h>
#include <net.h>
#include <asm/cache.h>
#include <asm/global_data.h>
#include <asm/io.h>
#include <linux/sizes.h>
#include <tpm-v2.h>
#include <u-boot/sha256.h>
#if defined(CONFIG_CMD_USB)
#include <usb.h>
#endif
#else
#include "mkimage.h"
#endif

#include <bootm.h>
#include <image.h>

#define MAX_CMDLINE_SIZE	SZ_4K

#define IH_INITRD_ARCH IH_ARCH_DEFAULT

#ifndef USE_HOSTCC

DECLARE_GLOBAL_DATA_PTR;

struct bootm_headers images;		/* pointers to os/initrd/fdt images */

__weak void board_quiesce_devices(void)
{
}

#if CONFIG_IS_ENABLED(LEGACY_IMAGE_FORMAT)
/**
 * image_get_kernel - verify legacy format kernel image
 * @img_addr: in RAM address of the legacy format image to be verified
 * @verify: data CRC verification flag
 *
 * image_get_kernel() verifies legacy image integrity and returns pointer to
 * legacy image header if image verification was completed successfully.
 *
 * returns:
 *     pointer to a legacy image header if valid image was found
 *     otherwise return NULL
 */
static struct legacy_img_hdr *image_get_kernel(ulong img_addr, int verify)
{
	struct legacy_img_hdr *hdr = (struct legacy_img_hdr *)img_addr;

	if (!image_check_magic(hdr)) {
		puts("Bad Magic Number\n");
		bootstage_error(BOOTSTAGE_ID_CHECK_MAGIC);
		return NULL;
	}
	bootstage_mark(BOOTSTAGE_ID_CHECK_HEADER);

	if (!image_check_hcrc(hdr)) {
		puts("Bad Header Checksum\n");
		bootstage_error(BOOTSTAGE_ID_CHECK_HEADER);
		return NULL;
	}

	bootstage_mark(BOOTSTAGE_ID_CHECK_CHECKSUM);
	image_print_contents(hdr);

	if (verify) {
		puts("   Verifying Checksum ... ");
		if (!image_check_dcrc(hdr)) {
			printf("Bad Data CRC\n");
			bootstage_error(BOOTSTAGE_ID_CHECK_CHECKSUM);
			return NULL;
		}
		puts("OK\n");
	}
	bootstage_mark(BOOTSTAGE_ID_CHECK_ARCH);

	if (!image_check_target_arch(hdr)) {
		printf("Unsupported Architecture 0x%x\n", image_get_arch(hdr));
		bootstage_error(BOOTSTAGE_ID_CHECK_ARCH);
		return NULL;
	}
	return hdr;
}
#endif

/**
 * boot_get_kernel() - find kernel image
 *
 * @addr_fit: first argument to bootm: address, fit configuration, etc.
 * @os_data: pointer to a ulong variable, will hold os data start address
 * @os_len: pointer to a ulong variable, will hold os data length
 *     address and length, otherwise NULL
 *     pointer to image header if valid image was found, plus kernel start
 * @kernp: image header if valid image was found, otherwise NULL
 *
 * boot_get_kernel() tries to find a kernel image, verifies its integrity
 * and locates kernel data.
 *
 * Return: 0 on success, -ve on error. -EPROTOTYPE means that the image is in
 * a wrong or unsupported format
 */
static int boot_get_kernel(const char *addr_fit, struct bootm_headers *images,
			   ulong *os_data, ulong *os_len, const void **kernp)
{
#if CONFIG_IS_ENABLED(LEGACY_IMAGE_FORMAT)
	struct legacy_img_hdr	*hdr;
#endif
	ulong		img_addr;
	const void *buf;
	const char *fit_uname_config = NULL, *fit_uname_kernel = NULL;
#if CONFIG_IS_ENABLED(FIT)
	int		os_noffset;
#endif

#ifdef CONFIG_ANDROID_BOOT_IMAGE
	const void *boot_img;
	const void *vendor_boot_img;
#endif
	img_addr = genimg_get_kernel_addr_fit(addr_fit, &fit_uname_config,
					      &fit_uname_kernel);

	if (IS_ENABLED(CONFIG_CMD_BOOTM_PRE_LOAD))
		img_addr += image_load_offset;

	bootstage_mark(BOOTSTAGE_ID_CHECK_MAGIC);

	/* check image type, for FIT images get FIT kernel node */
	*os_data = *os_len = 0;
	buf = map_sysmem(img_addr, 0);
	switch (genimg_get_format(buf)) {
#if CONFIG_IS_ENABLED(LEGACY_IMAGE_FORMAT)
	case IMAGE_FORMAT_LEGACY:
		printf("## Booting kernel from Legacy Image at %08lx ...\n",
		       img_addr);
		hdr = image_get_kernel(img_addr, images->verify);
		if (!hdr)
			return -EINVAL;
		bootstage_mark(BOOTSTAGE_ID_CHECK_IMAGETYPE);

		/* get os_data and os_len */
		switch (image_get_type(hdr)) {
		case IH_TYPE_KERNEL:
		case IH_TYPE_KERNEL_NOLOAD:
			*os_data = image_get_data(hdr);
			*os_len = image_get_data_size(hdr);
			break;
		case IH_TYPE_MULTI:
			image_multi_getimg(hdr, 0, os_data, os_len);
			break;
		case IH_TYPE_STANDALONE:
			*os_data = image_get_data(hdr);
			*os_len = image_get_data_size(hdr);
			break;
		default:
			bootstage_error(BOOTSTAGE_ID_CHECK_IMAGETYPE);
			return -EPROTOTYPE;
		}

		/*
		 * copy image header to allow for image overwrites during
		 * kernel decompression.
		 */
		memmove(&images->legacy_hdr_os_copy, hdr,
			sizeof(struct legacy_img_hdr));

		/* save pointer to image header */
		images->legacy_hdr_os = hdr;

		images->legacy_hdr_valid = 1;
		bootstage_mark(BOOTSTAGE_ID_DECOMP_IMAGE);
		break;
#endif
#if CONFIG_IS_ENABLED(FIT)
	case IMAGE_FORMAT_FIT:
		os_noffset = fit_image_load(images, img_addr,
				&fit_uname_kernel, &fit_uname_config,
				IH_ARCH_DEFAULT, IH_TYPE_KERNEL,
				BOOTSTAGE_ID_FIT_KERNEL_START,
				FIT_LOAD_IGNORED, os_data, os_len);
		if (os_noffset < 0)
			return -ENOENT;

		images->fit_hdr_os = map_sysmem(img_addr, 0);
		images->fit_uname_os = fit_uname_kernel;
		images->fit_uname_cfg = fit_uname_config;
		images->fit_noffset_os = os_noffset;
		break;
#endif
#ifdef CONFIG_ANDROID_BOOT_IMAGE
	case IMAGE_FORMAT_ANDROID: {
		int ret;

		boot_img = buf;
		vendor_boot_img = NULL;
		if (IS_ENABLED(CONFIG_CMD_ABOOTIMG)) {
			boot_img = map_sysmem(get_abootimg_addr(), 0);
			vendor_boot_img = map_sysmem(get_avendor_bootimg_addr(), 0);
		}
		printf("## Booting Android Image at 0x%08lx ...\n", img_addr);
		ret = android_image_get_kernel(boot_img, vendor_boot_img,
					       images->verify, os_data, os_len);
		if (IS_ENABLED(CONFIG_CMD_ABOOTIMG)) {
			unmap_sysmem(vendor_boot_img);
			unmap_sysmem(boot_img);
		}
		if (ret)
			return ret;
		break;
	}
#endif
	default:
		bootstage_error(BOOTSTAGE_ID_CHECK_IMAGETYPE);
		return -EPROTOTYPE;
	}

	debug("   kernel data at 0x%08lx, len = 0x%08lx (%ld)\n",
	      *os_data, *os_len, *os_len);
	*kernp = buf;

	return 0;
}

#ifdef CONFIG_LMB
static void boot_start_lmb(struct bootm_headers *images)
{
	phys_addr_t	mem_start;
	phys_size_t	mem_size;

	mem_start = env_get_bootm_low();
	mem_size = env_get_bootm_size();

	lmb_init_and_reserve_range(&images->lmb, mem_start,
				   mem_size, NULL);
}
#else
#define lmb_reserve(lmb, base, size)
static inline void boot_start_lmb(struct bootm_headers *images) { }
#endif

static int bootm_start(void)
{
	memset((void *)&images, 0, sizeof(images));
	images.verify = env_get_yesno("verify");

	boot_start_lmb(&images);

	bootstage_mark_name(BOOTSTAGE_ID_BOOTM_START, "bootm_start");
	images.state = BOOTM_STATE_START;

	return 0;
}

static ulong bootm_data_addr(const char *addr_str)
{
	ulong addr;

	if (addr_str)
		addr = hextoul(addr_str, NULL);
	else
		addr = image_load_addr;

	return addr;
}

/**
 * bootm_pre_load() - Handle the pre-load processing
 *
 * This can be used to do a full signature check of the image, for example.
 * It calls image_pre_load() with the data address of the image to check.
 *
 * @addr_str: String containing load address in hex, or NULL to use
 * image_load_addr
 * Return: 0 if OK, CMD_RET_FAILURE on failure
 */
static int bootm_pre_load(const char *addr_str)
{
	ulong data_addr = bootm_data_addr(addr_str);
	int ret = 0;

	if (IS_ENABLED(CONFIG_CMD_BOOTM_PRE_LOAD))
		ret = image_pre_load(data_addr);

	if (ret)
		ret = CMD_RET_FAILURE;

	return ret;
}

/**
 * bootm_find_os(): Find the OS to boot
 *
 * @cmd_name: Command name that started this boot, e.g. "bootm"
 * @addr_fit: Address and/or FIT specifier (first arg of bootm command)
 * Return: 0 on success, -ve on error
 */
static int bootm_find_os(const char *cmd_name, const char *addr_fit)
{
	const void *os_hdr;
#ifdef CONFIG_ANDROID_BOOT_IMAGE
	const void *vendor_boot_img;
	const void *boot_img;
#endif
	bool ep_found = false;
	int ret;

	/* get kernel image header, start address and length */
	ret = boot_get_kernel(addr_fit, &images, &images.os.image_start,
			      &images.os.image_len, &os_hdr);
	if (ret) {
		if (ret == -EPROTOTYPE)
			printf("Wrong Image Type for %s command\n", cmd_name);

		printf("ERROR %dE: can't get kernel image!\n", ret);
		return 1;
	}

	/* get image parameters */
	switch (genimg_get_format(os_hdr)) {
#if CONFIG_IS_ENABLED(LEGACY_IMAGE_FORMAT)
	case IMAGE_FORMAT_LEGACY:
		images.os.type = image_get_type(os_hdr);
		images.os.comp = image_get_comp(os_hdr);
		images.os.os = image_get_os(os_hdr);

		images.os.end = image_get_image_end(os_hdr);
		images.os.load = image_get_load(os_hdr);
		images.os.arch = image_get_arch(os_hdr);
		break;
#endif
#if CONFIG_IS_ENABLED(FIT)
	case IMAGE_FORMAT_FIT:
		if (fit_image_get_type(images.fit_hdr_os,
				       images.fit_noffset_os,
				       &images.os.type)) {
			puts("Can't get image type!\n");
			bootstage_error(BOOTSTAGE_ID_FIT_TYPE);
			return 1;
		}

		if (fit_image_get_comp(images.fit_hdr_os,
				       images.fit_noffset_os,
				       &images.os.comp)) {
			puts("Can't get image compression!\n");
			bootstage_error(BOOTSTAGE_ID_FIT_COMPRESSION);
			return 1;
		}

		if (fit_image_get_os(images.fit_hdr_os, images.fit_noffset_os,
				     &images.os.os)) {
			puts("Can't get image OS!\n");
			bootstage_error(BOOTSTAGE_ID_FIT_OS);
			return 1;
		}

		if (fit_image_get_arch(images.fit_hdr_os,
				       images.fit_noffset_os,
				       &images.os.arch)) {
			puts("Can't get image ARCH!\n");
			return 1;
		}

		images.os.end = fit_get_end(images.fit_hdr_os);

		if (fit_image_get_load(images.fit_hdr_os, images.fit_noffset_os,
				       &images.os.load)) {
			puts("Can't get image load address!\n");
			bootstage_error(BOOTSTAGE_ID_FIT_LOADADDR);
			return 1;
		}
		break;
#endif
#ifdef CONFIG_ANDROID_BOOT_IMAGE
	case IMAGE_FORMAT_ANDROID:
		boot_img = os_hdr;
		vendor_boot_img = NULL;
		if (IS_ENABLED(CONFIG_CMD_ABOOTIMG)) {
			boot_img = map_sysmem(get_abootimg_addr(), 0);
			vendor_boot_img = map_sysmem(get_avendor_bootimg_addr(), 0);
		}
		images.os.type = IH_TYPE_KERNEL;
		images.os.comp = android_image_get_kcomp(boot_img, vendor_boot_img);
		images.os.os = IH_OS_LINUX;
		images.os.end = android_image_get_end(boot_img, vendor_boot_img);
		images.os.load = android_image_get_kload(boot_img, vendor_boot_img);
		images.ep = images.os.load;
		ep_found = true;
		if (IS_ENABLED(CONFIG_CMD_ABOOTIMG)) {
			unmap_sysmem(vendor_boot_img);
			unmap_sysmem(boot_img);
		}
		break;
#endif
	default:
		puts("ERROR: unknown image format type!\n");
		return 1;
	}

	/* If we have a valid setup.bin, we will use that for entry (x86) */
	if (images.os.arch == IH_ARCH_I386 ||
	    images.os.arch == IH_ARCH_X86_64) {
		ulong len;

		ret = boot_get_setup(&images, IH_ARCH_I386, &images.ep, &len);
		if (ret < 0 && ret != -ENOENT) {
			puts("Could not find a valid setup.bin for x86\n");
			return 1;
		}
		/* Kernel entry point is the setup.bin */
	} else if (images.legacy_hdr_valid) {
		images.ep = image_get_ep(&images.legacy_hdr_os_copy);
#if CONFIG_IS_ENABLED(FIT)
	} else if (images.fit_uname_os) {
		int ret;

		ret = fit_image_get_entry(images.fit_hdr_os,
					  images.fit_noffset_os, &images.ep);
		if (ret) {
			puts("Can't get entry point property!\n");
			return 1;
		}
#endif
	} else if (!ep_found) {
		puts("Could not find kernel entry point!\n");
		return 1;
	}

	if (images.os.type == IH_TYPE_KERNEL_NOLOAD) {
		images.os.load = images.os.image_start;
		images.ep += images.os.image_start;
	}

	images.os.start = map_to_sysmem(os_hdr);

	return 0;
}

/**
 * check_overlap() - Check if an image overlaps the OS
 *
 * @name: Name of image to check (used to print error)
 * @base: Base address of image
 * @end: End address of image (+1)
 * @os_start: Start of OS
 * @os_size: Size of OS in bytes
 * Return: 0 if OK, -EXDEV if the image overlaps the OS
 */
static int check_overlap(const char *name, ulong base, ulong end,
			 ulong os_start, ulong os_size)
{
	ulong os_end;

	if (!base)
		return 0;
	os_end = os_start + os_size;

	if ((base >= os_start && base < os_end) ||
	    (end > os_start && end <= os_end) ||
	    (base < os_start && end >= os_end)) {
		printf("ERROR: %s image overlaps OS image (OS=%lx..%lx)\n",
		       name, os_start, os_end);

		return -EXDEV;
	}

	return 0;
}

int bootm_find_images(ulong img_addr, const char *conf_ramdisk,
		      const char *conf_fdt, ulong start, ulong size)
{
	const char *select = conf_ramdisk;
	char addr_str[17];
	void *buf;
	int ret;

	if (IS_ENABLED(CONFIG_ANDROID_BOOT_IMAGE)) {
		/* Look for an Android boot image */
		buf = map_sysmem(images.os.start, 0);
		if (buf && genimg_get_format(buf) == IMAGE_FORMAT_ANDROID) {
			strcpy(addr_str, simple_xtoa(img_addr));
			select = addr_str;
		}
	}

	if (conf_ramdisk)
		select = conf_ramdisk;

	/* find ramdisk */
	ret = boot_get_ramdisk(select, &images, IH_INITRD_ARCH,
			       &images.rd_start, &images.rd_end);
	if (ret) {
		puts("Ramdisk image is corrupt or invalid\n");
		return 1;
	}

	/* check if ramdisk overlaps OS image */
	if (check_overlap("RD", images.rd_start, images.rd_end, start, size))
		return 1;

	if (CONFIG_IS_ENABLED(OF_LIBFDT)) {
		buf = map_sysmem(img_addr, 0);

		/* find flattened device tree */
		ret = boot_get_fdt(buf, conf_fdt, IH_ARCH_DEFAULT, &images,
				   &images.ft_addr, &images.ft_len);
		if (ret) {
			puts("Could not find a valid device tree\n");
			return 1;
		}

		/* check if FDT overlaps OS image */
		if (check_overlap("FDT", map_to_sysmem(images.ft_addr),
				  images.ft_len, start, size))
			return 1;

		if (IS_ENABLED(CONFIG_CMD_FDT))
			set_working_fdt_addr(map_to_sysmem(images.ft_addr));
	}

#if CONFIG_IS_ENABLED(FIT)
	if (IS_ENABLED(CONFIG_FPGA)) {
		/* find bitstreams */
		ret = boot_get_fpga(&images);
		if (ret) {
			printf("FPGA image is corrupted or invalid\n");
			return 1;
		}
	}

	/* find all of the loadables */
	ret = boot_get_loadable(&images);
	if (ret) {
		printf("Loadable(s) is corrupt or invalid\n");
		return 1;
	}
#endif

	return 0;
}

static int bootm_find_other(ulong img_addr, const char *conf_ramdisk,
			    const char *conf_fdt)
{
	if ((images.os.type == IH_TYPE_KERNEL ||
	     images.os.type == IH_TYPE_KERNEL_NOLOAD ||
	     images.os.type == IH_TYPE_MULTI) &&
	    (images.os.os == IH_OS_LINUX || images.os.os == IH_OS_VXWORKS ||
	     images.os.os == IH_OS_EFI || images.os.os == IH_OS_TEE)) {
		return bootm_find_images(img_addr, conf_ramdisk, conf_fdt, 0,
					 0);
	}

	return 0;
}
#endif /* USE_HOSTC */

#if !defined(USE_HOSTCC) || defined(CONFIG_FIT_SIGNATURE)
/**
 * handle_decomp_error() - display a decompression error
 *
 * This function tries to produce a useful message. In the case where the
 * uncompressed size is the same as the available space, we can assume that
 * the image is too large for the buffer.
 *
 * @comp_type:		Compression type being used (IH_COMP_...)
 * @uncomp_size:	Number of bytes uncompressed
 * @buf_size:		Number of bytes the decompresion buffer was
 * @ret:		errno error code received from compression library
 * Return: Appropriate BOOTM_ERR_ error code
 */
static int handle_decomp_error(int comp_type, size_t uncomp_size,
			       size_t buf_size, int ret)
{
	const char *name = genimg_get_comp_name(comp_type);

	/* ENOSYS means unimplemented compression type, don't reset. */
	if (ret == -ENOSYS)
		return BOOTM_ERR_UNIMPLEMENTED;

	if (uncomp_size >= buf_size)
		printf("Image too large: increase CONFIG_SYS_BOOTM_LEN\n");
	else
		printf("%s: uncompress error %d\n", name, ret);

	/*
	 * The decompression routines are now safe, so will not write beyond
	 * their bounds. Probably it is not necessary to reset, but maintain
	 * the current behaviour for now.
	 */
	printf("Must RESET board to recover\n");
#ifndef USE_HOSTCC
	bootstage_error(BOOTSTAGE_ID_DECOMP_IMAGE);
#endif

	return BOOTM_ERR_RESET;
}
#endif

#ifndef USE_HOSTCC
static int bootm_load_os(struct bootm_headers *images, int boot_progress)
{
	struct image_info os = images->os;
	ulong load = os.load;
	ulong load_end;
	ulong blob_start = os.start;
	ulong blob_end = os.end;
	ulong image_start = os.image_start;
	ulong image_len = os.image_len;
	ulong flush_start = ALIGN_DOWN(load, ARCH_DMA_MINALIGN);
	bool no_overlap;
	void *load_buf, *image_buf;
	int err;

	/*
	 * For a "noload" compressed kernel we need to allocate a buffer large
	 * enough to decompress in to and use that as the load address now.
	 * Assume that the kernel compression is at most a factor of 4 since
	 * zstd almost achieves that.
	 * Use an alignment of 2MB since this might help arm64
	 */
	if (os.type == IH_TYPE_KERNEL_NOLOAD && os.comp != IH_COMP_NONE) {
		ulong req_size = ALIGN(image_len * 4, SZ_1M);

		load = lmb_alloc(&images->lmb, req_size, SZ_2M);
		if (!load)
			return 1;
		os.load = load;
		images->ep = load;
		debug("Allocated %lx bytes at %lx for kernel (size %lx) decompression\n",
		      req_size, load, image_len);
	}

	load_buf = map_sysmem(load, 0);
	image_buf = map_sysmem(os.image_start, image_len);
	err = image_decomp(os.comp, load, os.image_start, os.type,
			   load_buf, image_buf, image_len,
			   CONFIG_SYS_BOOTM_LEN, &load_end);
	if (err) {
		err = handle_decomp_error(os.comp, load_end - load,
					  CONFIG_SYS_BOOTM_LEN, err);
		bootstage_error(BOOTSTAGE_ID_DECOMP_IMAGE);
		return err;
	}
	/* We need the decompressed image size in the next steps */
	images->os.image_len = load_end - load;

	flush_cache(flush_start, ALIGN(load_end, ARCH_DMA_MINALIGN) - flush_start);

	debug("   kernel loaded at 0x%08lx, end = 0x%08lx\n", load, load_end);
	bootstage_mark(BOOTSTAGE_ID_KERNEL_LOADED);

	no_overlap = (os.comp == IH_COMP_NONE && load == image_start);

	if (!no_overlap && load < blob_end && load_end > blob_start) {
		debug("images.os.start = 0x%lX, images.os.end = 0x%lx\n",
		      blob_start, blob_end);
		debug("images.os.load = 0x%lx, load_end = 0x%lx\n", load,
		      load_end);

		/* Check what type of image this is. */
		if (images->legacy_hdr_valid) {
			if (image_get_type(&images->legacy_hdr_os_copy)
					== IH_TYPE_MULTI)
				puts("WARNING: legacy format multi component image overwritten\n");
			return BOOTM_ERR_OVERLAP;
		} else {
			puts("ERROR: new format image overwritten - must RESET the board to recover\n");
			bootstage_error(BOOTSTAGE_ID_OVERWRITTEN);
			return BOOTM_ERR_RESET;
		}
	}

	if (IS_ENABLED(CONFIG_CMD_BOOTI) && images->os.arch == IH_ARCH_ARM64 &&
	    images->os.os == IH_OS_LINUX) {
		ulong relocated_addr;
		ulong image_size;
		int ret;

		ret = booti_setup(load, &relocated_addr, &image_size, false);
		if (ret) {
			printf("Failed to prep arm64 kernel (err=%d)\n", ret);
			return BOOTM_ERR_RESET;
		}

		/* Handle BOOTM_STATE_LOADOS */
		if (relocated_addr != load) {
			printf("Moving Image from 0x%lx to 0x%lx, end=%lx\n",
			       load, relocated_addr,
			       relocated_addr + image_size);
			memmove((void *)relocated_addr, load_buf, image_size);
		}

		images->ep = relocated_addr;
		images->os.start = relocated_addr;
		images->os.end = relocated_addr + image_size;
	}

	lmb_reserve(&images->lmb, images->os.load, (load_end -
						    images->os.load));
	return 0;
}

/**
 * bootm_disable_interrupts() - Disable interrupts in preparation for load/boot
 *
 * Return: interrupt flag (0 if interrupts were disabled, non-zero if they were
 *	enabled)
 */
ulong bootm_disable_interrupts(void)
{
	ulong iflag;

	/*
	 * We have reached the point of no return: we are going to
	 * overwrite all exception vector code, so we cannot easily
	 * recover from any failures any more...
	 */
	iflag = disable_interrupts();
#ifdef CONFIG_NETCONSOLE
	/* Stop the ethernet stack if NetConsole could have left it up */
	eth_halt();
#endif

#if defined(CONFIG_CMD_USB)
	/*
	 * turn off USB to prevent the host controller from writing to the
	 * SDRAM while Linux is booting. This could happen (at least for OHCI
	 * controller), because the HCCA (Host Controller Communication Area)
	 * lies within the SDRAM and the host controller writes continously to
	 * this area (as busmaster!). The HccaFrameNumber is for example
	 * updated every 1 ms within the HCCA structure in SDRAM! For more
	 * details see the OpenHCI specification.
	 */
	usb_stop();
#endif
	return iflag;
}

#define CONSOLE_ARG		"console="
#define NULL_CONSOLE		(CONSOLE_ARG "ttynull")
#define CONSOLE_ARG_SIZE	sizeof(NULL_CONSOLE)

/**
 * fixup_silent_linux() - Handle silencing the linux boot if required
 *
 * This uses the silent_linux envvar to control whether to add/set a "console="
 * parameter to the command line
 *
 * @buf: Buffer containing the string to process
 * @maxlen: Maximum length of buffer
 * Return: 0 if OK, -ENOSPC if @maxlen is too small
 */
static int fixup_silent_linux(char *buf, int maxlen)
{
	int want_silent;
	char *cmdline;
	int size;

	/*
	 * Move the input string to the end of buffer. The output string will be
	 * built up at the start.
	 */
	size = strlen(buf) + 1;
	if (size * 2 > maxlen)
		return -ENOSPC;
	cmdline = buf + maxlen - size;
	memmove(cmdline, buf, size);
	/*
	 * Only fix cmdline when requested. The environment variable can be:
	 *
	 *	no - we never fixup
	 *	yes - we always fixup
	 *	unset - we rely on the console silent flag
	 */
	want_silent = env_get_yesno("silent_linux");
	if (want_silent == 0)
		return 0;
	else if (want_silent == -1 && !(gd->flags & GD_FLG_SILENT))
		return 0;

	debug("before silent fix-up: %s\n", cmdline);
	if (*cmdline) {
		char *start = strstr(cmdline, CONSOLE_ARG);

		/* Check space for maximum possible new command line */
		if (size + CONSOLE_ARG_SIZE > maxlen)
			return -ENOSPC;

		if (start) {
			char *end = strchr(start, ' ');
			int start_bytes;

			start_bytes = start - cmdline;
			strncpy(buf, cmdline, start_bytes);
			strncpy(buf + start_bytes, NULL_CONSOLE, CONSOLE_ARG_SIZE);
			if (end)
				strcpy(buf + start_bytes + CONSOLE_ARG_SIZE - 1, end);
			else
				buf[start_bytes + CONSOLE_ARG_SIZE] = '\0';
		} else {
			sprintf(buf, "%s %s", cmdline, NULL_CONSOLE);
		}
		if (buf + strlen(buf) >= cmdline)
			return -ENOSPC;
	} else {
		if (maxlen < CONSOLE_ARG_SIZE)
			return -ENOSPC;
		strcpy(buf, NULL_CONSOLE);
	}
	debug("after silent fix-up: %s\n", buf);

	return 0;
}

/**
 * process_subst() - Handle substitution of ${...} fields in the environment
 *
 * Handle variable substitution in the provided buffer
 *
 * @buf: Buffer containing the string to process
 * @maxlen: Maximum length of buffer
 * Return: 0 if OK, -ENOSPC if @maxlen is too small
 */
static int process_subst(char *buf, int maxlen)
{
	char *cmdline;
	int size;
	int ret;

	/* Move to end of buffer */
	size = strlen(buf) + 1;
	cmdline = buf + maxlen - size;
	if (buf + size > cmdline)
		return -ENOSPC;
	memmove(cmdline, buf, size);

	ret = cli_simple_process_macros(cmdline, buf, cmdline - buf);

	return ret;
}

int bootm_process_cmdline(char *buf, int maxlen, int flags)
{
	int ret;

	/* Check config first to enable compiler to eliminate code */
	if (IS_ENABLED(CONFIG_SILENT_CONSOLE) &&
	    !IS_ENABLED(CONFIG_SILENT_U_BOOT_ONLY) &&
	    (flags & BOOTM_CL_SILENT)) {
		ret = fixup_silent_linux(buf, maxlen);
		if (ret)
			return log_msg_ret("silent", ret);
	}
	if (IS_ENABLED(CONFIG_BOOTARGS_SUBST) && IS_ENABLED(CONFIG_CMDLINE) &&
	    (flags & BOOTM_CL_SUBST)) {
		ret = process_subst(buf, maxlen);
		if (ret)
			return log_msg_ret("subst", ret);
	}

	return 0;
}

int bootm_process_cmdline_env(int flags)
{
	const int maxlen = MAX_CMDLINE_SIZE;
	bool do_silent;
	const char *env;
	char *buf;
	int ret;

	/* First check if any action is needed */
	do_silent = IS_ENABLED(CONFIG_SILENT_CONSOLE) &&
	    !IS_ENABLED(CONFIG_SILENT_U_BOOT_ONLY) && (flags & BOOTM_CL_SILENT);
	if (!do_silent && !IS_ENABLED(CONFIG_BOOTARGS_SUBST))
		return 0;

	env = env_get("bootargs");
	if (env && strlen(env) >= maxlen)
		return -E2BIG;
	buf = malloc(maxlen);
	if (!buf)
		return -ENOMEM;
	if (env)
		strcpy(buf, env);
	else
		*buf = '\0';
	ret = bootm_process_cmdline(buf, maxlen, flags);
	if (!ret) {
		ret = env_set("bootargs", buf);

		/*
		 * If buf is "" and bootargs does not exist, this will produce
		 * an error trying to delete bootargs. Ignore it
		 */
		if (ret == -ENOENT)
			ret = 0;
	}
	free(buf);
	if (ret)
		return log_msg_ret("env", ret);

	return 0;
}

/*
 * Content injected into the devicetree by the platform firmware that does
 * not describe the SOFTWARE being measured, and so must not be part of the
 * DTB measurement. Two classes:
 *
 *   - boot-varying state: the random /chosen/kaslr-seed and /chosen/rng-seed,
 *     and the /chosen/bootloader node (reset reason 'rsts', reset counter
 *     'count'). These differ between any two boots.
 *
 *   - ENVIRONMENT state: /chosen/power holds the result of the USB Power
 *     Delivery negotiation (max_current, usbpd_power_data_objects,
 *     usb_max_current_enable, over-current flags). It describes the power
 *     supply, port and cable attached to the board -- not the software. It is
 *     renegotiated on a COLD power-up but not on a warm reboot, so the
 *     resulting instability is invisible to warm-reboot testing.
 *
 * Measured on Raspberry Pi 5 with an unchanged boot.img: PSU cold boot and
 * PSU warm reboot both gave PCR0 = F6361032..., while a cold boot powered
 * from a PC USB-C port gave 3B1136DE..., and returning to the PSU restored
 * F6361032... Leaving /chosen/power in the measurement therefore makes
 * attestation REJECT a perfectly healthy device whenever its power source
 * changes -- a false positive, which erodes trust in the mechanism faster
 * than a missed detection would.
 *
 * General principle: a measurement should cover what is executing, not the
 * conditions it happens to be executing under. Any firmware-populated
 * devicetree should be audited for runtime-recorded values (power, thermal,
 * clock, link state) before it is measured.
 */
static const char * const dtb_strip_props[] = {
	"kaslr-seed",
	"rng-seed",
};

static const char * const dtb_strip_nodes[] = {
	"bootloader",
	"power",
};

/*
 * Measure a sanitized copy of the devicetree into PCR 0: copy the blob,
 * delete the boot-varying properties/nodes listed above, repack (so that
 * neither the deleted bytes nor blob padding influence the digest), and
 * hash the result. The original devicetree handed to the OS is untouched.
 */
static int tcg2_measure_dtb_sanitized(struct udevice *dev,
				      struct tcg2_event_log *elog,
				      void *fdt, u32 fdt_len)
{
	void *buf;
	int nodeoff;
	int err;
	int i;
	int ret;

	buf = malloc(fdt_len + SZ_4K);
	if (!buf)
		return -ENOMEM;

	err = fdt_open_into(fdt, buf, fdt_len + SZ_4K);
	if (err) {
		printf("[MBOOT] dtb_sanitize: fdt_open_into failed (%d)\n",
		       err);
		ret = -EINVAL;
		goto out;
	}

	nodeoff = fdt_path_offset(buf, "/chosen");
	if (nodeoff >= 0) {
		for (i = 0; i < ARRAY_SIZE(dtb_strip_props); i++) {
			err = fdt_delprop(buf, nodeoff, dtb_strip_props[i]);
			if (err && err != -FDT_ERR_NOTFOUND)
				printf("[MBOOT] dtb_sanitize: delprop %s failed (%d)\n",
				       dtb_strip_props[i], err);
		}
		for (i = 0; i < ARRAY_SIZE(dtb_strip_nodes); i++) {
			int sub = fdt_subnode_offset(buf, nodeoff,
						     dtb_strip_nodes[i]);
			if (sub >= 0)
				fdt_del_node(buf, sub);
		}
	}

	fdt_pack(buf);

	printf("[MBOOT] dtb_sanitize: measuring sanitized DTB -> PCR 0 (len 0x%x -> 0x%x)\n",
	       fdt_len, fdt_totalsize(buf));

	ret = tcg2_measure_data(dev, elog, 0, fdt_totalsize(buf), buf,
				EV_TABLE_OF_DEVICES, strlen("dts") + 1,
				(u8 *)"dts");
out:
	free(buf);
	return ret;
}

#if CONFIG_IS_ENABLED(MEASURE_NV_EXTEND)
/* Domain-separation context for the DUID-derived NV authValue. Must match the
 * provisioning step (provisioning/nv-extend/provision-nv-index.sh). */
#define MEASURE_NV_AUTH_CTX	"rp5-nv-auth-v1"

/*
 * Derive the NV index authValue ("factory secret") from the SoC DUID that the
 * firmware exposes at /chosen/rpi-duid in the device tree. The DUID lives in
 * OTP (not on the SD card) and is read here inside the SoC, so the secret is
 * never carried on removable media. The provisioning step derives the same
 * value identically. See docs/hardening-and-secret-storage.md.
 */
static int measure_factory_secret(const void *fdt, u8 secret[TPM2_DIGEST_LEN])
{
	sha256_context ctx;
	const void *duid;
	int node, len;

	node = fdt_path_offset(fdt, "/chosen");
	if (node < 0)
		return -1;
	duid = fdt_getprop(fdt, node, "rpi-duid", &len);
	if (!duid || len <= 0)
		return -1;

	sha256_starts(&ctx);
	sha256_update(&ctx, (const u8 *)MEASURE_NV_AUTH_CTX,
		      strlen(MEASURE_NV_AUTH_CTX));
	sha256_update(&ctx, duid, len);
	sha256_finish(&ctx, secret);
	return 0;
}

/*
 * Extend @len bytes at @data into the measured-boot NV extend index, using the
 * same digest the PCR receives (SHA256(data)). Authorization is a fresh policy
 * session satisfying PolicyAuthValue (HMAC proves the DUID-derived secret).
 * One session per extend keeps the (rolling) session nonce handling trivial.
 */
/*
 * PCRs the NV index commits to. MUST match the set the attestation server
 * quotes, and MUST be in ascending order, because the digest below is
 * composed the same way the TPM composes a quote's pcrDigest -- which lets
 * the verifier additionally check
 *     NV value == SHA256(0x00 * 32 || quote.pcrDigest)
 * and so bind "these measurements" to "a board holding the DUID secret".
 * If this set ever changes, the verifier must change with it: divergence
 * would silently weaken the check rather than fail visibly.
 */
static const u8 nv_commit_pcrs[] = { 0, 1, 8, 9 };

/*
 * Compose the digest the NV index commits to: SHA256 over the concatenated
 * current values of nv_commit_pcrs, i.e. the same composite a quote reports.
 *
 * Committing to the PCR set rather than to the kernel alone is what makes
 * board binding cover the whole measured state. The kernel was previously the
 * only component recorded here; the devicetree, kernel command line and
 * initrd lived only in ordinary PCRs, which an attacker on a substituted
 * board can reproduce -- their inputs are public and extending is
 * deterministic. Widening the commitment costs nothing in confidentiality,
 * because the protection is the authority to WRITE the index, not the secrecy
 * of its contents.
 */
static int measure_nv_compose(struct udevice *dev, u8 *out)
{
	struct tpm_chip_priv *priv = dev_get_uclass_priv(dev);
	u8 pcr[TPM2_DIGEST_LEN];
	unsigned int updates;
	sha256_context ctx;
	u32 rc;
	int i;

	if (!priv)
		return -1;

	sha256_starts(&ctx);
	for (i = 0; i < ARRAY_SIZE(nv_commit_pcrs); i++) {
		/*
		 * pcr_select_min is the chip's minimum pcrSelect array size in
		 * BYTES (typically 3, i.e. PCRs 0..23). Passing a fixed number
		 * here would build a malformed TPML_PCR_SELECTION and the TPM
		 * would reject the command, so take it from the device as the
		 * other callers of tpm2_pcr_read() do.
		 */
		rc = tpm2_pcr_read(dev, nv_commit_pcrs[i], priv->pcr_select_min,
				   TPM2_ALG_SHA256,
				   pcr, TPM2_DIGEST_LEN, &updates);
		if (rc) {
			printf("[MBOOT] NV commit: PCR %u read failed 0x%x\n",
			       nv_commit_pcrs[i], rc);
			return -1;
		}
		sha256_update(&ctx, pcr, TPM2_DIGEST_LEN);
	}
	sha256_finish(&ctx, out);

	return 0;
}

static int measure_nv_extend(struct udevice *dev, const void *fdt)
{
	struct tpm2_auth_session session;
	u8 secret[TPM2_DIGEST_LEN];
	u8 digest[TPM2_DIGEST_LEN];
	u8 nv_name[68];
	u32 nv_name_len = sizeof(nv_name);
	u32 rc;

	if (measure_factory_secret(fdt, secret)) {
		printf("[MBOOT] no rpi-duid: cannot derive NV secret, skipping\n");
		return -1;
	}

	if (measure_nv_compose(dev, digest))
		return -1;

	rc = tpm2_nv_read_public(dev, CONFIG_MEASURE_NV_INDEX,
				 nv_name, &nv_name_len);
	if (rc) {
		printf("[MBOOT] NV read_public failed 0x%x\n", rc);
		return rc;
	}
	rc = tpm2_start_auth_session(dev, TPM_SE_POLICY, &session);
	if (rc) {
		printf("[MBOOT] NV start_auth_session failed 0x%x\n", rc);
		return rc;
	}
	rc = tpm2_policy_auth_value(dev, &session);
	if (!rc)
		rc = tpm2_nv_extend(dev, CONFIG_MEASURE_NV_INDEX,
				    nv_name, nv_name_len,
				    secret, TPM2_DIGEST_LEN,
				    &session, digest, TPM2_DIGEST_LEN);
	tpm2_flush_context(dev, session.handle);
	if (rc)
		printf("[MBOOT] NV extend failed 0x%x\n", rc);
	else
		printf("[MBOOT] NV commit OK (PCR composite %02x%02x%02x%02x...)\n",
		       digest[0], digest[1], digest[2], digest[3]);
	return rc;
}
#else
static inline int measure_nv_extend(struct udevice *dev, const void *fdt)
{
	return 0;
}
#endif

int bootm_measure(struct bootm_headers *images)
{
	int ret = 0;

	printf("[MBOOT] bootm_measure: enter (os.os=%d)\n", images->os.os);

	/* Skip measurement if EFI is going to do it */
	if (images->os.os == IH_OS_EFI &&
	    IS_ENABLED(CONFIG_EFI_TCG2_PROTOCOL) &&
	    IS_ENABLED(CONFIG_BOOTM_EFI)) {
		printf("[MBOOT] bootm_measure: SKIPPING - EFI TCG2 will handle it\n");
		return ret;
	}

	if (IS_ENABLED(CONFIG_MEASURED_BOOT)) {
		struct tcg2_event_log elog;
		struct udevice *dev;
		void *initrd_buf;
		void *image_buf;
		const char *s;
		u32 rd_len;
		bool ign;
		ulong kernel_start, kernel_len;

		printf("[MBOOT] bootm_measure: CONFIG_MEASURED_BOOT active\n");

		elog.log_size = SZ_64K;
		elog.log = malloc(SZ_64K);
		if (!elog.log) {
			printf("[MBOOT] bootm_measure: failed to allocate event log\n");
			return -ENOMEM;
		}
		ign = IS_ENABLED(CONFIG_MEASURE_IGNORE_LOG);
		ret = tcg2_measurement_init(&dev, &elog, ign);
		if (ret) {
			printf("[MBOOT] bootm_measure: measurement_init FAILED ret=%d\n", ret);
			free(elog.log);
			return ret;
		}

		/*
		 * bootm sets os.image_start/image_len (via boot_get_kernel),
		 * but booti only sets os.start/os.end. Fall back to the
		 * latter so that raw Image boots (booti) get measured too.
		 *
		 * For booti, os.end - os.start is the ARM64 Image header's
		 * image_size which includes BSS. Measuring BSS would hash
		 * uninitialized memory, producing different values each boot.
		 * Use the filesize env var (set by the load command) to get
		 * the actual kernel file size excluding BSS.
		 */
		kernel_start = images->os.image_start;
		kernel_len = images->os.image_len;
		if (!kernel_start && !kernel_len && images->os.start) {
			kernel_start = images->os.start;
			s = env_get("filesize");
			if (s)
				kernel_len = hextoul(s, NULL);
			else
				kernel_len = images->os.end - images->os.start;
		}

		printf("[MBOOT] bootm_measure: measuring kernel -> PCR 8 (start=0x%lx, len=0x%lx)\n",
		       kernel_start, kernel_len);
		image_buf = map_sysmem(kernel_start, kernel_len);
		ret = tcg2_measure_data(dev, &elog, 8, kernel_len,
					image_buf, EV_COMPACT_HASH,
					strlen("linux") + 1, (u8 *)"linux");
		if (ret) {
			printf("[MBOOT] bootm_measure: kernel measure FAILED ret=%d\n", ret);
			goto unmap_image;
		}

		rd_len = images->rd_end - images->rd_start;
		printf("[MBOOT] bootm_measure: measuring initrd -> PCR 9 (rd_start=0x%lx, rd_len=0x%x)\n",
		       images->rd_start, rd_len);
		initrd_buf = map_sysmem(images->rd_start, rd_len);
		ret = tcg2_measure_data(dev, &elog, 9, rd_len, initrd_buf,
					EV_COMPACT_HASH, strlen("initrd") + 1,
					(u8 *)"initrd");
		if (ret) {
			printf("[MBOOT] bootm_measure: initrd measure FAILED ret=%d\n", ret);
			goto unmap_initrd;
		}

		if (IS_ENABLED(CONFIG_MEASURE_DEVICETREE)) {
			printf("[MBOOT] bootm_measure: measuring DTB -> PCR 0 (ft_addr=%p, ft_len=0x%x)\n",
			       images->ft_addr, images->ft_len);
			if (IS_ENABLED(CONFIG_MEASURE_DEVICETREE_SANITIZE))
				ret = tcg2_measure_dtb_sanitized(dev, &elog,
								 images->ft_addr,
								 images->ft_len);
			else
				ret = tcg2_measure_data(dev, &elog, 0,
							images->ft_len,
							(u8 *)images->ft_addr,
							EV_TABLE_OF_DEVICES,
							strlen("dts") + 1,
							(u8 *)"dts");
			if (ret) {
				printf("[MBOOT] bootm_measure: DTB measure FAILED ret=%d\n", ret);
				goto unmap_initrd;
			}
		} else {
			printf("[MBOOT] bootm_measure: CONFIG_MEASURE_DEVICETREE not enabled, skipping DTB\n");
		}

		s = env_get("bootargs");
		if (!s)
			s = "";
		printf("[MBOOT] bootm_measure: measuring bootargs -> PCR 1 (len=%zu)\n",
		       strlen(s));
		ret = tcg2_measure_data(dev, &elog, 1, strlen(s) + 1, (u8 *)s,
					EV_PLATFORM_CONFIG_FLAGS,
					strlen(s) + 1, (u8 *)s);
		if (ret)
			printf("[MBOOT] bootm_measure: bootargs measure FAILED ret=%d\n", ret);

		/*
		 * LAST: commit the whole measured state to the DUID-protected
		 * NV index. This must run after every PCR above is final --
		 * it reads them back and extends the index with their
		 * composite. Only a bootloader able to derive the DUID secret
		 * can perform this write, which is what binds the evidence to
		 * the genuine board.
		 */
		printf("[MBOOT] bootm_measure: NV-committing PCR composite\n");
		measure_nv_extend(dev, images->ft_addr);

unmap_initrd:
		unmap_sysmem(initrd_buf);

unmap_image:
		unmap_sysmem(image_buf);
		printf("[MBOOT] bootm_measure: calling measurement_term (error=%d)\n", ret != 0);
		tcg2_measurement_term(dev, &elog, ret != 0);
		free(elog.log);
	} else {
		printf("[MBOOT] bootm_measure: CONFIG_MEASURED_BOOT not enabled\n");
	}

	printf("[MBOOT] bootm_measure: exit ret=%d\n", ret);
	return ret;
}

int bootm_run_states(struct bootm_info *bmi, int states)
{
	struct bootm_headers *images = bmi->images;
	boot_os_fn *boot_fn;
	ulong iflag = 0;
	int ret = 0, need_boot_fn;

	images->state |= states;

	/*
	 * Work through the states and see how far we get. We stop on
	 * any error.
	 */
	if (states & BOOTM_STATE_START)
		ret = bootm_start();

	if (!ret && (states & BOOTM_STATE_PRE_LOAD))
		ret = bootm_pre_load(bmi->addr_img);

	if (!ret && (states & BOOTM_STATE_FINDOS))
		ret = bootm_find_os(bmi->cmd_name, bmi->addr_img);

	if (!ret && (states & BOOTM_STATE_FINDOTHER)) {
		ulong img_addr;

		img_addr = bmi->addr_img ? hextoul(bmi->addr_img, NULL)
			: image_load_addr;
		ret = bootm_find_other(img_addr, bmi->conf_ramdisk,
				       bmi->conf_fdt);
	}

	if (IS_ENABLED(CONFIG_MEASURED_BOOT) && !ret &&
	    (states & BOOTM_STATE_MEASURE))
		bootm_measure(images);

	/* Load the OS */
	if (!ret && (states & BOOTM_STATE_LOADOS)) {
		iflag = bootm_disable_interrupts();
		ret = bootm_load_os(images, 0);
		if (ret && ret != BOOTM_ERR_OVERLAP)
			goto err;
		else if (ret == BOOTM_ERR_OVERLAP)
			ret = 0;
	}

	/* Relocate the ramdisk */
#ifdef CONFIG_SYS_BOOT_RAMDISK_HIGH
	if (!ret && (states & BOOTM_STATE_RAMDISK)) {
		ulong rd_len = images->rd_end - images->rd_start;

		ret = boot_ramdisk_high(&images->lmb, images->rd_start,
			rd_len, &images->initrd_start, &images->initrd_end);
		if (!ret) {
			env_set_hex("initrd_start", images->initrd_start);
			env_set_hex("initrd_end", images->initrd_end);
		}
	}
#endif
#if CONFIG_IS_ENABLED(OF_LIBFDT) && defined(CONFIG_LMB)
	if (!ret && (states & BOOTM_STATE_FDT)) {
		boot_fdt_add_mem_rsv_regions(&images->lmb, images->ft_addr);
		ret = boot_relocate_fdt(&images->lmb, &images->ft_addr,
					&images->ft_len);
	}
#endif

	/* From now on, we need the OS boot function */
	if (ret)
		return ret;
	boot_fn = bootm_os_get_boot_func(images->os.os);
	need_boot_fn = states & (BOOTM_STATE_OS_CMDLINE |
			BOOTM_STATE_OS_BD_T | BOOTM_STATE_OS_PREP |
			BOOTM_STATE_OS_FAKE_GO | BOOTM_STATE_OS_GO);
	if (boot_fn == NULL && need_boot_fn) {
		if (iflag)
			enable_interrupts();
		printf("ERROR: booting os '%s' (%d) is not supported\n",
		       genimg_get_os_name(images->os.os), images->os.os);
		bootstage_error(BOOTSTAGE_ID_CHECK_BOOT_OS);
		return 1;
	}

	/* Call various other states that are not generally used */
	if (!ret && (states & BOOTM_STATE_OS_CMDLINE))
		ret = boot_fn(BOOTM_STATE_OS_CMDLINE, bmi);
	if (!ret && (states & BOOTM_STATE_OS_BD_T))
		ret = boot_fn(BOOTM_STATE_OS_BD_T, bmi);
	if (!ret && (states & BOOTM_STATE_OS_PREP)) {
		int flags = 0;
		/* For Linux OS do all substitutions at console processing */
		if (images->os.os == IH_OS_LINUX)
			flags = BOOTM_CL_ALL;
		ret = bootm_process_cmdline_env(flags);
		if (ret) {
			printf("Cmdline setup failed (err=%d)\n", ret);
			ret = CMD_RET_FAILURE;
			goto err;
		}
		ret = boot_fn(BOOTM_STATE_OS_PREP, bmi);
	}

#ifdef CONFIG_TRACE
	/* Pretend to run the OS, then run a user command */
	if (!ret && (states & BOOTM_STATE_OS_FAKE_GO)) {
		char *cmd_list = env_get("fakegocmd");

		ret = boot_selected_os(BOOTM_STATE_OS_FAKE_GO, bmi, boot_fn);
		if (!ret && cmd_list)
			ret = run_command_list(cmd_list, -1, 0);
	}
#endif

	/* Check for unsupported subcommand. */
	if (ret) {
		printf("subcommand failed (err=%d)\n", ret);
		return ret;
	}

	/* Now run the OS! We hope this doesn't return */
	if (!ret && (states & BOOTM_STATE_OS_GO))
		ret = boot_selected_os(BOOTM_STATE_OS_GO, bmi, boot_fn);

	/* Deal with any fallout */
err:
	if (iflag)
		enable_interrupts();

	if (ret == BOOTM_ERR_UNIMPLEMENTED) {
		bootstage_error(BOOTSTAGE_ID_DECOMP_UNIMPL);
	} else if (ret == BOOTM_ERR_RESET) {
		printf("Resetting the board...\n");
		reset_cpu();
	}

	return ret;
}

int boot_run(struct bootm_info *bmi, const char *cmd, int extra_states)
{
	int states;

	bmi->cmd_name = cmd;
	states = BOOTM_STATE_MEASURE | BOOTM_STATE_OS_PREP |
		BOOTM_STATE_OS_FAKE_GO | BOOTM_STATE_OS_GO;
	if (IS_ENABLED(CONFIG_SYS_BOOT_RAMDISK_HIGH))
		states |= BOOTM_STATE_RAMDISK;
	states |= extra_states;

	return bootm_run_states(bmi, states);
}

int bootm_run(struct bootm_info *bmi)
{
	return boot_run(bmi, "bootm", BOOTM_STATE_START | BOOTM_STATE_FINDOS |
			BOOTM_STATE_PRE_LOAD | BOOTM_STATE_FINDOTHER |
			BOOTM_STATE_LOADOS);
}

int bootz_run(struct bootm_info *bmi)
{
	return boot_run(bmi, "bootz", 0);
}

int booti_run(struct bootm_info *bmi)
{
	return boot_run(bmi, "booti", 0);
}

int bootm_boot_start(ulong addr, const char *cmdline)
{
	char addr_str[30];
	struct bootm_info bmi;
	int states;
	int ret;

	states = BOOTM_STATE_START | BOOTM_STATE_FINDOS | BOOTM_STATE_PRE_LOAD |
		BOOTM_STATE_FINDOTHER | BOOTM_STATE_LOADOS |
		BOOTM_STATE_OS_PREP | BOOTM_STATE_OS_FAKE_GO |
		BOOTM_STATE_OS_GO;
	if (IS_ENABLED(CONFIG_SYS_BOOT_RAMDISK_HIGH))
		states |= BOOTM_STATE_RAMDISK;
	if (IS_ENABLED(CONFIG_PPC) || IS_ENABLED(CONFIG_MIPS))
		states |= BOOTM_STATE_OS_CMDLINE;
	images.state |= states;

	snprintf(addr_str, sizeof(addr_str), "%lx", addr);

	ret = env_set("bootargs", cmdline);
	if (ret) {
		printf("Failed to set cmdline\n");
		return ret;
	}
	bootm_init(&bmi);
	bmi.addr_img = addr_str;
	bmi.cmd_name = "bootm";
	ret = bootm_run_states(&bmi, states);

	return ret;
}

void bootm_init(struct bootm_info *bmi)
{
	memset(bmi, '\0', sizeof(struct bootm_info));
	bmi->boot_progress = true;
	if (IS_ENABLED(CONFIG_CMD_BOOTM))
		bmi->images = &images;
}

/**
 * switch_to_non_secure_mode() - switch to non-secure mode
 *
 * This routine is overridden by architectures requiring this feature.
 */
void __weak switch_to_non_secure_mode(void)
{
}

#else /* USE_HOSTCC */

#if defined(CONFIG_FIT_SIGNATURE)
static int bootm_host_load_image(const void *fit, int req_image_type,
				 int cfg_noffset)
{
	const char *fit_uname_config = NULL;
	ulong data, len;
	struct bootm_headers images;
	int noffset;
	ulong load_end, buf_size;
	uint8_t image_type;
	uint8_t image_comp;
	void *load_buf;
	int ret;

	fit_uname_config = fdt_get_name(fit, cfg_noffset, NULL);
	memset(&images, '\0', sizeof(images));
	images.verify = 1;
	noffset = fit_image_load(&images, (ulong)fit,
		NULL, &fit_uname_config,
		IH_ARCH_DEFAULT, req_image_type, -1,
		FIT_LOAD_IGNORED, &data, &len);
	if (noffset < 0)
		return noffset;
	if (fit_image_get_type(fit, noffset, &image_type)) {
		puts("Can't get image type!\n");
		return -EINVAL;
	}

	if (fit_image_get_comp(fit, noffset, &image_comp))
		image_comp = IH_COMP_NONE;

	/* Allow the image to expand by a factor of 4, should be safe */
	buf_size = (1 << 20) + len * 4;
	load_buf = malloc(buf_size);
	ret = image_decomp(image_comp, 0, data, image_type, load_buf,
			   (void *)data, len, buf_size, &load_end);
	free(load_buf);

	if (ret) {
		ret = handle_decomp_error(image_comp, load_end - 0, buf_size, ret);
		if (ret != BOOTM_ERR_UNIMPLEMENTED)
			return ret;
	}

	return 0;
}

int bootm_host_load_images(const void *fit, int cfg_noffset)
{
	static uint8_t image_types[] = {
		IH_TYPE_KERNEL,
		IH_TYPE_FLATDT,
		IH_TYPE_RAMDISK,
	};
	int err = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(image_types); i++) {
		int ret;

		ret = bootm_host_load_image(fit, image_types[i], cfg_noffset);
		if (!err && ret && ret != -ENOENT)
			err = ret;
	}

	/* Return the first error we found */
	return err;
}
#endif

#endif /* ndef USE_HOSTCC */
