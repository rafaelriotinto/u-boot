// SPDX-License-Identifier: GPL-2.0+
/*
 * Raspberry Pi firmware cryptography service over the property mailbox.
 * See include/rpi_fwcrypto.h.
 */
#include <command.h>
#include <env.h>
#include <hexdump.h>
#include <malloc.h>
#include <memalign.h>
#include <rpi_fwcrypto.h>
#include <u-boot/sha256.h>
#include <asm/arch/mbox.h>
#include <dm.h>
#include <tpm-v2.h>
#include <tpm_api.h>
#include <linux/errno.h>
#include <linux/string.h>

#define TAG_GET_CRYPTO_LAST_ERROR	0x0003008e
#define TAG_GET_CRYPTO_KEY_STATUS	0x00030090
#define TAG_SET_CRYPTO_KEY_STATUS	0x00038090
#define TAG_GET_CRYPTO_ECDSA_SIGN	0x00030091
#define TAG_GET_CRYPTO_PUBLIC_KEY	0x00030093

#define VC_ERROR			0x80000000

/* four-word value buffer, as rpifwcrypto's struct firmware_msg */
struct fwc_small_msg {
	struct bcm2835_mbox_hdr hdr;
	struct bcm2835_mbox_tag_hdr tag_hdr;
	u32 value[4];
	u32 end_tag;
};

struct fwc_sign_msg {
	struct bcm2835_mbox_hdr hdr;
	struct bcm2835_mbox_tag_hdr tag_hdr;
	union {
		struct { u32 flags, key_id, length; u8 hash[32]; } req;
		struct { u32 status, length; u8 sig[RPI_FWC_SIG_MAX]; } resp;
	} body;
	u32 end_tag;
};

struct fwc_pubkey_msg {
	struct bcm2835_mbox_hdr hdr;
	struct bcm2835_mbox_tag_hdr tag_hdr;
	union {
		struct { u32 flags, key_id; } req;
		struct { u32 status, length; u8 pubkey[RPI_FWC_PUBKEY_MAX]; } resp;
	} body;
	u32 end_tag;
};

static void fwc_hdr(struct bcm2835_mbox_hdr *hdr, struct bcm2835_mbox_tag_hdr *t,
		    size_t total, u32 tag, u32 buf_size)
{
	hdr->buf_size = total;
	hdr->code = 0;
	t->tag = tag;
	t->val_buf_size = buf_size;
	t->val_len = 0;		/* as the reference library */
}

static int fwc_small(u32 tag, u32 buf_size, u32 v0, u32 v1, u32 *out0)
{
	ALLOC_CACHE_ALIGN_BUFFER(struct fwc_small_msg, msg, 1);
	int ret;

	memset(msg, 0, sizeof(*msg));
	fwc_hdr(&msg->hdr, &msg->tag_hdr, sizeof(*msg), tag, buf_size);
	msg->value[0] = v0;
	msg->value[1] = v1;
	ret = bcm2835_mbox_call_prop(BCM2835_MBOX_PROP_CHAN, &msg->hdr);
	if (ret)
		return -EIO;
	if (out0)
		*out0 = msg->value[0];
	return 0;
}

int rpi_fwc_last_error(void)
{
	u32 v;

	if (fwc_small(TAG_GET_CRYPTO_LAST_ERROR, 4, 0, 0, &v))
		return -EIO;
	return v;
}

int rpi_fwc_get_key_status(u32 key_id, u32 *status)
{
	u32 v;

	if (fwc_small(TAG_GET_CRYPTO_KEY_STATUS, 4, key_id, 0, &v))
		return -EIO;
	if (v & VC_ERROR)
		return -ENOENT;
	*status = v;
	return 0;
}

int rpi_fwc_set_key_status(u32 key_id, u32 status)
{
	return fwc_small(TAG_SET_CRYPTO_KEY_STATUS, 8, key_id, status, NULL);
}

int rpi_fwc_get_pubkey(u32 key_id, u8 *out, size_t max, size_t *len)
{
	ALLOC_CACHE_ALIGN_BUFFER(struct fwc_pubkey_msg, msg, 1);

	memset(msg, 0, sizeof(*msg));
	fwc_hdr(&msg->hdr, &msg->tag_hdr, sizeof(*msg), TAG_GET_CRYPTO_PUBLIC_KEY,
		4 + 4 + RPI_FWC_PUBKEY_MAX);
	msg->body.req.key_id = key_id;
	if (bcm2835_mbox_call_prop(BCM2835_MBOX_PROP_CHAN, &msg->hdr))
		return -EIO;
	if ((msg->body.resp.status & VC_ERROR) || msg->body.resp.length > max ||
	    msg->body.resp.length > RPI_FWC_PUBKEY_MAX)
		return -EINVAL;
	memcpy(out, msg->body.resp.pubkey, msg->body.resp.length);
	*len = msg->body.resp.length;
	return 0;
}

int rpi_fwc_sign(u32 key_id, const u8 digest[32], u8 *sig, size_t max, size_t *len)
{
	ALLOC_CACHE_ALIGN_BUFFER(struct fwc_sign_msg, msg, 1);

	memset(msg, 0, sizeof(*msg));
	fwc_hdr(&msg->hdr, &msg->tag_hdr, sizeof(*msg), TAG_GET_CRYPTO_ECDSA_SIGN, 128);
	msg->body.req.key_id = key_id;
	msg->body.req.length = 32;
	memcpy(msg->body.req.hash, digest, 32);
	if (bcm2835_mbox_call_prop(BCM2835_MBOX_PROP_CHAN, &msg->hdr))
		return -EIO;
	if (msg->body.resp.length > max || msg->body.resp.length > RPI_FWC_SIG_MAX ||
	    msg->body.resp.length < 8)
		return -EINVAL;
	memcpy(sig, msg->body.resp.sig, msg->body.resp.length);
	*len = msg->body.resp.length;
	return 0;
}

/* DER: 30 L 02 Lr r 02 Ls s ; integers may carry a leading 00 or be shorter than 32 bytes */
static int der_int(const u8 **p, const u8 *end, u8 out[32])
{
	size_t l;

	if (*p + 2 > end || (*p)[0] != 0x02)
		return -EINVAL;
	l = (*p)[1];
	*p += 2;
	if (l == 0 || *p + l > end)
		return -EINVAL;
	while (l > 32 && **p == 0) {
		(*p)++;
		l--;
	}
	if (l > 32)
		return -EINVAL;
	memset(out, 0, 32);
	memcpy(out + 32 - l, *p, l);
	*p += l;
	return 0;
}

int rpi_fwc_der_to_rs(const u8 *der, size_t len, u8 r[32], u8 s[32])
{
	const u8 *p = der, *end = der + len;

	if (len < 8 || p[0] != 0x30 || p[1] != len - 2)
		return -EINVAL;
	p += 2;
	if (der_int(&p, end, r) || der_int(&p, end, s) || p != end)
		return -EINVAL;
	return 0;
}


/* DER prefix of a P-256 SubjectPublicKeyInfo up to and including the 0x04 point marker */
static const u8 p256_spki_prefix[27] = {
	0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
};

int rpi_fwc_pubkey_xy(u32 key_id, u8 x[32], u8 y[32])
{
	u8 der[RPI_FWC_PUBKEY_MAX];
	size_t len;
	int ret;

	ret = rpi_fwc_get_pubkey(key_id, der, sizeof(der), &len);
	if (ret)
		return ret;
	if (len != sizeof(p256_spki_prefix) + 64 ||
	    memcmp(der, p256_spki_prefix, sizeof(p256_spki_prefix)))
		return -EINVAL;
	memcpy(x, der + sizeof(p256_spki_prefix), 32);
	memcpy(y, der + sizeof(p256_spki_prefix) + 32, 32);
	return 0;
}

int rpi_fwc_policy_signed_session(struct udevice *dev, const u8 cp_hash[32],
				  const char *policy_ref, struct tpm2_auth_session *session,
				  u32 *key_handle)
{
	u8 x[32], y[32], ahash[32], der[RPI_FWC_SIG_MAX], r[32], s[32];
	u16 ref_len = policy_ref ? strlen(policy_ref) : 0;
	size_t der_len;
	int ret;

	*key_handle = 0;
	session->handle = 0;
	ret = rpi_fwc_pubkey_xy(RPI_FWC_KEY_DEVICE, x, y);
	if (ret)
		return ret;
	ret = tpm2_load_external_ecc_p256(dev, x, y, key_handle);
	if (ret)
		goto fail;
	ret = tpm2_start_auth_session(dev, TPM_SE_POLICY, session);
	if (ret)
		goto fail;
	tpm2_policy_signed_ahash(session, 0, cp_hash, (const u8 *)policy_ref, ref_len, ahash);
	ret = rpi_fwc_sign(RPI_FWC_KEY_DEVICE, ahash, der, sizeof(der), &der_len);
	if (ret)
		goto fail;
	ret = rpi_fwc_der_to_rs(der, der_len, r, s);
	if (ret)
		goto fail;
	ret = tpm2_policy_signed(dev, session, *key_handle, 0, cp_hash,
				 (const u8 *)policy_ref, ref_len, r, s);
	if (ret)
		goto fail;
	return 0;
fail:
	if (session->handle)
		tpm2_flush_context(dev, session->handle);
	if (*key_handle)
		tpm2_flush_context(dev, *key_handle);
	session->handle = 0;
	*key_handle = 0;
	return ret ? ret : -EIO;
}

#if CONFIG_IS_ENABLED(MEASURE_NV_AUTH_FWKEY)
#include <bootm.h>
#include <hang.h>
#include <cpu_func.h>
#include <linux/delay.h>
/*
 * Runs on every ARM boot path immediately before "Starting kernel". Nothing after
 * U-Boot may use the firmware key until the next reset: lock every operation, read
 * the status back, and refuse to start the kernel if the locks are not all in place.
 */
void board_quiesce_devices(void)
{
	u32 st = 0;
	int ret;

	ret = rpi_fwc_set_key_status(RPI_FWC_KEY_DEVICE, RPI_FWC_STATUS_ALL_LOCKS);
	if (!ret)
		ret = rpi_fwc_get_key_status(RPI_FWC_KEY_DEVICE, &st);
	if (ret || (st & RPI_FWC_STATUS_ALL_LOCKS) != RPI_FWC_STATUS_ALL_LOCKS) {
		printf("[FWKEY] could not lock the firmware key (ret %d, status 0x%08x) -- "
		       "refusing to start the kernel; resetting\n", ret, st);
		mdelay(500);
		do_reset(NULL, 0, 0, NULL);
		hang();
	}
	printf("[FWKEY] firmware key locked until reset (status 0x%08x)\n", st);
}
#endif

#if CONFIG_IS_ENABLED(RPI_FACTORY_GUARD)
#include <bootm.h>
#include <hang.h>
#include <linux/delay.h>
/* Factory U-Boot: only a board whose firmware key slot is still blank may run the factory image. */
void board_quiesce_devices(void)
{
	u8 pub[RPI_FWC_PUBKEY_MAX];
	size_t len;

	if (!rpi_fwc_get_pubkey(RPI_FWC_KEY_DEVICE, pub, sizeof(pub), &len)) {
		printf("[FACTORY] this board is already provisioned (firmware key present) -- "
		       "refusing to start the factory image; resetting\n");
		mdelay(500);
		do_reset(NULL, 0, 0, NULL);
		hang();
	}
	printf("[FACTORY] firmware key slot blank: factory image allowed\n");
}
#endif

#if CONFIG_IS_ENABLED(CMDLINE) && IS_ENABLED(CONFIG_CMD_RPI_FWCRYPTO)
static void set_hex_env(const char *name, const u8 *buf, size_t len)
{
	char *hex = malloc(2 * len + 1);

	if (!hex)
		return;
	bin2hex(hex, buf, len);
	hex[2 * len] = '\0';
	env_set(name, hex);
	free(hex);
}

/*
 * fwcrypto status | pubkey | sign-test | lock
 * Results are also stored in environment variables fwc_* so that a script can
 * export them (env export -t) to a file.
 */
static int do_fwcrypto(struct cmd_tbl *cmdtp, int flag, int argc, char *const argv[])
{
	u8 buf[RPI_FWC_PUBKEY_MAX], r[32], s[32], digest[32];
	size_t len;
	u32 st;
	int ret;

	if (argc < 2)
		return CMD_RET_USAGE;

	if (!strcmp(argv[1], "status")) {
		ret = rpi_fwc_get_key_status(RPI_FWC_KEY_DEVICE, &st);
		if (ret) {
			printf("fwcrypto: status failed %d (fw error %d)\n", ret, rpi_fwc_last_error());
			env_set("fwc_status", "error");
			return CMD_RET_FAILURE;
		}
		printf("fwcrypto: key %d status 0x%08x\n", RPI_FWC_KEY_DEVICE, st);
		env_set_hex("fwc_status", st);
		return 0;
	}
	if (!strcmp(argv[1], "pubkey")) {
		ret = rpi_fwc_get_pubkey(RPI_FWC_KEY_DEVICE, buf, sizeof(buf), &len);
		if (ret) {
			printf("fwcrypto: pubkey failed %d (fw error %d)\n", ret, rpi_fwc_last_error());
			env_set("fwc_pubkey", "error");
			return CMD_RET_FAILURE;
		}
		printf("fwcrypto: public key %zu bytes\n", len);
		set_hex_env("fwc_pubkey", buf, len);
		return 0;
	}
	if (!strcmp(argv[1], "sign-test")) {
		static const char msg[] = "u-boot rpi-fw-crypto test";

		sha256_csum_wd((const u8 *)msg, sizeof(msg) - 1, digest, CHUNKSZ_SHA256);
		set_hex_env("fwc_digest", digest, 32);
		ret = rpi_fwc_sign(RPI_FWC_KEY_DEVICE, digest, buf, RPI_FWC_SIG_MAX, &len);
		if (ret) {
			int e = rpi_fwc_last_error();

			printf("fwcrypto: sign refused %d (fw error %d)\n", ret, e);
			env_set_hex("fwc_sign_err", e);
			env_set("fwc_sig", "refused");
			return CMD_RET_FAILURE;
		}
		set_hex_env("fwc_sig", buf, len);
		if (rpi_fwc_der_to_rs(buf, len, r, s)) {
			printf("fwcrypto: signature %zu bytes, DER parse FAILED\n", len);
			env_set("fwc_sig_rs", "parse-error");
			return CMD_RET_FAILURE;
		}
		memcpy(buf, r, 32);
		memcpy(buf + 32, s, 32);
		set_hex_env("fwc_sig_rs", buf, 64);
		printf("fwcrypto: signature %zu bytes (DER), r||s parsed\n", len);
		return 0;
	}
	if (!strcmp(argv[1], "lock")) {
		ret = rpi_fwc_set_key_status(RPI_FWC_KEY_DEVICE, RPI_FWC_STATUS_READ_LOCKED |
					     RPI_FWC_STATUS_SIGN_LOCKED | RPI_FWC_STATUS_HMAC_LOCKED |
					     RPI_FWC_STATUS_GEN_LOCKED | RPI_FWC_STATUS_USAGE_LOCKED);
		if (ret || rpi_fwc_get_key_status(RPI_FWC_KEY_DEVICE, &st) ||
		    (st & RPI_FWC_STATUS_ALL_LOCKS) != RPI_FWC_STATUS_ALL_LOCKS) {
			printf("fwcrypto: LOCK FAILED (ret %d, status 0x%08x)\n", ret, st);
			env_set("fwc_lock", "failed");
			return CMD_RET_FAILURE;
		}
		printf("fwcrypto: all locks set, status 0x%08x\n", st);
		env_set_hex("fwc_lock", st);
		return 0;
	}
	if (!strcmp(argv[1], "tpmtest") && argc == 3) {
		/* Signed NV_Extend of a fixed value into the index at HR_NV_INDEX + offset */
		static const char ref[] = "rp5-nv-meas-v1";
		static const char tmsg[] = "u-boot policysigned nv-extend test";
		u32 off = hextoul(argv[2], NULL), key_handle, rc;
		struct tpm2_auth_session session;
		u8 nv_name[68], name[TPM2_SHA256_NAME_SIZE], x[32], y[32], data[32], cph[32];
		u32 nv_name_len = sizeof(nv_name);
		struct udevice *dev;

		if (uclass_first_device_err(UCLASS_TPM, &dev)) {
			env_set("fwc_tpmtest", "no-tpm");
			return CMD_RET_FAILURE;
		}
		rc = tpm_auto_start(dev);
		env_set_hex("fwc_tpm_start", rc);
		if (!rpi_fwc_pubkey_xy(RPI_FWC_KEY_DEVICE, x, y)) {
			tpm2_ecc_p256_name(x, y, name);
			set_hex_env("fwc_key_name", name, sizeof(name));
		}
		sha256_csum_wd((const u8 *)tmsg, sizeof(tmsg) - 1, data, CHUNKSZ_SHA256);
		set_hex_env("fwc_ext_data", data, 32);
		rc = tpm2_nv_read_public(dev, off, nv_name, &nv_name_len);
		if (rc) {
			env_set_hex("fwc_tpmtest", rc);
			printf("fwcrypto: nv_read_public 0x%x failed 0x%x\n", off, rc);
			return CMD_RET_FAILURE;
		}
		set_hex_env("fwc_nv_name", nv_name, nv_name_len);
		tpm2_nv_extend_cphash(nv_name, nv_name_len, data, 32, cph);
		ret = rpi_fwc_policy_signed_session(dev, cph, ref, &session, &key_handle);
		if (ret) {
			env_set_hex("fwc_tpmtest", (u32)ret);
			printf("fwcrypto: policy-signed session failed 0x%x\n", ret);
			return CMD_RET_FAILURE;
		}
		rc = tpm2_nv_extend(dev, off, nv_name, nv_name_len, NULL, 0, &session, data, 32);
		tpm2_flush_context(dev, session.handle);
		tpm2_flush_context(dev, key_handle);
		env_set_hex("fwc_tpmtest", rc);
		printf("fwcrypto: signed NV extend %s (0x%x)\n", rc ? "FAILED" : "OK", rc);
		return rc ? CMD_RET_FAILURE : 0;
	}
	return CMD_RET_USAGE;
}

U_BOOT_CMD(fwcrypto, 3, 0, do_fwcrypto,
	   "Raspberry Pi firmware crypto service (OTP key)",
	   "status    - key status bits\n"
	   "fwcrypto pubkey    - public key (DER) into $fwc_pubkey\n"
	   "fwcrypto sign-test - sign SHA-256 of a fixed string, into $fwc_sig / $fwc_sig_rs\n"
	   "fwcrypto lock      - set READ/SIGN/HMAC/GEN/USAGE locks until reset and verify\n"
	   "fwcrypto tpmtest <nv offset> - PolicySigned NV_Extend of a fixed value");
#endif
