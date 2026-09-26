/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Raspberry Pi firmware cryptography service (rpi-fw-crypto) over the VideoCore
 * property mailbox. The private key lives in OTP and is used by the firmware;
 * U-Boot only ever sees public keys and signatures.
 *
 * Tag numbers and message layouts follow raspberrypi/utils rpifwcrypto.c.
 */
#ifndef __RPI_FWCRYPTO_H
#define __RPI_FWCRYPTO_H

#include <linux/types.h>

#define RPI_FWC_KEY_DEVICE		1	/* the single OTP key slot on BCM2712 */

/* key status bits (rpifwcrypto.h) */
#define RPI_FWC_STATUS_DEVICE		(1 << 0)
#define RPI_FWC_STATUS_READ_LOCKED	(1 << 8)
#define RPI_FWC_STATUS_GEN_LOCKED	(1 << 9)
#define RPI_FWC_STATUS_SIGN_LOCKED	(1 << 10)
#define RPI_FWC_STATUS_HMAC_LOCKED	(1 << 11)
#define RPI_FWC_STATUS_USAGE_LOCKED	(1 << 12)
#define RPI_FWC_STATUS_ALL_LOCKS	(RPI_FWC_STATUS_READ_LOCKED | RPI_FWC_STATUS_GEN_LOCKED | \
					 RPI_FWC_STATUS_SIGN_LOCKED | RPI_FWC_STATUS_HMAC_LOCKED | \
					 RPI_FWC_STATUS_USAGE_LOCKED)

#define RPI_FWC_PUBKEY_MAX		512
#define RPI_FWC_SIG_MAX			128

int rpi_fwc_get_key_status(u32 key_id, u32 *status);
/* Adds lock bits; the firmware ORs them into the current status until reset. */
int rpi_fwc_set_key_status(u32 key_id, u32 status);
/* DER SubjectPublicKeyInfo */
int rpi_fwc_get_pubkey(u32 key_id, u8 *out, size_t max, size_t *len);
/* ECDSA P-256 over a 32-byte digest; DER SEQUENCE { r, s } */
int rpi_fwc_sign(u32 key_id, const u8 digest[32], u8 *sig, size_t max, size_t *len);
/* Last firmware crypto error code (RPI_FW_CRYPTO_STATUS), or negative on mailbox failure */
int rpi_fwc_last_error(void);
/* Convert a DER ECDSA signature to fixed 32-byte r and s (big-endian). */
int rpi_fwc_der_to_rs(const u8 *der, size_t len, u8 r[32], u8 s[32]);

struct udevice;
struct tpm2_auth_session;
/*
 * Open a TPM policy session and satisfy TPM2_PolicySigned with a signature made by the
 * firmware over SHA256(nonceTPM || 0 || cp_hash || policy_ref). The firmware public key is
 * loaded into TPM_RH_NULL; *key_handle must be flushed by the caller, as must the session.
 */
int rpi_fwc_policy_signed_session(struct udevice *dev, const u8 cp_hash[32],
				  const char *policy_ref, struct tpm2_auth_session *session,
				  u32 *key_handle);
/* Extract x, y from the firmware's DER P-256 SubjectPublicKeyInfo (91 bytes). */
int rpi_fwc_pubkey_xy(u32 key_id, u8 x[32], u8 y[32]);

#endif
