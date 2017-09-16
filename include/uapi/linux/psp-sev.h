
/*
 * Userspace interface for AMD Secure Encrypted Virtualization (SEV)
 *
 * Copyright (C) 2016-2017 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __PSP_SEV_USER_H__
#define __PSP_SEV_USER_H__

#include <linux/types.h>

/**
 * SEV platform commands
 */
enum {
	SEV_USER_CMD_FACTORY_RESET = 0,
	SEV_USER_CMD_PLATFORM_STATUS,
	SEV_USER_CMD_PEK_GEN,
	SEV_USER_CMD_PEK_CSR,
	SEV_USER_CMD_PDH_GEN,
	SEV_USER_CMD_PDH_CERT_EXPORT,
	SEV_USER_CMD_PEK_CERT_IMPORT,

	SEV_USER_CMD_MAX,
};

/**
 * struct sev_user_data_status - PLATFORM_STATUS command parameters
 *
 * @major: major API version
 * @minor: minor API version
 * @state: platform state
 * @owner: self-owned or externally owned
 * @config: platform config flags
 * @build: firmware build id for API version
 * @guest_count: number of active guests
 */
struct sev_user_data_status {
	__u8 api_major;				/* Out */
	__u8 api_minor;				/* Out */
	__u8 state;				/* Out */
	__u8 owner : 1;				/* Out */
	__u8 reserved1 : 7;
	__u32 config : 1;			/* Out */
	__u32 reserved2 : 23;
	__u32 build : 8;			/* Out */
	__u32 guest_count;			/* Out */
} __attribute__ ((__packed__));

/**
 * struct sev_user_data_pek_csr - PEK_CSR command parameters
 *
 * @address: PEK certificate chain
 * @length: length of certificate
 */
struct sev_user_data_pek_csr {
	__u64 address;				/* In */
	__u32 length;				/* In/Out */
};

/**
 * struct sev_user_data_cert_import - PEK_CERT_IMPORT command parameters
 *
 * @pek_address: PEK certificate chain
 * @pek_len: length of PEK certificate
 * @oca_address: OCA certificate chain
 * @oca_len: length of OCA certificate
 */
struct sev_user_data_pek_cert_import {
	__u64 pek_cert_address;			/* In */
	__u32 pek_cert_len;			/* In */
	__u64 oca_cert_address;			/* In */
	__u32 oca_cert_len;			/* In */
};

/**
 * struct sev_user_data_pdh_cert_export - PDH_CERT_EXPORT command parameters
 *
 * @pdh_address: PDH certificate address
 * @pdh_len: length of PDH certificate
 * @cert_chain_address: PDH certificate chain
 * @cert_chain_len: length of PDH certificate chain
 */
struct sev_user_data_pdh_cert_export {
	__u64 pdh_cert_address;			/* In */
	__u32 pdh_cert_len;			/* In/Out */
	__u64 cert_chain_address;		/* In */
	__u32 cert_chain_len;			/* In/Out */
};

/**
 * struct sev_issue_cmd - SEV ioctl parameters
 *
 * @cmd: SEV commands to execute
 * @opaque: pointer to the command structure
 * @error: SEV FW return code on failure
 */
struct sev_issue_cmd {
	__u32 cmd;				/* In */
	__u64 data;				/* In */
	__u32 error;				/* Out */
};

#define SEV_IOC_TYPE		'S'
#define SEV_ISSUE_CMD	_IOWR(SEV_IOC_TYPE, 0x0, struct sev_issue_cmd)

#endif /* __PSP_USER_SEV_H */
