/*
 * AMD Platform Security Processor (PSP) interface
 *
 * Copyright (C) 2016-2017 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/hw_random.h>
#include <linux/ccp.h>

#include <uapi/linux/psp-sev.h>

#include "sp-dev.h"
#include "psp-dev.h"

#define DEVICE_NAME	"sev"

static unsigned int sev_poll;
module_param(sev_poll, uint, 0444);
MODULE_PARM_DESC(sev_poll, "Poll for sev command completion - any non-zero value");

DEFINE_MUTEX(sev_cmd_mutex);
static bool sev_fops_registered;

const struct psp_vdata psp_entry = {
	.offset = 0x10500,
};

static struct psp_device *psp_alloc_struct(struct sp_device *sp)
{
	struct device *dev = sp->dev;
	struct psp_device *psp;

	psp = devm_kzalloc(dev, sizeof(*psp), GFP_KERNEL);
	if (!psp)
		return NULL;

	psp->dev = dev;
	psp->sp = sp;

	snprintf(psp->name, sizeof(psp->name), "psp-%u", sp->ord);

	return psp;
}

irqreturn_t psp_irq_handler(int irq, void *data)
{
	struct psp_device *psp = data;
	unsigned int status;

	/* read the interrupt status */
	status = ioread32(psp->io_regs + PSP_P2CMSG_INTSTS);

	/* check if its command completion */
	if (status & (1 << PSP_CMD_COMPLETE_REG)) {
		int reg;

		/* check if its SEV command completion */
		reg = ioread32(psp->io_regs + PSP_CMDRESP);
		if (reg & PSP_CMDRESP_RESP) {
			psp->sev_int_rcvd = 1;
			wake_up(&psp->sev_int_queue);
		}
	}

	/* clear the interrupt status by writing 1 */
	iowrite32(status, psp->io_regs + PSP_P2CMSG_INTSTS);

	return IRQ_HANDLED;
}

static struct psp_device *psp_get_master_device(void)
{
	struct sp_device *sp = sp_get_psp_master_device();

	return sp ? sp->psp_data : NULL;
}

static int sev_wait_cmd_poll(struct psp_device *psp, unsigned int timeout,
			     unsigned int *reg)
{
	int wait = timeout * 10;	/* 100ms sleep => timeout * 10 */

	while (--wait) {
		msleep(100);

		*reg = ioread32(psp->io_regs + PSP_CMDRESP);
		if (*reg & PSP_CMDRESP_RESP)
			break;
	}

	if (!wait) {
		dev_err(psp->dev, "sev command timed out\n");
		return -ETIMEDOUT;
	}

	return 0;
}

static int sev_wait_cmd_ioc(struct psp_device *psp, unsigned int *reg)
{
	psp->sev_int_rcvd = 0;

	wait_event(psp->sev_int_queue, psp->sev_int_rcvd);
	*reg = ioread32(psp->io_regs + PSP_CMDRESP);

	return 0;
}

static int sev_wait_cmd(struct psp_device *psp, unsigned int *reg)
{
	return (*reg & PSP_CMDRESP_IOC) ? sev_wait_cmd_ioc(psp, reg)
					: sev_wait_cmd_poll(psp, 10, reg);
}

static int sev_cmd_buffer_len(int cmd)
{
	switch (cmd) {
	case SEV_CMD_INIT:
		return sizeof(struct sev_data_init);
	case SEV_CMD_PLATFORM_STATUS:
		return sizeof(struct sev_data_status);
	case SEV_CMD_PEK_CSR:
		return sizeof(struct sev_data_pek_csr);
	case SEV_CMD_PEK_CERT_IMPORT:
		return sizeof(struct sev_data_pek_cert_import);
	case SEV_CMD_PDH_CERT_EXPORT:
		return sizeof(struct sev_data_pdh_cert_export);
	case SEV_CMD_LAUNCH_START:
		return sizeof(struct sev_data_launch_start);
	case SEV_CMD_LAUNCH_UPDATE_DATA:
		return sizeof(struct sev_data_launch_update_data);
	case SEV_CMD_LAUNCH_UPDATE_VMSA:
		return sizeof(struct sev_data_launch_update_vmsa);
	case SEV_CMD_LAUNCH_FINISH:
		return sizeof(struct sev_data_launch_finish);
	case SEV_CMD_LAUNCH_UPDATE_SECRET:
		return sizeof(struct sev_data_launch_secret);
	case SEV_CMD_LAUNCH_MEASURE:
		return sizeof(struct sev_data_launch_measure);
	case SEV_CMD_ACTIVATE:
		return sizeof(struct sev_data_activate);
	case SEV_CMD_DEACTIVATE:
		return sizeof(struct sev_data_deactivate);
	case SEV_CMD_DECOMMISSION:
		return sizeof(struct sev_data_decommission);
	case SEV_CMD_GUEST_STATUS:
		return sizeof(struct sev_data_guest_status);
	case SEV_CMD_DBG_DECRYPT:
	case SEV_CMD_DBG_ENCRYPT:
		return sizeof(struct sev_data_dbg);
	case SEV_CMD_SEND_START:
		return sizeof(struct sev_data_send_start);
	case SEV_CMD_SEND_UPDATE_DATA:
		return sizeof(struct sev_data_send_update_data);
	case SEV_CMD_SEND_UPDATE_VMSA:
		return sizeof(struct sev_data_send_update_vmsa);
	case SEV_CMD_SEND_FINISH:
		return sizeof(struct sev_data_send_finish);
	case SEV_CMD_RECEIVE_START:
		return sizeof(struct sev_data_receive_start);
	case SEV_CMD_RECEIVE_UPDATE_DATA:
		return sizeof(struct sev_data_receive_update_data);
	case SEV_CMD_RECEIVE_UPDATE_VMSA:
		return sizeof(struct sev_data_receive_update_vmsa);
	case SEV_CMD_RECEIVE_FINISH:
		return sizeof(struct sev_data_receive_finish);
	default:
		return 0;
	}

	return 0;
}

static int sev_handle_cmd(int cmd, void *data, int *psp_ret)
{
	struct psp_device *psp = psp_get_master_device();
	unsigned int phys_lsb, phys_msb;
	unsigned int reg, ret;

	if (!psp)
		return -ENODEV;

	/* Set the physical address for the PSP */
	phys_lsb = data ? lower_32_bits(__psp_pa(data)) : 0;
	phys_msb = data ? upper_32_bits(__psp_pa(data)) : 0;

	dev_dbg(psp->dev, "sev command id %#x buffer 0x%08x%08x\n",
			cmd, phys_msb, phys_lsb);
	print_hex_dump_debug("(in):  ", DUMP_PREFIX_OFFSET, 16, 2, data,
			sev_cmd_buffer_len(cmd), false);

	/* Only one command at a time... */
	mutex_lock(&sev_cmd_mutex);

	iowrite32(phys_lsb, psp->io_regs + PSP_CMDBUFF_ADDR_LO);
	iowrite32(phys_msb, psp->io_regs + PSP_CMDBUFF_ADDR_HI);

	reg = cmd;
	reg <<= PSP_CMDRESP_CMD_SHIFT;
	reg |= sev_poll ? 0 : PSP_CMDRESP_IOC;
	iowrite32(reg, psp->io_regs + PSP_CMDRESP);

	ret = sev_wait_cmd(psp, &reg);
	if (ret)
		goto unlock;

	if (psp_ret)
		*psp_ret = reg & PSP_CMDRESP_ERR_MASK;

	if (reg & PSP_CMDRESP_ERR_MASK) {
		dev_dbg(psp->dev, "sev command %#x failed (%#010x)\n",
			cmd, reg & PSP_CMDRESP_ERR_MASK);
		ret = -EIO;
	}

unlock:
	mutex_unlock(&sev_cmd_mutex);
	print_hex_dump_debug("(out): ", DUMP_PREFIX_OFFSET, 16, 2, data,
			sev_cmd_buffer_len(cmd), false);
	return ret;
}

static int sev_platform_get_state(int *state, int *error)
{
	struct sev_data_status *data;
	int ret;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	ret = sev_handle_cmd(SEV_CMD_PLATFORM_STATUS, data, error);
	if (!ret)
		*state = data->state;

	kfree(data);
	return ret;
}

static int sev_firmware_init(int *error)
{
	struct sev_data_init *data;
	int rc;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	rc = sev_handle_cmd(SEV_CMD_INIT, data, error);

	kfree(data);
	return rc;
}

static inline int sev_ioctl_factory_reset(struct sev_issue_cmd *argp)
{
	return sev_handle_cmd(SEV_CMD_FACTORY_RESET, 0, &argp->error);
}

static int sev_ioctl_platform_status(struct sev_issue_cmd *argp)
{
	struct sev_data_status *data;
	int ret;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	ret = sev_handle_cmd(SEV_CMD_PLATFORM_STATUS, data, &argp->error);
	if (ret)
		goto e_free;

	if (copy_to_user((void __user *)(uintptr_t) argp->data,
			 data, sizeof(*data))) {
		ret = -EFAULT;
		goto e_free;
	}
e_free:
	kfree(data);
	return ret;
}

static void *copy_user_blob(u64 __user uaddr, u32 len)
{
	void *data;

	if (!uaddr || !len)
		return ERR_PTR(-EINVAL);

	/* verify that blob length does not exceed our limit */
	if (len > SEV_FW_BLOB_MAX_SIZE)
		return ERR_PTR(-EINVAL);

	data = kmalloc(len, GFP_KERNEL);
	if (!data)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(data, (void __user *)(uintptr_t)uaddr, len))
		goto e_free;

	return data;
e_free:
	kfree(data);
	return ERR_PTR(-EFAULT);
}

static int sev_ioctl_pek_csr(struct sev_issue_cmd *argp)
{
	struct sev_user_data_pek_csr input;
	struct sev_data_pek_csr *data;
	int do_shutdown = 0;
	int ret, state;
	void *blob;

	if (copy_from_user(&input, (void __user *)(uintptr_t)argp->data,
			   sizeof(struct sev_user_data_pek_csr)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;


	/* copy the PEK certificate blob from userspace */
	blob = NULL;
	if (input.address) {
		blob = copy_user_blob(input.address, input.length);
		if (IS_ERR(blob)) {
			ret = PTR_ERR(blob);
			goto e_free;
		}

		data->address = __psp_pa(blob);
		data->len = input.length;
	}

	ret = sev_platform_get_state(&state, &argp->error);
	if (ret)
		goto e_free_blob;

	/*
	 * PEK_CERT command can be issued only when we are in INIT state.
	 * if current state is WORKING then reject it, if state is UNINIT
	 * then transition the platform to INIT state before issuing the
	 * command.
	 */
	if (state == SEV_STATE_WORKING) {
		ret = -EBUSY;
		goto e_free_blob;
	} else if (state == SEV_STATE_UNINIT) {
		ret = sev_firmware_init(&argp->error);
		if (ret)
			goto e_free_blob;
		do_shutdown = 1;
	}

	ret = sev_handle_cmd(SEV_CMD_PEK_CSR, data, &argp->error);

	input.length = data->len;

	if (copy_to_user((void __user *)(uintptr_t)argp->data, &input,
			 sizeof(struct sev_user_data_pek_csr)))
		ret = -EFAULT;

	/* transition the plaform into INIT state */
	if (do_shutdown)
		sev_handle_cmd(SEV_CMD_SHUTDOWN, 0, NULL);

e_free_blob:
	kfree(blob);
e_free:
	kfree(data);
	return ret;
}

static int sev_ioctl_pdh_gen(struct sev_issue_cmd *argp)
{
	int ret, state, do_shutdown = 0;

	/*
	 * PDH_GEN command can be issued when platform is in INIT or WORKING
	 * state. If we are in UNINIT state then transition into INIT state
	 * before issuing the command.
	 */
	ret = sev_platform_get_state(&state, &argp->error);
	if (ret)
		return ret;

	if (state == SEV_STATE_UNINIT) {
		/* transition the plaform into INIT state */
		ret = sev_firmware_init(&argp->error);
		if (ret)
			return ret;
		do_shutdown = 1;
	}

	ret = sev_handle_cmd(SEV_CMD_PDH_GEN, 0, &argp->error);

	if (do_shutdown)
		sev_handle_cmd(SEV_CMD_SHUTDOWN, 0, NULL);

	return ret;
}

static int sev_ioctl_pek_gen(struct sev_issue_cmd *argp)
{
	int do_shutdown = 0;
	int ret, state;

	/*
	 * PEK_GEN command can be issued only when firmware is in INIT state.
	 * If firmware is in UNINIT state then we transition it into INIT state
	 * and issue the command.
	 */
	ret = sev_platform_get_state(&state, &argp->error);
	if (ret)
		return ret;

	if (state == SEV_STATE_WORKING) {
		return -EBUSY;
	} else if (state == SEV_STATE_UNINIT) {
		/* transition the plaform into INIT state */
		ret = sev_firmware_init(&argp->error);
		if (ret)
			return ret;

		do_shutdown = 1;
	}

	ret = sev_handle_cmd(SEV_CMD_PEK_GEN, 0, &argp->error);

	if (do_shutdown)
		sev_handle_cmd(SEV_CMD_SHUTDOWN, 0, NULL);

	return ret;
}

static int sev_ioctl_pek_cert_import(struct sev_issue_cmd *argp)
{
	struct sev_user_data_pek_cert_import input;
	struct sev_data_pek_cert_import *data;
	int ret, state, do_shutdown = 0;
	void *pek_blob, *oca_blob;

	if (copy_from_user(&input, (void __user *)(uintptr_t) argp->data,
			   sizeof(struct sev_user_data_pek_cert_import)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	/* copy PEK certificate blobs from userspace */
	pek_blob = copy_user_blob(input.pek_cert_address, input.pek_cert_len);
	if (IS_ERR(pek_blob)) {
		ret = PTR_ERR(pek_blob);
		goto e_free;
	}

	data->pek_cert_address = __psp_pa(pek_blob);
	data->pek_cert_len = input.pek_cert_len;

	/* copy PEK certificate blobs from userspace */
	oca_blob = copy_user_blob(input.oca_cert_address, input.oca_cert_len);
	if (IS_ERR(oca_blob)) {
		ret = PTR_ERR(oca_blob);
		goto e_free_pek;
	}

	data->oca_cert_address = __psp_pa(oca_blob);
	data->oca_cert_len = input.oca_cert_len;

	ret = sev_platform_get_state(&state, &argp->error);
	if (ret)
		goto e_free_oca;

	/*
	 * PEK_CERT_IMPORT command can be issued only when platform is in INIT
	 * state. If we are in UNINIT state then transition into INIT state
	 * before issuing the command.
	 */
	if (state == SEV_STATE_WORKING) {
		ret = -EBUSY;
		goto e_free_oca;
	} else if (state == SEV_STATE_UNINIT) {
		/* transition platform init INIT state */
		ret = sev_firmware_init(&argp->error);
		if (ret)
			goto e_free_oca;
		do_shutdown = 1;
	}

	ret = sev_handle_cmd(SEV_CMD_PEK_CERT_IMPORT, data, &argp->error);

	if (do_shutdown)
		sev_handle_cmd(SEV_CMD_SHUTDOWN, 0, NULL);
e_free_oca:
	kfree(oca_blob);
e_free_pek:
	kfree(pek_blob);
e_free:
	kfree(data);
	return ret;
}

static int sev_ioctl_pdh_cert_export(struct sev_issue_cmd *argp)
{
	struct sev_user_data_pdh_cert_export input;
	struct sev_data_pdh_cert_export *data;
	int ret, state, need_shutdown = 0;
	void *pdh_blob, *cert_blob;

	if (copy_from_user(&input, (void __user *)(uintptr_t)argp->data,
			   sizeof(struct sev_user_data_pdh_cert_export)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	pdh_blob = NULL;
	if (input.pdh_cert_address) {
		if (!access_ok(VERIFY_WRITE, input.pdh_cert_address,
			       input.pdh_cert_len)) {
			ret = -EFAULT;
			goto e_free;
		}

		if (input.pdh_cert_len > SEV_FW_BLOB_MAX_SIZE) {
			ret = -EINVAL;
			goto e_free;
		}

		pdh_blob = kmalloc(input.pdh_cert_len, GFP_KERNEL);
		if (!pdh_blob) {
			ret = -ENOMEM;
			goto e_free;
		}

		data->pdh_cert_address = __psp_pa(pdh_blob);
		data->pdh_cert_len = input.pdh_cert_len;
	}

	cert_blob = NULL;
	if (input.cert_chain_address) {
		if (!access_ok(VERIFY_WRITE, input.cert_chain_address,
			       input.cert_chain_len)) {
			ret = -EFAULT;
			goto e_free_pdh;
		}

		if (input.cert_chain_len > SEV_FW_BLOB_MAX_SIZE) {
			ret = -EINVAL;
			goto e_free_pdh;
		}

		cert_blob = kmalloc(input.cert_chain_len, GFP_KERNEL);
		if (!cert_blob) {
			ret = -ENOMEM;
			goto e_free_pdh;
		}

		data->cert_chain_address = __psp_pa(cert_blob);
		data->cert_chain_len = input.cert_chain_len;
	}

	ret = sev_platform_get_state(&state, &argp->error);
	if (ret)
		goto e_free_cert;

	/*
	 * CERT_EXPORT command can be issued in INIT or WORKING state.
	 * If we are in UNINIT state then transition into INIT state and
	 * shutdown before exiting. But if platform is in WORKING state
	 * then EXPORT the certificate but do not shutdown the platform.
	 */
	if (state == SEV_STATE_UNINIT) {
		ret = sev_firmware_init(&argp->error);
		if (ret)
			goto e_free_cert;

		need_shutdown = 1;
	}

	ret = sev_handle_cmd(SEV_CMD_PDH_CERT_EXPORT, data, &argp->error);

	input.cert_chain_len = data->cert_chain_len;
	input.pdh_cert_len = data->pdh_cert_len;

	/* copy certificate length to userspace */
	if (copy_to_user((void __user *)(uintptr_t)argp->data, &input,
			 sizeof(struct sev_user_data_pdh_cert_export)))
		ret = -EFAULT;

	if (ret)
		goto e_shutdown;

	/* copy PDH certificate to userspace */
	if (pdh_blob &&
	    copy_to_user((void __user *)(uintptr_t)input.pdh_cert_address,
			 pdh_blob, input.pdh_cert_len)) {
		ret = -EFAULT;
		goto e_shutdown;
	}

	/* copy certificate chain to userspace */
	if (cert_blob &&
	    copy_to_user((void __user *)(uintptr_t)input.cert_chain_address,
			cert_blob, input.cert_chain_len)) {
		ret = -EFAULT;
		goto e_shutdown;
	}

e_shutdown:
	if (need_shutdown)
		sev_handle_cmd(SEV_CMD_SHUTDOWN, 0, NULL);
e_free_cert:
	kfree(cert_blob);
e_free_pdh:
	kfree(pdh_blob);
e_free:
	kfree(data);
	return ret;
}

static long sev_ioctl(struct file *file, unsigned int ioctl, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct sev_issue_cmd input;
	int ret = -EFAULT;

	if (ioctl != SEV_ISSUE_CMD)
		return -EINVAL;

	if (copy_from_user(&input, argp, sizeof(struct sev_issue_cmd)))
		return -EFAULT;

	if (input.cmd > SEV_CMD_MAX)
		return -EINVAL;

	switch (input.cmd) {

	case SEV_USER_CMD_FACTORY_RESET: {
		ret = sev_ioctl_factory_reset(&input);
		break;
	}
	case SEV_USER_CMD_PLATFORM_STATUS: {
		ret = sev_ioctl_platform_status(&input);
		break;
	}
	case SEV_USER_CMD_PEK_GEN: {
		ret = sev_ioctl_pek_gen(&input);
		break;
	}
	case SEV_USER_CMD_PDH_GEN: {
		ret = sev_ioctl_pdh_gen(&input);
		break;
	}
	case SEV_USER_CMD_PEK_CSR: {
		ret = sev_ioctl_pek_csr(&input);
		break;
	}
	case SEV_USER_CMD_PEK_CERT_IMPORT: {
		ret = sev_ioctl_pek_cert_import(&input);
		break;
	}
	case SEV_USER_CMD_PDH_CERT_EXPORT: {
		ret = sev_ioctl_pdh_cert_export(&input);
		break;
	}
	default:
		ret = -EINVAL;
		break;
	}

	if (copy_to_user(argp, &input, sizeof(struct sev_issue_cmd)))
		ret = -EFAULT;

	return ret;
}


const struct file_operations sev_fops = {
	.owner	= THIS_MODULE,
	.unlocked_ioctl = sev_ioctl,
};

int sev_platform_init(struct sev_data_init *data, int *error)
{
	return sev_handle_cmd(SEV_CMD_INIT, data, error);
}
EXPORT_SYMBOL_GPL(sev_platform_init);

int sev_platform_shutdown(int *error)
{
	return sev_handle_cmd(SEV_CMD_SHUTDOWN, 0, error);
}
EXPORT_SYMBOL_GPL(sev_platform_shutdown);

int sev_platform_status(struct sev_data_status *data, int *error)
{
	return sev_handle_cmd(SEV_CMD_PLATFORM_STATUS, data, error);
}
EXPORT_SYMBOL_GPL(sev_platform_status);

int sev_issue_cmd_external_user(struct file *filep, unsigned int cmd,
				void *data, int *error)
{
	if (!filep || filep->f_op != &sev_fops)
		return -EBADF;

	return sev_handle_cmd(cmd, data, error);
}
EXPORT_SYMBOL_GPL(sev_issue_cmd_external_user);

int sev_guest_deactivate(struct sev_data_deactivate *data, int *error)
{
	return sev_handle_cmd(SEV_CMD_DEACTIVATE, data, error);
}
EXPORT_SYMBOL_GPL(sev_guest_deactivate);

int sev_guest_activate(struct sev_data_activate *data, int *error)
{
	return sev_handle_cmd(SEV_CMD_ACTIVATE, data, error);
}
EXPORT_SYMBOL_GPL(sev_guest_activate);

int sev_guest_decommission(struct sev_data_decommission *data, int *error)
{
	return sev_handle_cmd(SEV_CMD_DECOMMISSION, data, error);
}
EXPORT_SYMBOL_GPL(sev_guest_decommission);

int sev_guest_df_flush(int *error)
{
	return sev_handle_cmd(SEV_CMD_DF_FLUSH, 0, error);
}
EXPORT_SYMBOL_GPL(sev_guest_df_flush);

static int sev_ops_init(struct psp_device *psp)
{
	struct miscdevice *misc = &psp->sev_misc;
	int ret = 0;

	/*
	 * SEV feature support can be detected on the multiple devices but the
	 * SEV FW commands must be issued on the master. During probe time we
	 * do not know the master hence we create /dev/sev on the first device
	 * probe. sev_handle_cmd() finds the right master device to when issuing
	 * the command to the firmware.
	 */
	if (!sev_fops_registered) {
		misc->minor = MISC_DYNAMIC_MINOR;
		misc->name = DEVICE_NAME;
		misc->fops = &sev_fops;

		ret = misc_register(misc);
		if (!ret) {
			sev_fops_registered = true;
			psp->has_sev_fops = true;
			init_waitqueue_head(&psp->sev_int_queue);
		}
	}

	return ret;
}

static int sev_init(struct psp_device *psp)
{
	/* Check if device supports SEV feature */
	if (!(ioread32(psp->io_regs + PSP_FEATURE_REG) & 1)) {
		dev_dbg(psp->dev, "device does not support SEV\n");
		return 1;
	}

	return sev_ops_init(psp);
}

static void sev_exit(struct psp_device *psp)
{
	if (psp->has_sev_fops)
		misc_deregister(&psp->sev_misc);
}

int psp_dev_init(struct sp_device *sp)
{
	struct device *dev = sp->dev;
	struct psp_device *psp;
	int ret;

	ret = -ENOMEM;
	psp = psp_alloc_struct(sp);
	if (!psp)
		goto e_err;

	sp->psp_data = psp;

	psp->vdata = (struct psp_vdata *)sp->dev_vdata->psp_vdata;
	if (!psp->vdata) {
		ret = -ENODEV;
		dev_err(dev, "missing driver data\n");
		goto e_err;
	}

	psp->io_regs = sp->io_map + psp->vdata->offset;

	/* Disable and clear interrupts until ready */
	iowrite32(0, psp->io_regs + PSP_P2CMSG_INTEN);
	iowrite32(-1, psp->io_regs + PSP_P2CMSG_INTSTS);

	dev_dbg(dev, "requesting an IRQ ...\n");
	/* Request an irq */
	ret = sp_request_psp_irq(psp->sp, psp_irq_handler, psp->name, psp);
	if (ret) {
		dev_err(dev, "psp: unable to allocate an IRQ\n");
		goto e_err;
	}

	if (sp->set_psp_master_device)
		sp->set_psp_master_device(sp);

	ret = sev_init(psp);
	if (ret)
		goto e_irq;

	/* Enable interrupt */
	dev_dbg(dev, "Enabling interrupts ...\n");
	iowrite32(-1, psp->io_regs + PSP_P2CMSG_INTEN);

	dev_notice(dev, "psp enabled\n");

	return 0;

e_irq:
	sp_free_psp_irq(psp->sp, psp);
e_err:
	sp->psp_data = NULL;

	dev_notice(dev, "psp initialization failed\n");

	return ret;
}

void psp_dev_destroy(struct sp_device *sp)
{
	struct psp_device *psp = sp->psp_data;

	sev_exit(psp);
	sp_free_psp_irq(sp, psp);
}
