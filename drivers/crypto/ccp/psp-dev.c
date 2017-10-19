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

#include "sp-dev.h"
#include "psp-dev.h"

#define DEVICE_NAME	"sev"

static DEFINE_MUTEX(sev_cmd_mutex);
static DEFINE_MUTEX(fw_init_mutex);

static struct sev_misc_dev *sev_misc_dev;
static int fw_init_count;

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

static irqreturn_t psp_irq_handler(int irq, void *data)
{
	struct psp_device *psp = data;
	unsigned int status;
	int reg;

	/* Read the interrupt status: */
	status = ioread32(psp->io_regs + PSP_P2CMSG_INTSTS);

	/* Check if it is command completion: */
	if (!(status & BIT(PSP_CMD_COMPLETE_REG)))
		goto done;

	/* Check if it is SEV command completion: */
	reg = ioread32(psp->io_regs + PSP_CMDRESP);
	if (reg & PSP_CMDRESP_RESP) {
		psp->sev_int_rcvd = 1;
		wake_up(&psp->sev_int_queue);
	}

done:
	/* Clear the interrupt status by writing the same value we read. */
	iowrite32(status, psp->io_regs + PSP_P2CMSG_INTSTS);

	return IRQ_HANDLED;
}

static void sev_wait_cmd_ioc(struct psp_device *psp, unsigned int *reg)
{
	psp->sev_int_rcvd = 0;

	wait_event(psp->sev_int_queue, psp->sev_int_rcvd);
	*reg = ioread32(psp->io_regs + PSP_CMDRESP);
}

static int sev_cmd_buffer_len(int cmd)
{
	switch (cmd) {
	case SEV_CMD_INIT:			return sizeof(struct sev_data_init);
	case SEV_CMD_PLATFORM_STATUS:		return sizeof(struct sev_user_data_status);
	case SEV_CMD_PEK_CSR:			return sizeof(struct sev_data_pek_csr);
	case SEV_CMD_PEK_CERT_IMPORT:		return sizeof(struct sev_data_pek_cert_import);
	case SEV_CMD_PDH_CERT_EXPORT:		return sizeof(struct sev_data_pdh_cert_export);
	case SEV_CMD_LAUNCH_START:		return sizeof(struct sev_data_launch_start);
	case SEV_CMD_LAUNCH_UPDATE_DATA:	return sizeof(struct sev_data_launch_update_data);
	case SEV_CMD_LAUNCH_UPDATE_VMSA:	return sizeof(struct sev_data_launch_update_vmsa);
	case SEV_CMD_LAUNCH_FINISH:		return sizeof(struct sev_data_launch_finish);
	case SEV_CMD_LAUNCH_MEASURE:		return sizeof(struct sev_data_launch_measure);
	case SEV_CMD_ACTIVATE:			return sizeof(struct sev_data_activate);
	case SEV_CMD_DEACTIVATE:		return sizeof(struct sev_data_deactivate);
	case SEV_CMD_DECOMMISSION:		return sizeof(struct sev_data_decommission);
	case SEV_CMD_GUEST_STATUS:		return sizeof(struct sev_data_guest_status);
	case SEV_CMD_DBG_DECRYPT:		return sizeof(struct sev_data_dbg);
	case SEV_CMD_DBG_ENCRYPT:		return sizeof(struct sev_data_dbg);
	case SEV_CMD_SEND_START:		return sizeof(struct sev_data_send_start);
	case SEV_CMD_SEND_UPDATE_DATA:		return sizeof(struct sev_data_send_update_data);
	case SEV_CMD_SEND_UPDATE_VMSA:		return sizeof(struct sev_data_send_update_vmsa);
	case SEV_CMD_SEND_FINISH:		return sizeof(struct sev_data_send_finish);
	case SEV_CMD_RECEIVE_START:		return sizeof(struct sev_data_receive_start);
	case SEV_CMD_RECEIVE_FINISH:		return sizeof(struct sev_data_receive_finish);
	case SEV_CMD_RECEIVE_UPDATE_DATA:	return sizeof(struct sev_data_receive_update_data);
	case SEV_CMD_RECEIVE_UPDATE_VMSA:	return sizeof(struct sev_data_receive_update_vmsa);
	case SEV_CMD_LAUNCH_UPDATE_SECRET:	return sizeof(struct sev_data_launch_secret);
	default:				return 0;
	}

	return 0;
}

static int sev_do_cmd(int cmd, void *data, int *psp_ret)
{
	unsigned int phys_lsb, phys_msb;
	unsigned int reg, ret = 0;
	struct psp_device *psp;
	struct sp_device *sp;

	sp = sp_get_psp_master_device();
	if (!sp)
		return -ENODEV;

	psp = sp->psp_data;
	if (!psp)
		return -ENODEV;

	/* Get the physical address of the command buffer */
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
	reg |= PSP_CMDRESP_IOC;
	iowrite32(reg, psp->io_regs + PSP_CMDRESP);

	/* wait for command completion */
	sev_wait_cmd_ioc(psp, &reg);

	if (psp_ret)
		*psp_ret = reg & PSP_CMDRESP_ERR_MASK;

	if (reg & PSP_CMDRESP_ERR_MASK) {
		dev_dbg(psp->dev, "sev command %#x failed (%#010x)\n",
			cmd, reg & PSP_CMDRESP_ERR_MASK);
		ret = -EIO;
	}

	mutex_unlock(&sev_cmd_mutex);
	print_hex_dump_debug("(out): ", DUMP_PREFIX_OFFSET, 16, 2, data,
			     sev_cmd_buffer_len(cmd), false);
	return ret;
}

static int sev_ioctl_do_platform_status(struct sev_issue_cmd *argp)
{
	struct sev_user_data_status *data;
	int ret;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	ret = sev_do_cmd(SEV_CMD_PLATFORM_STATUS, data, &argp->error);
	if (ret)
		goto e_free;

	if (copy_to_user((void __user *)argp->data, data, sizeof(*data)))
		ret = -EFAULT;

e_free:
	kfree(data);
	return ret;
}

static int sev_ioctl_do_pek_pdh_gen(int cmd, struct sev_issue_cmd *argp)
{
	int ret, err;

	ret = sev_platform_init(NULL, &argp->error);
	if (ret)
		return ret;

	ret = sev_do_cmd(cmd, 0, &argp->error);

	if (sev_platform_shutdown(&err)) {
		argp->error = err;
		ret = -EIO;
	}

	return ret;
}

static int sev_ioctl_do_pek_csr(struct sev_issue_cmd *argp)
{
	struct sev_user_data_pek_csr input;
	struct sev_data_pek_csr *data;
	void *blob = NULL;
	int ret, err;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	/* userspace wants to query CSR length */
	if (!input.address || !input.length)
		goto cmd;

	/* allocate a physically contiguous buffer to store the CSR blob */
	if (!access_ok(VERIFY_WRITE, input.address, input.length) ||
	    input.length > SEV_FW_BLOB_MAX_SIZE) {
		ret = -EFAULT;
		goto e_free;
	}

	blob = kmalloc(input.length, GFP_KERNEL);
	if (!blob) {
		ret = -ENOMEM;
		goto e_free;
	}

	data->address = __psp_pa(blob);
	data->len = input.length;

cmd:
	ret = sev_platform_init(NULL, &argp->error);
	if (ret)
		goto e_free_blob;

	ret = sev_do_cmd(SEV_CMD_PEK_CSR, data, &argp->error);

	/*
	 * If we query the CSR length, FW responded with expected data
	 */
	input.length = data->len;

	if (blob) {
		if (copy_to_user((void __user *)input.address, blob, input.length))
			ret = -EFAULT;
	}

	if (sev_platform_shutdown(&err)) {
		ret = -EIO;
		argp->error = err;
	}

	if (copy_to_user((void __user *)argp->data, &input, sizeof(input)))
		ret = -EFAULT;

e_free_blob:
	kfree(blob);
e_free:
	kfree(data);
	return ret;
}

void *psp_copy_user_blob(u64 __user uaddr, u32 len)
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
EXPORT_SYMBOL_GPL(psp_copy_user_blob);

static int sev_ioctl_do_pek_cert_import(struct sev_issue_cmd *argp)
{
	struct sev_user_data_pek_cert_import input;
	struct sev_data_pek_cert_import *data;
	void *pek_blob, *oca_blob;
	int ret, err;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	/* copy PEK certificate blobs from userspace */
	pek_blob = psp_copy_user_blob(input.pek_cert_address, input.pek_cert_len);
	if (IS_ERR(pek_blob)) {
		ret = PTR_ERR(pek_blob);
		goto e_free;
	}

	data->pek_cert_address = __psp_pa(pek_blob);
	data->pek_cert_len = input.pek_cert_len;

	/* copy PEK certificate blobs from userspace */
	oca_blob = psp_copy_user_blob(input.oca_cert_address, input.oca_cert_len);
	if (IS_ERR(oca_blob)) {
		ret = PTR_ERR(oca_blob);
		goto e_free_pek;
	}

	data->oca_cert_address = __psp_pa(oca_blob);
	data->oca_cert_len = input.oca_cert_len;

	ret = sev_platform_init(NULL, &argp->error);
	if (ret)
		goto e_free_oca;

	ret = sev_do_cmd(SEV_CMD_PEK_CERT_IMPORT, data, &argp->error);

	if (sev_platform_shutdown(&err)) {
		ret = -EIO;
		argp->error = err;
	}

e_free_oca:
	kfree(oca_blob);
e_free_pek:
	kfree(pek_blob);
e_free:
	kfree(data);
	return ret;
}

static int sev_ioctl_do_pdh_cert_export(struct sev_issue_cmd *argp)
{
	struct sev_user_data_pdh_cert_export input;
	void *pdh_blob = NULL, *cert_blob = NULL;
	struct sev_data_pdh_cert_export *data;
	int ret, err;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	/* Userspace wants to query the certificate length */
	if (!input.pdh_cert_address || !input.pdh_cert_len ||
	    !input.cert_chain_address || !input.cert_chain_address)
		goto cmd;

	/* allocate a physically contiguous buffer to store the PDH blob */
	if (!access_ok(VERIFY_WRITE, input.pdh_cert_address, input.pdh_cert_len) ||
	    (input.pdh_cert_len > SEV_FW_BLOB_MAX_SIZE)) {
		ret = -EFAULT;
		goto e_free;
	}

	pdh_blob = kmalloc(input.pdh_cert_len, GFP_KERNEL);
	if (!pdh_blob) {
		ret = -ENOMEM;
		goto e_free;
	}

	data->pdh_cert_address = __psp_pa(pdh_blob);
	data->pdh_cert_len = input.pdh_cert_len;

	/* allocate a physically contiguous buffer to store the cert chain blob */
	if (!access_ok(VERIFY_WRITE, input.cert_chain_address, input.cert_chain_len) ||
	    (input.cert_chain_len > SEV_FW_BLOB_MAX_SIZE)) {
		ret = -EFAULT;
		goto e_free_pdh;
	}

	cert_blob = kmalloc(input.cert_chain_len, GFP_KERNEL);
	if (!cert_blob) {
		ret = -ENOMEM;
		goto e_free_pdh;
	}

	data->cert_chain_address = __psp_pa(cert_blob);
	data->cert_chain_len = input.cert_chain_len;

cmd:
	ret = sev_platform_init(NULL, &argp->error);
	if (ret)
		goto e_free_cert;

	ret = sev_do_cmd(SEV_CMD_PDH_CERT_EXPORT, data, &argp->error);

	/*
	 * If we query the length, FW responded with expected data
	 */
	input.cert_chain_len = data->cert_chain_len;
	input.pdh_cert_len = data->pdh_cert_len;

	if (copy_to_user((void __user *)argp->data, &input, sizeof(input)))
		ret = -EFAULT;

	if (sev_platform_shutdown(&err)) {
		ret = -EIO;
		argp->error = err;
		goto e_free_cert;
	}

	if (pdh_blob) {
		if (copy_to_user((void __user *)input.pdh_cert_address,
				 pdh_blob, input.pdh_cert_len)) {
			ret = -EFAULT;
			goto e_free_cert;
		}
	}

	if (cert_blob) {
		if (copy_to_user((void __user *)input.cert_chain_address,
				 cert_blob, input.cert_chain_len))
			ret = -EFAULT;
	}

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

	if (input.cmd > SEV_MAX)
		return -EINVAL;

	switch (input.cmd) {

	case SEV_FACTORY_RESET:
		ret = sev_do_cmd(SEV_CMD_FACTORY_RESET, 0, &input.error);
		break;
	case SEV_PLATFORM_STATUS:
		ret = sev_ioctl_do_platform_status(&input);
		break;
	case SEV_PEK_GEN:
		ret = sev_ioctl_do_pek_pdh_gen(SEV_CMD_PEK_GEN, &input);
		break;
	case SEV_PDH_GEN:
		ret = sev_ioctl_do_pek_pdh_gen(SEV_CMD_PDH_GEN, &input);
		break;
	case SEV_PEK_CSR:
		ret = sev_ioctl_do_pek_csr(&input);
		break;
	case SEV_PEK_CERT_IMPORT:
		ret = sev_ioctl_do_pek_cert_import(&input);
		break;
	case SEV_PDH_CERT_EXPORT:
		ret = sev_ioctl_do_pdh_cert_export(&input);
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

	if (copy_to_user(argp, &input, sizeof(struct sev_issue_cmd)))
		ret = -EFAULT;
out:
	return ret;
}

static const struct file_operations sev_fops = {
	.owner	= THIS_MODULE,
	.unlocked_ioctl = sev_ioctl,
};

static int __sev_platform_init(struct sev_data_init *data, int *error)
{
	int rc = 0;

	mutex_lock(&fw_init_mutex);

	if (!fw_init_count) {
		rc = sev_do_cmd(SEV_CMD_INIT, data, error);
		if (rc)
			goto unlock;
	}

	fw_init_count++;

unlock:
	mutex_unlock(&fw_init_mutex);
	return rc;

}

int sev_platform_init(struct sev_data_init *data, int *error)
{
	struct sev_data_init *input = NULL;
	int rc;

	if (!data) {
		input = kzalloc(sizeof(*input), GFP_KERNEL);
		if (!input)
			return -ENOMEM;

		data = input;
	}

	rc = __sev_platform_init(data, error);

	kfree(input);
	return rc;
}
EXPORT_SYMBOL_GPL(sev_platform_init);

int sev_platform_shutdown(int *error)
{
	int rc = 0;

	mutex_lock(&fw_init_mutex);

	if (!fw_init_count)
		goto unlock;

	if (fw_init_count == 1) {
		rc = sev_do_cmd(SEV_CMD_SHUTDOWN, 0, error);
		if (rc)
			goto unlock;
	}

	fw_init_count--;

unlock:
	mutex_unlock(&fw_init_mutex);
	return rc;
}
EXPORT_SYMBOL_GPL(sev_platform_shutdown);

int sev_platform_status(struct sev_user_data_status *data, int *error)
{
	return sev_do_cmd(SEV_CMD_PLATFORM_STATUS, data, error);
}
EXPORT_SYMBOL_GPL(sev_platform_status);

int sev_issue_cmd_external_user(struct file *filep, unsigned int cmd,
				void *data, int *error)
{
	if (!filep || filep->f_op != &sev_fops)
		return -EBADF;

	return sev_do_cmd(cmd, data, error);
}
EXPORT_SYMBOL_GPL(sev_issue_cmd_external_user);

int sev_guest_deactivate(struct sev_data_deactivate *data, int *error)
{
	return sev_do_cmd(SEV_CMD_DEACTIVATE, data, error);
}
EXPORT_SYMBOL_GPL(sev_guest_deactivate);

int sev_guest_activate(struct sev_data_activate *data, int *error)
{
	return sev_do_cmd(SEV_CMD_ACTIVATE, data, error);
}
EXPORT_SYMBOL_GPL(sev_guest_activate);

int sev_guest_decommission(struct sev_data_decommission *data, int *error)
{
	return sev_do_cmd(SEV_CMD_DECOMMISSION, data, error);
}
EXPORT_SYMBOL_GPL(sev_guest_decommission);

int sev_guest_df_flush(int *error)
{
	return sev_do_cmd(SEV_CMD_DF_FLUSH, 0, error);
}
EXPORT_SYMBOL_GPL(sev_guest_df_flush);

static int sev_ops_init(struct psp_device *psp)
{
	struct device *dev = psp->dev;
	int ret;

	/*
	 * SEV feature support can be detected on multiple devices but the SEV
	 * FW commands must be issued on the master. During probe, we do not
	 * know the master hence we create /dev/sev on the first device probe.
	 * sev_do_cmd() finds the right master device to which to issue the
	 * command to the firmware.
	 */
	if (!sev_misc_dev) {
		struct miscdevice *misc;

		sev_misc_dev = devm_kzalloc(dev, sizeof(*sev_misc_dev), GFP_KERNEL);
		if (!sev_misc_dev)
			return -ENOMEM;

		misc = &sev_misc_dev->misc;
		misc->minor = MISC_DYNAMIC_MINOR;
		misc->name = DEVICE_NAME;
		misc->fops = &sev_fops;

		ret = misc_register(misc);
		if (ret)
			return ret;

		kref_init(&sev_misc_dev->refcount);
	} else {
		kref_get(&sev_misc_dev->refcount);
	}

	init_waitqueue_head(&psp->sev_int_queue);
	psp->sev_misc = sev_misc_dev;
	dev_info(dev, "registered SEV device\n");

	return 0;
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

static void sev_exit(struct kref *ref)
{
	struct sev_misc_dev *sev_dev = container_of(ref, struct sev_misc_dev, refcount);

	misc_deregister(&sev_dev->misc);
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
	iowrite32(-1, psp->io_regs + PSP_P2CMSG_INTEN);

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

	if (psp->sev_misc)
		kref_put(&sev_misc_dev->refcount, sev_exit);

	sp_free_psp_irq(sp, psp);
}
