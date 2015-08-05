/*
 * Copyright (C) 2015 Stefano Garzarella (stefano.garzarella@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __PCI_VIRTIO_PTNETMAP_H__
#define __PCI_VIRTIO_PTNETMAP_H__

#ifdef BHYVE_VIRTIO_PTNETMAP
#include <machine/vmm.h>
#include <machine/vmm_dev.h>	/* VM_LAPIC_MSI */
#include <vmmapi.h>

#include "ptnetmap.h"

/* ptnetmap virtio register BASE */
#define PTNETMAP_VIRTIO_IO_BASE         sizeof(struct virtio_net_config)

static void
ptnetmap_configure_csb(struct vmctx *ctx, struct paravirt_csb** csb, uint32_t csbbal,
		uint32_t csbbah)
{
	uint64_t len = 4096;
	uint64_t base = ((uint64_t)csbbah << 32) | csbbal;

	/*
	 * We require that writes to the CSB address registers
	 * are in the order CSBBAH , CSBBAL so on the second one
	 * we have a valid 64-bit memory address.
	 * Any previous region is unmapped, and handlers terminated.
	 * The CSB is then remapped if the new pointer is != 0
	 */
	if (*csb) {
		*csb = NULL;
	}
	if (base) {
		*csb = paddr_guest2host(ctx, base, len);
	}

}

static void
pci_vtnet_ptnetmap_init(struct pci_vtnet_softc *sc, struct virtio_consts *vc)
{
	sc->ptn.up = 0;

	sc->ptn.state = netbe_get_ptnetmap(sc->vsc_be);
	if (sc->ptn.state == NULL) {
		printf("ptnetmap not supported by backend\n");
		sc->ptn.features = 0;
		return;
	}

	sc->ptn.features = ptnetmap_get_features(sc->ptn.state, NET_PTN_FEATURES_BASE);

	/* backend require ptnetmap support? */
	if (!(sc->ptn.features & NET_PTN_FEATURES_BASE)) {
		printf("ptnetmap not supported/required\n");
		sc->ptn.state = NULL;
		sc->ptn.features = 0;
		return;
	}

	/* extend cfgsize. virtio creates PCIBAR for us */
	vc->vc_cfgsize += PTNEMTAP_VIRTIO_IO_SIZE;
}

static int
pci_vtnet_ptnetmap_get_mem(struct pci_vtnet_softc *sc)
{
	struct ptnetmap_state *ptns = sc->ptn.state;
	struct paravirt_csb *csb = sc->ptn.csb;
	int ret;

	ret = ptnetmap_get_mem(ptns);
	if (ret)
	 	return ret;

	if (csb == NULL) {
	 	printf("ERROR ptnetmap: csb not initialized\n");
	 	return ret;
	}
	/* share netmap_if info to the guest through CSB */
	csb->nifp_offset = ptns->offset;
	csb->num_tx_rings = ptns->num_tx_rings;
	csb->num_rx_rings = ptns->num_rx_rings;
	csb->num_tx_slots = ptns->num_tx_slots;
	csb->num_rx_slots = ptns->num_rx_slots;

	return ret;
}

static int
pci_vtnet_ptnetmap_up(struct pci_vtnet_softc *sc)
{
	struct ptnetmap_state *ptns = sc->ptn.state;
	struct paravirt_csb *csb = sc->ptn.csb;
	struct pci_devinst *pi;
	struct vmctx *vmctx;
	struct vqueue_info *vq;
	struct msix_table_entry *mte;
	struct iovec iov[1];
	uint16_t idx;
	int ret;

	if (sc->ptn.up) {
		printf("ERROR ptnetmap: already UP\n");
		return -1;
	}

	if (csb == NULL) {
		printf("ERROR ptnetmap: CSB undefined\n");
		return -1;
	}

	/* TODO: add support for multiqueue */
	pi = sc->vsc_vs.vs_pi;
	vmctx = pi->pi_vmctx;

	/* Configure the RX ring */
	sc->ptn.cfg.rx_ring.irqfd = vm_get_fd(vmctx);
	sc->ptn.cfg.rx_ring.ioctl.com = VM_LAPIC_MSI;
	vq = &sc->vsc_queues[VTNET_RXQ];
	mte = &pi->pi_msix.table[vq->vq_msix_idx];
	sc->ptn.cfg.rx_ring.ioctl.data.msix.msg = mte->msg_data;
	sc->ptn.cfg.rx_ring.ioctl.data.msix.addr = mte->addr;
	/* push fake-elem in the rx queue to enable interrupts */
	if (vq_getchain(vq, &idx, iov, 1, NULL) > 0) {
		vq_relchain(vq, idx, 0);
	}
	/* enable rx notification from guest */
	vq->vq_used->vu_flags &= ~VRING_USED_F_NO_NOTIFY;
	/*
	 * Stop processing guest/host IO notifications in bhyve.
	 * Start processing them in ptnetmap.
	 */
	ret = vm_io_reg_handler(vmctx, pi->pi_bar[0].addr + VTCFG_R_QNOTIFY, 0,
			0xFFFFFFFF, VTNET_RXQ, VM_IO_REGH_KWEVENTS, (void *) vq);
	if (ret != 0) {
		printf("ERROR ptnetmap: vm_io_reg_handler %d\n", ret);
		goto err_reg_rx;
	}
	sc->ptn.cfg.rx_ring.ioeventfd = (uint64_t) vq;

	/* Configure the TX ring */
	sc->ptn.cfg.tx_ring.irqfd = vm_get_fd(vmctx);
	sc->ptn.cfg.tx_ring.ioctl.com = VM_LAPIC_MSI;
	vq = &sc->vsc_queues[VTNET_TXQ];
	mte = &pi->pi_msix.table[vq->vq_msix_idx];
	sc->ptn.cfg.tx_ring.ioctl.data.msix.msg = mte->msg_data;
	sc->ptn.cfg.tx_ring.ioctl.data.msix.addr = mte->addr;
	/* push fake-elem in the tx queue to enable interrupts */
	if (vq_getchain(vq, &idx, iov, 1, NULL) > 0) {
		vq_relchain(vq, idx, 0);
	}
	/* enable tx notification from guest */
	vq->vq_used->vu_flags &= ~VRING_USED_F_NO_NOTIFY;
	/*
	 * Stop processing guest/host IO notifications in bhyve.
	 * Start processing them in ptnetmap.
	 */
	ret = vm_io_reg_handler(vmctx, pi->pi_bar[0].addr + VTCFG_R_QNOTIFY, 0,
			0xFFFFFFFF, VTNET_TXQ, VM_IO_REGH_KWEVENTS, (void *) vq);
	if (ret != 0) {
		printf("ERROR ptnetmap: vm_io_reg_handler %d\n", ret);
		goto err_reg_tx;
	}
	sc->ptn.cfg.tx_ring.ioeventfd = (uint64_t) vq;

	/* Initialize CSB */
	sc->ptn.cfg.csb = sc->ptn.csb;
	sc->ptn.csb->host_need_txkick = 1;
	sc->ptn.csb->guest_need_txkick = 0;
	sc->ptn.csb->guest_need_rxkick = 1;
	sc->ptn.csb->host_need_rxkick = 1;

	sc->ptn.cfg.features = PTNETMAP_CFG_FEAT_CSB | PTNETMAP_CFG_FEAT_EVENTFD |
				PTNETMAP_CFG_FEAT_IOCTL;

	/* Configure the net backend. */
	ret = ptnetmap_create(sc->ptn.state, &sc->ptn.cfg);
	if (ret)
		goto err_ptn_create;

	sc->ptn.up = 1;

	return (0);

err_ptn_create:
	vm_io_reg_handler(vmctx, pi->pi_bar[0].addr + VTCFG_R_QNOTIFY, 0,
			0xFFFFFFFF, VTNET_TXQ, VM_IO_REGH_DELETE, 0);
err_reg_tx:
	vm_io_reg_handler(vmctx, pi->pi_bar[0].addr + VTCFG_R_QNOTIFY, 0,
			0xFFFFFFFF, VTNET_RXQ, VM_IO_REGH_DELETE, 0);
err_reg_rx:
	return (ret);
}

static int
pci_vtnet_ptnetmap_down(struct pci_vtnet_softc *sc)
{
	struct pci_devinst *pi;
	struct vmctx *vmctx;
	int ret;

	if (!sc->ptn.state || !sc->ptn.up) {
		return (0);
	}

	pi = sc->vsc_vs.vs_pi;
	vmctx = pi->pi_vmctx;

	/*
	 * Start processing guest/host IO notifications in bhyve.
	 */
	vm_io_reg_handler(vmctx, pi->pi_bar[0].addr + VTCFG_R_QNOTIFY, 0,
			0xFFFFFFFF, VTNET_RXQ, VM_IO_REGH_DELETE, 0);
	vm_io_reg_handler(vmctx, pi->pi_bar[0].addr + VTCFG_R_QNOTIFY, 0,
			0xFFFFFFFF, VTNET_TXQ, VM_IO_REGH_DELETE, 0);

	sc->ptn.up = 0;

	return (ptnetmap_delete(sc->ptn.state));
}

static int
pci_vtnet_ptnetmap_write(struct pci_vtnet_softc *sc, int offset, int size, uint32_t value)
{
	uint32_t *val, ret;

	if (sc->ptn.state == NULL) {
		printf("ERROR ptnetmap: not supported by backend\n");
		return -1;
	}

	offset -= PTNETMAP_VIRTIO_IO_BASE;
	memcpy(&sc->ptn.reg[offset], &value, size);

	switch (offset) {
	case PTNETMAP_VIRTIO_IO_PTFEAT:
		val = (uint32_t *)(sc->ptn.reg + offset);
		ret = (sc->ptn.features &= *val);
		ptnetmap_ack_features(sc->ptn.state, sc->ptn.features);

		sc->ptn.reg[PTNETMAP_VIRTIO_IO_PTFEAT] = ret;
		break;
	case PTNETMAP_VIRTIO_IO_PTCTL:
		val = (uint32_t *)(sc->ptn.reg + offset);

		ret = EINVAL;
		switch(*val) {
		case NET_PARAVIRT_PTCTL_CONFIG:
			ret = pci_vtnet_ptnetmap_get_mem(sc);
			break;
		case NET_PARAVIRT_PTCTL_REGIF:
			ret = pci_vtnet_ptnetmap_up(sc);
			break;
		case NET_PARAVIRT_PTCTL_UNREGIF:
			ret = pci_vtnet_ptnetmap_down(sc);
			break;
		case NET_PARAVIRT_PTCTL_HOSTMEMID:
			ret = ptnetmap_get_hostmemid(sc->ptn.state);
			break;
		case NET_PARAVIRT_PTCTL_IFNEW:
		case NET_PARAVIRT_PTCTL_IFDELETE:
		case NET_PARAVIRT_PTCTL_FINALIZE:
		case NET_PARAVIRT_PTCTL_DEREF:
			ret = 0;
			break;
		}
		sc->ptn.reg[PTNETMAP_VIRTIO_IO_PTSTS] = ret;
		break;
	case PTNETMAP_VIRTIO_IO_CSBBAH:
		break;
	case PTNETMAP_VIRTIO_IO_CSBBAL:
		ptnetmap_configure_csb(sc->vsc_vs.vs_pi->pi_vmctx, &sc->ptn.csb,
			*((uint32_t *)(sc->ptn.reg + PTNETMAP_VIRTIO_IO_CSBBAL)),
			*((uint32_t *)(sc->ptn.reg + PTNETMAP_VIRTIO_IO_CSBBAH)));
		break;
	default:
		break;
	}

	return (0);
}

static int
pci_vtnet_ptnetmap_read(struct pci_vtnet_softc *sc, int offset, int size, uint32_t *value)
{
	if (sc->ptn.state == NULL) {
		printf("ERROR ptnetmap: not supported by backend\n");
		return -1;
	}

	offset -= PTNETMAP_VIRTIO_IO_BASE;

	memcpy(value, &sc->ptn.reg[offset], size);
#if 0
	switch (offset) {
	case PTNETMAP_VIRTIO_IO_PTFEAT:
	case PTNETMAP_VIRTIO_IO_PTSTS:
		break;
	default:
		printf("pci_vtnet_ptnentmap: write io reg unexpected\n");
		break;
	}
#endif

	return (0);
}
#endif /* BHYVE_VIRTIO_PTNETMAP */
#endif /* __PCI_VIRTIO_PTNETMAP_H__ */
