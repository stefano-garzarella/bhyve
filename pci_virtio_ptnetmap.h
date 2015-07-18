#ifndef __PCI_VIRTIO_PTNETMAP_H__
#define __PCI_VIRTIO_PTNETMAP_H__

/* XXX-ste: move in other file and split in .c .h? */
#ifdef BHYVE_VIRTIO_PTNETMAP

/* ptnetmap virtio register BASE */
#define PTNETMAP_VIRTIO_IO_BASE         sizeof(struct virtio_net_config)
#include "ptnetmap.h"

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
		/* TODO: unmap */
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

	printf("ptnetmap-virtio init END\n");
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
	csb->nifp_offset = ptns->offset;
	csb->num_tx_rings = ptns->num_tx_rings;
	csb->num_rx_rings = ptns->num_rx_rings;
	csb->num_tx_slots = ptns->num_tx_slots;
	csb->num_rx_slots = ptns->num_rx_slots;
	printf("txr %u rxr %u txd %u rxd %u nifp_offset %u\n",
	 	        csb->num_tx_rings,
	 	        csb->num_rx_rings,
	 	        csb->num_tx_slots,
	 	        csb->num_rx_slots,
	 	        csb->nifp_offset);

	return ret;
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
			printf("ptnetmap acked features: %x\n", sc->ptn.features);

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
					//ret = virtio_net_ptnetmap_up(sc);
					break;
				case NET_PARAVIRT_PTCTL_UNREGIF:
					//ret = virtio_net_ptnetmap_down(sc);
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
			printf("PTSTS - ret %d\n", ret);
			sc->ptn.reg[PTNETMAP_VIRTIO_IO_PTSTS] = ret;
			break;
		case PTNETMAP_VIRTIO_IO_CSBBAH:
			break;
		case PTNETMAP_VIRTIO_IO_CSBBAL:
			ptnetmap_configure_csb(sc->vsc_vs.vs_pi->pi_vmctx, &sc->ptn.csb, *((uint32_t *)(sc->ptn.reg + PTNETMAP_VIRTIO_IO_CSBBAL)),
					*((uint32_t *)(sc->ptn.reg + PTNETMAP_VIRTIO_IO_CSBBAH)));
			break;
		default:
			break;
	}

	printf("ptnentmap_vtnet: io_write - offset: %d size: %d val: %u\n", offset, size, value);

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
			break;
	}
#endif
	printf("ptnentmap_vtnet: io_read - offset: %d size: %d ret: %u\n", offset, size, *value);

	return (0);
}
#endif /* BHYVE_VIRTIO_PTNETMAP */
#endif /* __PCI_VIRTIO_PTNETMAP_H__ */
