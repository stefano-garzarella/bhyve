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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <net/if.h>			/* IFNAMSIZ */
#include <net/netmap.h>
#include <dev/netmap/netmap_virt.h>

#include <machine/vmm.h>
#include <vmmapi.h>

#include "bhyverun.h"
#include "pci_emul.h"
#include "ptnetmap.h"

/*
 * ptnetmap memdev PCI device
 *
 * This device is used to map netmap memory allocator (the same allocator can
 * be shared between multiple netmap ports) on the guest VM through PCI_BAR.
 *
 * Each netmap allocator has a unique ID assigned by netmap module.
 *
 * It is based on QEMU/KVM ptnetmap-memdev implementation.
 */

struct ptn_memdev_softc {
	struct pci_devinst *pi;		/* PCI device instance */

	void *mem_ptr;			/* netmap shared memory */
	uint64_t mem_size;		/* netmap shared memory size */
	uint16_t mem_id;		/* netmap memory allocator ID */

	TAILQ_ENTRY(ptn_memdev_softc) next;
};
static TAILQ_HEAD(, ptn_memdev_softc) ptn_memdevs = TAILQ_HEAD_INITIALIZER(ptn_memdevs);

/*
 * ptn_memdev_softc can be created by pe_init or ptnetmap backend,
 * this depends on the order of initialization.
 */
static struct ptn_memdev_softc *
ptn_memdev_create()
{
	struct ptn_memdev_softc *sc;

	sc = calloc(1, sizeof(struct ptn_memdev_softc));

	if (sc != NULL) {
		TAILQ_INSERT_TAIL(&ptn_memdevs, sc, next);
	}

	return sc;
}

static void
ptn_memdev_delete(struct ptn_memdev_softc *sc)
{
	TAILQ_REMOVE(&ptn_memdevs, sc, next);

	free(sc);
}

/*
 * Find ptn_memdev through mem_id (netmap memory allocator ID)
 */
static struct ptn_memdev_softc *
ptn_memdev_find_memid(uint16_t mem_id)
{
	struct ptn_memdev_softc *sc;

	TAILQ_FOREACH(sc, &ptn_memdevs, next) {
		if (sc->mem_ptr != NULL && mem_id == sc->mem_id) {
			return sc;
		}
	}

	return NULL;
}

/*
 * Find ptn_memdev that has not netmap memory (attached by ptnetmap backend)
 */
static struct ptn_memdev_softc *
ptn_memdev_find_empty_mem()
{
	struct ptn_memdev_softc *sc;

	TAILQ_FOREACH(sc, &ptn_memdevs, next) {
		if (sc->mem_ptr == NULL) {
			return sc;
		}
	}

	return NULL;
}

/*
 * Find ptn_memdev that has not PCI device istance (created by pe_init)
 */
static struct ptn_memdev_softc *
ptn_memdev_find_empty_pi()
{
	struct ptn_memdev_softc *sc;

	TAILQ_FOREACH(sc, &ptn_memdevs, next) {
		if (sc->pi == NULL) {
			return sc;
		}
	}

	return NULL;
}

/*
 * Handle read on ptnetmap-memdev register
 */
static uint64_t
ptn_pci_read(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
 		int baridx, uint64_t offset, int size)
{
	struct ptn_memdev_softc *sc = pi->pi_arg;
	uint64_t ret = 0;

	if (sc == NULL)
		return 0;

	if (baridx == PTNETMAP_MEM_PCI_BAR) {
		printf("ptnetmap_memdev: unexpected MEM read - \
				offset: %lx size: %d ret: %lx\n",
				offset, size, ret);
		return 0;
	}

	switch (offset) {
	case PTNETMAP_IO_PCI_MEMSIZE:
		ret = sc->mem_size;
		break;
	case PTNETMAP_IO_PCI_HOSTID:
		ret = sc->mem_id;
		break;
	default:
		printf("ptnentmap_memdev: read io reg unexpected\n");
		break;
	}


	return ret;
}

/*
 * Handle write on ptnetmap-memdev register (unused for now)
 */
static void
ptn_pci_write(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
  		int baridx, uint64_t offset, int size, uint64_t value)
{
	struct ptn_memdev_softc *sc = pi->pi_arg;

	if (sc == NULL)
		return;

	if (baridx == PTNETMAP_MEM_PCI_BAR) {
		printf("ptnetmap_memdev: unexpected MEM write - \
				offset: %lx size: %d value: %lx\n",
				offset, size, value);
		return;
	}

	switch (offset) {
	default:
		printf("ptnentmap_memdev: write io reg unexpected\n");
		break;
	}
}

/*
 * Configure the ptnetmap-memdev PCI-BARs
 *
 * Only if the PCI device is created and netmap memory is attached,
 * we can create the PCI-BARs.
 */
static int
ptn_memdev_configure_bars(struct ptn_memdev_softc *sc)
{
	int ret;

	if (sc->pi == NULL || sc->mem_ptr == NULL)
		return 0;

	/* alloc IO-BAR */
	ret = pci_emul_alloc_bar(sc->pi, PTNETMAP_IO_PCI_BAR, PCIBAR_IO,
			PTNEMTAP_IO_SIZE);
	if (ret) {
		printf("ptnetmap_memdev: iobar allocation error %d\n", ret);
		return ret;
	}

	/* alloc MEM-BAR */
	ret = pci_emul_alloc_bar(sc->pi, PTNETMAP_MEM_PCI_BAR, PCIBAR_MEM32,
			sc->mem_size);
	if (ret) {
		printf("ptnetmap_memdev: membar allocation error %d\n", ret);
		return ret;
	}

	/* map netmap memory on the MEM-BAR */
	ret = vm_map_user_buf(sc->pi->pi_vmctx,
			sc->pi->pi_bar[PTNETMAP_MEM_PCI_BAR].addr,
			sc->mem_size, sc->mem_ptr);
	if (ret) {
		printf("ptnetmap_memdev: membar map error %d\n", ret);
		return ret;
	}

	return 0;
}

/*
 * PCI device initialization
 */
static int
ptn_memdev_init(struct vmctx *ctx, struct pci_devinst *pi, char *opts)
{
	struct ptn_memdev_softc *sc;
	int ret;

	sc = ptn_memdev_find_empty_pi();
	if (sc == NULL) {
		sc = ptn_memdev_create();
		if (sc == NULL) {
			printf("ptnetmap_memdev: calloc error\n");
			return (ENOMEM);
		}
	}

	/* link our softc in pi */
	pi->pi_arg = sc;
	sc->pi = pi;

	/* initialize config space */
	pci_set_cfgdata16(pi, PCIR_VENDOR, PTNETMAP_PCI_VENDOR_ID);
	pci_set_cfgdata16(pi, PCIR_DEVICE, PTNETMAP_PCI_DEVICE_ID);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_NETWORK);
	pci_set_cfgdata16(pi, PCIR_SUBDEV_0, 1);
	pci_set_cfgdata16(pi, PCIR_SUBVEND_0, PTNETMAP_PCI_VENDOR_ID);

	/* configure device PCI-BARs */
	ret = ptn_memdev_configure_bars(sc);
	if (ret) {
		printf("ptnetmap_memdev: configure error\n");
		goto err;
	}

 	return (0);
err:
	ptn_memdev_delete(sc);
	pi->pi_arg = NULL;
	return ret;
}

/*
 * used by ptnetmap backend to attach the netmap memory allocator to the
 * ptnetmap-memdev. (shared with the guest VM through PCI-BAR)
 */
int
ptn_memdev_attach(void *mem_ptr, uint32_t mem_size, uint16_t mem_id)
{
	struct ptn_memdev_softc *sc;
	int ret;

	/* if a device with the same mem_id is already attached, we are done */
	if (ptn_memdev_find_memid(mem_id)) {
		printf("ptnetmap_memdev: already attched\n");
		return 0;
	}

	sc = ptn_memdev_find_empty_mem();
	if (sc == NULL) {
		sc = ptn_memdev_create();
		if (sc == NULL) {
			printf("ptnetmap_memdev: calloc error\n");
			return (ENOMEM);
		}
	}

	sc->mem_ptr = mem_ptr;
	sc->mem_size = mem_size;
	sc->mem_id = mem_id;

	/* configure device PCI-BARs */
	ret = ptn_memdev_configure_bars(sc);
	if (ret) {
		printf("ptnetmap_memdev: configure error\n");
		goto err;
	}


	return 0;
err:
	ptn_memdev_delete(sc);
	sc->pi->pi_arg = NULL;
	return ret;
}


struct pci_devemu pci_de_ptnetmap = {
	.pe_emu = 	PTN_MEMDEV_NAME,
	.pe_init =	ptn_memdev_init,
	.pe_barwrite =	ptn_pci_write,
	.pe_barread =	ptn_pci_read
};
PCI_EMUL_SET(pci_de_ptnetmap);
