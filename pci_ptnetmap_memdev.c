#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <errno.h>
//#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
//#include <string.h>
//#include <strings.h>
//#include <unistd.h>
//#include <assert.h>

#include <machine/vmm.h>
#include <vmmapi.h>
#include "bhyverun.h"
#include "pci_emul.h"
#include "ptnetmap.h"


/* ptnetmap memdev PCI-ID and PCI-BARS XXX-ste: remove*/
#define PTN_MEMDEV_NAME                 "ptnetmap-memdev"
#define PTNETMAP_PCI_VENDOR_ID          0x3333  /* XXX-ste: set vendor_id */
#define PTNETMAP_PCI_DEVICE_ID          0x0001
#define PTNETMAP_IO_PCI_BAR             0
#define PTNETMAP_MEM_PCI_BAR            1

/* ptnetmap memdev register */
/* 32 bit r/o */
#define PTNETMAP_IO_PCI_FEATURES        0
/* 32 bit r/o */
#define PTNETMAP_IO_PCI_MEMSIZE         4
/* 16 bit r/o */
#define PTNETMAP_IO_PCI_HOSTID          8
#define PTNEMTAP_IO_SIZE                10

struct ptn_memdev_softc {
	struct pci_devinst *pi;		/* PCI device instance */

	void *mem_ptr;			/* netmap shared memory */
	uint64_t mem_size;		/* netmap shared memory size */
	uint16_t mem_id;		/* netmap memory allocator ID */

	TAILQ_ENTRY(ptn_memdev_softc) next;
};
static TAILQ_HEAD(, ptn_memdev_softc) ptn_memdevs = TAILQ_HEAD_INITIALIZER(ptn_memdevs);

/*
 * find ptn_memdev through mem_id
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
 * find ptn_memdev that has not memory
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
 * find ptn_memdev that has not PCI device istance
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


static uint64_t
ptn_pci_read(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
 		int baridx, uint64_t offset, int size)
{
	struct ptn_memdev_softc *sc = pi->pi_arg;
	uint64_t ret = 0;

	if (baridx == PTNETMAP_MEM_PCI_BAR) {
		printf("ptnetmap_memdev: MEM read\n");
		printf("ptnentmap_memdev: mem_read - offset: %lx size: %d ret: %lx\n", offset, size, ret);
		return 0; /* XXX */
	}

	/* XXX probably should do something better than just assert() */
	assert(baridx == PTNETMAP_IO_PCI_BAR);

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

	printf("ptnentmap_memdev: io_read - offset: %lx size: %d ret: %llu\n", offset, size,(unsigned long long)ret);

	return ret;
}

static void
ptn_pci_write(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
  		int baridx, uint64_t offset, int size, uint64_t value)
{
	struct ptn_memdev_softc *sc = pi->pi_arg;

	if (baridx == PTNETMAP_MEM_PCI_BAR) {
		printf("ptnetmap_memdev: MEM write\n");
		return; /* XXX */
	}

	/* XXX probably should do something better than just assert() */
	assert(baridx == PTNETMAP_IO_PCI_BAR);

	switch (offset) {

	default:
		printf("ptnentmap_memdev: write io reg unexpected\n");
		break;
	}


	printf("ptnentmap_memdev: io_write - offset: %lx size: %d val: %lx\n", offset, size, value);
}

static int
ptn_memdev_configure(struct ptn_memdev_softc *sc)
{
	int ret;

	printf("ptnetmap_memdev: configuring\n");

	if (sc->pi == NULL || sc->mem_ptr == NULL)
		return 0;


	/* init iobar */
	ret = pci_emul_alloc_bar(sc->pi, PTNETMAP_IO_PCI_BAR, PCIBAR_IO, PTNEMTAP_IO_SIZE);
	if (ret) {
		printf("ptnetmap_memdev: iobar allocation error %d\n", ret);
		return ret;
	}


	/* init membar */
	/* XXX MEM64 has MEM_PREFETCH */
	/* TODO-ste: add API to map user buffer in the guest
	 * now there is vm_map_pptdev_mmio() but it maps only physical
	 * page. This function is implemented in the host kernel through
	 * sglist_append_phys().
	 * Maybe with sglist_append_user() we can do the same for the
	 * user buffer
	 */
	ret = pci_emul_alloc_bar(sc->pi, PTNETMAP_MEM_PCI_BAR, PCIBAR_MEM32, sc->mem_size);
	if (ret) {
		printf("ptnetmap_memdev: membar allocation error %d\n", ret);
		return ret;
	}
	printf("ptnetmap_memdev: pci_addr: %llx, mem_size: %llu, mem_ptr: %p\n",
			(unsigned long long) sc->pi->pi_bar[PTNETMAP_MEM_PCI_BAR].addr,
			(unsigned long long) sc->mem_size, sc->mem_ptr);
	if (0) {
		uint64_t i;
		uint8_t *mem = (uint8_t *)sc->mem_ptr;

		for (i = 0; i < 2900000; i += 100000) {
			printf("%lu %p %x\n", i, mem,  *mem);
			mem += i;
		}
	}
	ret = vm_map_user_buf(sc->pi->pi_vmctx, sc->pi->pi_bar[PTNETMAP_MEM_PCI_BAR].addr,
			sc->mem_size, sc->mem_ptr);
	if (ret) {
		printf("ptnetmap_memdev: membar map error %d\n", ret);
		return ret;
	}

	printf("ptnetmap_memdev: configured\n");

	return 0;
}

static int
ptn_memdev_init(struct vmctx *ctx, struct pci_devinst *pi, char *opts)
{
	struct ptn_memdev_softc *sc;
	uint64_t size;
	int ret;

	printf("ptnetmap_memdev: loading\n");

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
	pci_set_cfgdata16(pi, PCIR_SUBDEV_0, 1); /* XXX-ste remove? */
	pci_set_cfgdata16(pi, PCIR_SUBVEND_0, PTNETMAP_PCI_VENDOR_ID); /* XXX-ste remove? */

	ret = ptn_memdev_configure(sc);
	if (ret) {
		printf("ptnetmap_memdev: configure error\n");
		goto err;
	}

	printf("ptnetmap_memdev: loaded\n");

 	return (0);
err:
	ptn_memdev_delete(sc);
	pi->pi_arg = NULL;
	return ret;
}

int
ptn_memdev_attach(void *mem_ptr, uint32_t mem_size, uint16_t mem_id)
{
	struct ptn_memdev_softc *sc;
	int ret;
	printf("ptnetmap_memdev: attaching\n");

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

	printf("ptnetmap_memdev_attach: mem_id: %u, mem_size: %lu, mem_ptr: %p\n", mem_id,
			(unsigned long) mem_size, mem_ptr);

	/* TODO: configure device BARs */
	ret = ptn_memdev_configure(sc);
	if (ret) {
		printf("ptnetmap_memdev: configure error\n");
		goto err;
	}

	printf("ptnetmap_memdev: attached\n");

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
