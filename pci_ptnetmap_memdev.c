#include "bhyverun.h"
#include "pci_emul.h"


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

static uint64_t
ptn_pci_read(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
 		int baridx, uint64_t offset, int size)
{
	struct ptn_memdev_softc *sc = pi->pi_arg;
	uint64_t ret = 0;

	if (baridx == PTNETMAP_MEM_PCI_BAR) {
		printf("ptnetmap_memdev: MEM read\n");
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

	printf("ptnentmap_memdev: io_read - addr: %lx size: %d ret: %lx\n", addr, size, ret);
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

	switch (addr) {

	default:
		printf("ptnentmap_memdev: write io reg unexpected\n");
		break;
	}


	printf("ptnentmap_memdev: io_write - addr: %lx size: %d val: %lx\n", addr, size, val);
}

static int
ptn_memdev_init(struct vmctx *ctx, struct pci_devinst *pi, char *opts)
{
	struct ptn_memdev_softc *sc;
	uint64_t size;
	int ret;

	printf("ptnetmap_memdev: loading\n");

	sc = calloc(1, sizeof(struct ptn_memdev_softc));
	if (sc == NULL) {
		printf("ptnetmap_memdev: calloc error\n");
		return (ENOMEM);
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

	/* init iobar */
	ret = pci_emul_alloc_bar(pi, PTNETMAP_IO_PCI_BAR, PCIBAR_IO, PTNEMTAP_IO_SIZE);
	if (ret) {
		printf("ptnetmap_memdev: iobar allocation error\n");
		goto err;
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


	TAILQ_INSERT_TAIL(&ptn_memdevs, sc, next);
	printf("ptnetmap_memdev: loaded\n");

 	return (0);
err:
	free(sc);
	pi->pi_arg = NULL;
	return ret;
}

/*
 * find ptn_state through mem_id
 */
static struct ptn_memdev_softc *
ptnetmap_memdev_find(uint16_t mem_id)
{
	struct ptn_memdev_softc *sc;

	TAILQ_FOREACH(sc, &ptn_memdevs, next) {
		if (mem_id == sc->mem_id) {
			return sc;
		}
	}

	return NULL;
}

int
ptnetmap_memdev_create(void *mem_ptr, uint32_t mem_size, uint16_t mem_id)
{
	struct ptn_memdev_softc *sc;
	printf("ptnetmap_memdev: creating\n");

	if (ptnetmap_memdev_find(mem_id)) {
		printf("ptnetmap_memdev: already created\n");
		return 0;
	}

#if 0
	/* TODO: find primary bus */

	/* TODO: create ptnetmap PCI device */

	/* TODO: set ptnetmap shared memory parameter */
	ptn_state = PTNETMAP_MEMDEV(dev);
	ptn_state->mem_ptr = mem_ptr;
	ptn_state->mem_size = mem_size;
	ptn_state->mem_id = mem_id;

	/* TODO: init device */
	qdev_init_nofail(&dev->qdev);
#endif

	printf("ptnetmap_memdev: created\n");

	return 0;
}


struct pci_devemu pci_de_ptnetmap = {
	.pe_emu = 	PTN_MEMDEV_NAME,
	.pe_init =	ptn_memdev_init,
	.pe_barwrite =	ptn_pci_write,
	.pe_barread =	ptn_pci_read
};
PCI_EMUL_SET(pci_de_vnet);
