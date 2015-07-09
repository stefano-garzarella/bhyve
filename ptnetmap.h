#ifndef __PTNETMAP_H__
#define __PTNETMAP_H__

struct paravirt_csb;

static void
ptnetmap_configure_csb(struct paravirt_csb** csb, uint32_t csbbal,
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
	}
	if (base) {
		/* TODO: map  *csb = */
	}

}

struct ptnetmap_state {
	struct net_backend *ptn_be;

	/* netmap info */
	uint32_t offset;
	uint16_t num_tx_rings;
	uint16_t num_rx_rings;
	uint16_t num_tx_slots;
	uint16_t num_rx_slots;

};

struct ptnetmap_cfg;

/* ptnetmap-backend */
uint32_t ptnetmap_get_features(struct ptnetmap_state *ptns, uint32_t features);
void ptnetmap_ack_features(struct ptnetmap_state *ptns, uint32_t features);
int ptnetmap_get_mem(struct ptnetmap_state *ptns);
int ptnetmap_get_hostmemid(struct ptnetmap_state *ptns);
int ptnetmap_create(struct ptnetmap_state *ptns, struct ptnetmap_cfg *conf);
int ptnetmap_delete(struct ptnetmap_state *ptns);

/* ptnetmap-memdev */
int ptn_memdev_attach(void *mem_ptr, uint32_t mem_size, uint16_t mem_id);

#endif /* __PTNETMAP_H__ */
