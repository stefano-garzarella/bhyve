#ifndef __PTNETMAP_H__
#define __PTNETMAP_H__

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
