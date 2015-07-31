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
