/*
 * QEMU rocker switch emulation - logical ports
 *
 * Copyright (c) 2018 lkpdn <den@klaipeden.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "qemu/osdep.h"
#include "net/clients.h"

#include "rocker.h"
#include "rocker_hw.h"
#include "rocker_lp.h"
#include "rocker_world.h"

void *lg_port_priv(const LgPort *port)
{
    return (char *)port + sizeof(LgPort);
}

LgPort *lg_port_alloc(uint32_t parents_num, uint32_t *parents,
                      uint32_t index, LgPortOps *ops)
{
    LgPort *port = g_new0(LgPort, 1);

    port->parents_num = parents_num;
    port->index = index;
    port->ops = ops;

    if (parents_num > 0) {
        port->parents = g_malloc(sizeof(uint32_t) * parents_num);
        memcpy(port->parents, parents, sizeof(uint32_t) * parents_num);
    }

    return port;
}
