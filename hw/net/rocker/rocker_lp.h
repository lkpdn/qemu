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

#ifndef ROCKER_LP_H
#define ROCKER_LP_H

#define ROCKER_LP_PORTS_MAX 65535

typedef struct lg_port LgPort;
typedef struct lg_port_ops {
    char *(*get_name)(LgPort *port);
    void (*set_name)(LgPort *port, char *name);
    bool (*get_link_up)(LgPort *port);
    void (*set_link)(LgPort *port, bool up);
    void (*get_macaddr)(LgPort *port, MACAddr *macaddr);
    void (*set_macaddr)(LgPort *port, MACAddr *macaddr);
    uint8_t (*get_learning)(LgPort *port);
    void (*set_learning)(LgPort *port, uint8_t learning);
    bool (*enabled)(LgPort *port);
    void (*enable)(LgPort *port);
    void (*disable)(LgPort *port);
    void (*free)(LgPort *port);
    void (*reset)(LgPort *port);
} LgPortOps;

/* TODO: Support limited dynamic msix_entries for logical ports.
 * Currently no dedicated MSI-X vector so we need to invoke msix_notify
 * via front-panel ports ones only. */
typedef struct lg_port {
    /* things like ref counting is up to its impl for now */
    uint32_t parents_num;
    uint32_t *parents;
    uint32_t index;
    bool enabled;
    LgPortOps *ops;
} LgPort;

void *lg_port_priv(const LgPort *port);

LgPort *lg_port_alloc(uint32_t parents_num, uint32_t *parents,
                      uint32_t index, LgPortOps *ops);

#endif /* ROCKER_LP_H */
