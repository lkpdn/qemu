/*
 * QEMU rocker switch emulation - SecY support
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

#ifndef ROCKER_SECY_H
#define ROCKER_SECY_H

#include "qemu/bitops.h"

#define ROCKER_SECY_CRYPTO_OK  0
#define ROCKER_SECY_CRYPTO_ERR 1

#define ROCKER_SECY_TCI_BIT_VERSION BIT(7)
#define ROCKER_SECY_TCI_BIT_ES      BIT(6)
#define ROCKER_SECY_TCI_BIT_SC      BIT(5)
#define ROCKER_SECY_TCI_BIT_SCB     BIT(4)
#define ROCKER_SECY_TCI_BIT_E       BIT(3)
#define ROCKER_SECY_TCI_BIT_C       BIT(2)
#define ROCKER_SECY_TCI_AN_MASK     (0x3)

World *secy_world_alloc(Rocker *r);

#endif /* ROCKER_SECY_H */
