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

#define ROCKER_SECY_CRYPTO_OK  0
#define ROCKER_SECY_CRYPTO_ERR 1

World *secy_world_alloc(Rocker *r);

#endif /* ROCKER_SECY_H */
