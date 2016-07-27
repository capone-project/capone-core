/*
 * Copyright (C) 2016 Patrick Steinhardt
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * \defgroup service-synergy Synergy service
 * \ingroup services
 *
 * @brief Service handling input devices via Synergy
 *
 * The synergy service will handle the connection via two Synergy
 * instances, used for connecting mouse and/or keyboard to a
 * remote server. The synergy client will be executed on the
 * server and connect to a synergy instance spawned at the
 * client's device.
 */

struct cpn_service;

int cpn_synergy_init_service(struct cpn_service *service);
