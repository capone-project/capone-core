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
 * \defgroup service-exec Exec service
 * \ingroup services
 *
 * @brief Service handling execution of programs
 *
 * The exec service is a simple service handling the execution of
 * a program with a set of command line arguments and environment
 * variables set as parameters by the client.
 *
 * Output will be relayed to the client and input from the client
 * will be forwarded to the application through the encrypted
 * channel.
 */

struct cpn_service_plugin;

int cpn_exec_init_service(const struct cpn_service_plugin **plugin);
