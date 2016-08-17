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
 * \defgroup service-xpra Xpra service
 * \ingroup services
 *
 * @brief Service handling xpra display connections
 *
 * The Xpra service provides the ability to connect a display to
 * an xpra instance running on a client and like this forward the
 * client's windows to the service and display it.
 *
 * Xpra is a multi-platform screen and application forwarding
 * system that builds upon the X11 windowing system. Despite its
 * X11 heritage, it also provides implementations for Microsoft
 * Windows and OS X to forward their applications.
 *
 * The architecture is such that the client wishing to connect to
 * the service has to start a local Xpra server. The Xpra server
 * starts a virtual framebuffer in which the applications which
 * are to be forwarded are spawned in.
 *
 * When connecting to the service, the server will start an Xpra
 * client which will connect to the Xpra server running on the
 * client. All traffic between Xpra server and client will now be
 * tunneled through an encrypted channel.
 */

struct cpn_service_plugin;

int cpn_xpra_init_service(const struct cpn_service_plugin **plugin);
