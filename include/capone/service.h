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
 * \defgroup services Services
 */

/**
 * \defgroup cpn-service Service
 * \ingroup cpn-lib
 *
 * @brief Module providing service handling
 *
 * Services are implemented by providing different plugins. This
 * module provides functions to handle these services.
 *
 * @{
 */

#ifndef CPN_LIB_SERVICE_H
#define CPN_LIB_SERVICE_H

#include "capone/cfg.h"
#include "capone/keys.h"
#include "capone/session.h"

struct cpn_channel;

/** @brief Function executed when a client starts a remote service
 *
 * This function is invoked on the client-side.
 *
 * @param[in] channel Channel to the remote service
 * @param[in] session Session that is being handled
 * @param[in] cfg Configuration for the client
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
typedef int (*cpn_service_client_fn)(struct cpn_channel *channel,
        const struct cpn_session *session,
        const struct cpn_cfg *cfg);

/** @brief Function executed when a service is started by a client
 *
 * This function is invoked on the server-side.
 *
 * @param[in] channel Channel to the remote service
 * @param[in] invoker Invoker of the session
 * @param[in] session Session associated with the invocation
 * @param[in] cfg Configuration of the server
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
typedef int (*cpn_service_server_fn)(struct cpn_channel *channel,
        const struct cpn_sign_key_public *invoker,
        const struct cpn_session *session,
        const struct cpn_cfg *cfg);

/** @brief Function parsing a client command line
 *
 * This function will be invoked prior to connecting to the
 * remote service in order to parse the client's given
 * parameters.
 *
 * @param[out] out Protobuf containing parsed parameters
 * @param[in] argc Number of arguments
 * @param[in] argv Arguments
 * */
typedef int (*cpn_service_parse_fn)(ProtobufCMessage **out, int argc, const char **argv);

struct cpn_service_plugin {
    /** @brief Category of the sevice
     *
     * Services have certain categories which should help users
     * to distinguish services. Exemplary categories are:
     *  - Input
     *  - Display
     *  - Shell
     */
    const char *category;

    /** @brief Type of the service
     *
     * This is the specific type of a service. E.g. one type of a
     * service of category "Display" may be "xpra".
     */
    const char *type;

    /** @brief Version of the plugin */
    const char *version;

    /** \see cpn_service_server_fn */
    cpn_service_server_fn server_fn;
    /** \see cpn_service_client_fn */
    cpn_service_client_fn client_fn;
    /** \see  cpn_service_parse_fn */
    cpn_service_parse_fn parse_fn;
    /** @brief Protobuf descriptor for parameters */
    const ProtobufCMessageDescriptor *params_desc;
};

/** @brief Structure wrapping a service's functionality
 */
struct cpn_service {
    /** @brief Name of the service
     *
     * The name is chosen freely by the user specifying the
     * server's configuration.
     */
    char *name;

    /** @brief Port of the service
     *
     * This may be chosen freely by the user specifying the
     * server's configuraiton.
     */
    char *port;

    /** @brief Location of the service
     *
     * This may be chosen freely by the user specifying the
     * server's configuraiton. Examples are e.g. "Cellar, or
     * "Meeting Room 14a".
     */
    char *location;

    const struct cpn_service_plugin *plugin;
};

/** @brief Register a service with the system
 *
 * Registering services enables to be able to read them from
 * configuration files and subsequently using them to handle
 * service functionality.
 *
 * @param[in] service Service which shall be registered
 * @return <code>0</code> on success, <code>-1</code> if a
 *         service with the same type has already been registered
 */
int cpn_service_plugin_register(const struct cpn_service_plugin *service);

/** @brief Register all built-in services
 *
 * Register all services that are built into the server's
 * sources. This currently includes the following list:
 *
 * - Capability
 * - Invoke
 * - Shell
 * - Synergy
 * - Xpra
 *
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_service_plugin_register_builtins(void);

/** @brief Initialize service for a given service type
 *
 * Service plugins are registered with a given service type. This
 * function searches these types and then lets the plugin
 * initialize the struct.
 *
 * @param[out] out Service to initialize
 * @param[in] type Type of the service to initialize. \see
 *            cpn_service::type
 * @return <code>0</code> on success, <code>-1</code> on error
 *         or if the service type was not found
 */
int cpn_service_plugin_for_type(const struct cpn_service_plugin **out, const char *type);

/** @brief Initialize a service from a configuration file
 *
 * Services started up by a server are usually specified in a
 * configuration file. This function parses the file and
 * populates the service struct with the specified type, port,
 * location and name. Example:
 *
 * \code{.unparse}
 * [service]
 * name=Display
 * type=xpra
 * location=Cellar
 * port = 12345
 * \endcode
 *
 * @param[out] out Service to initialize
 * @param[in] name Name specified in the configuration file.
 * @param[in] file Configuration file to parse
 * @return <code>0</code> on success, <code>-1</code> on error
 */
int cpn_service_from_config_file(struct cpn_service *out, const char *name, const char *file);

/** @brief Initialize a service from a configuration
 *
 * Initialize a service from a configuration
 *
 * @param[out] out Service to initialize
 * @param[in] name Name specified in the configuration file.
 * @param[in] cfg Configuration to initialize from.
 * @return <code>0</code> on success, <code>-1</code> on error
 *
 * \see cpn_service_from_config_file
 */
int cpn_service_from_config(struct cpn_service *out, const char *name, const struct cpn_cfg *cfg);

/** @brief Initialize a service from a configuration section
 *
 * Initialize a service from a specific section.
 *
 * @param[out] out Service to initialize
 * @param[in] name Name specified in the configuration file.
 * @param[in] section section to initialize from.
 * @return <code>0</code> on success, <code>-1</code> on error
 *
 * \see cpn_service_from_config_file
 */
int cpn_service_from_section(struct cpn_service *out, const struct cpn_cfg_section *section);

/** @brief Free a service
 *
 * @param[in] service Service to free
 */
void cpn_service_free(struct cpn_service *service);

/** @brief Initialize services from a configuration file
 *
 * Initialize multiple services from a configuration file. The
 * caller is responsible for freeing the services array.
 *
 * @param[out] out Pointer to store services at.
 * @param[in] file Configuration file to initialize from.
 * return Number of services parsed or <code>-1</code> on failure
 *
 * \see cpn_service_from_config_file
 */
int cpn_services_from_config_file(struct cpn_service **out, const char *file);

/** @brief Initialize services from a configuration
 *
 * Initialize multiple services from a configuration. The caller
 * is responsible for freeing the services array.
 *
 * @param[out] out Pointer to store services at.
 * @param[in] cfg Configuration file to initialize from.
 * return Number of services parsed or <code>-1</code> on failure
 *
 * \see cpn_service_from_config_file
 */
int cpn_services_from_config(struct cpn_service **out, const struct cpn_cfg *cfg);

#endif

/** @} */
