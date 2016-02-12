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

#include "cfg.h"

struct sd_service {
    char *name;
    char *type;
    char *port;
};

int sd_service_from_config_file(struct sd_service *out, const char *name, const char *file);
int sd_service_from_config(struct sd_service *out, const char *name, const struct cfg *cfg);
int sd_service_from_section(struct sd_service *out, const struct cfg_section *section);
void sd_service_free(struct sd_service *service);

int sd_services_from_config_file(struct sd_service **out, const char *file);
int sd_services_from_config(struct sd_service **out, const struct cfg *cfg);
