/**
 * @file
 * Color and attribute parsing
 *
 * @authors
 * Copyright (C) 2018 Richard Russon <rich@flatcap.org>
 *
 * @copyright
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @page lib_color Color
 *
 * Colour handling code
 *
 * | File                | Description                |
 * | :------------------ | :------------------------- |
 * | color/color.c       | @subpage color_color       |
 * | color/command.c     | @subpage color_command     |
 * | color/notify.c      | @subpage color_notify      |
 * | color/quoted.c      | @subpage color_quote       |
 * | color/regex.c       | @subpage color_regex       |
 * | color/simple.c      | @subpage color_simple      |
 */

#ifndef MUTT_COLOR_LIB_H
#define MUTT_COLOR_LIB_H

#include "config.h"
#include <stdbool.h>
#include <stdint.h>
#include "mutt/lib.h"
#include "core/lib.h"

// IWYU pragma: begin_exports
#include "color.h"
#include "command2.h"
#include "notify2.h"
#include "quoted.h"
#include "regex4.h"
#include "simple2.h"
// IWYU pragma: end_exports

bool mutt_color_is_header(enum ColorId color_id);
int mutt_color_alloc  (uint32_t fg, uint32_t bg);
int mutt_color_combine(uint32_t fg_attr, uint32_t bg_attr);
void mutt_color_free  (uint32_t fg, uint32_t bg);

void mutt_colors_init(void);
void mutt_colors_cleanup(void);

void colors_clear(void);

#endif /* MUTT_COLOR_LIB_H */
