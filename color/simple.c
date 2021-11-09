/**
 * @file
 * Simple colour
 *
 * @authors
 * Copyright (C) 2021 Richard Russon <rich@flatcap.org>
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
 * @page color_simple Simple colour
 *
 * Manage the colours of the 'simple' graphical objects -- those that can only
 * have one colour, plus attributes.
 */

#include "config.h"
#include <stddef.h>
#include <stdbool.h>
#include "mutt/lib.h"
#include "gui/lib.h"
#include "debug.h"

struct AttrColor SimpleColors[MT_COLOR_MAX]; ///< Array of Simple colours

/**
 * simple_colors_init - Initialise the simple colour definitions
 */
void simple_colors_init(void)
{
  // Set some defaults
  color_debug("init indicator, markers, etc\n");
  SimpleColors[MT_COLOR_INDICATOR].attrs = A_REVERSE;
  SimpleColors[MT_COLOR_MARKERS].attrs = A_REVERSE;
  SimpleColors[MT_COLOR_SEARCH].attrs = A_REVERSE;
#ifdef USE_SIDEBAR
  SimpleColors[MT_COLOR_SIDEBAR_HIGHLIGHT].attrs = A_UNDERLINE;
#endif
  SimpleColors[MT_COLOR_STATUS].attrs = A_REVERSE;
}

/**
 * simple_colors_clear - Reset the simple colour definitions
 */
void simple_colors_clear(void)
{
  color_debug("clean up defs\n");
  for (size_t i = 0; i < MT_COLOR_MAX; i++)
  {
    attr_color_clear(&SimpleColors[i]);
  }
}

/**
 * simple_color_get - Get the colour of an object by its ID
 * @param id Colour ID, e.g. #MT_COLOR_SEARCH
 * @retval ptr AttrColor of the object
 *
 * @note Do not free the returned object
 */
struct AttrColor *simple_color_get(enum ColorId color)
{
  if (color >= MT_COLOR_MAX)
  {
    mutt_error("colour overflow %d", color);
    return NULL;
  }
  if (color <= MT_COLOR_NONE)
  {
    mutt_error("colour underflow %d", color);
    return NULL;
  }

  return &SimpleColors[color];
}

/**
 * simple_color_is_set - Is the object coloured?
 * @param color Colour color, e.g. #MT_COLOR_SEARCH
 * @retval true Yes, a 'color' command has been used on this object
 */
bool simple_color_is_set(enum ColorId color)
{
  return attr_color_is_set(simple_color_get(color));
}

/**
 * simple_color_is_header - Colour is for an Email header
 * @param color_id Colour, e.g. #MT_COLOR_HEADER
 * @retval true Colour is for an Email header
 */
bool simple_color_is_header(enum ColorId color)
{
  return (color == MT_COLOR_HEADER) || (color == MT_COLOR_HDRDEFAULT);
}

/**
 * simple_color_set - Set the colour of a simple object
 * @param id    Colour ID, e.g. #MT_COLOR_SEARCH
 * @param fg    Foreground colour
 * @param bg    Background colour
 * @param attrs Attributes, e.g. A_UNDERLINE
 * @retval ptr Colour
 */
struct AttrColor *simple_color_set(enum ColorId color, int fg, int bg, int attrs)
{
  struct AttrColor *ac = simple_color_get(color);
  if (!ac)
    return NULL;

  struct CursesColor *cc = curses_color_new(fg, bg);
  curses_color_free(&ac->curses_color);
  ac->curses_color = cc;
  ac->attrs = attrs;

  return ac;
}

/**
 * simple_color_reset - Clear the colour of a simple object
 * @param color Colour color, e.g. #MT_COLOR_SEARCH
 */
void simple_color_reset(enum ColorId color)
{
  struct AttrColor *ac = simple_color_get(color);
  if (!ac)
    return;

  struct Buffer *buf = mutt_buffer_pool_get();
  get_colorid_name(color, buf);
  mutt_debug(LL_NOTIFY, "NT_COLOR_RESET: %s\n", buf->data);
  mutt_buffer_pool_release(&buf);

  struct EventColor ev_c = { color, ac };
  notify_send(ColorsNotify, NT_COLOR, NT_COLOR_RESET, &ev_c);

  attr_color_clear(ac);
}
