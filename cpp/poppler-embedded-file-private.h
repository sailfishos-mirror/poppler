/*
 * Copyright (C) 2009, 2011, Pino Toscano <pino@kde.org>
 * Copyright (C) 2018, 2021, 2022, Albert Astals Cid <aacid@kde.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef POPPLER_EMBEDDED_FILE_PRIVATE_H
#define POPPLER_EMBEDDED_FILE_PRIVATE_H

#include <FileSpec.h>

#include <memory>

namespace poppler {

class embedded_file_private
{
public:
    explicit embedded_file_private(std::unique_ptr<FileSpec> &&fs);

    static embedded_file *create(std::unique_ptr<FileSpec> &&fs);

    std::unique_ptr<FileSpec> file_spec;
};

}

#endif
