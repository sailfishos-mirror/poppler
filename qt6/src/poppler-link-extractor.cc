/* poppler-link-extractor_p.h: qt interface to poppler
 * Copyright (C) 2007, 2008, 2011, Pino Toscano <pino@kde.org>
 * Copyright (C) 2008, Albert Astals Cid <aacid@kde.org>
 * Copyright (C) 2021, Oliver Sander <oliver.sander@tu-dresden.de>
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

#include "poppler-link-extractor-private.h"

#include <GfxState.h>
#include <Link.h>
#include <Object.h>
#include <Page.h>
#include <Annot.h>

#include "poppler-qt6.h"
#include "poppler-page-private.h"

namespace Poppler {

LinkExtractorOutputDev::LinkExtractorOutputDev(PageData *data) : m_data(data)
{
    Q_ASSERT(m_data);
    ::Page *popplerPage = m_data->page;
    m_pageCropWidth = popplerPage->getCropWidth();
    m_pageCropHeight = popplerPage->getCropHeight();
    if (popplerPage->getRotate() == 90 || popplerPage->getRotate() == 270) {
        qSwap(m_pageCropWidth, m_pageCropHeight);
    }
    GfxState gfxState(72.0, 72.0, popplerPage->getCropBox(), popplerPage->getRotate(), true);
    setDefaultCTM(gfxState.getCTM());
}

LinkExtractorOutputDev::~LinkExtractorOutputDev() = default;

void LinkExtractorOutputDev::processLink(::AnnotLink *link)
{
    if (!link->isOk()) {
        return;
    }

    double left, top, right, bottom;
    int leftAux, topAux, rightAux, bottomAux;
    link->getRect(&left, &top, &right, &bottom);
    QRectF linkArea;

    cvtUserToDev(left, top, &leftAux, &topAux);
    cvtUserToDev(right, bottom, &rightAux, &bottomAux);
    linkArea.setLeft((double)leftAux / m_pageCropWidth);
    linkArea.setTop((double)topAux / m_pageCropHeight);
    linkArea.setRight((double)rightAux / m_pageCropWidth);
    linkArea.setBottom((double)bottomAux / m_pageCropHeight);

    std::unique_ptr<Link> popplerLink = m_data->convertLinkActionToLink(link->getAction(), linkArea);
    if (popplerLink) {
        m_links.push_back(std::move(popplerLink));
    }
    OutputDev::processLink(link);
}

std::vector<std::unique_ptr<Link>> LinkExtractorOutputDev::links()
{
    return std::move(m_links);
}

}
