//========================================================================
//
// FoFiType1C.cc
//
// Copyright 1999-2003 Glyph & Cog, LLC
//
//========================================================================

//========================================================================
//
// Modified under the Poppler project - http://poppler.freedesktop.org
//
// All changes made under the Poppler project to this file are licensed
// under GPL version 2 or later
//
// Copyright (C) 2009, 2010, 2017-2022 Albert Astals Cid <aacid@kde.org>
// Copyright (C) 2012 Thomas Freitag <Thomas.Freitag@alfa.de>
// Copyright (C) 2018 Adam Reichold <adam.reichold@t-online.de>
// Copyright (C) 2019 Tomoyuki Kubota <himajin100000@gmail.com>
// Copyright (C) 2019 Volker Krause <vkrause@kde.org>
// Copyright (C) 2022, 2024 Oliver Sander <oliver.sander@tu-dresden.de>
// Copyright (C) 2025 g10 Code GmbH, Author: Sune Stolborg Vuorela <sune@vuorela.dk>
//
// To see a description of the changes please see the Changelog file that
// came with your tarball or type make ChangeLog if you are building from git
//
//========================================================================

#include <config.h>

#include <cstdlib>
#include <cstring>
#include <cmath>
#include "goo/gmem.h"
#include "goo/gstrtod.h"
#include "goo/GooLikely.h"
#include "goo/GooString.h"
#include "poppler/Error.h"
#include "FoFiEncodings.h"
#include "FoFiType1C.h"

//------------------------------------------------------------------------

static const char hexChars[17] = "0123456789ABCDEF";

//------------------------------------------------------------------------
// FoFiType1C
//------------------------------------------------------------------------

std::unique_ptr<FoFiType1C> FoFiType1C::make(std::vector<unsigned char> &&fileA)
{
    auto ff = std::make_unique<FoFiType1C>(std::move(fileA));
    if (!ff->parse()) {
        return nullptr;
    }
    return ff;
}
std::unique_ptr<FoFiType1C> FoFiType1C::make(std::span<unsigned char> data)
{
    auto ff = std::make_unique<FoFiType1C>(data);
    if (!ff->parse()) {
        return nullptr;
    }
    return ff;
}

std::unique_ptr<FoFiType1C> FoFiType1C::load(const char *fileName)
{
    std::optional<std::vector<unsigned char>> fileA;

    if (!(fileA = FoFiBase::readFile(fileName))) {
        return nullptr;
    }
    auto ff = std::make_unique<FoFiType1C>(std::move(fileA.value()));
    if (!ff->parse()) {
        return nullptr;
    }
    return ff;
}

FoFiType1C::FoFiType1C(std::vector<unsigned char> &&fileA, PrivateTag) : FoFiBase(std::move(fileA))
{
    encoding = nullptr;
    privateDicts = nullptr;
    fdSelect = nullptr;
    charset = nullptr;
    charsetLength = 0;
}

FoFiType1C::FoFiType1C(std::span<unsigned char> data, PrivateTag) : FoFiBase(data)
{
    encoding = nullptr;
    privateDicts = nullptr;
    fdSelect = nullptr;
    charset = nullptr;
    charsetLength = 0;
}

FoFiType1C::~FoFiType1C()
{
    int i;

    if (encoding && encoding != fofiType1StandardEncoding && encoding != fofiType1ExpertEncoding) {
        for (i = 0; i < 256; ++i) {
            gfree(encoding[i]);
        }
        gfree(static_cast<void *>(encoding));
    }
    if (privateDicts) {
        gfree(privateDicts);
    }
    if (fdSelect) {
        gfree(fdSelect);
    }
    if (charset && charset != fofiType1CISOAdobeCharset && charset != fofiType1CExpertCharset && charset != fofiType1CExpertSubsetCharset) {
        gfree(const_cast<unsigned short *>(charset));
    }
}

const char *FoFiType1C::getName() const
{
    return name ? name->c_str() : nullptr;
}

char **FoFiType1C::getEncoding() const
{
    return encoding;
}

GooString *FoFiType1C::getGlyphName(int gid) const
{
    char buf[256];
    bool ok;

    ok = true;
    if (gid < 0 || gid >= charsetLength) {
        return nullptr;
    }
    getString(charset[gid], buf, &ok);
    if (!ok) {
        return nullptr;
    }
    return new GooString(buf);
}

std::vector<int> FoFiType1C::getCIDToGIDMap() const
{
    int n, i;

    // a CID font's top dict has ROS as the first operator
    if (topDict.firstOp != 0x0c1e) {
        return {};
    }

    // in a CID font, the charset data is the GID-to-CID mapping, so all
    // we have to do is reverse it
    n = 0;
    for (i = 0; i < nGlyphs && i < charsetLength; ++i) {
        if (charset[i] > n) {
            n = charset[i];
        }
    }
    ++n;
    std::vector<int> map;
    map.resize(n, 0);
    for (i = 0; i < nGlyphs; ++i) {
        map[charset[i]] = i;
    }
    return map;
}

void FoFiType1C::getFontMatrix(double *mat) const
{
    int i;

    if (topDict.firstOp == 0x0c1e && privateDicts[0].hasFontMatrix) {
        if (topDict.hasFontMatrix) {
            mat[0] = topDict.fontMatrix[0] * privateDicts[0].fontMatrix[0] + topDict.fontMatrix[1] * privateDicts[0].fontMatrix[2];
            mat[1] = topDict.fontMatrix[0] * privateDicts[0].fontMatrix[1] + topDict.fontMatrix[1] * privateDicts[0].fontMatrix[3];
            mat[2] = topDict.fontMatrix[2] * privateDicts[0].fontMatrix[0] + topDict.fontMatrix[3] * privateDicts[0].fontMatrix[2];
            mat[3] = topDict.fontMatrix[2] * privateDicts[0].fontMatrix[1] + topDict.fontMatrix[3] * privateDicts[0].fontMatrix[3];
            mat[4] = topDict.fontMatrix[4] * privateDicts[0].fontMatrix[0] + topDict.fontMatrix[5] * privateDicts[0].fontMatrix[2];
            mat[5] = topDict.fontMatrix[4] * privateDicts[0].fontMatrix[1] + topDict.fontMatrix[5] * privateDicts[0].fontMatrix[3];
        } else {
            for (i = 0; i < 6; ++i) {
                mat[i] = privateDicts[0].fontMatrix[i];
            }
        }
    } else {
        for (i = 0; i < 6; ++i) {
            mat[i] = topDict.fontMatrix[i];
        }
    }
}

void FoFiType1C::convertToType1(const char *psName, const char **newEncoding, bool ascii, FoFiOutputFunc outputFunc, void *outputStream)
{
    int psNameLen;
    Type1CEexecBuf eb;
    Type1CIndex subrIdx;
    Type1CIndexVal val;
    char buf2[256];
    bool ok;
    int i;

    if (psName) {
        psNameLen = strlen(psName);
    } else {
        psName = name->c_str();
        psNameLen = name->getLength();
    }

    // write header and font dictionary, up to encoding
    ok = true;
    (*outputFunc)(outputStream, "%!FontType1-1.0: ", 17);
    (*outputFunc)(outputStream, psName, psNameLen);
    if (topDict.versionSID != 0) {
        getString(topDict.versionSID, buf2, &ok);
        (*outputFunc)(outputStream, buf2, strlen(buf2));
    }
    (*outputFunc)(outputStream, "\n", 1);
    // the dictionary needs room for 12 entries: the following 9, plus
    // Private and CharStrings (in the eexec section) and FID (which is
    // added by definefont)
    (*outputFunc)(outputStream, "12 dict begin\n", 14);
    (*outputFunc)(outputStream, "/FontInfo 10 dict dup begin\n", 28);
    if (topDict.versionSID != 0) {
        (*outputFunc)(outputStream, "/version ", 9);
        writePSString(buf2, outputFunc, outputStream);
        (*outputFunc)(outputStream, " readonly def\n", 14);
    }
    if (topDict.noticeSID != 0) {
        getString(topDict.noticeSID, buf2, &ok);
        (*outputFunc)(outputStream, "/Notice ", 8);
        writePSString(buf2, outputFunc, outputStream);
        (*outputFunc)(outputStream, " readonly def\n", 14);
    }
    if (topDict.copyrightSID != 0) {
        getString(topDict.copyrightSID, buf2, &ok);
        (*outputFunc)(outputStream, "/Copyright ", 11);
        writePSString(buf2, outputFunc, outputStream);
        (*outputFunc)(outputStream, " readonly def\n", 14);
    }
    if (topDict.fullNameSID != 0) {
        getString(topDict.fullNameSID, buf2, &ok);
        (*outputFunc)(outputStream, "/FullName ", 10);
        writePSString(buf2, outputFunc, outputStream);
        (*outputFunc)(outputStream, " readonly def\n", 14);
    }
    if (topDict.familyNameSID != 0) {
        getString(topDict.familyNameSID, buf2, &ok);
        (*outputFunc)(outputStream, "/FamilyName ", 12);
        writePSString(buf2, outputFunc, outputStream);
        (*outputFunc)(outputStream, " readonly def\n", 14);
    }
    if (topDict.weightSID != 0) {
        getString(topDict.weightSID, buf2, &ok);
        (*outputFunc)(outputStream, "/Weight ", 8);
        writePSString(buf2, outputFunc, outputStream);
        (*outputFunc)(outputStream, " readonly def\n", 14);
    }
    if (topDict.isFixedPitch) {
        (*outputFunc)(outputStream, "/isFixedPitch true def\n", 23);
    } else {
        (*outputFunc)(outputStream, "/isFixedPitch false def\n", 24);
    }
    std::string buf = GooString::format("/ItalicAngle {0:.4g} def\n", topDict.italicAngle);
    (*outputFunc)(outputStream, buf.c_str(), buf.size());
    buf = GooString::format("/UnderlinePosition {0:.4g} def\n", topDict.underlinePosition);
    (*outputFunc)(outputStream, buf.c_str(), buf.size());
    buf = GooString::format("/UnderlineThickness {0:.4g} def\n", topDict.underlineThickness);
    (*outputFunc)(outputStream, buf.c_str(), buf.size());
    (*outputFunc)(outputStream, "end readonly def\n", 17);
    (*outputFunc)(outputStream, "/FontName /", 11);
    (*outputFunc)(outputStream, psName, psNameLen);
    (*outputFunc)(outputStream, " def\n", 5);
    buf = GooString::format("/PaintType {0:d} def\n", topDict.paintType);
    (*outputFunc)(outputStream, buf.c_str(), buf.size());
    (*outputFunc)(outputStream, "/FontType 1 def\n", 16);
    buf = GooString::format("/FontMatrix [{0:.8g} {1:.8g} {2:.8g} {3:.8g} {4:.8g} {5:.8g}] readonly def\n", topDict.fontMatrix[0], topDict.fontMatrix[1], topDict.fontMatrix[2], topDict.fontMatrix[3], topDict.fontMatrix[4],
                            topDict.fontMatrix[5]);
    (*outputFunc)(outputStream, buf.c_str(), buf.size());
    buf = GooString::format("/FontBBox [{0:.4g} {1:.4g} {2:.4g} {3:.4g}] readonly def\n", topDict.fontBBox[0], topDict.fontBBox[1], topDict.fontBBox[2], topDict.fontBBox[3]);
    (*outputFunc)(outputStream, buf.c_str(), buf.size());
    buf = GooString::format("/StrokeWidth {0:.4g} def\n", topDict.strokeWidth);
    (*outputFunc)(outputStream, buf.c_str(), buf.size());
    if (topDict.uniqueID != 0) {
        buf = GooString::format("/UniqueID {0:d} def\n", topDict.uniqueID);
        (*outputFunc)(outputStream, buf.c_str(), buf.size());
    }

    // write the encoding
    (*outputFunc)(outputStream, "/Encoding ", 10);
    if (!newEncoding && encoding == fofiType1StandardEncoding) {
        (*outputFunc)(outputStream, "StandardEncoding def\n", 21);
    } else {
        (*outputFunc)(outputStream, "256 array\n", 10);
        (*outputFunc)(outputStream, "0 1 255 {1 index exch /.notdef put} for\n", 40);
        const char **enc = newEncoding ? newEncoding : (const char **)encoding;
        for (i = 0; i < 256; ++i) {
            if (enc && enc[i]) {
                buf = GooString::format("dup {0:d} /{1:s} put\n", i, enc[i]);
                (*outputFunc)(outputStream, buf.c_str(), buf.size());
            }
        }
        (*outputFunc)(outputStream, "readonly def\n", 13);
    }
    (*outputFunc)(outputStream, "currentdict end\n", 16);

    // start the binary section
    (*outputFunc)(outputStream, "currentfile eexec\n", 18);
    eb.outputFunc = outputFunc;
    eb.outputStream = outputStream;
    eb.ascii = ascii;
    eb.r1 = 55665;
    eb.line = 0;

    // write the private dictionary
    eexecWrite(&eb, "\x83\xca\x73\xd5");
    eexecWrite(&eb, "dup /Private 32 dict dup begin\n");
    eexecWrite(&eb,
               "/RD {string currentfile exch readstring pop}"
               " executeonly def\n");
    eexecWrite(&eb, "/ND {noaccess def} executeonly def\n");
    eexecWrite(&eb, "/NP {noaccess put} executeonly def\n");
    eexecWrite(&eb, "/MinFeature {16 16} def\n");
    eexecWrite(&eb, "/password 5839 def\n");
    if (privateDicts[0].nBlueValues) {
        eexecWrite(&eb, "/BlueValues [");
        for (i = 0; i < privateDicts[0].nBlueValues; ++i) {
            buf = GooString::format("{0:s}{1:d}", i > 0 ? " " : "", privateDicts[0].blueValues[i]);
            eexecWrite(&eb, buf.c_str());
        }
        eexecWrite(&eb, "] def\n");
    }
    if (privateDicts[0].nOtherBlues) {
        eexecWrite(&eb, "/OtherBlues [");
        for (i = 0; i < privateDicts[0].nOtherBlues; ++i) {
            buf = GooString::format("{0:s}{1:d}", i > 0 ? " " : "", privateDicts[0].otherBlues[i]);
            eexecWrite(&eb, buf.c_str());
        }
        eexecWrite(&eb, "] def\n");
    }
    if (privateDicts[0].nFamilyBlues) {
        eexecWrite(&eb, "/FamilyBlues [");
        for (i = 0; i < privateDicts[0].nFamilyBlues; ++i) {
            buf = GooString::format("{0:s}{1:d}", i > 0 ? " " : "", privateDicts[0].familyBlues[i]);
            eexecWrite(&eb, buf.c_str());
        }
        eexecWrite(&eb, "] def\n");
    }
    if (privateDicts[0].nFamilyOtherBlues) {
        eexecWrite(&eb, "/FamilyOtherBlues [");
        for (i = 0; i < privateDicts[0].nFamilyOtherBlues; ++i) {
            buf = GooString::format("{0:s}{1:d}", i > 0 ? " " : "", privateDicts[0].familyOtherBlues[i]);
            eexecWrite(&eb, buf.c_str());
        }
        eexecWrite(&eb, "] def\n");
    }
    if (privateDicts[0].blueScale != 0.039625) {
        buf = GooString::format("/BlueScale {0:.4g} def\n", privateDicts[0].blueScale);
        eexecWrite(&eb, buf.c_str());
    }
    if (privateDicts[0].blueShift != 7) {
        buf = GooString::format("/BlueShift {0:d} def\n", privateDicts[0].blueShift);
        eexecWrite(&eb, buf.c_str());
    }
    if (privateDicts[0].blueFuzz != 1) {
        buf = GooString::format("/BlueFuzz {0:d} def\n", privateDicts[0].blueFuzz);
        eexecWrite(&eb, buf.c_str());
    }
    if (privateDicts[0].hasStdHW) {
        buf = GooString::format("/StdHW [{0:.4g}] def\n", privateDicts[0].stdHW);
        eexecWrite(&eb, buf.c_str());
    }
    if (privateDicts[0].hasStdVW) {
        buf = GooString::format("/StdVW [{0:.4g}] def\n", privateDicts[0].stdVW);
        eexecWrite(&eb, buf.c_str());
    }
    if (privateDicts[0].nStemSnapH) {
        eexecWrite(&eb, "/StemSnapH [");
        for (i = 0; i < privateDicts[0].nStemSnapH; ++i) {
            buf = GooString::format("{0:s}{1:.4g}", i > 0 ? " " : "", privateDicts[0].stemSnapH[i]);
            eexecWrite(&eb, buf.c_str());
        }
        eexecWrite(&eb, "] def\n");
    }
    if (privateDicts[0].nStemSnapV) {
        eexecWrite(&eb, "/StemSnapV [");
        for (i = 0; i < privateDicts[0].nStemSnapV; ++i) {
            buf = GooString::format("{0:s}{1:.4g}", i > 0 ? " " : "", privateDicts[0].stemSnapV[i]);
            eexecWrite(&eb, buf.c_str());
        }
        eexecWrite(&eb, "] def\n");
    }
    if (privateDicts[0].hasForceBold) {
        buf = GooString::format("/ForceBold {0:s} def\n", privateDicts[0].forceBold ? "true" : "false");
        eexecWrite(&eb, buf.c_str());
    }
    if (privateDicts[0].forceBoldThreshold != 0) {
        buf = GooString::format("/ForceBoldThreshold {0:.4g} def\n", privateDicts[0].forceBoldThreshold);
        eexecWrite(&eb, buf.c_str());
    }
    if (privateDicts[0].languageGroup != 0) {
        buf = GooString::format("/LanguageGroup {0:d} def\n", privateDicts[0].languageGroup);
        eexecWrite(&eb, buf.c_str());
    }
    if (privateDicts[0].expansionFactor != 0.06) {
        buf = GooString::format("/ExpansionFactor {0:.4g} def\n", privateDicts[0].expansionFactor);
        eexecWrite(&eb, buf.c_str());
    }

    // set up subroutines
    ok = true;
    getIndex(privateDicts[0].subrsOffset, &subrIdx, &ok);
    if (!ok) {
        subrIdx.pos = -1;
    }

    // write the CharStrings
    buf = GooString::format("2 index /CharStrings {0:d} dict dup begin\n", nGlyphs);
    eexecWrite(&eb, buf.c_str());
    for (i = 0; i < nGlyphs; ++i) {
        ok = true;
        getIndexVal(&charStringsIdx, i, &val, &ok);
        if (ok && i < charsetLength) {
            getString(charset[i], buf2, &ok);
            if (ok) {
                eexecCvtGlyph(&eb, buf2, val.pos, val.len, &subrIdx, &privateDicts[0]);
            }
        }
    }
    eexecWrite(&eb, "end\n");
    eexecWrite(&eb, "end\n");
    eexecWrite(&eb, "readonly put\n");
    eexecWrite(&eb, "noaccess put\n");
    eexecWrite(&eb, "dup /FontName get exch definefont pop\n");
    eexecWrite(&eb, "mark currentfile closefile\n");

    // trailer
    if (ascii && eb.line > 0) {
        (*outputFunc)(outputStream, "\n", 1);
    }
    for (i = 0; i < 8; ++i) {
        (*outputFunc)(outputStream, "0000000000000000000000000000000000000000000000000000000000000000\n", 65);
    }
    (*outputFunc)(outputStream, "cleartomark\n", 12);
}

void FoFiType1C::convertToCIDType0(const char *psName, const std::vector<int> &codeMap, FoFiOutputFunc outputFunc, void *outputStream)
{
    std::vector<int> cidMap;
    GooString charStrings;
    int *charStringOffsets;
    Type1CIndex subrIdx;
    Type1CIndexVal val;
    int gdBytes;
    char buf2[256];
    bool ok;
    int gid, offset, n, j, k;

    // compute the CID count and build the CID-to-GID mapping
    if (!codeMap.empty()) {
        cidMap.reserve(codeMap.size());
        for (int c : codeMap) {
            if (c >= 0 && c < nGlyphs) {
                cidMap.push_back(c);
            } else {
                cidMap.push_back(-1);
            }
        }
    } else if (topDict.firstOp == 0x0c1e) {
        int nCIDs = 0;
        for (int i = 0; i < nGlyphs && i < charsetLength; ++i) {
            if (charset[i] >= nCIDs) {
                nCIDs = charset[i] + 1;
            }
        }
        cidMap.resize(nCIDs, -1);
        for (int i = 0; i < nGlyphs && i < charsetLength; ++i) {
            cidMap[charset[i]] = i;
        }
    } else {
        int nCIDs = nGlyphs;
        cidMap.resize(nCIDs, 0);
        for (int i = 0; i < nCIDs; ++i) {
            cidMap[i] = i;
        }
    }

    // build the charstrings
    charStringOffsets = (int *)gmallocn(cidMap.size() + 1, sizeof(int));
    for (size_t i = 0; i < cidMap.size(); ++i) {
        charStringOffsets[i] = charStrings.getLength();
        if ((gid = cidMap[i]) >= 0) {
            ok = true;
            getIndexVal(&charStringsIdx, gid, &val, &ok);
            if (ok) {
                getIndex(privateDicts[fdSelect ? fdSelect[gid] : 0].subrsOffset, &subrIdx, &ok);
                if (!ok) {
                    subrIdx.pos = -1;
                }
                std::set<int> offsetBeingParsed;
                cvtGlyph(val.pos, val.len, &charStrings, &subrIdx, &privateDicts[fdSelect ? fdSelect[gid] : 0], true, offsetBeingParsed);
            }
        }
    }
    charStringOffsets[cidMap.size()] = charStrings.getLength();

    // compute gdBytes = number of bytes needed for charstring offsets
    // (offset size needs to account for the charstring offset table,
    // with a worst case of five bytes per entry, plus the charstrings
    // themselves)
    int i = (cidMap.size() + 1) * 5 + charStrings.getLength();
    if (i < 0x100) {
        gdBytes = 1;
    } else if (i < 0x10000) {
        gdBytes = 2;
    } else if (i < 0x1000000) {
        gdBytes = 3;
    } else {
        gdBytes = 4;
    }

    // begin the font dictionary
    (*outputFunc)(outputStream, "/CIDInit /ProcSet findresource begin\n", 37);
    (*outputFunc)(outputStream, "20 dict begin\n", 14);
    (*outputFunc)(outputStream, "/CIDFontName /", 14);
    (*outputFunc)(outputStream, psName, strlen(psName));
    (*outputFunc)(outputStream, " def\n", 5);
    (*outputFunc)(outputStream, "/CIDFontType 0 def\n", 19);
    (*outputFunc)(outputStream, "/CIDSystemInfo 3 dict dup begin\n", 32);
    if (topDict.registrySID > 0 && topDict.orderingSID > 0) {
        ok = true;
        getString(topDict.registrySID, buf2, &ok);
        if (ok) {
            (*outputFunc)(outputStream, "  /Registry (", 13);
            (*outputFunc)(outputStream, buf2, strlen(buf2));
            (*outputFunc)(outputStream, ") def\n", 6);
        }
        ok = true;
        getString(topDict.orderingSID, buf2, &ok);
        if (ok) {
            (*outputFunc)(outputStream, "  /Ordering (", 13);
            (*outputFunc)(outputStream, buf2, strlen(buf2));
            (*outputFunc)(outputStream, ") def\n", 6);
        }
    } else {
        (*outputFunc)(outputStream, "  /Registry (Adobe) def\n", 24);
        (*outputFunc)(outputStream, "  /Ordering (Identity) def\n", 27);
    }
    std::string buf = GooString::format("  /Supplement {0:d} def\n", topDict.supplement);
    (*outputFunc)(outputStream, buf.c_str(), buf.size());
    (*outputFunc)(outputStream, "end def\n", 8);
    if (topDict.hasFontMatrix) {
        buf = GooString::format("/FontMatrix [{0:.8g} {1:.8g} {2:.8g} {3:.8g} {4:.8g} {5:.8g}] def\n", topDict.fontMatrix[0], topDict.fontMatrix[1], topDict.fontMatrix[2], topDict.fontMatrix[3], topDict.fontMatrix[4],
                                topDict.fontMatrix[5]);
        (*outputFunc)(outputStream, buf.c_str(), buf.size());
    } else if (privateDicts[0].hasFontMatrix) {
        (*outputFunc)(outputStream, "/FontMatrix [1 0 0 1 0 0] def\n", 30);
    } else {
        (*outputFunc)(outputStream, "/FontMatrix [0.001 0 0 0.001 0 0] def\n", 38);
    }
    buf = GooString::format("/FontBBox [{0:.4g} {1:.4g} {2:.4g} {3:.4g}] def\n", topDict.fontBBox[0], topDict.fontBBox[1], topDict.fontBBox[2], topDict.fontBBox[3]);
    (*outputFunc)(outputStream, buf.c_str(), buf.size());
    (*outputFunc)(outputStream, "/FontInfo 1 dict dup begin\n", 27);
    (*outputFunc)(outputStream, "  /FSType 8 def\n", 16);
    (*outputFunc)(outputStream, "end def\n", 8);

    // CIDFont-specific entries
    buf = GooString::format("/CIDCount {0:d} def\n", int(cidMap.size()));
    (*outputFunc)(outputStream, buf.c_str(), buf.size());
    (*outputFunc)(outputStream, "/FDBytes 1 def\n", 15);
    buf = GooString::format("/GDBytes {0:d} def\n", gdBytes);
    (*outputFunc)(outputStream, buf.c_str(), buf.size());
    (*outputFunc)(outputStream, "/CIDMapOffset 0 def\n", 20);
    if (topDict.paintType != 0) {
        buf = GooString::format("/PaintType {0:d} def\n", topDict.paintType);
        (*outputFunc)(outputStream, buf.c_str(), buf.size());
        buf = GooString::format("/StrokeWidth {0:.4g} def\n", topDict.strokeWidth);
        (*outputFunc)(outputStream, buf.c_str(), buf.size());
    }

    // FDArray entry
    buf = GooString::format("/FDArray {0:d} array\n", nFDs);
    (*outputFunc)(outputStream, buf.c_str(), buf.size());
    for (i = 0; i < nFDs; ++i) {
        buf = GooString::format("dup {0:d} 10 dict begin\n", i);
        (*outputFunc)(outputStream, buf.c_str(), buf.size());
        (*outputFunc)(outputStream, "/FontType 1 def\n", 16);
        if (privateDicts[i].hasFontMatrix) {
            buf = GooString::format("/FontMatrix [{0:.8g} {1:.8g} {2:.8g} {3:.8g} {4:.8g} {5:.8g}] def\n", privateDicts[i].fontMatrix[0], privateDicts[i].fontMatrix[1], privateDicts[i].fontMatrix[2], privateDicts[i].fontMatrix[3],
                                    privateDicts[i].fontMatrix[4], privateDicts[i].fontMatrix[5]);
            (*outputFunc)(outputStream, buf.c_str(), buf.size());
        } else {
            (*outputFunc)(outputStream, "/FontMatrix [1 0 0 1 0 0] def\n", 30);
        }
        buf = GooString::format("/PaintType {0:d} def\n", topDict.paintType);
        (*outputFunc)(outputStream, buf.c_str(), buf.size());
        (*outputFunc)(outputStream, "/Private 32 dict begin\n", 23);
        if (privateDicts[i].nBlueValues) {
            (*outputFunc)(outputStream, "/BlueValues [", 13);
            for (j = 0; j < privateDicts[i].nBlueValues; ++j) {
                buf = GooString::format("{0:s}{1:d}", j > 0 ? " " : "", privateDicts[i].blueValues[j]);
                (*outputFunc)(outputStream, buf.c_str(), buf.size());
            }
            (*outputFunc)(outputStream, "] def\n", 6);
        }
        if (privateDicts[i].nOtherBlues) {
            (*outputFunc)(outputStream, "/OtherBlues [", 13);
            for (j = 0; j < privateDicts[i].nOtherBlues; ++j) {
                buf = GooString::format("{0:s}{1:d}", j > 0 ? " " : "", privateDicts[i].otherBlues[j]);
                (*outputFunc)(outputStream, buf.c_str(), buf.size());
            }
            (*outputFunc)(outputStream, "] def\n", 6);
        }
        if (privateDicts[i].nFamilyBlues) {
            (*outputFunc)(outputStream, "/FamilyBlues [", 14);
            for (j = 0; j < privateDicts[i].nFamilyBlues; ++j) {
                buf = GooString::format("{0:s}{1:d}", j > 0 ? " " : "", privateDicts[i].familyBlues[j]);
                (*outputFunc)(outputStream, buf.c_str(), buf.size());
            }
            (*outputFunc)(outputStream, "] def\n", 6);
        }
        if (privateDicts[i].nFamilyOtherBlues) {
            (*outputFunc)(outputStream, "/FamilyOtherBlues [", 19);
            for (j = 0; j < privateDicts[i].nFamilyOtherBlues; ++j) {
                buf = GooString::format("{0:s}{1:d}", j > 0 ? " " : "", privateDicts[i].familyOtherBlues[j]);
                (*outputFunc)(outputStream, buf.c_str(), buf.size());
            }
            (*outputFunc)(outputStream, "] def\n", 6);
        }
        if (privateDicts[i].blueScale != 0.039625) {
            buf = GooString::format("/BlueScale {0:.4g} def\n", privateDicts[i].blueScale);
            (*outputFunc)(outputStream, buf.c_str(), buf.size());
        }
        if (privateDicts[i].blueShift != 7) {
            buf = GooString::format("/BlueShift {0:d} def\n", privateDicts[i].blueShift);
            (*outputFunc)(outputStream, buf.c_str(), buf.size());
        }
        if (privateDicts[i].blueFuzz != 1) {
            buf = GooString::format("/BlueFuzz {0:d} def\n", privateDicts[i].blueFuzz);
            (*outputFunc)(outputStream, buf.c_str(), buf.size());
        }
        if (privateDicts[i].hasStdHW) {
            buf = GooString::format("/StdHW [{0:.4g}] def\n", privateDicts[i].stdHW);
            (*outputFunc)(outputStream, buf.c_str(), buf.size());
        }
        if (privateDicts[i].hasStdVW) {
            buf = GooString::format("/StdVW [{0:.4g}] def\n", privateDicts[i].stdVW);
            (*outputFunc)(outputStream, buf.c_str(), buf.size());
        }
        if (privateDicts[i].nStemSnapH) {
            (*outputFunc)(outputStream, "/StemSnapH [", 12);
            for (j = 0; j < privateDicts[i].nStemSnapH; ++j) {
                buf = GooString::format("{0:s}{1:.4g}", j > 0 ? " " : "", privateDicts[i].stemSnapH[j]);
                (*outputFunc)(outputStream, buf.c_str(), buf.size());
            }
            (*outputFunc)(outputStream, "] def\n", 6);
        }
        if (privateDicts[i].nStemSnapV) {
            (*outputFunc)(outputStream, "/StemSnapV [", 12);
            for (j = 0; j < privateDicts[i].nStemSnapV; ++j) {
                buf = GooString::format("{0:s}{1:.4g}", j > 0 ? " " : "", privateDicts[i].stemSnapV[j]);
                (*outputFunc)(outputStream, buf.c_str(), buf.size());
            }
            (*outputFunc)(outputStream, "] def\n", 6);
        }
        if (privateDicts[i].hasForceBold) {
            buf = GooString::format("/ForceBold {0:s} def\n", privateDicts[i].forceBold ? "true" : "false");
            (*outputFunc)(outputStream, buf.c_str(), buf.size());
        }
        if (privateDicts[i].forceBoldThreshold != 0) {
            buf = GooString::format("/ForceBoldThreshold {0:.4g} def\n", privateDicts[i].forceBoldThreshold);
            (*outputFunc)(outputStream, buf.c_str(), buf.size());
        }
        if (privateDicts[i].languageGroup != 0) {
            buf = GooString::format("/LanguageGroup {0:d} def\n", privateDicts[i].languageGroup);
            (*outputFunc)(outputStream, buf.c_str(), buf.size());
        }
        if (privateDicts[i].expansionFactor != 0.06) {
            buf = GooString::format("/ExpansionFactor {0:.4g} def\n", privateDicts[i].expansionFactor);
            (*outputFunc)(outputStream, buf.c_str(), buf.size());
        }
        (*outputFunc)(outputStream, "currentdict end def\n", 20);
        (*outputFunc)(outputStream, "currentdict end put\n", 20);
    }
    (*outputFunc)(outputStream, "def\n", 4);

    // start the binary section
    offset = (cidMap.size() + 1) * (1 + gdBytes);
    buf = GooString::format("(Hex) {0:d} StartData\n", offset + charStrings.getLength());
    (*outputFunc)(outputStream, buf.c_str(), buf.size());

    // write the charstring offset (CIDMap) table
    for (i = 0; i <= int(cidMap.size()); i += 6) {
        for (j = 0; j < 6 && i + j <= int(cidMap.size()); ++j) {
            if (i + j < int(cidMap.size()) && cidMap[i + j] >= 0 && fdSelect) {
                buf2[0] = (char)fdSelect[cidMap[i + j]];
            } else {
                buf2[0] = (char)0;
            }
            n = offset + charStringOffsets[i + j];
            for (k = gdBytes; k >= 1; --k) {
                buf2[k] = (char)(n & 0xff);
                n >>= 8;
            }
            for (k = 0; k <= gdBytes; ++k) {
                buf = GooString::format("{0:02x}", buf2[k] & 0xff);
                (*outputFunc)(outputStream, buf.c_str(), buf.size());
            }
        }
        (*outputFunc)(outputStream, "\n", 1);
    }

    // write the charstring data
    n = charStrings.getLength();
    for (i = 0; i < n; i += 32) {
        for (j = 0; j < 32 && i + j < n; ++j) {
            buf = GooString::format("{0:02x}", charStrings.getChar(i + j) & 0xff);
            (*outputFunc)(outputStream, buf.c_str(), buf.size());
        }
        if (i + 32 >= n) {
            (*outputFunc)(outputStream, ">", 1);
        }
        (*outputFunc)(outputStream, "\n", 1);
    }

    gfree(charStringOffsets);
}

void FoFiType1C::convertToType0(const char *psName, const std::vector<int> &codeMap, FoFiOutputFunc outputFunc, void *outputStream)
{
    std::vector<int> cidMap;
    Type1CIndex subrIdx;
    Type1CIndexVal val;
    Type1CEexecBuf eb;
    bool ok;
    int fd, j, k;

    // compute the CID count and build the CID-to-GID mapping
    if (!codeMap.empty()) {
        cidMap.reserve(codeMap.size());
        for (int c : codeMap) {
            if (c >= 0 && c < nGlyphs) {
                cidMap.push_back(c);
            } else {
                cidMap.push_back(-1);
            }
        }
    } else if (topDict.firstOp == 0x0c1e) {
        int nCIDs = 0;
        for (int i = 0; i < nGlyphs && i < charsetLength; ++i) {
            if (charset[i] >= nCIDs) {
                nCIDs = charset[i] + 1;
            }
        }
        cidMap.resize(nCIDs, -1);
        for (int i = 0; i < nGlyphs && i < charsetLength; ++i) {
            cidMap[charset[i]] = i;
        }
    } else {
        int nCIDs = nGlyphs;
        cidMap.resize(nCIDs);
        for (int i = 0; i < nCIDs; ++i) {
            cidMap[i] = i;
        }
    }

    if (privateDicts) {
        // write the descendant Type 1 fonts
        for (int i = 0; i < int(cidMap.size()); i += 256) {

            //~ this assumes that all CIDs in this block have the same FD --
            //~ to handle multiple FDs correctly, need to somehow divide the
            //~ font up by FD; as a kludge we ignore CID 0, which is .notdef
            fd = 0;
            // if fdSelect is NULL, we have an 8-bit font, so just leave fd=0
            if (fdSelect) {
                for (j = i == 0 ? 1 : 0; j < 256 && i + j < int(cidMap.size()); ++j) {
                    if (cidMap[i + j] >= 0) {
                        fd = fdSelect[cidMap[i + j]];
                        break;
                    }
                }
            }

            if (fd >= nFDs) {
                continue;
            }

            // font dictionary (unencrypted section)
            (*outputFunc)(outputStream, "16 dict begin\n", 14);
            (*outputFunc)(outputStream, "/FontName /", 11);
            (*outputFunc)(outputStream, psName, strlen(psName));
            std::string buf = GooString::format("_{0:02x} def\n", i >> 8);
            (*outputFunc)(outputStream, buf.c_str(), buf.size());
            (*outputFunc)(outputStream, "/FontType 1 def\n", 16);
            if (privateDicts[fd].hasFontMatrix) {
                buf = GooString::format("/FontMatrix [{0:.8g} {1:.8g} {2:.8g} {3:.8g} {4:.8g} {5:.8g}] def\n", privateDicts[fd].fontMatrix[0], privateDicts[fd].fontMatrix[1], privateDicts[fd].fontMatrix[2], privateDicts[fd].fontMatrix[3],
                                        privateDicts[fd].fontMatrix[4], privateDicts[fd].fontMatrix[5]);
                (*outputFunc)(outputStream, buf.c_str(), buf.size());
            } else if (topDict.hasFontMatrix) {
                (*outputFunc)(outputStream, "/FontMatrix [1 0 0 1 0 0] def\n", 30);
            } else {
                (*outputFunc)(outputStream, "/FontMatrix [0.001 0 0 0.001 0 0] def\n", 38);
            }
            buf = GooString::format("/FontBBox [{0:.4g} {1:.4g} {2:.4g} {3:.4g}] def\n", topDict.fontBBox[0], topDict.fontBBox[1], topDict.fontBBox[2], topDict.fontBBox[3]);
            (*outputFunc)(outputStream, buf.c_str(), buf.size());
            buf = GooString::format("/PaintType {0:d} def\n", topDict.paintType);
            (*outputFunc)(outputStream, buf.c_str(), buf.size());
            if (topDict.paintType != 0) {
                buf = GooString::format("/StrokeWidth {0:.4g} def\n", topDict.strokeWidth);
                (*outputFunc)(outputStream, buf.c_str(), buf.size());
            }
            (*outputFunc)(outputStream, "/Encoding 256 array\n", 20);
            for (j = 0; j < 256 && i + j < int(cidMap.size()); ++j) {
                buf = GooString::format("dup {0:d} /c{1:02x} put\n", j, j);
                (*outputFunc)(outputStream, buf.c_str(), buf.size());
            }
            if (j < 256) {
                buf = GooString::format("{0:d} 1 255 {{ 1 index exch /.notdef put }} for\n", j);
                (*outputFunc)(outputStream, buf.c_str(), buf.size());
            }
            (*outputFunc)(outputStream, "readonly def\n", 13);
            (*outputFunc)(outputStream, "currentdict end\n", 16);

            // start the binary section
            (*outputFunc)(outputStream, "currentfile eexec\n", 18);
            eb.outputFunc = outputFunc;
            eb.outputStream = outputStream;
            eb.ascii = true;
            eb.r1 = 55665;
            eb.line = 0;

            // start the private dictionary
            eexecWrite(&eb, "\x83\xca\x73\xd5");
            eexecWrite(&eb, "dup /Private 32 dict dup begin\n");
            eexecWrite(&eb,
                       "/RD {string currentfile exch readstring pop}"
                       " executeonly def\n");
            eexecWrite(&eb, "/ND {noaccess def} executeonly def\n");
            eexecWrite(&eb, "/NP {noaccess put} executeonly def\n");
            eexecWrite(&eb, "/MinFeature {16 16} def\n");
            eexecWrite(&eb, "/password 5839 def\n");
            if (privateDicts[fd].nBlueValues) {
                eexecWrite(&eb, "/BlueValues [");
                for (k = 0; k < privateDicts[fd].nBlueValues; ++k) {
                    buf = GooString::format("{0:s}{1:d}", k > 0 ? " " : "", privateDicts[fd].blueValues[k]);
                    eexecWrite(&eb, buf.c_str());
                }
                eexecWrite(&eb, "] def\n");
            }
            if (privateDicts[fd].nOtherBlues) {
                eexecWrite(&eb, "/OtherBlues [");
                for (k = 0; k < privateDicts[fd].nOtherBlues; ++k) {
                    buf = GooString::format("{0:s}{1:d}", k > 0 ? " " : "", privateDicts[fd].otherBlues[k]);
                    eexecWrite(&eb, buf.c_str());
                }
                eexecWrite(&eb, "] def\n");
            }
            if (privateDicts[fd].nFamilyBlues) {
                eexecWrite(&eb, "/FamilyBlues [");
                for (k = 0; k < privateDicts[fd].nFamilyBlues; ++k) {
                    buf = GooString::format("{0:s}{1:d}", k > 0 ? " " : "", privateDicts[fd].familyBlues[k]);
                    eexecWrite(&eb, buf.c_str());
                }
                eexecWrite(&eb, "] def\n");
            }
            if (privateDicts[fd].nFamilyOtherBlues) {
                eexecWrite(&eb, "/FamilyOtherBlues [");
                for (k = 0; k < privateDicts[fd].nFamilyOtherBlues; ++k) {
                    buf = GooString::format("{0:s}{1:d}", k > 0 ? " " : "", privateDicts[fd].familyOtherBlues[k]);
                    eexecWrite(&eb, buf.c_str());
                }
                eexecWrite(&eb, "] def\n");
            }
            if (privateDicts[fd].blueScale != 0.039625) {
                buf = GooString::format("/BlueScale {0:.4g} def\n", privateDicts[fd].blueScale);
                eexecWrite(&eb, buf.c_str());
            }
            if (privateDicts[fd].blueShift != 7) {
                buf = GooString::format("/BlueShift {0:d} def\n", privateDicts[fd].blueShift);
                eexecWrite(&eb, buf.c_str());
            }
            if (privateDicts[fd].blueFuzz != 1) {
                buf = GooString::format("/BlueFuzz {0:d} def\n", privateDicts[fd].blueFuzz);
                eexecWrite(&eb, buf.c_str());
            }
            if (privateDicts[fd].hasStdHW) {
                buf = GooString::format("/StdHW [{0:.4g}] def\n", privateDicts[fd].stdHW);
                eexecWrite(&eb, buf.c_str());
            }
            if (privateDicts[fd].hasStdVW) {
                buf = GooString::format("/StdVW [{0:.4g}] def\n", privateDicts[fd].stdVW);
                eexecWrite(&eb, buf.c_str());
            }
            if (privateDicts[fd].nStemSnapH) {
                eexecWrite(&eb, "/StemSnapH [");
                for (k = 0; k < privateDicts[fd].nStemSnapH; ++k) {
                    buf = GooString::format("{0:s}{1:.4g}", k > 0 ? " " : "", privateDicts[fd].stemSnapH[k]);
                    eexecWrite(&eb, buf.c_str());
                }
                eexecWrite(&eb, "] def\n");
            }
            if (privateDicts[fd].nStemSnapV) {
                eexecWrite(&eb, "/StemSnapV [");
                for (k = 0; k < privateDicts[fd].nStemSnapV; ++k) {
                    buf = GooString::format("{0:s}{1:.4g}", k > 0 ? " " : "", privateDicts[fd].stemSnapV[k]);
                    eexecWrite(&eb, buf.c_str());
                }
                eexecWrite(&eb, "] def\n");
            }
            if (privateDicts[fd].hasForceBold) {
                buf = GooString::format("/ForceBold {0:s} def\n", privateDicts[fd].forceBold ? "true" : "false");
                eexecWrite(&eb, buf.c_str());
            }
            if (privateDicts[fd].forceBoldThreshold != 0) {
                buf = GooString::format("/ForceBoldThreshold {0:.4g} def\n", privateDicts[fd].forceBoldThreshold);
                eexecWrite(&eb, buf.c_str());
            }
            if (privateDicts[fd].languageGroup != 0) {
                buf = GooString::format("/LanguageGroup {0:d} def\n", privateDicts[fd].languageGroup);
                eexecWrite(&eb, buf.c_str());
            }
            if (privateDicts[fd].expansionFactor != 0.06) {
                buf = GooString::format("/ExpansionFactor {0:.4g} def\n", privateDicts[fd].expansionFactor);
                eexecWrite(&eb, buf.c_str());
            }

            // set up the subroutines
            ok = true;
            getIndex(privateDicts[fd].subrsOffset, &subrIdx, &ok);
            if (!ok) {
                subrIdx.pos = -1;
            }

            // start the CharStrings
            eexecWrite(&eb, "2 index /CharStrings 256 dict dup begin\n");

            // write the .notdef CharString
            ok = true;
            getIndexVal(&charStringsIdx, 0, &val, &ok);
            if (ok) {
                eexecCvtGlyph(&eb, ".notdef", val.pos, val.len, &subrIdx, &privateDicts[fd]);
            }

            // write the CharStrings
            for (j = 0; j < 256 && i + j < int(cidMap.size()); ++j) {
                if (cidMap[i + j] >= 0) {
                    ok = true;
                    getIndexVal(&charStringsIdx, cidMap[i + j], &val, &ok);
                    if (ok) {
                        buf = GooString::format("c{0:02x}", j);
                        eexecCvtGlyph(&eb, buf.c_str(), val.pos, val.len, &subrIdx, &privateDicts[fd]);
                    }
                }
            }
            eexecWrite(&eb, "end\n");
            eexecWrite(&eb, "end\n");
            eexecWrite(&eb, "readonly put\n");
            eexecWrite(&eb, "noaccess put\n");
            eexecWrite(&eb, "dup /FontName get exch definefont pop\n");
            eexecWrite(&eb, "mark currentfile closefile\n");

            // trailer
            if (eb.line > 0) {
                (*outputFunc)(outputStream, "\n", 1);
            }
            for (j = 0; j < 8; ++j) {
                (*outputFunc)(outputStream, "0000000000000000000000000000000000000000000000000000000000000000\n", 65);
            }
            (*outputFunc)(outputStream, "cleartomark\n", 12);
        }
    } else {
        error(errSyntaxError, -1, "FoFiType1C::convertToType0 without privateDicts");
    }

    // write the Type 0 parent font
    (*outputFunc)(outputStream, "16 dict begin\n", 14);
    (*outputFunc)(outputStream, "/FontName /", 11);
    (*outputFunc)(outputStream, psName, strlen(psName));
    (*outputFunc)(outputStream, " def\n", 5);
    (*outputFunc)(outputStream, "/FontType 0 def\n", 16);
    if (topDict.hasFontMatrix) {
        const std::string buf = GooString::format("/FontMatrix [{0:.8g} {1:.8g} {2:.8g} {3:.8g} {4:.8g} {5:.8g}] def\n", topDict.fontMatrix[0], topDict.fontMatrix[1], topDict.fontMatrix[2], topDict.fontMatrix[3], topDict.fontMatrix[4],
                                                  topDict.fontMatrix[5]);
        (*outputFunc)(outputStream, buf.c_str(), buf.size());
    } else {
        (*outputFunc)(outputStream, "/FontMatrix [1 0 0 1 0 0] def\n", 30);
    }
    (*outputFunc)(outputStream, "/FMapType 2 def\n", 16);
    (*outputFunc)(outputStream, "/Encoding [\n", 12);
    for (int i = 0; i < int(cidMap.size()); i += 256) {
        const std::string buf = GooString::format("{0:d}\n", i >> 8);
        (*outputFunc)(outputStream, buf.c_str(), buf.size());
    }
    (*outputFunc)(outputStream, "] def\n", 6);
    (*outputFunc)(outputStream, "/FDepVector [\n", 14);
    for (int i = 0; i < int(cidMap.size()); i += 256) {
        (*outputFunc)(outputStream, "/", 1);
        (*outputFunc)(outputStream, psName, strlen(psName));
        const std::string buf = GooString::format("_{0:02x} findfont\n", i >> 8);
        (*outputFunc)(outputStream, buf.c_str(), buf.size());
    }
    (*outputFunc)(outputStream, "] def\n", 6);
    (*outputFunc)(outputStream, "FontName currentdict end definefont pop\n", 40);
}

void FoFiType1C::eexecCvtGlyph(Type1CEexecBuf *eb, const char *glyphName, int offset, int nBytes, const Type1CIndex *subrIdx, const Type1CPrivateDict *pDict)
{
    GooString charBuf;

    // generate the charstring
    std::set<int> offsetBeingParsed;
    cvtGlyph(offset, nBytes, &charBuf, subrIdx, pDict, true, offsetBeingParsed);

    const std::string buf = GooString::format("/{0:s} {1:d} RD ", glyphName, charBuf.getLength());
    eexecWrite(eb, buf.c_str());
    eexecWriteCharstring(eb, (unsigned char *)charBuf.c_str(), charBuf.getLength());
    eexecWrite(eb, " ND\n");
}

void FoFiType1C::cvtGlyph(int offset, int nBytes, GooString *charBuf, const Type1CIndex *subrIdx, const Type1CPrivateDict *pDict, bool top, std::set<int> &offsetBeingParsed)
{
    Type1CIndexVal val;
    bool ok, dFP;
    double d, dx, dy;
    unsigned short r2;
    unsigned char byte;
    int pos, subrBias, start, i, k;

    if (offsetBeingParsed.find(offset) != offsetBeingParsed.end()) {
        return;
    }

    auto offsetEmplaceResult = offsetBeingParsed.emplace(offset);

    start = charBuf->getLength();
    if (top) {
        charBuf->append('\x49'); // 73;
        charBuf->append('\x3A'); // 58;
        charBuf->append('\x93'); // 147;
        charBuf->append('\x86'); // 134;
        nOps = 0;
        nHints = 0;
        firstOp = true;
        openPath = false;
    }

    pos = offset;
    while (pos < offset + nBytes) {
        ok = true;
        pos = getOp(pos, true, &ok);
        if (!ok) {
            break;
        }
        if (!ops[nOps - 1].isNum) {
            --nOps; // drop the operator
            switch (ops[nOps].op) {
            case 0x0001: // hstem
                if (firstOp) {
                    cvtGlyphWidth(nOps & 1, charBuf, pDict);
                    firstOp = false;
                }
                if (nOps & 1) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 hstem", nOps);
                }
                d = 0;
                dFP = false;
                for (k = 0; k < nOps; k += 2) {
                    // convert Type 2 edge hints (-20 or -21) to Type 1 ghost hints
                    if (ops[k + 1].num < 0) {
                        d += ops[k].num + ops[k + 1].num;
                        dFP |= ops[k].isFP | ops[k + 1].isFP;
                        cvtNum(d, dFP, charBuf);
                        cvtNum(-ops[k + 1].num, ops[k + 1].isFP, charBuf);
                    } else {
                        d += ops[k].num;
                        dFP |= ops[k].isFP;
                        cvtNum(d, dFP, charBuf);
                        cvtNum(ops[k + 1].num, ops[k + 1].isFP, charBuf);
                        d += ops[k + 1].num;
                        dFP |= ops[k + 1].isFP;
                    }
                    charBuf->append((char)1);
                }
                nHints += nOps / 2;
                nOps = 0;
                break;
            case 0x0003: // vstem
                if (firstOp) {
                    cvtGlyphWidth(nOps & 1, charBuf, pDict);
                    firstOp = false;
                }
                if (nOps & 1) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 vstem", nOps);
                }
                d = 0;
                dFP = false;
                for (k = 0; k < nOps; k += 2) {
                    // convert Type 2 edge hints (-20 or -21) to Type 1 ghost hints
                    if (ops[k + 1].num < 0) {
                        d += ops[k].num + ops[k + 1].num;
                        dFP |= ops[k].isFP | ops[k + 1].isFP;
                        cvtNum(d, dFP, charBuf);
                        cvtNum(-ops[k + 1].num, ops[k + 1].isFP, charBuf);
                    } else {
                        d += ops[k].num;
                        dFP |= ops[k].isFP;
                        cvtNum(d, dFP, charBuf);
                        cvtNum(ops[k + 1].num, ops[k + 1].isFP, charBuf);
                        d += ops[k + 1].num;
                        dFP |= ops[k + 1].isFP;
                    }
                    charBuf->append((char)3);
                }
                nHints += nOps / 2;
                nOps = 0;
                break;
            case 0x0004: // vmoveto
                if (firstOp) {
                    cvtGlyphWidth(nOps == 2, charBuf, pDict);
                    firstOp = false;
                }
                if (openPath) {
                    charBuf->append((char)9);
                    openPath = false;
                }
                if (nOps != 1) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 vmoveto", nOps);
                }
                cvtNum(ops[0].num, ops[0].isFP, charBuf);
                charBuf->append((char)4);
                nOps = 0;
                break;
            case 0x0005: // rlineto
                if (nOps < 2 || nOps % 2 != 0) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 rlineto", nOps);
                }
                for (k = 0; k < nOps; k += 2) {
                    cvtNum(ops[k].num, ops[k].isFP, charBuf);
                    cvtNum(ops[k + 1].num, ops[k + 1].isFP, charBuf);
                    charBuf->append((char)5);
                }
                nOps = 0;
                openPath = true;
                break;
            case 0x0006: // hlineto
                if (nOps < 1) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 hlineto", nOps);
                }
                for (k = 0; k < nOps; ++k) {
                    cvtNum(ops[k].num, ops[k].isFP, charBuf);
                    charBuf->append((char)((k & 1) ? 7 : 6));
                }
                nOps = 0;
                openPath = true;
                break;
            case 0x0007: // vlineto
                if (nOps < 1) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 vlineto", nOps);
                }
                for (k = 0; k < nOps; ++k) {
                    cvtNum(ops[k].num, ops[k].isFP, charBuf);
                    charBuf->append((char)((k & 1) ? 6 : 7));
                }
                nOps = 0;
                openPath = true;
                break;
            case 0x0008: // rrcurveto
                if (nOps < 6 || nOps % 6 != 0) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 rrcurveto", nOps);
                }
                for (k = 0; k < nOps; k += 6) {
                    cvtNum(ops[k].num, ops[k].isFP, charBuf);
                    cvtNum(ops[k + 1].num, ops[k + 1].isFP, charBuf);
                    cvtNum(ops[k + 2].num, ops[k + 2].isFP, charBuf);
                    cvtNum(ops[k + 3].num, ops[k + 3].isFP, charBuf);
                    cvtNum(ops[k + 4].num, ops[k + 4].isFP, charBuf);
                    cvtNum(ops[k + 5].num, ops[k + 5].isFP, charBuf);
                    charBuf->append((char)8);
                }
                nOps = 0;
                openPath = true;
                break;
            case 0x000a: // callsubr
                if (nOps >= 1) {
                    subrBias = (subrIdx->len < 1240) ? 107 : (subrIdx->len < 33900) ? 1131 : 32768;
                    k = subrBias + (int)ops[nOps - 1].num;
                    --nOps;
                    ok = true;
                    getIndexVal(subrIdx, k, &val, &ok);
                    if (likely(ok && val.pos != offset)) {
                        cvtGlyph(val.pos, val.len, charBuf, subrIdx, pDict, false, offsetBeingParsed);
                    }
                } else {
                    //~ error(-1, "Too few args to Type 2 callsubr");
                }
                // don't clear the stack
                break;
            case 0x000b: // return
                // don't clear the stack
                break;
            case 0x000e: // endchar / seac
                if (firstOp) {
                    cvtGlyphWidth(nOps == 1 || nOps == 5, charBuf, pDict);
                    firstOp = false;
                }
                if (openPath) {
                    charBuf->append((char)9);
                    openPath = false;
                }
                if (nOps == 4) {
                    cvtNum(0, false, charBuf);
                    cvtNum(ops[0].num, ops[0].isFP, charBuf);
                    cvtNum(ops[1].num, ops[1].isFP, charBuf);
                    cvtNum(ops[2].num, ops[2].isFP, charBuf);
                    cvtNum(ops[3].num, ops[3].isFP, charBuf);
                    charBuf->append((char)12)->append((char)6);
                } else if (nOps == 0) {
                    charBuf->append((char)14);
                } else {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 endchar", nOps);
                }
                nOps = 0;
                break;
            case 0x000f: // (obsolete)
                // this op is ignored, but we need the glyph width
                if (firstOp) {
                    cvtGlyphWidth(nOps > 0, charBuf, pDict);
                    firstOp = false;
                }
                nOps = 0;
                break;
            case 0x0010: // blend
                //~ error(-1, "Unimplemented Type 2 charstring op: %d", file[i]);
                nOps = 0;
                break;
            case 0x0012: // hstemhm
                // ignored
                if (firstOp) {
                    cvtGlyphWidth(nOps & 1, charBuf, pDict);
                    firstOp = false;
                }
                if (nOps & 1) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 hstemhm", nOps);
                }
                nHints += nOps / 2;
                nOps = 0;
                break;
            case 0x0013: // hintmask
                // ignored
                if (firstOp) {
                    cvtGlyphWidth(nOps & 1, charBuf, pDict);
                    firstOp = false;
                }
                if (nOps > 0) {
                    if (nOps & 1) {
                        //~ error(-1, "Wrong number of args (%d) to Type 2 hintmask/vstemhm",
                        //~       nOps);
                    }
                    nHints += nOps / 2;
                }
                pos += (nHints + 7) >> 3;
                nOps = 0;
                break;
            case 0x0014: // cntrmask
                // ignored
                if (firstOp) {
                    cvtGlyphWidth(nOps & 1, charBuf, pDict);
                    firstOp = false;
                }
                if (nOps > 0) {
                    if (nOps & 1) {
                        //~ error(-1, "Wrong number of args (%d) to Type 2 cntrmask/vstemhm",
                        //~       nOps);
                    }
                    nHints += nOps / 2;
                }
                pos += (nHints + 7) >> 3;
                nOps = 0;
                break;
            case 0x0015: // rmoveto
                if (firstOp) {
                    cvtGlyphWidth(nOps == 3, charBuf, pDict);
                    firstOp = false;
                }
                if (openPath) {
                    charBuf->append((char)9);
                    openPath = false;
                }
                if (nOps != 2) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 rmoveto", nOps);
                }
                cvtNum(ops[0].num, ops[0].isFP, charBuf);
                cvtNum(ops[1].num, ops[1].isFP, charBuf);
                charBuf->append((char)21);
                nOps = 0;
                break;
            case 0x0016: // hmoveto
                if (firstOp) {
                    cvtGlyphWidth(nOps == 2, charBuf, pDict);
                    firstOp = false;
                }
                if (openPath) {
                    charBuf->append((char)9);
                    openPath = false;
                }
                if (nOps != 1) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 hmoveto", nOps);
                }
                cvtNum(ops[0].num, ops[0].isFP, charBuf);
                charBuf->append((char)22);
                nOps = 0;
                break;
            case 0x0017: // vstemhm
                // ignored
                if (firstOp) {
                    cvtGlyphWidth(nOps & 1, charBuf, pDict);
                    firstOp = false;
                }
                if (nOps & 1) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 vstemhm", nOps);
                }
                nHints += nOps / 2;
                nOps = 0;
                break;
            case 0x0018: // rcurveline
                if (nOps < 8 || (nOps - 2) % 6 != 0) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 rcurveline", nOps);
                }
                for (k = 0; k < nOps - 2; k += 6) {
                    cvtNum(ops[k].num, ops[k].isFP, charBuf);
                    cvtNum(ops[k + 1].num, ops[k + 1].isFP, charBuf);
                    cvtNum(ops[k + 2].num, ops[k + 2].isFP, charBuf);
                    cvtNum(ops[k + 3].num, ops[k + 3].isFP, charBuf);
                    cvtNum(ops[k + 4].num, ops[k + 4].isFP, charBuf);
                    cvtNum(ops[k + 5].num, ops[k + 5].isFP, charBuf);
                    charBuf->append((char)8);
                }
                if (likely(k + 1 < nOps)) {
                    cvtNum(ops[k].num, ops[k].isFP, charBuf);
                    cvtNum(ops[k + 1].num, ops[k + 1].isFP, charBuf);
                    charBuf->append((char)5);
                }
                nOps = 0;
                openPath = true;
                break;
            case 0x0019: // rlinecurve
                if (nOps < 8 || (nOps - 6) % 2 != 0) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 rlinecurve", nOps);
                }
                for (k = 0; k < nOps - 6; k += 2) {
                    cvtNum(ops[k].num, ops[k].isFP, charBuf);
                    cvtNum(ops[k + 1].num, ops[k + 1].isFP, charBuf);
                    charBuf->append((char)5);
                }
                cvtNum(ops[k].num, ops[k].isFP, charBuf);
                cvtNum(ops[k + 1].num, ops[k + 1].isFP, charBuf);
                cvtNum(ops[k + 2].num, ops[k + 2].isFP, charBuf);
                cvtNum(ops[k + 3].num, ops[k + 3].isFP, charBuf);
                cvtNum(ops[k + 4].num, ops[k + 4].isFP, charBuf);
                cvtNum(ops[k + 5].num, ops[k + 5].isFP, charBuf);
                charBuf->append((char)8);
                nOps = 0;
                openPath = true;
                break;
            case 0x001a: // vvcurveto
                if (nOps < 4 || !(nOps % 4 == 0 || (nOps - 1) % 4 == 0)) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 vvcurveto", nOps);
                }
                if (nOps % 2 == 1) {
                    cvtNum(ops[0].num, ops[0].isFP, charBuf);
                    cvtNum(ops[1].num, ops[1].isFP, charBuf);
                    cvtNum(ops[2].num, ops[2].isFP, charBuf);
                    cvtNum(ops[3].num, ops[3].isFP, charBuf);
                    cvtNum(0, false, charBuf);
                    cvtNum(ops[4].num, ops[4].isFP, charBuf);
                    charBuf->append((char)8);
                    k = 5;
                } else {
                    k = 0;
                }
                for (; k < nOps; k += 4) {
                    cvtNum(0, false, charBuf);
                    cvtNum(ops[k].num, ops[k].isFP, charBuf);
                    cvtNum(ops[k + 1].num, ops[k + 1].isFP, charBuf);
                    cvtNum(ops[k + 2].num, ops[k + 2].isFP, charBuf);
                    cvtNum(0, false, charBuf);
                    cvtNum(ops[k + 3].num, ops[k + 3].isFP, charBuf);
                    charBuf->append((char)8);
                }
                nOps = 0;
                openPath = true;
                break;
            case 0x001b: // hhcurveto
                if (nOps < 4 || !(nOps % 4 == 0 || (nOps - 1) % 4 == 0)) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 hhcurveto", nOps);
                }
                if (nOps % 2 == 1) {
                    cvtNum(ops[1].num, ops[1].isFP, charBuf);
                    cvtNum(ops[0].num, ops[0].isFP, charBuf);
                    cvtNum(ops[2].num, ops[2].isFP, charBuf);
                    cvtNum(ops[3].num, ops[3].isFP, charBuf);
                    cvtNum(ops[4].num, ops[4].isFP, charBuf);
                    cvtNum(0, false, charBuf);
                    charBuf->append((char)8);
                    k = 5;
                } else {
                    k = 0;
                }
                for (; k < nOps; k += 4) {
                    cvtNum(ops[k].num, ops[k].isFP, charBuf);
                    cvtNum(0, false, charBuf);
                    cvtNum(ops[k + 1].num, ops[k + 1].isFP, charBuf);
                    cvtNum(ops[k + 2].num, ops[k + 2].isFP, charBuf);
                    cvtNum(ops[k + 3].num, ops[k + 3].isFP, charBuf);
                    cvtNum(0, false, charBuf);
                    charBuf->append((char)8);
                }
                nOps = 0;
                openPath = true;
                break;
            case 0x001d: // callgsubr
                if (nOps >= 1) {
                    k = gsubrBias + (int)ops[nOps - 1].num;
                    --nOps;
                    ok = true;
                    getIndexVal(&gsubrIdx, k, &val, &ok);
                    if (likely(ok && val.pos != offset)) {
                        cvtGlyph(val.pos, val.len, charBuf, subrIdx, pDict, false, offsetBeingParsed);
                    }
                } else {
                    //~ error(-1, "Too few args to Type 2 callgsubr");
                }
                // don't clear the stack
                break;
            case 0x001e: // vhcurveto
                if (nOps < 4 || !(nOps % 4 == 0 || (nOps - 1) % 4 == 0)) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 vhcurveto", nOps);
                }
                for (k = 0; k < nOps && k != nOps - 5; k += 4) {
                    if (k % 8 == 0) {
                        cvtNum(ops[k].num, ops[k].isFP, charBuf);
                        cvtNum(ops[k + 1].num, ops[k + 1].isFP, charBuf);
                        cvtNum(ops[k + 2].num, ops[k + 2].isFP, charBuf);
                        cvtNum(ops[k + 3].num, ops[k + 3].isFP, charBuf);
                        charBuf->append((char)30);
                    } else {
                        cvtNum(ops[k].num, ops[k].isFP, charBuf);
                        cvtNum(ops[k + 1].num, ops[k + 1].isFP, charBuf);
                        cvtNum(ops[k + 2].num, ops[k + 2].isFP, charBuf);
                        cvtNum(ops[k + 3].num, ops[k + 3].isFP, charBuf);
                        charBuf->append((char)31);
                    }
                }
                if (k == nOps - 5) {
                    if (k % 8 == 0) {
                        cvtNum(0, false, charBuf);
                        cvtNum(ops[k].num, ops[k].isFP, charBuf);
                        cvtNum(ops[k + 1].num, ops[k + 1].isFP, charBuf);
                        cvtNum(ops[k + 2].num, ops[k + 2].isFP, charBuf);
                        cvtNum(ops[k + 3].num, ops[k + 3].isFP, charBuf);
                        cvtNum(ops[k + 4].num, ops[k + 4].isFP, charBuf);
                    } else {
                        cvtNum(ops[k].num, ops[k].isFP, charBuf);
                        cvtNum(0, false, charBuf);
                        cvtNum(ops[k + 1].num, ops[k + 1].isFP, charBuf);
                        cvtNum(ops[k + 2].num, ops[k + 2].isFP, charBuf);
                        cvtNum(ops[k + 4].num, ops[k + 4].isFP, charBuf);
                        cvtNum(ops[k + 3].num, ops[k + 3].isFP, charBuf);
                    }
                    charBuf->append((char)8);
                }
                nOps = 0;
                openPath = true;
                break;
            case 0x001f: // hvcurveto
                if (nOps < 4 || !(nOps % 4 == 0 || (nOps - 1) % 4 == 0)) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 hvcurveto", nOps);
                }
                for (k = 0; k < nOps && k != nOps - 5; k += 4) {
                    if (k % 8 == 0) {
                        cvtNum(ops[k].num, ops[k].isFP, charBuf);
                        cvtNum(ops[k + 1].num, ops[k + 1].isFP, charBuf);
                        cvtNum(ops[k + 2].num, ops[k + 2].isFP, charBuf);
                        cvtNum(ops[k + 3].num, ops[k + 3].isFP, charBuf);
                        charBuf->append((char)31);
                    } else {
                        cvtNum(ops[k].num, ops[k].isFP, charBuf);
                        cvtNum(ops[k + 1].num, ops[k + 1].isFP, charBuf);
                        cvtNum(ops[k + 2].num, ops[k + 2].isFP, charBuf);
                        cvtNum(ops[k + 3].num, ops[k + 3].isFP, charBuf);
                        charBuf->append((char)30);
                    }
                }
                if (k == nOps - 5) {
                    if (k % 8 == 0) {
                        cvtNum(ops[k].num, ops[k].isFP, charBuf);
                        cvtNum(0, false, charBuf);
                        cvtNum(ops[k + 1].num, ops[k + 1].isFP, charBuf);
                        cvtNum(ops[k + 2].num, ops[k + 2].isFP, charBuf);
                        cvtNum(ops[k + 4].num, ops[k + 4].isFP, charBuf);
                        cvtNum(ops[k + 3].num, ops[k + 3].isFP, charBuf);
                    } else {
                        cvtNum(0, false, charBuf);
                        cvtNum(ops[k].num, ops[k].isFP, charBuf);
                        cvtNum(ops[k + 1].num, ops[k + 1].isFP, charBuf);
                        cvtNum(ops[k + 2].num, ops[k + 2].isFP, charBuf);
                        cvtNum(ops[k + 3].num, ops[k + 3].isFP, charBuf);
                        cvtNum(ops[k + 4].num, ops[k + 4].isFP, charBuf);
                    }
                    charBuf->append((char)8);
                }
                nOps = 0;
                openPath = true;
                break;
            case 0x0c00: // dotsection (should be Type 1 only?)
                // ignored
                nOps = 0;
                break;
            case 0x0c03: // and
            case 0x0c04: // or
            case 0x0c05: // not
            case 0x0c08: // store
            case 0x0c09: // abs
            case 0x0c0a: // add
            case 0x0c0b: // sub
            case 0x0c0c: // div
            case 0x0c0d: // load
            case 0x0c0e: // neg
            case 0x0c0f: // eq
            case 0x0c12: // drop
            case 0x0c14: // put
            case 0x0c15: // get
            case 0x0c16: // ifelse
            case 0x0c17: // random
            case 0x0c18: // mul
            case 0x0c1a: // sqrt
            case 0x0c1b: // dup
            case 0x0c1c: // exch
            case 0x0c1d: // index
            case 0x0c1e: // roll
                //~ error(-1, "Unimplemented Type 2 charstring op: 12.%d", file[i+1]);
                nOps = 0;
                break;
            case 0x0c22: // hflex
                if (nOps != 7) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 hflex", nOps);
                }
                cvtNum(ops[0].num, ops[0].isFP, charBuf);
                cvtNum(0, false, charBuf);
                cvtNum(ops[1].num, ops[1].isFP, charBuf);
                cvtNum(ops[2].num, ops[2].isFP, charBuf);
                cvtNum(ops[3].num, ops[3].isFP, charBuf);
                cvtNum(0, false, charBuf);
                charBuf->append((char)8);
                cvtNum(ops[4].num, ops[4].isFP, charBuf);
                cvtNum(0, false, charBuf);
                cvtNum(ops[5].num, ops[5].isFP, charBuf);
                cvtNum(-ops[2].num, ops[2].isFP, charBuf);
                cvtNum(ops[6].num, ops[6].isFP, charBuf);
                cvtNum(0, false, charBuf);
                charBuf->append((char)8);
                nOps = 0;
                openPath = true;
                break;
            case 0x0c23: // flex
                if (nOps != 13) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 flex", nOps);
                }
                cvtNum(ops[0].num, ops[0].isFP, charBuf);
                cvtNum(ops[1].num, ops[1].isFP, charBuf);
                cvtNum(ops[2].num, ops[2].isFP, charBuf);
                cvtNum(ops[3].num, ops[3].isFP, charBuf);
                cvtNum(ops[4].num, ops[4].isFP, charBuf);
                cvtNum(ops[5].num, ops[5].isFP, charBuf);
                charBuf->append((char)8);
                cvtNum(ops[6].num, ops[6].isFP, charBuf);
                cvtNum(ops[7].num, ops[7].isFP, charBuf);
                cvtNum(ops[8].num, ops[8].isFP, charBuf);
                cvtNum(ops[9].num, ops[9].isFP, charBuf);
                cvtNum(ops[10].num, ops[10].isFP, charBuf);
                cvtNum(ops[11].num, ops[11].isFP, charBuf);
                charBuf->append((char)8);
                nOps = 0;
                openPath = true;
                break;
            case 0x0c24: // hflex1
                if (nOps != 9) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 hflex1", nOps);
                }
                cvtNum(ops[0].num, ops[0].isFP, charBuf);
                cvtNum(ops[1].num, ops[1].isFP, charBuf);
                cvtNum(ops[2].num, ops[2].isFP, charBuf);
                cvtNum(ops[3].num, ops[3].isFP, charBuf);
                cvtNum(ops[4].num, ops[4].isFP, charBuf);
                cvtNum(0, false, charBuf);
                charBuf->append((char)8);
                cvtNum(ops[5].num, ops[5].isFP, charBuf);
                cvtNum(0, false, charBuf);
                cvtNum(ops[6].num, ops[6].isFP, charBuf);
                cvtNum(ops[7].num, ops[7].isFP, charBuf);
                cvtNum(ops[8].num, ops[8].isFP, charBuf);
                cvtNum(-(ops[1].num + ops[3].num + ops[7].num), ops[1].isFP | ops[3].isFP | ops[7].isFP, charBuf);
                charBuf->append((char)8);
                nOps = 0;
                openPath = true;
                break;
            case 0x0c25: // flex1
                if (nOps != 11) {
                    //~ error(-1, "Wrong number of args (%d) to Type 2 flex1", nOps);
                }
                cvtNum(ops[0].num, ops[0].isFP, charBuf);
                cvtNum(ops[1].num, ops[1].isFP, charBuf);
                cvtNum(ops[2].num, ops[2].isFP, charBuf);
                cvtNum(ops[3].num, ops[3].isFP, charBuf);
                cvtNum(ops[4].num, ops[4].isFP, charBuf);
                cvtNum(ops[5].num, ops[5].isFP, charBuf);
                charBuf->append((char)8);
                cvtNum(ops[6].num, ops[6].isFP, charBuf);
                cvtNum(ops[7].num, ops[7].isFP, charBuf);
                cvtNum(ops[8].num, ops[8].isFP, charBuf);
                cvtNum(ops[9].num, ops[9].isFP, charBuf);
                dx = ops[0].num + ops[2].num + ops[4].num + ops[6].num + ops[8].num;
                dy = ops[1].num + ops[3].num + ops[5].num + ops[7].num + ops[9].num;
                if (fabs(dx) > fabs(dy)) {
                    cvtNum(ops[10].num, ops[10].isFP, charBuf);
                    cvtNum(-dy, ops[1].isFP | ops[3].isFP | ops[5].isFP | ops[7].isFP | ops[9].isFP, charBuf);
                } else {
                    cvtNum(-dx, ops[0].isFP | ops[2].isFP | ops[4].isFP | ops[6].isFP | ops[8].isFP, charBuf);
                    cvtNum(ops[10].num, ops[10].isFP, charBuf);
                }
                charBuf->append((char)8);
                nOps = 0;
                openPath = true;
                break;
            default:
                //~ error(-1, "Illegal Type 2 charstring op: %04x",
                //~       ops[nOps].op);
                nOps = 0;
                break;
            }
        }
    }

    // charstring encryption
    if (top) {
        r2 = 4330;
        for (i = start; i < charBuf->getLength(); ++i) {
            byte = charBuf->getChar(i) ^ (r2 >> 8);
            charBuf->setChar(i, byte);
            r2 = (byte + r2) * 52845 + 22719;
        }
    }

    offsetBeingParsed.erase(offsetEmplaceResult.first);
}

void FoFiType1C::cvtGlyphWidth(bool useOp, GooString *charBuf, const Type1CPrivateDict *pDict)
{
    double w;
    bool wFP;
    int i;

    if (useOp) {
        w = pDict->nominalWidthX + ops[0].num;
        wFP = pDict->nominalWidthXFP | ops[0].isFP;
        for (i = 1; i < nOps; ++i) {
            ops[i - 1] = ops[i];
        }
        --nOps;
    } else {
        w = pDict->defaultWidthX;
        wFP = pDict->defaultWidthXFP;
    }
    cvtNum(0, false, charBuf);
    cvtNum(w, wFP, charBuf);
    charBuf->append((char)13);
}

void FoFiType1C::cvtNum(double x, bool isFP, GooString *charBuf) const
{
    unsigned char buf[12];
    int y, n;

    n = 0;
    if (isFP) {
        if (x >= -32768 && x < 32768) {
            y = (int)(x * 256.0);
            buf[0] = 255;
            buf[1] = (unsigned char)(y >> 24);
            buf[2] = (unsigned char)(y >> 16);
            buf[3] = (unsigned char)(y >> 8);
            buf[4] = (unsigned char)y;
            buf[5] = 255;
            buf[6] = 0;
            buf[7] = 0;
            buf[8] = 1;
            buf[9] = 0;
            buf[10] = 12;
            buf[11] = 12;
            n = 12;
        } else {
            //~ error(-1, "Type 2 fixed point constant out of range");
        }
    } else {
        y = (int)x;
        if (y >= -107 && y <= 107) {
            buf[0] = (unsigned char)(y + 139);
            n = 1;
        } else if (y > 107 && y <= 1131) {
            y -= 108;
            buf[0] = (unsigned char)((y >> 8) + 247);
            buf[1] = (unsigned char)(y & 0xff);
            n = 2;
        } else if (y < -107 && y >= -1131) {
            y = -y - 108;
            buf[0] = (unsigned char)((y >> 8) + 251);
            buf[1] = (unsigned char)(y & 0xff);
            n = 2;
        } else {
            buf[0] = 255;
            buf[1] = (unsigned char)(y >> 24);
            buf[2] = (unsigned char)(y >> 16);
            buf[3] = (unsigned char)(y >> 8);
            buf[4] = (unsigned char)y;
            n = 5;
        }
    }
    charBuf->append((char *)buf, n);
}

void FoFiType1C::eexecWrite(Type1CEexecBuf *eb, const char *s) const
{
    unsigned char *p;
    unsigned char x;

    for (p = (unsigned char *)s; *p; ++p) {
        x = *p ^ (eb->r1 >> 8);
        eb->r1 = (x + eb->r1) * 52845 + 22719;
        if (eb->ascii) {
            (*eb->outputFunc)(eb->outputStream, &hexChars[x >> 4], 1);
            (*eb->outputFunc)(eb->outputStream, &hexChars[x & 0x0f], 1);
            eb->line += 2;
            if (eb->line == 64) {
                (*eb->outputFunc)(eb->outputStream, "\n", 1);
                eb->line = 0;
            }
        } else {
            (*eb->outputFunc)(eb->outputStream, (char *)&x, 1);
        }
    }
}

void FoFiType1C::eexecWriteCharstring(Type1CEexecBuf *eb, const unsigned char *s, int n) const
{
    unsigned char x;
    int i;

    // eexec encryption
    for (i = 0; i < n; ++i) {
        x = s[i] ^ (eb->r1 >> 8);
        eb->r1 = (x + eb->r1) * 52845 + 22719;
        if (eb->ascii) {
            (*eb->outputFunc)(eb->outputStream, &hexChars[x >> 4], 1);
            (*eb->outputFunc)(eb->outputStream, &hexChars[x & 0x0f], 1);
            eb->line += 2;
            if (eb->line == 64) {
                (*eb->outputFunc)(eb->outputStream, "\n", 1);
                eb->line = 0;
            }
        } else {
            (*eb->outputFunc)(eb->outputStream, (char *)&x, 1);
        }
    }
}

void FoFiType1C::writePSString(const char *s, FoFiOutputFunc outputFunc, void *outputStream) const
{
    char buf[80];
    const char *p;
    int i, c;

    i = 0;
    buf[i++] = '(';
    for (p = s; *p; ++p) {
        c = *p & 0xff;
        if (c == '(' || c == ')' || c == '\\') {
            buf[i++] = '\\';
            buf[i++] = c;
        } else if (c < 0x20 || c >= 0x80) {
            buf[i++] = '\\';
            buf[i++] = '0' + ((c >> 6) & 7);
            buf[i++] = '0' + ((c >> 3) & 7);
            buf[i++] = '0' + (c & 7);
        } else {
            buf[i++] = c;
        }
        if (i >= 64) {
            buf[i++] = '\\';
            buf[i++] = '\n';
            (*outputFunc)(outputStream, buf, i);
            i = 0;
        }
    }
    buf[i++] = ')';
    (*outputFunc)(outputStream, buf, i);
}

bool FoFiType1C::parse()
{
    Type1CIndex fdIdx;
    Type1CIndexVal val;
    int i;

    parsedOk = true;

    // some tools embed Type 1C fonts with an extra whitespace char at
    // the beginning
    if (!file.empty() && file[0] != '\x01') {
        file = file.subspan(1);
    }

    // find the indexes
    getIndex(getU8(2, &parsedOk), &nameIdx, &parsedOk);
    getIndex(nameIdx.endPos, &topDictIdx, &parsedOk);
    getIndex(topDictIdx.endPos, &stringIdx, &parsedOk);
    getIndex(stringIdx.endPos, &gsubrIdx, &parsedOk);
    if (!parsedOk) {
        return false;
    }
    gsubrBias = (gsubrIdx.len < 1240) ? 107 : (gsubrIdx.len < 33900) ? 1131 : 32768;

    // read the first font name
    getIndexVal(&nameIdx, 0, &val, &parsedOk);
    if (!parsedOk) {
        return false;
    }
    name = std::make_unique<GooString>((char *)&file[val.pos], val.len);

    // read the top dict for the first font
    readTopDict();

    // for CID fonts: read the FDArray dicts and private dicts
    if (topDict.firstOp == 0x0c1e) {
        if (topDict.fdArrayOffset == 0) {
            nFDs = 1;
            privateDicts = (Type1CPrivateDict *)gmalloc(sizeof(Type1CPrivateDict));
            readPrivateDict(0, 0, &privateDicts[0]);
        } else {
            getIndex(topDict.fdArrayOffset, &fdIdx, &parsedOk);
            if (!parsedOk || fdIdx.len <= 0) {
                return false;
            }
            nFDs = fdIdx.len;
            privateDicts = (Type1CPrivateDict *)gmallocn(nFDs, sizeof(Type1CPrivateDict));
            for (i = 0; i < nFDs; ++i) {
                getIndexVal(&fdIdx, i, &val, &parsedOk);
                if (!parsedOk) {
                    return false;
                }
                readFD(val.pos, val.len, &privateDicts[i]);
            }
        }

        // for 8-bit fonts: read the private dict
    } else {
        nFDs = 1;
        privateDicts = (Type1CPrivateDict *)gmalloc(sizeof(Type1CPrivateDict));
        readPrivateDict(topDict.privateOffset, topDict.privateSize, &privateDicts[0]);
    }

    // check for parse errors in the private dict(s)
    if (!parsedOk) {
        return false;
    }

    // get the charstrings index
    if (topDict.charStringsOffset <= 0) {
        parsedOk = false;
        return false;
    }
    getIndex(topDict.charStringsOffset, &charStringsIdx, &parsedOk);
    if (!parsedOk) {
        return false;
    }
    nGlyphs = charStringsIdx.len;

    // for CID fonts: read the FDSelect table
    if (topDict.firstOp == 0x0c1e) {
        readFDSelect();
        if (!parsedOk) {
            return false;
        }
    }

    // read the charset
    if (!readCharset()) {
        parsedOk = false;
        return false;
    }

    // for 8-bit fonts: build the encoding
    if (topDict.firstOp != 0x0c14 && topDict.firstOp != 0x0c1e) {
        buildEncoding();
        if (!parsedOk) {
            return false;
        }
    }

    return parsedOk;
}

void FoFiType1C::readTopDict()
{
    Type1CIndexVal topDictPtr;
    int pos;

    topDict.firstOp = -1;
    topDict.versionSID = 0;
    topDict.noticeSID = 0;
    topDict.copyrightSID = 0;
    topDict.fullNameSID = 0;
    topDict.familyNameSID = 0;
    topDict.weightSID = 0;
    topDict.isFixedPitch = 0;
    topDict.italicAngle = 0;
    topDict.underlinePosition = -100;
    topDict.underlineThickness = 50;
    topDict.paintType = 0;
    topDict.charstringType = 2;
    topDict.fontMatrix[0] = 0.001;
    topDict.fontMatrix[1] = 0;
    topDict.fontMatrix[2] = 0;
    topDict.fontMatrix[3] = 0.001;
    topDict.fontMatrix[4] = 0;
    topDict.fontMatrix[5] = 0;
    topDict.hasFontMatrix = false;
    topDict.uniqueID = 0;
    topDict.fontBBox[0] = 0;
    topDict.fontBBox[1] = 0;
    topDict.fontBBox[2] = 0;
    topDict.fontBBox[3] = 0;
    topDict.strokeWidth = 0;
    topDict.charsetOffset = 0;
    topDict.encodingOffset = 0;
    topDict.charStringsOffset = 0;
    topDict.privateSize = 0;
    topDict.privateOffset = 0;
    topDict.registrySID = 0;
    topDict.orderingSID = 0;
    topDict.supplement = 0;
    topDict.fdArrayOffset = 0;
    topDict.fdSelectOffset = 0;

    getIndexVal(&topDictIdx, 0, &topDictPtr, &parsedOk);
    if (!parsedOk) {
        return;
    }
    pos = topDictPtr.pos;
    nOps = 0;
    while (pos < topDictPtr.pos + topDictPtr.len) {
        pos = getOp(pos, false, &parsedOk);
        if (!parsedOk) {
            break;
        }
        if (!ops[nOps - 1].isNum) {
            --nOps; // drop the operator
            if (topDict.firstOp < 0) {
                topDict.firstOp = ops[nOps].op;
            }
            switch (ops[nOps].op) {
            case 0x0000:
                topDict.versionSID = (int)ops[0].num;
                break;
            case 0x0001:
                topDict.noticeSID = (int)ops[0].num;
                break;
            case 0x0c00:
                topDict.copyrightSID = (int)ops[0].num;
                break;
            case 0x0002:
                topDict.fullNameSID = (int)ops[0].num;
                break;
            case 0x0003:
                topDict.familyNameSID = (int)ops[0].num;
                break;
            case 0x0004:
                topDict.weightSID = (int)ops[0].num;
                break;
            case 0x0c01:
                topDict.isFixedPitch = (int)ops[0].num;
                break;
            case 0x0c02:
                topDict.italicAngle = ops[0].num;
                break;
            case 0x0c03:
                topDict.underlinePosition = ops[0].num;
                break;
            case 0x0c04:
                topDict.underlineThickness = ops[0].num;
                break;
            case 0x0c05:
                topDict.paintType = (int)ops[0].num;
                break;
            case 0x0c06:
                topDict.charstringType = (int)ops[0].num;
                break;
            case 0x0c07:
                topDict.fontMatrix[0] = ops[0].num;
                topDict.fontMatrix[1] = ops[1].num;
                topDict.fontMatrix[2] = ops[2].num;
                topDict.fontMatrix[3] = ops[3].num;
                topDict.fontMatrix[4] = ops[4].num;
                topDict.fontMatrix[5] = ops[5].num;
                topDict.hasFontMatrix = true;
                break;
            case 0x000d:
                topDict.uniqueID = (int)ops[0].num;
                break;
            case 0x0005:
                topDict.fontBBox[0] = ops[0].num;
                topDict.fontBBox[1] = ops[1].num;
                topDict.fontBBox[2] = ops[2].num;
                topDict.fontBBox[3] = ops[3].num;
                break;
            case 0x0c08:
                topDict.strokeWidth = ops[0].num;
                break;
            case 0x000f:
                topDict.charsetOffset = (int)ops[0].num;
                break;
            case 0x0010:
                topDict.encodingOffset = (int)ops[0].num;
                break;
            case 0x0011:
                topDict.charStringsOffset = (int)ops[0].num;
                break;
            case 0x0012:
                topDict.privateSize = (int)ops[0].num;
                topDict.privateOffset = (int)ops[1].num;
                break;
            case 0x0c1e:
                topDict.registrySID = (int)ops[0].num;
                topDict.orderingSID = (int)ops[1].num;
                topDict.supplement = (int)ops[2].num;
                break;
            case 0x0c24:
                topDict.fdArrayOffset = (int)ops[0].num;
                break;
            case 0x0c25:
                topDict.fdSelectOffset = (int)ops[0].num;
                break;
            }
            nOps = 0;
        }
    }
}

// Read a CID font dict (FD) - this pulls out the private dict
// pointer, and reads the private dict.  It also pulls the FontMatrix
// (if any) out of the FD.
void FoFiType1C::readFD(int offset, int length, Type1CPrivateDict *pDict)
{
    int pSize, pOffset;
    double fontMatrix[6] = { 0 };
    bool hasFontMatrix;

    hasFontMatrix = false;
    fontMatrix[0] = fontMatrix[1] = fontMatrix[2] = 0; // make gcc happy
    fontMatrix[3] = fontMatrix[4] = fontMatrix[5] = 0;
    pSize = pOffset = 0;

    int posEnd;
    if (checkedAdd(offset, length, &posEnd)) {
        return;
    }

    int pos = offset;
    nOps = 0;
    while (pos < posEnd) {
        pos = getOp(pos, false, &parsedOk);
        if (!parsedOk) {
            return;
        }
        if (!ops[nOps - 1].isNum) {
            if (ops[nOps - 1].op == 0x0012) {
                if (nOps < 3) {
                    parsedOk = false;
                    return;
                }
                pSize = (int)ops[0].num;
                pOffset = (int)ops[1].num;
                break;
            } else if (ops[nOps - 1].op == 0x0c07) {
                fontMatrix[0] = ops[0].num;
                fontMatrix[1] = ops[1].num;
                fontMatrix[2] = ops[2].num;
                fontMatrix[3] = ops[3].num;
                fontMatrix[4] = ops[4].num;
                fontMatrix[5] = ops[5].num;
                hasFontMatrix = true;
            }
            nOps = 0;
        }
    }
    readPrivateDict(pOffset, pSize, pDict);
    if (hasFontMatrix) {
        pDict->fontMatrix[0] = fontMatrix[0];
        pDict->fontMatrix[1] = fontMatrix[1];
        pDict->fontMatrix[2] = fontMatrix[2];
        pDict->fontMatrix[3] = fontMatrix[3];
        pDict->fontMatrix[4] = fontMatrix[4];
        pDict->fontMatrix[5] = fontMatrix[5];
        pDict->hasFontMatrix = true;
    }
}

void FoFiType1C::readPrivateDict(int offset, int length, Type1CPrivateDict *pDict)
{
    pDict->hasFontMatrix = false;
    pDict->nBlueValues = 0;
    pDict->nOtherBlues = 0;
    pDict->nFamilyBlues = 0;
    pDict->nFamilyOtherBlues = 0;
    pDict->blueScale = 0.039625;
    pDict->blueShift = 7;
    pDict->blueFuzz = 1;
    pDict->hasStdHW = false;
    pDict->hasStdVW = false;
    pDict->nStemSnapH = 0;
    pDict->nStemSnapV = 0;
    pDict->hasForceBold = false;
    pDict->forceBoldThreshold = 0;
    pDict->languageGroup = 0;
    pDict->expansionFactor = 0.06;
    pDict->initialRandomSeed = 0;
    pDict->subrsOffset = 0;
    pDict->defaultWidthX = 0;
    pDict->defaultWidthXFP = false;
    pDict->nominalWidthX = 0;
    pDict->nominalWidthXFP = false;

    // no dictionary
    if (offset == 0 || length == 0) {
        return;
    }

    int posEnd;
    if (checkedAdd(offset, length, &posEnd)) {
        return;
    }

    int pos = offset;
    nOps = 0;
    while (pos < posEnd) {
        pos = getOp(pos, false, &parsedOk);
        if (!parsedOk) {
            break;
        }
        if (!ops[nOps - 1].isNum) {
            --nOps; // drop the operator
            switch (ops[nOps].op) {
            case 0x0006:
                pDict->nBlueValues = getDeltaIntArray(pDict->blueValues, type1CMaxBlueValues);
                break;
            case 0x0007:
                pDict->nOtherBlues = getDeltaIntArray(pDict->otherBlues, type1CMaxOtherBlues);
                break;
            case 0x0008:
                pDict->nFamilyBlues = getDeltaIntArray(pDict->familyBlues, type1CMaxBlueValues);
                break;
            case 0x0009:
                pDict->nFamilyOtherBlues = getDeltaIntArray(pDict->familyOtherBlues, type1CMaxOtherBlues);
                break;
            case 0x0c09:
                pDict->blueScale = ops[0].num;
                break;
            case 0x0c0a:
                pDict->blueShift = (int)ops[0].num;
                break;
            case 0x0c0b:
                pDict->blueFuzz = (int)ops[0].num;
                break;
            case 0x000a:
                pDict->stdHW = ops[0].num;
                pDict->hasStdHW = true;
                break;
            case 0x000b:
                pDict->stdVW = ops[0].num;
                pDict->hasStdVW = true;
                break;
            case 0x0c0c:
                pDict->nStemSnapH = getDeltaFPArray(pDict->stemSnapH, type1CMaxStemSnap);
                break;
            case 0x0c0d:
                pDict->nStemSnapV = getDeltaFPArray(pDict->stemSnapV, type1CMaxStemSnap);
                break;
            case 0x0c0e:
                pDict->forceBold = ops[0].num != 0;
                pDict->hasForceBold = true;
                break;
            case 0x0c0f:
                pDict->forceBoldThreshold = ops[0].num;
                break;
            case 0x0c11:
                pDict->languageGroup = (int)ops[0].num;
                break;
            case 0x0c12:
                pDict->expansionFactor = ops[0].num;
                break;
            case 0x0c13:
                pDict->initialRandomSeed = (int)ops[0].num;
                break;
            case 0x0013:
                pDict->subrsOffset = offset + (int)ops[0].num;
                break;
            case 0x0014:
                pDict->defaultWidthX = ops[0].num;
                pDict->defaultWidthXFP = ops[0].isFP;
                break;
            case 0x0015:
                pDict->nominalWidthX = ops[0].num;
                pDict->nominalWidthXFP = ops[0].isFP;
                break;
            }
            nOps = 0;
        }
    }
}

void FoFiType1C::readFDSelect()
{
    int fdSelectFmt, pos, nRanges, gid0, gid1, fd;

    fdSelect = (unsigned char *)gmalloc(nGlyphs);
    if (topDict.fdSelectOffset == 0) {
        for (int i = 0; i < nGlyphs; ++i) {
            fdSelect[i] = 0;
        }
    } else {
        pos = topDict.fdSelectOffset;
        fdSelectFmt = getU8(pos++, &parsedOk);
        if (!parsedOk) {
            return;
        }
        if (fdSelectFmt == 0) {
            if (!checkRegion(pos, nGlyphs)) {
                parsedOk = false;
                return;
            }
            memcpy(fdSelect, file.data() + pos, nGlyphs);
        } else if (fdSelectFmt == 3) {
            nRanges = getU16BE(pos, &parsedOk);
            pos += 2;
            gid0 = getU16BE(pos, &parsedOk);
            pos += 2;
            for (int i = 1; i <= nRanges; ++i) {
                fd = getU8(pos++, &parsedOk);
                gid1 = getU16BE(pos, &parsedOk);
                if (!parsedOk) {
                    return;
                }
                pos += 2;
                if (gid0 > gid1 || gid1 > nGlyphs) {
                    //~ error(-1, "Bad FDSelect table in CID font");
                    parsedOk = false;
                    return;
                }
                for (int j = gid0; j < gid1; ++j) {
                    fdSelect[j] = fd;
                }
                gid0 = gid1;
            }
            for (int i = gid0; i < nGlyphs; ++i) {
                fdSelect[i] = 0;
            }
        } else {
            //~ error(-1, "Unknown FDSelect table format in CID font");
            for (int i = 0; i < nGlyphs; ++i) {
                fdSelect[i] = 0;
            }
        }
    }
}

void FoFiType1C::buildEncoding()
{
    char buf[256];
    int nCodes, nRanges, encFormat;
    int pos, c, sid, nLeft, nSups, i, j;

    if (topDict.encodingOffset == 0) {
        encoding = (char **)fofiType1StandardEncoding;

    } else if (topDict.encodingOffset == 1) {
        encoding = (char **)fofiType1ExpertEncoding;

    } else {
        encoding = (char **)gmallocn(256, sizeof(char *));
        for (i = 0; i < 256; ++i) {
            encoding[i] = nullptr;
        }
        pos = topDict.encodingOffset;
        encFormat = getU8(pos++, &parsedOk);
        if (!parsedOk) {
            return;
        }
        if ((encFormat & 0x7f) == 0) {
            nCodes = 1 + getU8(pos++, &parsedOk);
            if (!parsedOk) {
                return;
            }
            if (nCodes > nGlyphs) {
                nCodes = nGlyphs;
            }
            for (i = 1; i < nCodes && i < charsetLength; ++i) {
                c = getU8(pos++, &parsedOk);
                if (!parsedOk) {
                    return;
                }
                if (encoding[c]) {
                    gfree(encoding[c]);
                }
                encoding[c] = copyString(getString(charset[i], buf, &parsedOk));
            }
        } else if ((encFormat & 0x7f) == 1) {
            nRanges = getU8(pos++, &parsedOk);
            if (!parsedOk) {
                return;
            }
            nCodes = 1;
            for (i = 0; i < nRanges; ++i) {
                c = getU8(pos++, &parsedOk);
                nLeft = getU8(pos++, &parsedOk);
                if (!parsedOk) {
                    return;
                }
                for (j = 0; j <= nLeft && nCodes < nGlyphs && nCodes < charsetLength; ++j) {
                    if (c < 256) {
                        if (encoding[c]) {
                            gfree(encoding[c]);
                        }
                        encoding[c] = copyString(getString(charset[nCodes], buf, &parsedOk));
                    }
                    ++nCodes;
                    ++c;
                }
            }
        }
        if (encFormat & 0x80) {
            nSups = getU8(pos++, &parsedOk);
            if (!parsedOk) {
                return;
            }
            for (i = 0; i < nSups; ++i) {
                c = getU8(pos++, &parsedOk);
                ;
                if (!parsedOk) {
                    return;
                    ;
                }
                sid = getU16BE(pos, &parsedOk);
                pos += 2;
                if (!parsedOk) {
                    return;
                }
                if (encoding[c]) {
                    gfree(encoding[c]);
                }
                encoding[c] = copyString(getString(sid, buf, &parsedOk));
            }
        }
    }
}

bool FoFiType1C::readCharset()
{
    int charsetFormat, c, pos;
    int nLeft, i, j;

    if (topDict.charsetOffset == 0) {
        charset = fofiType1CISOAdobeCharset;
        charsetLength = sizeof(fofiType1CISOAdobeCharset) / sizeof(unsigned short);
    } else if (topDict.charsetOffset == 1) {
        charset = fofiType1CExpertCharset;
        charsetLength = sizeof(fofiType1CExpertCharset) / sizeof(unsigned short);
    } else if (topDict.charsetOffset == 2) {
        charset = fofiType1CExpertSubsetCharset;
        charsetLength = sizeof(fofiType1CExpertSubsetCharset) / sizeof(unsigned short);
    } else {
        unsigned short *customCharset = (unsigned short *)gmallocn(nGlyphs, sizeof(unsigned short));
        charsetLength = nGlyphs;
        for (i = 0; i < nGlyphs; ++i) {
            customCharset[i] = 0;
        }
        pos = topDict.charsetOffset;
        charsetFormat = getU8(pos++, &parsedOk);
        if (charsetFormat == 0) {
            for (i = 1; i < nGlyphs; ++i) {
                customCharset[i] = (unsigned short)getU16BE(pos, &parsedOk);
                pos += 2;
                if (!parsedOk) {
                    break;
                }
            }
        } else if (charsetFormat == 1) {
            i = 1;
            while (i < nGlyphs) {
                c = getU16BE(pos, &parsedOk);
                pos += 2;
                nLeft = getU8(pos++, &parsedOk);
                if (!parsedOk) {
                    break;
                }
                for (j = 0; j <= nLeft && i < nGlyphs; ++j) {
                    customCharset[i++] = (unsigned short)c++;
                }
            }
        } else if (charsetFormat == 2) {
            i = 1;
            while (i < nGlyphs) {
                c = getU16BE(pos, &parsedOk);
                pos += 2;
                nLeft = getU16BE(pos, &parsedOk);
                pos += 2;
                if (!parsedOk) {
                    break;
                }
                for (j = 0; j <= nLeft && i < nGlyphs; ++j) {
                    customCharset[i++] = (unsigned short)c++;
                }
            }
        }
        if (!parsedOk) {
            gfree(customCharset);
            charset = nullptr;
            charsetLength = 0;
            return false;
        }
        charset = customCharset;
    }
    return true;
}

int FoFiType1C::getOp(int pos, bool charstring, bool *ok)
{
    static const char nybChars[16] = "0123456789.ee -";
    Type1COp op;
    char buf[65];
    int b0, b1, nyb0, nyb1, x, i;

    b0 = getU8(pos++, ok);

    if (b0 == 28) {
        x = getU8(pos++, ok);
        x = (x << 8) | getU8(pos++, ok);
        if (x & 0x8000) {
            x |= ~0xffff;
        }
        op.num = x;

    } else if (!charstring && b0 == 29) {
        x = getU8(pos++, ok);
        x = (x << 8) | getU8(pos++, ok);
        x = (x << 8) | getU8(pos++, ok);
        x = (x << 8) | getU8(pos++, ok);
        if (x & 0x80000000) {
            x |= ~0xffffffff;
        }
        op.num = x;

    } else if (!charstring && b0 == 30) {
        i = 0;
        do {
            b1 = getU8(pos++, ok);
            nyb0 = b1 >> 4;
            nyb1 = b1 & 0x0f;
            if (nyb0 == 0xf) {
                break;
            }
            buf[i++] = nybChars[nyb0];
            if (i == 64) {
                break;
            }
            if (nyb0 == 0xc) {
                buf[i++] = '-';
            }
            if (i == 64) {
                break;
            }
            if (nyb1 == 0xf) {
                break;
            }
            buf[i++] = nybChars[nyb1];
            if (i == 64) {
                break;
            }
            if (nyb1 == 0xc) {
                buf[i++] = '-';
            }
        } while (i < 64);
        buf[i] = '\0';
        op.num = gatof(buf);
        op.isFP = true;

    } else if (b0 >= 32 && b0 <= 246) {
        op.num = b0 - 139;

    } else if (b0 >= 247 && b0 <= 250) {
        op.num = ((b0 - 247) << 8) + getU8(pos++, ok) + 108;

    } else if (b0 >= 251 && b0 <= 254) {
        op.num = -((b0 - 251) << 8) - getU8(pos++, ok) - 108;

    } else if (charstring && b0 == 255) {
        x = getU8(pos++, ok);
        x = (x << 8) | getU8(pos++, ok);
        x = (x << 8) | getU8(pos++, ok);
        x = (x << 8) | getU8(pos++, ok);
        if (x & 0x80000000) {
            x |= ~0xffffffff;
        }
        op.num = (double)x / 65536.0;
        op.isFP = true;

    } else if (b0 == 12) {
        op.isNum = false;
        op.op = 0x0c00 + getU8(pos++, ok);

    } else {
        op.isNum = false;
        op.op = b0;
    }

    if (nOps < 49) {
        ops[nOps++] = op;
    }

    return pos;
}

// Convert the delta-encoded ops array to an array of ints.
int FoFiType1C::getDeltaIntArray(int *arr, int maxLen) const
{
    int x;
    int n, i;

    if ((n = nOps) > maxLen) {
        n = maxLen;
    }
    x = 0;
    for (i = 0; i < n; ++i) {
        int y;
        if (unlikely(std::isinf(ops[i].num))) {
            return i;
        }
        if (checkedAdd(x, (int)ops[i].num, &y)) {
            return i;
        }
        x = y;
        arr[i] = x;
    }
    return n;
}

// Convert the delta-encoded ops array to an array of doubles.
int FoFiType1C::getDeltaFPArray(double *arr, int maxLen) const
{
    double x;
    int n, i;

    if ((n = nOps) > maxLen) {
        n = maxLen;
    }
    x = 0;
    for (i = 0; i < n; ++i) {
        x += ops[i].num;
        arr[i] = x;
    }
    return n;
}

void FoFiType1C::getIndex(int pos, Type1CIndex *idx, bool *ok) const
{
    idx->pos = pos;
    idx->len = getU16BE(pos, ok);
    if (idx->len == 0) {
        // empty indexes are legal and contain just the length field
        idx->offSize = 0;
        idx->startPos = idx->endPos = pos + 2;
    } else {
        idx->offSize = getU8(pos + 2, ok);
        if (idx->offSize < 1 || idx->offSize > 4) {
            *ok = false;
        }
        idx->startPos = pos + 3 + (idx->len + 1) * idx->offSize - 1;
        if (idx->startPos < 0 || idx->startPos >= int(file.size())) {
            *ok = false;
        }
        idx->endPos = idx->startPos + getUVarBE(pos + 3 + idx->len * idx->offSize, idx->offSize, ok);
        if (idx->endPos < idx->startPos || idx->endPos > int(file.size())) {
            *ok = false;
        }
    }
}

void FoFiType1C::getIndexVal(const Type1CIndex *idx, int i, Type1CIndexVal *val, bool *ok) const
{
    int pos0, pos1;

    if (i < 0 || i >= idx->len) {
        *ok = false;
        return;
    }
    pos0 = idx->startPos + getUVarBE(idx->pos + 3 + i * idx->offSize, idx->offSize, ok);
    pos1 = idx->startPos + getUVarBE(idx->pos + 3 + (i + 1) * idx->offSize, idx->offSize, ok);
    if (pos0 < idx->startPos || pos0 > idx->endPos || pos1 <= idx->startPos || pos1 > idx->endPos || pos1 < pos0) {
        *ok = false;
        return;
    }
    val->pos = pos0;
    val->len = pos1 - pos0;
}

char *FoFiType1C::getString(int sid, char *buf, bool *ok) const
{
    Type1CIndexVal val;
    int n;

    if (sid < 0) {
        buf[0] = '\0';
    } else if (sid < 391) {
        strcpy(buf, fofiType1CStdStrings[sid]);
    } else {
        sid -= 391;
        getIndexVal(&stringIdx, sid, &val, ok);
        if (*ok) {
            if ((n = val.len) > 255) {
                n = 255;
            }
            strncpy(buf, (char *)&file[val.pos], n);
            buf[n] = '\0';
        } else {
            buf[0] = '\0';
        }
    }
    return buf;
}
