/* Support for the generic parts of PE/PEI; the common executable parts.
   Copyright (C) 1995-2025 Free Software Foundation, Inc.
   Written by Cygnus Solutions.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */


/* Most of this hacked by Steve Chamberlain <sac@cygnus.com>.

   PE/PEI rearrangement (and code added): Donn Terry
					  Softway Systems, Inc.  */

/* Hey look, some documentation [and in a place you expect to find it]!

   The main reference for the pei format is "Microsoft Portable Executable
   and Common Object File Format Specification 4.1".  Get it if you need to
   do some serious hacking on this code.

   Another reference:
   "Peering Inside the PE: A Tour of the Win32 Portable Executable
   File Format", MSJ 1994, Volume 9.

   The PE/PEI format is also used by .NET. ECMA-335 describes this:

   "Standard ECMA-335 Common Language Infrastructure (CLI)", 6th Edition, June 2012.

   This is also available at
   https://www.ecma-international.org/publications/files/ECMA-ST/ECMA-335.pdf.

   The *sole* difference between the pe format and the pei format is that the
   latter has an MSDOS 2.0 .exe header on the front that prints the message
   "This app must be run under Windows." (or some such).
   (FIXME: Whether that statement is *really* true or not is unknown.
   Are there more subtle differences between pe and pei formats?
   For now assume there aren't.  If you find one, then for God sakes
   document it here!)

   The Microsoft docs use the word "image" instead of "executable" because
   the former can also refer to a DLL (shared library).  Confusion can arise
   because the `i' in `pei' also refers to "image".  The `pe' format can
   also create images (i.e. executables), it's just that to run on a win32
   system you need to use the pei format.

   FIXME: Please add more docs here so the next poor fool that has to hack
   on this code has a chance of getting something accomplished without
   wasting too much time.  */

/* This expands into COFF_WITH_pe, COFF_WITH_pep, COFF_WITH_pex64,
   COFF_WITH_peAArch64 or COFF_WITH_peLoongArch64 or COFF_WITH_peRiscV64
   depending on whether we're compiling for straight PE or PE+.  */
#define COFF_WITH_XX

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "coff/internal.h"
#include "bfdver.h"
#include "libiberty.h"
#include <wchar.h>
#include <wctype.h>

/* NOTE: it's strange to be including an architecture specific header
   in what's supposed to be general (to PE/PEI) code.  However, that's
   where the definitions are, and they don't vary per architecture
   within PE/PEI, so we get them from there.  FIXME: The lack of
   variance is an assumption which may prove to be incorrect if new
   PE/PEI targets are created.  */
#if defined COFF_WITH_pex64
# include "coff/x86_64.h"
#elif defined COFF_WITH_pep
# include "coff/ia64.h"
#elif defined COFF_WITH_peAArch64
# include "coff/aarch64.h"
#elif defined COFF_WITH_peLoongArch64
# include "coff/loongarch64.h"
#elif defined COFF_WITH_peRiscV64
# include "coff/riscv64.h"
#else
# include "coff/i386.h"
#endif

#include "coff/pe.h"
#include "libcoff.h"
#include "libpei.h"
#include "safe-ctype.h"

#if defined COFF_WITH_pep || defined COFF_WITH_pex64 || defined COFF_WITH_peAArch64 || defined COFF_WITH_peLoongArch64 || defined COFF_WITH_peRiscV64
# undef AOUTSZ
# define AOUTSZ		PEPAOUTSZ
# define PEAOUTHDR	PEPAOUTHDR
#endif

#define HighBitSet(val)      ((val) & 0x80000000)
#define SetHighBit(val)      ((val) | 0x80000000)
#define WithoutHighBit(val)  ((val) & 0x7fffffff)

void _bfd_XXi_swap_sym_in(bfd *abfd, void *ext1, void *in1) {
    SYMENT *ext = (SYMENT *)ext1;
    struct internal_syment *in = (struct internal_syment *)in1;

    if (ext->e.e_name[0] == 0) {
        in->_n._n_n._n_zeroes = 0;
        in->_n._n_n._n_offset = H_GET_32(abfd, ext->e.e.e_offset);
    } else {
        memcpy(in->_n._n_name, ext->e.e_name, SYMNMLEN);
    }

    in->n_value = H_GET_32(abfd, ext->e_value);
    in->n_scnum = (short)H_GET_16(abfd, ext->e_scnum);

    in->n_type = (sizeof(ext->e_type) == 2) ? H_GET_16(abfd, ext->e_type) : H_GET_32(abfd, ext->e_type);
    in->n_sclass = H_GET_8(abfd, ext->e_sclass);
    in->n_numaux = H_GET_8(abfd, ext->e_numaux);

#ifndef STRICT_PE_FORMAT
    if (in->n_sclass == C_SECTION) {
        char namebuf[SYMNMLEN + 1];
        const char *name = NULL;
        in->n_value = 0x0;

        if (in->n_scnum == 0) {
            asection *sec;
            name = _bfd_coff_internal_syment_name(abfd, in, namebuf);
            if (name == NULL) {
                _bfd_error_handler(_("%pB: unable to find name for empty section"), abfd);
                bfd_set_error(bfd_error_invalid_target);
                return;
            }
            sec = bfd_get_section_by_name(abfd, name);
            if (sec != NULL) {
                in->n_scnum = sec->target_index;
            }
        }

        if (in->n_scnum == 0) {
            int unused_section_number = 0;
            asection *sec;
            flagword flags;
            size_t name_len;
            char *sec_name;

            for (sec = abfd->sections; sec; sec = sec->next) {
                if (unused_section_number <= sec->target_index) {
                    unused_section_number = sec->target_index + 1;
                }
            }

            name_len = (name ? strlen(name) : 0) + 1;
            sec_name = bfd_alloc(abfd, name_len);
            if (sec_name == NULL) {
                _bfd_error_handler(_("%pB: out of memory creating name for empty section"), abfd);
                return;
            }
            if (name) {
                memcpy(sec_name, name, name_len);
            } else {
                sec_name[0] = '\0';
            }

            flags = SEC_HAS_CONTENTS | SEC_ALLOC | SEC_DATA | SEC_LOAD | SEC_LINKER_CREATED;
            sec = bfd_make_section_anyway_with_flags(abfd, sec_name, flags);
            if (sec == NULL) {
                _bfd_error_handler(_("%pB: unable to create fake empty section"), abfd);
                return;
            }

            sec->alignment_power = 2;
            sec->target_index = unused_section_number;
            in->n_scnum = unused_section_number;
        }
        in->n_sclass = C_STAT;
    }
#endif
}

static bool abs_finder(bfd *abfd ATTRIBUTE_UNUSED, asection *sec, void *data) {
    if (!sec || !data) {
        return false;
    }
    bfd_vma abs_val = *(const bfd_vma *)data;
    if (sec->vma > abs_val) {
        return false;
    }
    if (abs_val >= sec->vma + (1ULL << 32)) {
        return false;
    }
    return true;
}

unsigned int _bfd_XXi_swap_sym_out(bfd *abfd, void *inp, void *extp)
{
    struct internal_syment *in = (struct internal_syment *)inp;
    SYMENT *ext = (SYMENT *)extp;

    if (in->_n._n_name[0] == 0) {
        H_PUT_32(abfd, 0, ext->e.e.e_zeroes);
        H_PUT_32(abfd, in->_n._n_n._n_offset, ext->e.e.e_offset);
    } else {
        memcpy(ext->e.e_name, in->_n._n_name, SYMNMLEN);
    }

    if (sizeof(in->n_value) > 4 &&
        in->n_value > 0xFFFFFFFFULL &&
        in->n_scnum == N_ABS) {
        asection *sec = bfd_sections_find_if(abfd, abs_finder, &in->n_value);
        if (sec) {
            in->n_value -= sec->vma;
            in->n_scnum = sec->target_index;
        }
    }

    H_PUT_32(abfd, in->n_value, ext->e_value);
    H_PUT_16(abfd, in->n_scnum, ext->e_scnum);

    if (sizeof(ext->e_type) == 2) {
        H_PUT_16(abfd, in->n_type, ext->e_type);
    } else {
        H_PUT_32(abfd, in->n_type, ext->e_type);
    }

    H_PUT_8(abfd, in->n_sclass, ext->e_sclass);
    H_PUT_8(abfd, in->n_numaux, ext->e_numaux);

    return SYMESZ;
}

void _bfd_XXi_swap_aux_in(bfd *abfd, void *ext1, int type, int in_class, int indx ATTRIBUTE_UNUSED, int numaux ATTRIBUTE_UNUSED, void *in1)
{
    AUXENT *ext = (AUXENT *)ext1;
    union internal_auxent *in = (union internal_auxent *)in1;

    memset(in, 0, sizeof(*in));

    if (in_class == C_FILE) {
        if (ext->x_file.x_fname[0] == 0) {
            in->x_file.x_n.x_n.x_zeroes = 0;
            in->x_file.x_n.x_n.x_offset = H_GET_32(abfd, ext->x_file.x_n.x_offset);
        } else {
#if FILNMLEN != E_FILNMLEN
#error we need to cope with truncating or extending x_fname
#endif
            memcpy(in->x_file.x_n.x_fname, ext->x_file.x_fname, FILNMLEN);
        }
        return;
    }

    if (in_class == C_STAT || in_class == C_LEAFSTAT || in_class == C_HIDDEN) {
        if (type == T_NULL) {
            in->x_scn.x_scnlen = GET_SCN_SCNLEN(abfd, ext);
            in->x_scn.x_nreloc = GET_SCN_NRELOC(abfd, ext);
            in->x_scn.x_nlinno = GET_SCN_NLINNO(abfd, ext);
            in->x_scn.x_checksum = H_GET_32(abfd, ext->x_scn.x_checksum);
            in->x_scn.x_associated = H_GET_16(abfd, ext->x_scn.x_associated);
            in->x_scn.x_comdat = H_GET_8(abfd, ext->x_scn.x_comdat);
            return;
        }
    }

    in->x_sym.x_tagndx.u32 = H_GET_32(abfd, ext->x_sym.x_tagndx);
    in->x_sym.x_tvndx = H_GET_16(abfd, ext->x_sym.x_tvndx);

    if (in_class == C_BLOCK || in_class == C_FCN || ISFCN(type) || ISTAG(in_class)) {
        in->x_sym.x_fcnary.x_fcn.x_lnnoptr = GET_FCN_LNNOPTR(abfd, ext);
        in->x_sym.x_fcnary.x_fcn.x_endndx.u32 = GET_FCN_ENDNDX(abfd, ext);
    } else {
        int i;
        for (i = 0; i < 4; ++i) {
            in->x_sym.x_fcnary.x_ary.x_dimen[i] =
                H_GET_16(abfd, ext->x_sym.x_fcnary.x_ary.x_dimen[i]);
        }
    }

    if (ISFCN(type)) {
        in->x_sym.x_misc.x_fsize = H_GET_32(abfd, ext->x_sym.x_misc.x_fsize);
    } else {
        in->x_sym.x_misc.x_lnsz.x_lnno = GET_LNSZ_LNNO(abfd, ext);
        in->x_sym.x_misc.x_lnsz.x_size = GET_LNSZ_SIZE(abfd, ext);
    }
}

unsigned int _bfd_XXi_swap_aux_out(bfd *abfd, void *inp, int type, int in_class, int indx ATTRIBUTE_UNUSED, int numaux ATTRIBUTE_UNUSED, void *extp)
{
    union internal_auxent *in = (union internal_auxent *)inp;
    AUXENT *ext = (AUXENT *)extp;

    if (!abfd || !inp || !extp) {
        return 0;
    }

    memset(ext, 0, AUXESZ);

    switch (in_class) {
        case C_FILE:
            if (in->x_file.x_n.x_fname[0] == 0) {
                H_PUT_32(abfd, 0, ext->x_file.x_n.x_zeroes);
                H_PUT_32(abfd, in->x_file.x_n.x_n.x_offset, ext->x_file.x_n.x_offset);
            } else {
#if FILNMLEN != E_FILNMLEN
#error we need to cope with truncating or extending x_fname
#endif
                memcpy(ext->x_file.x_fname, in->x_file.x_n.x_fname, E_FILNMLEN);
            }
            return AUXESZ;

        case C_STAT:
        case C_LEAFSTAT:
        case C_HIDDEN:
            if (type == T_NULL) {
                PUT_SCN_SCNLEN(abfd, in->x_scn.x_scnlen, ext);
                PUT_SCN_NRELOC(abfd, in->x_scn.x_nreloc, ext);
                PUT_SCN_NLINNO(abfd, in->x_scn.x_nlinno, ext);
                H_PUT_32(abfd, in->x_scn.x_checksum, ext->x_scn.x_checksum);
                H_PUT_16(abfd, in->x_scn.x_associated, ext->x_scn.x_associated);
                H_PUT_8(abfd, in->x_scn.x_comdat, ext->x_scn.x_comdat);
                return AUXESZ;
            }
            break;
    }

    H_PUT_32(abfd, in->x_sym.x_tagndx.u32, ext->x_sym.x_tagndx);
    H_PUT_16(abfd, in->x_sym.x_tvndx, ext->x_sym.x_tvndx);

    if (in_class == C_BLOCK || in_class == C_FCN || ISFCN(type) || ISTAG(in_class)) {
        PUT_FCN_LNNOPTR(abfd, in->x_sym.x_fcnary.x_fcn.x_lnnoptr, ext);
        PUT_FCN_ENDNDX(abfd, in->x_sym.x_fcnary.x_fcn.x_endndx.u32, ext);
    } else {
        int i;
        for (i = 0; i < 4; ++i) {
            H_PUT_16(abfd, in->x_sym.x_fcnary.x_ary.x_dimen[i], ext->x_sym.x_fcnary.x_ary.x_dimen[i]);
        }
    }

    if (ISFCN(type)) {
        H_PUT_32(abfd, in->x_sym.x_misc.x_fsize, ext->x_sym.x_misc.x_fsize);
    } else {
        PUT_LNSZ_LNNO(abfd, in->x_sym.x_misc.x_lnsz.x_lnno, ext);
        PUT_LNSZ_SIZE(abfd, in->x_sym.x_misc.x_lnsz.x_size, ext);
    }

    return AUXESZ;
}

void _bfd_XXi_swap_lineno_in(bfd *abfd, void *ext1, void *in1) {
    if (!abfd || !ext1 || !in1) {
        return;
    }

    LINENO *ext = (LINENO *)ext1;
    struct internal_lineno *in = (struct internal_lineno *)in1;

    in->l_addr.l_symndx = H_GET_32(abfd, ext->l_addr.l_symndx);
    in->l_lnno = GET_LINENO_LNNO(abfd, ext);
}

unsigned int _bfd_XXi_swap_lineno_out(bfd *abfd, void *inp, void *outp)
{
    if (!abfd || !inp || !outp)
        return 0;

    struct internal_lineno *in = (struct internal_lineno *)inp;
    struct external_lineno *ext = (struct external_lineno *)outp;

    H_PUT_32(abfd, in->l_addr.l_symndx, ext->l_addr.l_symndx);
    PUT_LINENO_LNNO(abfd, in->l_lnno, ext);

    return LINESZ;
}

void _bfd_XXi_swap_aouthdr_in(bfd *abfd, void *aouthdr_ext1, void *aouthdr_int1)
{
    if (abfd == NULL || aouthdr_ext1 == NULL || aouthdr_int1 == NULL)
        return;

    PEAOUTHDR *src = (PEAOUTHDR *)aouthdr_ext1;
    AOUTHDR *aouthdr_ext = (AOUTHDR *)aouthdr_ext1;
    struct internal_aouthdr *aouthdr_int = (struct internal_aouthdr *)aouthdr_int1;
    struct internal_extra_pe_aouthdr *a = &aouthdr_int->pe;

    unsigned idx = 0;

    aouthdr_int->magic = H_GET_16(abfd, aouthdr_ext->magic);
    aouthdr_int->vstamp = H_GET_16(abfd, aouthdr_ext->vstamp);
    aouthdr_int->tsize = GET_AOUTHDR_TSIZE(abfd, aouthdr_ext->tsize);
    aouthdr_int->dsize = GET_AOUTHDR_DSIZE(abfd, aouthdr_ext->dsize);
    aouthdr_int->bsize = GET_AOUTHDR_BSIZE(abfd, aouthdr_ext->bsize);
    aouthdr_int->entry = GET_AOUTHDR_ENTRY(abfd, aouthdr_ext->entry);
    aouthdr_int->text_start = GET_AOUTHDR_TEXT_START(abfd, aouthdr_ext->text_start);

#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined(COFF_WITH_peRiscV64)
    aouthdr_int->data_start = GET_AOUTHDR_DATA_START(abfd, aouthdr_ext->data_start);
    a->BaseOfData = aouthdr_int->data_start;
#endif

    a->Magic = aouthdr_int->magic;

    if (aouthdr_ext) {
        a->MajorLinkerVersion = H_GET_8(abfd, aouthdr_ext->vstamp);
        a->MinorLinkerVersion = H_GET_8(abfd, aouthdr_ext->vstamp + 1);
    } else {
        a->MajorLinkerVersion = 0;
        a->MinorLinkerVersion = 0;
    }

    a->SizeOfCode = aouthdr_int->tsize;
    a->SizeOfInitializedData = aouthdr_int->dsize;
    a->SizeOfUninitializedData = aouthdr_int->bsize;
    a->AddressOfEntryPoint = aouthdr_int->entry;
    a->BaseOfCode = aouthdr_int->text_start;
    a->ImageBase = GET_OPTHDR_IMAGE_BASE(abfd, src->ImageBase);
    a->SectionAlignment = H_GET_32(abfd, src->SectionAlignment);
    a->FileAlignment = H_GET_32(abfd, src->FileAlignment);
    a->MajorOperatingSystemVersion = H_GET_16(abfd, src->MajorOperatingSystemVersion);
    a->MinorOperatingSystemVersion = H_GET_16(abfd, src->MinorOperatingSystemVersion);
    a->MajorImageVersion = H_GET_16(abfd, src->MajorImageVersion);
    a->MinorImageVersion = H_GET_16(abfd, src->MinorImageVersion);
    a->MajorSubsystemVersion = H_GET_16(abfd, src->MajorSubsystemVersion);
    a->MinorSubsystemVersion = H_GET_16(abfd, src->MinorSubsystemVersion);
    a->Win32Version = H_GET_32(abfd, src->Win32Version);
    a->SizeOfImage = H_GET_32(abfd, src->SizeOfImage);
    a->SizeOfHeaders = H_GET_32(abfd, src->SizeOfHeaders);
    a->CheckSum = H_GET_32(abfd, src->CheckSum);
    a->Subsystem = H_GET_16(abfd, src->Subsystem);
    a->DllCharacteristics = H_GET_16(abfd, src->DllCharacteristics);
    a->SizeOfStackReserve = GET_OPTHDR_SIZE_OF_STACK_RESERVE(abfd, src->SizeOfStackReserve);
    a->SizeOfStackCommit = GET_OPTHDR_SIZE_OF_STACK_COMMIT(abfd, src->SizeOfStackCommit);
    a->SizeOfHeapReserve = GET_OPTHDR_SIZE_OF_HEAP_RESERVE(abfd, src->SizeOfHeapReserve);
    a->SizeOfHeapCommit = GET_OPTHDR_SIZE_OF_HEAP_COMMIT(abfd, src->SizeOfHeapCommit);
    a->LoaderFlags = H_GET_32(abfd, src->LoaderFlags);
    a->NumberOfRvaAndSizes = H_GET_32(abfd, src->NumberOfRvaAndSizes);

    for (idx = 0; idx < a->NumberOfRvaAndSizes && idx < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; idx++) {
        int size = H_GET_32(abfd, src->DataDirectory[idx][1]);
        int vma = (size != 0) ? H_GET_32(abfd, src->DataDirectory[idx][0]) : 0;

        a->DataDirectory[idx].Size = size;
        a->DataDirectory[idx].VirtualAddress = vma;
    }

    for (; idx < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; idx++) {
        a->DataDirectory[idx].Size = 0;
        a->DataDirectory[idx].VirtualAddress = 0;
    }

    if (aouthdr_int->entry) {
        aouthdr_int->entry += a->ImageBase;
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined(COFF_WITH_peRiscV64)
        aouthdr_int->entry &= 0xffffffff;
#endif
    }

    if (aouthdr_int->tsize) {
        aouthdr_int->text_start += a->ImageBase;
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined(COFF_WITH_peRiscV64)
        aouthdr_int->text_start &= 0xffffffff;
#endif
    }

#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined(COFF_WITH_peRiscV64)
    if (aouthdr_int->dsize) {
        aouthdr_int->data_start += a->ImageBase;
        aouthdr_int->data_start &= 0xffffffff;
    }
#endif
}

/* A support function for below.  */

static void add_data_entry(bfd *abfd,
                           struct internal_extra_pe_aouthdr *aout,
                           int idx,
                           char *name,
                           bfd_vma base)
{
    asection *sec = bfd_get_section_by_name(abfd, name);
    if (!sec)
        return;

    void *coff_data = coff_section_data(abfd, sec);
    if (!coff_data)
        return;

    struct pei_section_data_struct *psd = pei_section_data(abfd, sec);
    if (!psd)
        return;

    int size = psd->virt_size;
    aout->DataDirectory[idx].Size = size;

    if (size) {
        aout->DataDirectory[idx].VirtualAddress = (bfd_vma)((sec->vma - base) & 0xffffffff);
        sec->flags |= SEC_DATA;
    }
}

unsigned int _bfd_XXi_swap_aouthdr_out(bfd *abfd, void *in, void *out)
{
    struct internal_aouthdr *aouthdr_in = (struct internal_aouthdr *)in;
    pe_data_type *pe = pe_data(abfd);
    if (!pe)
        return 0;
    struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
    PEAOUTHDR *aouthdr_out = (PEAOUTHDR *)out;
    bfd_vma sa = extra->SectionAlignment;
    bfd_vma fa = extra->FileAlignment;
    bfd_vma ib = extra->ImageBase;
    IMAGE_DATA_DIRECTORY idata2 = pe->pe_opthdr.DataDirectory[PE_IMPORT_TABLE];
    IMAGE_DATA_DIRECTORY idata5 = pe->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE];
    IMAGE_DATA_DIRECTORY didat2 = pe->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR];
    IMAGE_DATA_DIRECTORY tls = pe->pe_opthdr.DataDirectory[PE_TLS_TABLE];
    IMAGE_DATA_DIRECTORY loadcfg = pe->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE];

#define FA_ALIGN(x) (((x) + fa - 1) & (~(fa - 1)))
#define SA_ALIGN(x) (((x) + sa - 1) & (~(sa - 1)))

    if (aouthdr_in->tsize) {
        aouthdr_in->text_start -= ib;
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined(COFF_WITH_peRiscV64)
        aouthdr_in->text_start &= 0xffffffff;
#endif
    }

    if (aouthdr_in->dsize) {
        aouthdr_in->data_start -= ib;
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined(COFF_WITH_peRiscV64)
        aouthdr_in->data_start &= 0xffffffff;
#endif
    }

    if (aouthdr_in->entry) {
        aouthdr_in->entry -= ib;
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined(COFF_WITH_peRiscV64)
        aouthdr_in->entry &= 0xffffffff;
#endif
    }

    aouthdr_in->bsize = FA_ALIGN(aouthdr_in->bsize);

    extra->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    add_data_entry(abfd, extra, PE_EXPORT_TABLE, ".edata", ib);
    add_data_entry(abfd, extra, PE_RESOURCE_TABLE, ".rsrc", ib);
    add_data_entry(abfd, extra, PE_EXCEPTION_TABLE, ".pdata", ib);

    extra->DataDirectory[PE_IMPORT_TABLE] = idata2;
    extra->DataDirectory[PE_IMPORT_ADDRESS_TABLE] = idata5;
    extra->DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR] = didat2;
    extra->DataDirectory[PE_TLS_TABLE] = tls;
    extra->DataDirectory[PE_LOAD_CONFIG_TABLE] = loadcfg;

    if (extra->DataDirectory[PE_IMPORT_TABLE].VirtualAddress == 0)
        add_data_entry(abfd, extra, PE_IMPORT_TABLE, ".idata", ib);

    if (pe->has_reloc_section)
        add_data_entry(abfd, extra, PE_BASE_RELOCATION_TABLE, ".reloc", ib);

    asection *sec;
    bfd_vma hsize = 0, dsize = 0, isize = 0, tsize = 0;

    for (sec = abfd->sections; sec; sec = sec->next) {
        int rounded = FA_ALIGN(sec->size);
        if (rounded == 0)
            continue;
        if (hsize == 0)
            hsize = sec->filepos;
        if (sec->flags & SEC_DATA)
            dsize += rounded;
        if (sec->flags & SEC_CODE)
            tsize += rounded;
        if (coff_section_data(abfd, sec) && pei_section_data(abfd, sec))
            isize = SA_ALIGN(sec->vma - extra->ImageBase + FA_ALIGN(pei_section_data(abfd, sec)->virt_size));
    }

    aouthdr_in->dsize = dsize;
    aouthdr_in->tsize = tsize;
    extra->SizeOfHeaders = hsize;
    extra->SizeOfImage = isize;

    H_PUT_16(abfd, aouthdr_in->magic, aouthdr_out->standard.magic);

    if (extra->MajorLinkerVersion || extra->MinorLinkerVersion) {
        H_PUT_8(abfd, extra->MajorLinkerVersion, aouthdr_out->standard.vstamp);
        H_PUT_8(abfd, extra->MinorLinkerVersion, aouthdr_out->standard.vstamp + 1);
    } else {
#define LINKER_VERSION_SHORT ((short)(BFD_VERSION / 1000000))
        H_PUT_16(abfd, (LINKER_VERSION_SHORT / 100 + (LINKER_VERSION_SHORT % 100) * 256),
                 aouthdr_out->standard.vstamp);
    }

    PUT_AOUTHDR_TSIZE(abfd, aouthdr_in->tsize, aouthdr_out->standard.tsize);
    PUT_AOUTHDR_DSIZE(abfd, aouthdr_in->dsize, aouthdr_out->standard.dsize);
    PUT_AOUTHDR_BSIZE(abfd, aouthdr_in->bsize, aouthdr_out->standard.bsize);
    PUT_AOUTHDR_ENTRY(abfd, aouthdr_in->entry, aouthdr_out->standard.entry);
    PUT_AOUTHDR_TEXT_START(abfd, aouthdr_in->text_start, aouthdr_out->standard.text_start);

#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined(COFF_WITH_peRiscV64)
    PUT_AOUTHDR_DATA_START(abfd, aouthdr_in->data_start, aouthdr_out->standard.data_start);
#endif

    PUT_OPTHDR_IMAGE_BASE(abfd, extra->ImageBase, aouthdr_out->ImageBase);
    H_PUT_32(abfd, extra->SectionAlignment, aouthdr_out->SectionAlignment);
    H_PUT_32(abfd, extra->FileAlignment, aouthdr_out->FileAlignment);
    H_PUT_16(abfd, extra->MajorOperatingSystemVersion, aouthdr_out->MajorOperatingSystemVersion);
    H_PUT_16(abfd, extra->MinorOperatingSystemVersion, aouthdr_out->MinorOperatingSystemVersion);
    H_PUT_16(abfd, extra->MajorImageVersion, aouthdr_out->MajorImageVersion);
    H_PUT_16(abfd, extra->MinorImageVersion, aouthdr_out->MinorImageVersion);
    H_PUT_16(abfd, extra->MajorSubsystemVersion, aouthdr_out->MajorSubsystemVersion);
    H_PUT_16(abfd, extra->MinorSubsystemVersion, aouthdr_out->MinorSubsystemVersion);
    H_PUT_32(abfd, extra->Win32Version, aouthdr_out->Win32Version);
    H_PUT_32(abfd, extra->SizeOfImage, aouthdr_out->SizeOfImage);
    H_PUT_32(abfd, extra->SizeOfHeaders, aouthdr_out->SizeOfHeaders);
    H_PUT_32(abfd, extra->CheckSum, aouthdr_out->CheckSum);
    H_PUT_16(abfd, extra->Subsystem, aouthdr_out->Subsystem);
    H_PUT_16(abfd, extra->DllCharacteristics, aouthdr_out->DllCharacteristics);
    PUT_OPTHDR_SIZE_OF_STACK_RESERVE(abfd, extra->SizeOfStackReserve, aouthdr_out->SizeOfStackReserve);
    PUT_OPTHDR_SIZE_OF_STACK_COMMIT(abfd, extra->SizeOfStackCommit, aouthdr_out->SizeOfStackCommit);
    PUT_OPTHDR_SIZE_OF_HEAP_RESERVE(abfd, extra->SizeOfHeapReserve, aouthdr_out->SizeOfHeapReserve);
    PUT_OPTHDR_SIZE_OF_HEAP_COMMIT(abfd, extra->SizeOfHeapCommit, aouthdr_out->SizeOfHeapCommit);
    H_PUT_32(abfd, extra->LoaderFlags, aouthdr_out->LoaderFlags);
    H_PUT_32(abfd, extra->NumberOfRvaAndSizes, aouthdr_out->NumberOfRvaAndSizes);

    for (int idx = 0; idx < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; idx++) {
        H_PUT_32(abfd, extra->DataDirectory[idx].VirtualAddress, aouthdr_out->DataDirectory[idx][0]);
        H_PUT_32(abfd, extra->DataDirectory[idx].Size, aouthdr_out->DataDirectory[idx][1]);
    }

    return AOUTSZ;
}

unsigned int _bfd_XXi_only_swap_filehdr_out(bfd *abfd, void *in, void *out)
{
    if (!abfd || !in || !out)
        return 0;

    struct internal_filehdr *filehdr_in = (struct internal_filehdr *) in;
    struct external_PEI_filehdr *filehdr_out = (struct external_PEI_filehdr *) out;
    int idx;

    const pe_data_type *pdata = pe_data(abfd);
    if (!pdata)
        return 0;

    if (pdata->has_reloc_section || pdata->dont_strip_reloc)
        filehdr_in->f_flags &= ~F_RELFLG;

    if (pdata->dll)
        filehdr_in->f_flags |= F_DLL;

    struct internal_pe_header *pe = &filehdr_in->pe;
    pe->e_magic    = IMAGE_DOS_SIGNATURE;
    pe->e_cblp     = 0x90;
    pe->e_cp       = 0x3;
    pe->e_crlc     = 0x0;
    pe->e_cparhdr  = 0x4;
    pe->e_minalloc = 0x0;
    pe->e_maxalloc = 0xffff;
    pe->e_ss       = 0x0;
    pe->e_sp       = 0xb8;
    pe->e_csum     = 0x0;
    pe->e_ip       = 0x0;
    pe->e_cs       = 0x0;
    pe->e_lfarlc   = 0x40;
    pe->e_ovno     = 0x0;

    for (idx = 0; idx < 4; ++idx)
        pe->e_res[idx] = 0x0;

    pe->e_oemid   = 0x0;
    pe->e_oeminfo = 0x0;

    for (idx = 0; idx < 10; ++idx)
        pe->e_res2[idx] = 0x0;

    pe->e_lfanew = 0x80;

    if (sizeof(pe->dos_message) != sizeof(pdata->dos_message))
        return 0;
    memcpy(pe->dos_message, pdata->dos_message, sizeof(pe->dos_message));

    pe->nt_signature = IMAGE_NT_SIGNATURE;

    H_PUT_16(abfd, filehdr_in->f_magic,   filehdr_out->f_magic);
    H_PUT_16(abfd, filehdr_in->f_nscns,   filehdr_out->f_nscns);

    if (pdata->timestamp == -1) {
        time_t now = bfd_get_current_time(0);
        H_PUT_32(abfd, now, filehdr_out->f_timdat);
    } else {
        H_PUT_32(abfd, pdata->timestamp, filehdr_out->f_timdat);
    }

    PUT_FILEHDR_SYMPTR(abfd, filehdr_in->f_symptr, filehdr_out->f_symptr);
    H_PUT_32(abfd, filehdr_in->f_nsyms,   filehdr_out->f_nsyms);
    H_PUT_16(abfd, filehdr_in->f_opthdr,  filehdr_out->f_opthdr);
    H_PUT_16(abfd, filehdr_in->f_flags,   filehdr_out->f_flags);

    H_PUT_16(abfd, pe->e_magic,   filehdr_out->e_magic);
    H_PUT_16(abfd, pe->e_cblp,    filehdr_out->e_cblp);
    H_PUT_16(abfd, pe->e_cp,      filehdr_out->e_cp);
    H_PUT_16(abfd, pe->e_crlc,    filehdr_out->e_crlc);
    H_PUT_16(abfd, pe->e_cparhdr, filehdr_out->e_cparhdr);
    H_PUT_16(abfd, pe->e_minalloc, filehdr_out->e_minalloc);
    H_PUT_16(abfd, pe->e_maxalloc, filehdr_out->e_maxalloc);
    H_PUT_16(abfd, pe->e_ss,      filehdr_out->e_ss);
    H_PUT_16(abfd, pe->e_sp,      filehdr_out->e_sp);
    H_PUT_16(abfd, pe->e_csum,    filehdr_out->e_csum);
    H_PUT_16(abfd, pe->e_ip,      filehdr_out->e_ip);
    H_PUT_16(abfd, pe->e_cs,      filehdr_out->e_cs);
    H_PUT_16(abfd, pe->e_lfarlc,  filehdr_out->e_lfarlc);
    H_PUT_16(abfd, pe->e_ovno,    filehdr_out->e_ovno);

    for (idx = 0; idx < 4; ++idx)
        H_PUT_16(abfd, pe->e_res[idx], filehdr_out->e_res[idx]);

    H_PUT_16(abfd, pe->e_oemid,   filehdr_out->e_oemid);
    H_PUT_16(abfd, pe->e_oeminfo, filehdr_out->e_oeminfo);

    for (idx = 0; idx < 10; ++idx)
        H_PUT_16(abfd, pe->e_res2[idx], filehdr_out->e_res2[idx]);

    H_PUT_32(abfd, pe->e_lfanew, filehdr_out->e_lfanew);

    if (sizeof(filehdr_out->dos_message) != sizeof(pe->dos_message))
        return 0;
    memcpy(filehdr_out->dos_message, pe->dos_message, sizeof(filehdr_out->dos_message));

    H_PUT_32(abfd, pe->nt_signature, filehdr_out->nt_signature);

    return FILHSZ;
}

unsigned int _bfd_XX_only_swap_filehdr_out(bfd *abfd, void *in, void *out)
{
    if (!abfd || !in || !out)
        return 0;

    struct internal_filehdr *filehdr_in = (struct internal_filehdr *)in;
    FILHDR *filehdr_out = (FILHDR *)out;

    H_PUT_16(abfd, filehdr_in->f_magic, filehdr_out->f_magic);
    H_PUT_16(abfd, filehdr_in->f_nscns, filehdr_out->f_nscns);
    H_PUT_32(abfd, filehdr_in->f_timdat, filehdr_out->f_timdat);
    PUT_FILEHDR_SYMPTR(abfd, filehdr_in->f_symptr, filehdr_out->f_symptr);
    H_PUT_32(abfd, filehdr_in->f_nsyms, filehdr_out->f_nsyms);
    H_PUT_16(abfd, filehdr_in->f_opthdr, filehdr_out->f_opthdr);
    H_PUT_16(abfd, filehdr_in->f_flags, filehdr_out->f_flags);

    return FILHSZ;
}

unsigned int _bfd_XXi_swap_scnhdr_out(bfd *abfd, void *in, void *out)
{
    struct internal_scnhdr *scnhdr_int = (struct internal_scnhdr *)in;
    SCNHDR *scnhdr_ext = (SCNHDR *)out;
    unsigned int ret = SCNHSZ;
    bfd_vma ps = 0;
    bfd_vma ss = 0;

    memcpy(scnhdr_ext->s_name, scnhdr_int->s_name, sizeof(scnhdr_int->s_name));

    bfd_vma image_base = pe_data(abfd)->pe_opthdr.ImageBase;
    ss = scnhdr_int->s_vaddr - image_base;
    if (scnhdr_int->s_vaddr < image_base) {
        _bfd_error_handler(_("%pB:%.8s: section below image base"), abfd, scnhdr_int->s_name);
    }
#if !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined(COFF_WITH_peRiscV64)
    else if (ss != (ss & 0xffffffff)) {
        _bfd_error_handler(_("%pB:%.8s: RVA truncated"), abfd, scnhdr_int->s_name);
        PUT_SCNHDR_VADDR(abfd, ss & 0xffffffff, scnhdr_ext->s_vaddr);
    } else {
        PUT_SCNHDR_VADDR(abfd, ss & 0xffffffff, scnhdr_ext->s_vaddr);
    }
#else
    PUT_SCNHDR_VADDR(abfd, ss, scnhdr_ext->s_vaddr);
#endif

    int is_bss = (scnhdr_int->s_flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;
    int is_pei = bfd_pei_p(abfd);

    if (is_bss) {
        if (is_pei) {
            ps = scnhdr_int->s_size;
            ss = 0;
        } else {
            ps = 0;
            ss = scnhdr_int->s_size;
        }
    } else {
        ps = is_pei ? scnhdr_int->s_paddr : 0;
        ss = scnhdr_int->s_size;
    }

    PUT_SCNHDR_SIZE(abfd, ss, scnhdr_ext->s_size);
    PUT_SCNHDR_PADDR(abfd, ps, scnhdr_ext->s_paddr);

    PUT_SCNHDR_SCNPTR(abfd, scnhdr_int->s_scnptr, scnhdr_ext->s_scnptr);
    PUT_SCNHDR_RELPTR(abfd, scnhdr_int->s_relptr, scnhdr_ext->s_relptr);
    PUT_SCNHDR_LNNOPTR(abfd, scnhdr_int->s_lnnoptr, scnhdr_ext->s_lnnoptr);

    typedef struct {
        char section_name[SCNNMLEN];
        unsigned long must_have;
    } pe_required_section_flags;

    static const pe_required_section_flags known_sections[] = {
        { ".CRT",   IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA },
        { ".arch",  IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_ALIGN_8BYTES },
        { ".bss",   IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_WRITE },
        { ".data",  IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_WRITE },
        { ".didat", IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_WRITE },
        { ".edata", IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA },
        { ".idata", IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA },
        { ".pdata", IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA },
        { ".rdata", IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA },
        { ".reloc", IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE },
        { ".rsrc",  IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA },
        { ".text",  IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE },
        { ".tls",   IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_WRITE },
        { ".xdata", IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA }
    };

    size_t i;
    for (i = 0; i < sizeof(known_sections) / sizeof(known_sections[0]); ++i) {
        if (memcmp(scnhdr_int->s_name, known_sections[i].section_name, SCNNMLEN) == 0) {
            int is_text = memcmp(scnhdr_int->s_name, ".text", sizeof(".text")) == 0;
            if (!(is_text && !(bfd_get_file_flags(abfd) & WP_TEXT))) {
                scnhdr_int->s_flags &= ~IMAGE_SCN_MEM_WRITE;
            }
            scnhdr_int->s_flags |= known_sections[i].must_have;
            break;
        }
    }

    H_PUT_32(abfd, scnhdr_int->s_flags, scnhdr_ext->s_flags);

    void *link_info = coff_data(abfd)->link_info;
    int is_text_section = memcmp(scnhdr_int->s_name, ".text", sizeof(".text")) == 0;
    if (link_info &&
        !bfd_link_relocatable(link_info) &&
        !bfd_link_pic(link_info) &&
        is_text_section) {
        H_PUT_16(abfd, (scnhdr_int->s_nlnno & 0xffff), scnhdr_ext->s_nlnno);
        H_PUT_16(abfd, (scnhdr_int->s_nlnno >> 16), scnhdr_ext->s_nreloc);
    } else {
        if (scnhdr_int->s_nlnno <= 0xffff) {
            H_PUT_16(abfd, scnhdr_int->s_nlnno, scnhdr_ext->s_nlnno);
        } else {
            _bfd_error_handler(_("%pB: line number overflow: 0x%lx > 0xffff"), abfd, scnhdr_int->s_nlnno);
            bfd_set_error(bfd_error_file_truncated);
            H_PUT_16(abfd, 0xffff, scnhdr_ext->s_nlnno);
            ret = 0;
        }

        if (scnhdr_int->s_nreloc < 0xffff) {
            H_PUT_16(abfd, scnhdr_int->s_nreloc, scnhdr_ext->s_nreloc);
        } else {
            H_PUT_16(abfd, 0xffff, scnhdr_ext->s_nreloc);
            scnhdr_int->s_flags |= IMAGE_SCN_LNK_NRELOC_OVFL;
            H_PUT_32(abfd, scnhdr_int->s_flags, scnhdr_ext->s_flags);
        }
    }

    return ret;
}


void _bfd_XXi_swap_debugdir_in(bfd *abfd, void *ext1, void *in1) {
    if (!abfd || !ext1 || !in1) {
        return;
    }

    struct external_IMAGE_DEBUG_DIRECTORY *ext = (struct external_IMAGE_DEBUG_DIRECTORY *)ext1;
    struct internal_IMAGE_DEBUG_DIRECTORY *in = (struct internal_IMAGE_DEBUG_DIRECTORY *)in1;

    in->Characteristics   = H_GET_32(abfd, ext->Characteristics);
    in->TimeDateStamp     = H_GET_32(abfd, ext->TimeDateStamp);
    in->MajorVersion      = H_GET_16(abfd, ext->MajorVersion);
    in->MinorVersion      = H_GET_16(abfd, ext->MinorVersion);
    in->Type              = H_GET_32(abfd, ext->Type);
    in->SizeOfData        = H_GET_32(abfd, ext->SizeOfData);
    in->AddressOfRawData  = H_GET_32(abfd, ext->AddressOfRawData);
    in->PointerToRawData  = H_GET_32(abfd, ext->PointerToRawData);
}

unsigned int _bfd_XXi_swap_debugdir_out(bfd *abfd, void *inp, void *extp)
{
    if (!abfd || !inp || !extp)
        return 0;

    struct external_IMAGE_DEBUG_DIRECTORY *ext = (struct external_IMAGE_DEBUG_DIRECTORY *)extp;
    struct internal_IMAGE_DEBUG_DIRECTORY *in = (struct internal_IMAGE_DEBUG_DIRECTORY *)inp;

    H_PUT_32(abfd, in->Characteristics, ext->Characteristics);
    H_PUT_32(abfd, in->TimeDateStamp, ext->TimeDateStamp);
    H_PUT_16(abfd, in->MajorVersion, ext->MajorVersion);
    H_PUT_16(abfd, in->MinorVersion, ext->MinorVersion);
    H_PUT_32(abfd, in->Type, ext->Type);
    H_PUT_32(abfd, in->SizeOfData, ext->SizeOfData);
    H_PUT_32(abfd, in->AddressOfRawData, ext->AddressOfRawData);
    H_PUT_32(abfd, in->PointerToRawData, ext->PointerToRawData);

    return sizeof(struct external_IMAGE_DEBUG_DIRECTORY);
}


CODEVIEW_INFO *
_bfd_XXi_slurp_codeview_record(bfd *abfd, file_ptr where, unsigned long length, CODEVIEW_INFO *cvinfo, char **pdb)
{
    char buffer[257];
    bfd_size_type nread;

    if (!abfd || !cvinfo)
        return NULL;

    if (length <= sizeof(CV_INFO_PDB70) && length <= sizeof(CV_INFO_PDB20))
        return NULL;

    if (length > 256)
        length = 256;

    if (bfd_seek(abfd, where, SEEK_SET) != 0)
        return NULL;

    nread = bfd_read(buffer, length, abfd);
    if (nread != length)
        return NULL;

    memset(buffer + nread, 0, sizeof(buffer) - nread);

    cvinfo->CVSignature = H_GET_32(abfd, buffer);
    cvinfo->Age = 0;
    cvinfo->SignatureLength = 0;
    memset(cvinfo->Signature, 0, sizeof(cvinfo->Signature));

    if (cvinfo->CVSignature == CVINFO_PDB70_CVSIGNATURE && length > sizeof(CV_INFO_PDB70)) {
        const CV_INFO_PDB70 *cvinfo70 = (const CV_INFO_PDB70 *)(buffer);

        cvinfo->Age = H_GET_32(abfd, cvinfo70->Age);

        bfd_putb32(bfd_getl32(cvinfo70->Signature), cvinfo->Signature);
        bfd_putb16(bfd_getl16(&cvinfo70->Signature[4]), &cvinfo->Signature[4]);
        bfd_putb16(bfd_getl16(&cvinfo70->Signature[6]), &cvinfo->Signature[6]);
        memcpy(&cvinfo->Signature[8], &cvinfo70->Signature[8], 8);

        cvinfo->SignatureLength = CV_INFO_SIGNATURE_LENGTH;

        if (pdb)
            *pdb = xstrdup(cvinfo70->PdbFileName);

        return cvinfo;
    }

    if (cvinfo->CVSignature == CVINFO_PDB20_CVSIGNATURE && length > sizeof(CV_INFO_PDB20)) {
        const CV_INFO_PDB20 *cvinfo20 = (const CV_INFO_PDB20 *)(buffer);

        cvinfo->Age = H_GET_32(abfd, cvinfo20->Age);
        memcpy(cvinfo->Signature, cvinfo20->Signature, 4);
        cvinfo->SignatureLength = 4;

        if (pdb)
            *pdb = xstrdup(cvinfo20->PdbFileName);

        return cvinfo;
    }

    return NULL;
}

unsigned int _bfd_XXi_write_codeview_record(bfd *abfd, file_ptr where, CODEVIEW_INFO *cvinfo, const char *pdb)
{
    if (abfd == NULL || cvinfo == NULL)
        return 0;

    size_t pdb_len = pdb ? strlen(pdb) : 0;
    bfd_size_type size = sizeof(CV_INFO_PDB70) + pdb_len + 1;

    if (bfd_seek(abfd, where, SEEK_SET) != 0)
        return 0;

    char *buffer = bfd_malloc(size);
    if (buffer == NULL)
        return 0;

    CV_INFO_PDB70 *cvinfo70 = (CV_INFO_PDB70 *) buffer;
    H_PUT_32(abfd, CVINFO_PDB70_CVSIGNATURE, cvinfo70->CvSignature);

    bfd_putl32(bfd_getb32(cvinfo->Signature), cvinfo70->Signature);
    bfd_putl16(bfd_getb16(&cvinfo->Signature[4]), &cvinfo70->Signature[4]);
    bfd_putl16(bfd_getb16(&cvinfo->Signature[6]), &cvinfo70->Signature[6]);
    memcpy(&cvinfo70->Signature[8], &cvinfo->Signature[8], 8);

    H_PUT_32(abfd, cvinfo->Age, cvinfo70->Age);

    if (pdb && pdb_len > 0) {
        memcpy(cvinfo70->PdbFileName, pdb, pdb_len);
        cvinfo70->PdbFileName[pdb_len] = '\0';
    } else {
        cvinfo70->PdbFileName[0] = '\0';
    }

    bfd_size_type written = bfd_write(buffer, size, abfd);
    free(buffer);

    if (written != size)
        return 0;

    return (unsigned int)size;
}

static char * dir_names[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] =
{
  N_("Export Directory [.edata (or where ever we found it)]"),
  N_("Import Directory [parts of .idata]"),
  N_("Resource Directory [.rsrc]"),
  N_("Exception Directory [.pdata]"),
  N_("Security Directory"),
  N_("Base Relocation Directory [.reloc]"),
  N_("Debug Directory"),
  N_("Description Directory"),
  N_("Special Directory"),
  N_("Thread Storage Directory [.tls]"),
  N_("Load Configuration Directory"),
  N_("Bound Import Directory"),
  N_("Import Address Table Directory"),
  N_("Delay Import Directory"),
  N_("CLR Runtime Header"),
  N_("Reserved")
};

static bool get_contents_sanity_check(bfd *abfd, asection *section, bfd_size_type dataoff, bfd_size_type datasize) {
    if ((section->flags & SEC_HAS_CONTENTS) == 0)
        return false;

    if (dataoff > section->size)
        return false;

    if (datasize > section->size - dataoff)
        return false;

    ufile_ptr filesize = bfd_get_file_size(abfd);
    if (filesize == 0)
        return true;

    ufile_ptr filepos = (ufile_ptr)section->filepos;
    if (filepos > filesize)
        return false;

    if (dataoff > filesize - filepos)
        return false;

    if (datasize > filesize - filepos - dataoff)
        return false;

    return true;
}

static bool
pe_print_idata(bfd *abfd, void *vfile)
{
    FILE *file = (FILE *)vfile;
    bfd_byte *data = NULL;
    asection *section = NULL;
    bfd_signed_vma adj;
    bfd_size_type datasize = 0;
    bfd_size_type dataoff;
    bfd_size_type i;

    const int onaline = 20;

    pe_data_type *pe = pe_data(abfd);
    struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;

    bfd_vma addr = extra->DataDirectory[PE_IMPORT_TABLE].VirtualAddress;

    if (addr == 0 && extra->DataDirectory[PE_IMPORT_TABLE].Size == 0)
    {
        section = bfd_get_section_by_name(abfd, ".idata");
        if (section == NULL || (section->flags & SEC_HAS_CONTENTS) == 0 || section->size == 0)
            return true;
        addr = section->vma;
        datasize = section->size;
    }
    else
    {
        addr += extra->ImageBase;
        for (section = abfd->sections; section != NULL; section = section->next)
        {
            datasize = section->size;
            if (addr >= section->vma && addr < section->vma + datasize)
                break;
        }
        if (section == NULL)
        {
            fprintf(file, _("\nThere is an import table, but the section containing it could not be found\n"));
            return true;
        }
        if (!(section->flags & SEC_HAS_CONTENTS))
        {
            fprintf(file, _("\nThere is an import table in %s, but that section has no contents\n"), section->name);
            return true;
        }
    }

    fprintf(file, _("\nThere is an import table in %s at 0x%lx\n"), section->name, (unsigned long)addr);

    dataoff = addr - section->vma;

    fprintf(file, _("\nThe Import Tables (interpreted %s section contents)\n"), section->name);
    fprintf(file,
        _("\
 vma:            Hint    Time      Forward  DLL       First\n\
                 Table   Stamp     Chain    Name      Thunk\n"));

    if (!bfd_malloc_and_get_section(abfd, section, &data) || data == NULL)
        return false;

    adj = section->vma - extra->ImageBase;

    for (i = dataoff; i + onaline <= datasize; i += onaline)
    {
        bfd_vma hint_addr, time_stamp, forward_chain, dll_name, first_thunk;
        bfd_size_type j;
        char *dll;
        bfd_size_type maxlen;
        int idx = 0;

        fprintf(file, " %08lx\t", (unsigned long)(i + adj));
        hint_addr = bfd_get_32(abfd, data + i);
        time_stamp = bfd_get_32(abfd, data + i + 4);
        forward_chain = bfd_get_32(abfd, data + i + 8);
        dll_name = bfd_get_32(abfd, data + i + 12);
        first_thunk = bfd_get_32(abfd, data + i + 16);

        fprintf(file, "%08lx %08lx %08lx %08lx %08lx\n",
            (unsigned long)hint_addr,
            (unsigned long)time_stamp,
            (unsigned long)forward_chain,
            (unsigned long)dll_name,
            (unsigned long)first_thunk);

        if (hint_addr == 0 && first_thunk == 0)
            break;

        if (dll_name < adj || (dll_name - adj) >= section->size)
            break;

        dll = (char *)data + dll_name - adj;
        maxlen = (char *)(data + datasize) - dll - 1;
        if (maxlen > 0)
            fprintf(file, _("\n\tDLL Name: %.*s\n"), (int)maxlen, dll);
        else
            fprintf(file, _("\n\tDLL Name: (invalid offset)\n"));

        if (hint_addr == 0)
            hint_addr = first_thunk;

        if (hint_addr != 0 && hint_addr >= adj && (hint_addr - adj) < datasize)
        {
            bfd_byte *ft_data = NULL;
            asection *ft_section = NULL;
            bfd_vma ft_addr;
            bfd_size_type ft_datasize = 0;
            int ft_idx = 0;
            bool ft_allocated = false;

            fprintf(file, _("\tvma:     Ordinal  Hint  Member-Name  Bound-To\n"));

            idx = hint_addr - adj;

            ft_addr = first_thunk + extra->ImageBase;
            ft_idx = first_thunk - adj;
            ft_data = data + ft_idx;
            ft_datasize = (ft_idx < (int)datasize) ? datasize - ft_idx : 0;
            ft_allocated = false;

            if (first_thunk != hint_addr)
            {
                for (ft_section = abfd->sections; ft_section != NULL; ft_section = ft_section->next)
                {
                    if (ft_addr >= ft_section->vma && ft_addr < ft_section->vma + ft_section->size)
                        break;
                }
                if (ft_section == NULL)
                {
                    fprintf(file,
                            _("\nThere is a first thunk, but the section containing it could not be found\n"));
                    continue;
                }
                if (ft_section != section)
                {
                    ft_idx = first_thunk - (ft_section->vma - extra->ImageBase);
                    ft_datasize = (ft_idx >= 0 && (bfd_size_type)ft_idx < ft_section->size) ? ft_section->size - ft_idx : 0;
                    if (ft_datasize == 0 || !get_contents_sanity_check(abfd, ft_section, ft_idx, ft_datasize))
                        continue;
                    ft_data = (bfd_byte *)bfd_malloc(ft_datasize);
                    if (ft_data == NULL)
                        continue;
                    if (!bfd_get_section_contents(abfd, ft_section, ft_data, (bfd_vma)ft_idx, ft_datasize))
                    {
                        free(ft_data);
                        continue;
                    }
                    ft_allocated = true;
                }
            }

#ifdef COFF_WITH_pex64
            for (j = 0; idx + j + 8 <= datasize; j += 8)
            {
                bfd_size_type amt;
                unsigned long member = bfd_get_32(abfd, data + idx + j);
                unsigned long member_high = bfd_get_32(abfd, data + idx + j + 4);

                if (!member && !member_high)
                    break;

                amt = member - adj;

                if (HighBitSet(member_high))
                {
                    unsigned int ordinal = member & 0xffff;
                    fprintf(file, "\t%08lx  %5u  <none> <none>",
                            (unsigned long)(first_thunk + j), ordinal);
                }
                else if (amt >= datasize || amt + 2 >= datasize)
                {
                    fprintf(file, _("\t<corrupt: 0x%08lx>"), member);
                }
                else
                {
                    unsigned int hint = bfd_get_16(abfd, data + amt);
                    char *member_name = (char *)data + amt + 2;
                    fprintf(file, "\t%08lx  <none>  %04x  %.*s",
                            (unsigned long)(first_thunk + j), hint,
                            (int)(datasize - (amt + 2)), member_name);
                }

                if (time_stamp != 0 &&
                    first_thunk != 0 &&
                    first_thunk != hint_addr &&
                    j + 4 <= ft_datasize)
                {
                    fprintf(file, "\t%08lx", (unsigned long) bfd_get_32(abfd, ft_data + j));
                }
                fprintf(file, "\n");
            }
#else
            for (j = 0; idx + j + 4 <= datasize; j += 4)
            {
                bfd_size_type amt;
                unsigned long member = bfd_get_32(abfd, data + idx + j);

                if (member == 0)
                    break;

                amt = member - adj;

                if (HighBitSet(member))
                {
                    unsigned int ordinal = member & 0xffff;
                    fprintf(file, "\t%08lx  %5u  <none> <none>", (unsigned long)(first_thunk + j), ordinal);
                }
                else if (amt >= datasize || amt + 2 >= datasize)
                {
                    fprintf(file, _("\t<corrupt: 0x%08lx>"), member);
                }
                else
                {
                    unsigned int hint = bfd_get_16(abfd, data + amt);
                    char *member_name = (char *)data + amt + 2;
                    fprintf(file, "\t%08lx  <none>  %04x  %.*s",
                            (unsigned long)(first_thunk + j), hint,
                            (int)(datasize - (amt + 2)), member_name);
                }

                if (time_stamp != 0 &&
                    first_thunk != 0 &&
                    first_thunk != hint_addr &&
                    j + 4 <= ft_datasize)
                {
                    fprintf(file, "\t%08lx",
                        (unsigned long) bfd_get_32(abfd, ft_data + j));
                }
                fprintf(file, "\n");
            }
#endif
            if (ft_allocated && ft_data != NULL)
                free(ft_data);
        }
        fprintf(file, "\n");
    }

    free(data);
    return true;
}


static bool
pe_print_edata(bfd *abfd, void *vfile)
{
    FILE *file = (FILE *)vfile;
    bfd_byte *data = NULL;
    asection *section = NULL;
    bfd_size_type datasize = 0;
    bfd_size_type dataoff = 0;
    bfd_size_type i;
    bfd_vma adj;
    struct {
        long export_flags;
        long time_stamp;
        short major_ver;
        short minor_ver;
        bfd_vma name;
        long base;
        unsigned long num_functions;
        unsigned long num_names;
        bfd_vma eat_addr;
        bfd_vma npt_addr;
        bfd_vma ot_addr;
    } edt;
    pe_data_type *pe = pe_data(abfd);
    struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
    bfd_vma addr;
    bool retval = true;

    addr = extra->DataDirectory[PE_EXPORT_TABLE].VirtualAddress;

    if (addr == 0 && extra->DataDirectory[PE_EXPORT_TABLE].Size == 0) {
        section = bfd_get_section_by_name(abfd, ".edata");
        if (section == NULL)
            return true;
        addr = section->vma;
        dataoff = 0;
        datasize = section->size;
        if (datasize == 0)
            return true;
    } else {
        addr += extra->ImageBase;
        for (section = abfd->sections; section != NULL; section = section->next) {
            if (addr >= section->vma && addr < section->vma + section->size)
                break;
        }
        if (section == NULL) {
            fprintf(file, _("\nThere is an export table, but the section containing it could not be found\n"));
            return true;
        }
        dataoff = addr - section->vma;
        datasize = extra->DataDirectory[PE_EXPORT_TABLE].Size;
    }

    if (datasize < 40) {
        fprintf(file, _("\nThere is an export table in %s, but it is too small (%d)\n"),
                section->name, (int)datasize);
        return true;
    }

    if (!get_contents_sanity_check(abfd, section, dataoff, datasize)) {
        fprintf(file, _("\nThere is an export table in %s, but contents cannot be read\n"),
                section->name);
        return true;
    }

    fprintf(file, _("\nThere is an export table in %s at 0x%lx\n"),
            section->name, (unsigned long)addr);

    data = (bfd_byte *)bfd_malloc(datasize);
    if (data == NULL)
        return false;

    if (!bfd_get_section_contents(abfd, section, data, (file_ptr)dataoff, datasize)) {
        free(data);
        return false;
    }

    edt.export_flags  = bfd_get_32(abfd, data +  0);
    edt.time_stamp    = bfd_get_32(abfd, data +  4);
    edt.major_ver     = bfd_get_16(abfd, data +  8);
    edt.minor_ver     = bfd_get_16(abfd, data + 10);
    edt.name          = bfd_get_32(abfd, data + 12);
    edt.base          = bfd_get_32(abfd, data + 16);
    edt.num_functions = bfd_get_32(abfd, data + 20);
    edt.num_names     = bfd_get_32(abfd, data + 24);
    edt.eat_addr      = bfd_get_32(abfd, data + 28);
    edt.npt_addr      = bfd_get_32(abfd, data + 32);
    edt.ot_addr       = bfd_get_32(abfd, data + 36);

    adj = section->vma - extra->ImageBase + dataoff;

    fprintf(file, _("\nThe Export Tables (interpreted %s section contents)\n\n"), section->name);
    fprintf(file, _("Export Flags \t\t\t%lx\n"), (unsigned long)edt.export_flags);
    fprintf(file, _("Time/Date stamp \t\t%lx\n"), (unsigned long)edt.time_stamp);
    fprintf(file, _("Major/Minor \t\t\t%d/%d\n"), edt.major_ver, edt.minor_ver);
    fprintf(file, _("Name \t\t\t\t"));
    bfd_fprintf_vma(abfd, file, edt.name);

    if ((edt.name >= adj) && (edt.name < adj + datasize)) {
        size_t maxlen = datasize - (edt.name - adj);
        fprintf(file, " %.*s\n", (int)maxlen, data + edt.name - adj);
    } else {
        fprintf(file, "(outside .edata section)\n");
    }

    fprintf(file, _("Ordinal Base \t\t\t%ld\n"), edt.base);
    fprintf(file, _("Number in:\n"));
    fprintf(file, _("\tExport Address Table \t\t%08lx\n"), edt.num_functions);
    fprintf(file, _("\t[Name Pointer/Ordinal] Table\t%08lx\n"), edt.num_names);
    fprintf(file, _("Table Addresses\n"));
    fprintf(file, _("\tExport Address Table \t\t"));
    bfd_fprintf_vma(abfd, file, edt.eat_addr);
    fprintf(file, "\n");
    fprintf(file, _("\tName Pointer Table \t\t"));
    bfd_fprintf_vma(abfd, file, edt.npt_addr);
    fprintf(file, "\n");
    fprintf(file, _("\tOrdinal Table \t\t\t"));
    bfd_fprintf_vma(abfd, file, edt.ot_addr);
    fprintf(file, "\n");

    fprintf(file, _("\nExport Address Table -- Ordinal Base %ld\n"), edt.base);
    fprintf(file, "\t          Ordinal  Address  Type\n");

    if (edt.eat_addr < adj ||
        edt.num_functions == 0 ||
        edt.num_functions > ((datasize - (edt.eat_addr - adj)) / 4) ||
        ((size_t)edt.num_functions + 1) > (SIZE_MAX / 4) ||
        (edt.eat_addr - adj + (edt.num_functions + 1) * 4) > datasize) {
        fprintf(file, _("\tInvalid Export Address Table rva (0x%lx) or entry count (0x%lx)\n"),
                (long)edt.eat_addr, (long)edt.num_functions);
    } else {
        for (i = 0; i < edt.num_functions; ++i) {
            size_t eat_offset = edt.eat_addr + (i * 4);
            if (eat_offset < adj || eat_offset - adj + 4 > datasize)
                continue;
            bfd_vma eat_member = bfd_get_32(abfd, data + eat_offset - adj);
            if (eat_member == 0)
                continue;

            if (eat_member >= adj && eat_member < adj + datasize) {
                size_t maxlen = datasize - (eat_member - adj);
                fprintf(file, "\t[%4ld] +base[%4ld] %08lx %s -- %.*s\n",
                        (long)i,
                        (long)(i + edt.base),
                        (unsigned long)eat_member,
                        _("Forwarder RVA"),
                        (int)maxlen,
                        data + eat_member - adj);
            } else {
                fprintf(file, "\t[%4ld] +base[%4ld] %08lx %s\n",
                        (long)i,
                        (long)(i + edt.base),
                        (unsigned long)eat_member,
                        _("Export RVA"));
            }
        }
    }

    fprintf(file, _("\n[Ordinal/Name Pointer] Table -- Ordinal Base %ld\n"), edt.base);
    fprintf(file, "\t          Ordinal   Hint Name\n");

    if (edt.num_names == 0 ||
        edt.npt_addr < adj ||
        (edt.npt_addr - adj + edt.num_names * 4) > datasize ||
        (size_t)edt.num_names > SIZE_MAX / 4 ||
        (data + edt.npt_addr - adj) < data) {
        fprintf(file, _("\tInvalid Name Pointer Table rva (0x%lx) or entry count (0x%lx)\n"),
                (long)edt.npt_addr, (long)edt.num_names);
    } else if (edt.ot_addr < adj ||
               (edt.ot_addr - adj + edt.num_names * 2) > datasize ||
               data + edt.ot_addr - adj < data) {
        fprintf(file, _("\tInvalid Ordinal Table rva (0x%lx) or entry count (0x%lx)\n"),
                (long)edt.ot_addr, (long)edt.num_names);
    } else {
        for (i = 0; i < edt.num_names; ++i) {
            size_t npt_off = edt.npt_addr + (i * 4);
            size_t ot_off  = edt.ot_addr  + (i * 2);
            if (npt_off < adj ||
                npt_off - adj + 4 > datasize ||
                ot_off < adj ||
                ot_off - adj + 2 > datasize)
                continue;

            bfd_vma ord = bfd_get_16(abfd, data + ot_off - adj);
            bfd_vma name_ptr = bfd_get_32(abfd, data + npt_off - adj);

            if (name_ptr < adj || (name_ptr - adj) >= datasize) {
                fprintf(file, "\t[%4ld] +base[%4ld]  %04lx <corrupt offset: %lx>\n",
                        (long)ord, (long)(ord + edt.base), (long)i, (long)name_ptr);
            } else {
                char *name = (char *)data + name_ptr - adj;
                int len = (int)(((char *)data + datasize) - name);
                if (len < 0) len = 0;
                fprintf(file, "\t[%4ld] +base[%4ld]  %04lx %.*s\n",
                        (long)ord, (long)(ord + edt.base), (long)i, len, name);
            }
        }
    }

    free(data);
    return retval;
}


/* This really is architecture dependent.  On IA-64, a .pdata entry
   consists of three dwords containing relative virtual addresses that
   specify the start and end address of the code range the entry
   covers and the address of the corresponding unwind info data.

   On ARM and SH-4, a compressed PDATA structure is used :
   _IMAGE_CE_RUNTIME_FUNCTION_ENTRY, whereas MIPS is documented to use
   _IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY.
   See http://msdn2.microsoft.com/en-us/library/ms253988(VS.80).aspx .

   This is the version for uncompressed data.  */

static bool
pe_print_pdata(bfd *abfd, void *vfile)
{
#if defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined(COFF_WITH_peRiscV64)
#define PDATA_ROW_SIZE	(3 * 8)
#else
#define PDATA_ROW_SIZE	(5 * 4)
#endif
    FILE *file = (FILE *) vfile;
    bfd_byte *data = NULL;
    asection *section = bfd_get_section_by_name(abfd, ".pdata");
    bfd_size_type datasize = 0;
    bfd_size_type i;
    bfd_size_type start = 0, stop;
    int onaline = PDATA_ROW_SIZE;
    struct pei_section_tdata *psd = NULL;

    if (!section || (section->flags & SEC_HAS_CONTENTS) == 0)
        return true;

    if (!coff_section_data(abfd, section))
        return true;

    psd = pei_section_data(abfd, section);
    if (!psd)
        return true;

    stop = psd->virt_size;

    if ((stop % onaline) != 0) {
        fprintf(file,
                _("warning, .pdata section size (%ld) is not a multiple of %d\n"),
                (long)stop, onaline);
    }

    fprintf(file,
            _("\nThe Function Table (interpreted .pdata section contents)\n"));
#if defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined(COFF_WITH_peRiscV64)
    fprintf(file,
            _(" vma:\t\t\tBegin Address    End Address      Unwind Info\n"));
#else
    fprintf(file, _("\
 vma:\t\tBegin    End      EH       EH       PrologEnd  Exception\n\
     \t\tAddress  Address  Handler  Data     Address    Mask\n"));
#endif

    datasize = section->size;
    if (datasize == 0)
        return true;

    if (datasize < stop) {
        fprintf(file, _("Virtual size of .pdata section (%ld) larger than real size (%ld)\n"),
                (long) stop, (long) datasize);
        return false;
    }

    if (!bfd_malloc_and_get_section(abfd, section, &data)) {
        return false;
    }

    for (i = start; i + PDATA_ROW_SIZE <= stop; i += onaline) {
        bfd_vma begin_addr = 0;
        bfd_vma end_addr = 0;
        bfd_vma eh_handler = 0;
        bfd_vma eh_data = 0;
        bfd_vma prolog_end_addr = 0;
#if !defined(COFF_WITH_pep) || defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined(COFF_WITH_peRiscV64)
        int em_data = 0;
#endif

        begin_addr      = GET_PDATA_ENTRY(abfd, data + i);
        end_addr        = GET_PDATA_ENTRY(abfd, data + i + 4);
        eh_handler      = GET_PDATA_ENTRY(abfd, data + i + 8);
        eh_data         = GET_PDATA_ENTRY(abfd, data + i + 12);
        prolog_end_addr = GET_PDATA_ENTRY(abfd, data + i + 16);

        if (begin_addr == 0 && end_addr == 0 && eh_handler == 0
            && eh_data == 0 && prolog_end_addr == 0)
            break;

#if !defined(COFF_WITH_pep) || defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined(COFF_WITH_peRiscV64)
        em_data = ((eh_handler & 0x1) << 2) | (prolog_end_addr & 0x3);
#endif
        eh_handler &= ~(bfd_vma)0x3;
        prolog_end_addr &= ~(bfd_vma)0x3;

        fputc(' ', file);
        bfd_fprintf_vma(abfd, file, i + section->vma); fputc('\t', file);
        bfd_fprintf_vma(abfd, file, begin_addr); fputc(' ', file);
        bfd_fprintf_vma(abfd, file, end_addr); fputc(' ', file);
        bfd_fprintf_vma(abfd, file, eh_handler);
#if !defined(COFF_WITH_pep) || defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined(COFF_WITH_peRiscV64)
        fputc(' ', file);
        bfd_fprintf_vma(abfd, file, eh_data); fputc(' ', file);
        bfd_fprintf_vma(abfd, file, prolog_end_addr);
        fprintf(file, "   %x", em_data);
#endif
        fprintf(file, "\n");
    }

    free(data);
    return true;
#undef PDATA_ROW_SIZE
}

typedef struct sym_cache
{
  int	     symcount;
  asymbol ** syms;
} sym_cache;

static asymbol **slurp_symtab(bfd *abfd, sym_cache *psc)
{
    asymbol **sy = NULL;
    long storage;

    psc->symcount = 0;

    if ((bfd_get_file_flags(abfd) & HAS_SYMS) == 0)
        return NULL;

    storage = bfd_get_symtab_upper_bound(abfd);
    if (storage <= 0)
        return NULL;

    sy = (asymbol **)bfd_malloc((size_t)storage);
    if (sy == NULL)
        return NULL;

    psc->symcount = bfd_canonicalize_symtab(abfd, sy);
    if (psc->symcount < 0) {
        free(sy);
        psc->symcount = 0;
        return NULL;
    }
    return sy;
}

static const char *
my_symbol_for_address(bfd *abfd, bfd_vma func, sym_cache *psc)
{
    if (psc == NULL || abfd == NULL)
        return NULL;

    if (psc->syms == NULL)
        psc->syms = slurp_symtab(abfd, psc);

    if (psc->syms == NULL)
        return NULL;

    for (int i = 0; i < psc->symcount; i++) {
        if (psc->syms[i] == NULL || psc->syms[i]->section == NULL)
            continue;
        if ((psc->syms[i]->section->vma + psc->syms[i]->value) == func)
            return psc->syms[i]->name ? psc->syms[i]->name : NULL;
    }

    return NULL;
}

static void cleanup_syms(sym_cache *psc) {
    if (psc == NULL) {
        return;
    }
    psc->symcount = 0;
    free(psc->syms);
    psc->syms = NULL;
}

/* This is the version for "compressed" pdata.  */

bool
_bfd_XX_print_ce_compressed_pdata(bfd *abfd, void *vfile)
{
#define PDATA_ROW_SIZE (2 * 4)
    FILE *file = (FILE *)vfile;
    bfd_byte *data = NULL;
    asection *section = bfd_get_section_by_name(abfd, ".pdata");
    bfd_size_type datasize = 0;
    bfd_size_type i;
    bfd_size_type start = 0, stop;
    const int onaline = PDATA_ROW_SIZE;
    struct sym_cache cache = {0, 0};

    if (!section ||
        !(section->flags & SEC_HAS_CONTENTS) ||
        !coff_section_data(abfd, section) ||
        !pei_section_data(abfd, section))
        return true;

    stop = pei_section_data(abfd, section)->virt_size;
    if ((stop % onaline) != 0)
        fprintf(file,
                _("warning, .pdata section size (%ld) is not a multiple of %d\n"),
                (long)stop, onaline);

    fprintf(file, _("\nThe Function Table (interpreted .pdata section contents)\n"));
    fprintf(file, _("\
 vma:\t\tBegin    Prolog   Function Flags    Exception EH\n\
     \t\tAddress  Length   Length   32b exc  Handler   Data\n"));

    datasize = section->size;
    if (datasize == 0)
        return true;

    if (!bfd_malloc_and_get_section(abfd, section, &data)) {
        free(data);
        return false;
    }

    if (stop > datasize)
        stop = datasize;

    for (i = start; i + PDATA_ROW_SIZE <= stop; i += onaline) {
        bfd_vma begin_addr = GET_PDATA_ENTRY(abfd, data + i);
        bfd_vma other_data = GET_PDATA_ENTRY(abfd, data + i + 4);

        if (begin_addr == 0 && other_data == 0)
            break;

        bfd_vma prolog_length = (other_data & 0x000000FF);
        bfd_vma function_length = (other_data & 0x3FFFFF00) >> 8;
        int flag32bit = (int)((other_data & 0x40000000) >> 30);
        int exception_flag = (int)((other_data & 0x80000000) >> 31);

        fputc(' ', file);
        bfd_fprintf_vma(abfd, file, i + section->vma); fputc('\t', file);
        bfd_fprintf_vma(abfd, file, begin_addr); fputc(' ', file);
        bfd_fprintf_vma(abfd, file, prolog_length); fputc(' ', file);
        bfd_fprintf_vma(abfd, file, function_length); fputc(' ', file);
        fprintf(file, "%2d  %2d   ", flag32bit, exception_flag);

        asection *tsection = bfd_get_section_by_name(abfd, ".text");
        if (tsection && coff_section_data(abfd, tsection) && pei_section_data(abfd, tsection)) {
            bfd_vma eh_off = (begin_addr >= 8 ? (begin_addr - 8) : 0) - tsection->vma;
            bfd_byte *tdata = (bfd_byte *)bfd_malloc(8);
            if (tdata) {
                if (bfd_get_section_contents(abfd, tsection, tdata, eh_off, 8)) {
                    bfd_vma eh = bfd_get_32(abfd, tdata);
                    bfd_vma eh_data = bfd_get_32(abfd, tdata + 4);
                    fprintf(file, "%08x  ", (unsigned int)eh);
                    fprintf(file, "%08x", (unsigned int)eh_data);
                    if (eh != 0) {
                        const char *s = my_symbol_for_address(abfd, eh, &cache);
                        if (s)
                            fprintf(file, " (%s) ", s);
                    }
                }
                free(tdata);
            }
        }
        fprintf(file, "\n");
    }

    free(data);
    cleanup_syms(&cache);

    return true;
#undef PDATA_ROW_SIZE
}


#define IMAGE_REL_BASED_HIGHADJ 4
static const char * const tbl[] =
{
  "ABSOLUTE",
  "HIGH",
  "LOW",
  "HIGHLOW",
  "HIGHADJ",
  "MIPS_JMPADDR",
  "SECTION",
  "REL32",
  "RESERVED1",
  "MIPS_JMPADDR16",
  "DIR64",
  "HIGH3ADJ",
  "UNKNOWN",   /* MUST be last.  */
};

static bool
pe_print_reloc(bfd *abfd, void *vfile)
{
    FILE *file = (FILE *)vfile;
    bfd_byte *data = NULL;
    asection *section = bfd_get_section_by_name(abfd, ".reloc");
    bfd_byte *p;
    bfd_byte *end;

    if (!section || section->size == 0 || (section->flags & SEC_HAS_CONTENTS) == 0)
        return true;

    fprintf(file, _("\n\nPE File Base Relocations (interpreted .reloc section contents)\n"));

    if (!bfd_malloc_and_get_section(abfd, section, &data) || !data)
        return false;

    p = data;
    end = data + section->size;

    while (p + 8 <= end)
    {
        bfd_vma virtual_address;
        unsigned long size, number;
        bfd_byte *chunk_end;
        int j = 0;

        virtual_address = bfd_get_32(abfd, p);
        size = bfd_get_32(abfd, p + 4);
        if (size == 0)
            break;

        number = (size > 8) ? ((size - 8) / 2) : 0;

        fprintf(file, _("\nVirtual Address: %08lx Chunk size %lu (0x%lx) Number of fixups %lu\n"),
                (unsigned long)virtual_address, size, size, number);

        p += 8;

        if (size > (unsigned long)(end - (p - 8)))  /* Prevent chunk_end wrap */
            chunk_end = end;
        else
            chunk_end = p - 8 + size;

        while (p + 2 <= chunk_end)
        {
            unsigned short e = bfd_get_16(abfd, p);
            unsigned int t = (e & 0xF000) >> 12;
            int off = e & 0x0FFF;
            unsigned int tmax = sizeof(tbl) / sizeof(tbl[0]);

            if (t >= tmax)
                t = tmax - 1;

            fprintf(file, _("\treloc %4d offset %4x [%4lx] %s"),
                    j, off, (unsigned long)(off + virtual_address), tbl[t]);

            p += 2;
            j++;

            if (t == IMAGE_REL_BASED_HIGHADJ && p + 2 <= chunk_end)
            {
                fprintf(file, " (%4x)", (unsigned int) bfd_get_16(abfd, p));
                p += 2;
                j++;
            }

            fprintf(file, "\n");
        }
        /* Make sure we don't get stuck if there is some malformed input. */
        if (p < chunk_end)
            p = chunk_end;
    }

    free(data);
    return true;
}

/* A data structure describing the regions of a .rsrc section.
   Some fields are filled in as the section is parsed.  */

typedef struct rsrc_regions
{
  bfd_byte * section_start;
  bfd_byte * section_end;
  bfd_byte * strings_start;
  bfd_byte * resource_start;
} rsrc_regions;

static bfd_byte *
rsrc_print_resource_directory (FILE * , bfd *, unsigned int, bfd_byte *,
			       rsrc_regions *, bfd_vma);

/* Print the resource entry at DATA, with the text indented by INDENT.
   Recusively calls rsrc_print_resource_directory to print the contents
   of directory entries.
   Returns the address of the end of the data associated with the entry
   or section_end + 1 upon failure.  */

static bfd_byte *
rsrc_print_resource_entries(FILE *file,
                           bfd *abfd,
                           unsigned int indent,
                           bool is_name,
                           bfd_byte *data,
                           rsrc_regions *regions,
                           bfd_vma rva_bias)
{
    unsigned long entry, addr, size;
    bfd_byte *leaf;

    if (!file || !abfd || !data || !regions || regions->section_start == NULL || regions->section_end == NULL)
        return NULL;

    if (data + 8 >= regions->section_end)
        return regions->section_end + 1;

    fprintf(file, _("%03x %*.s Entry: "), (int)(data - regions->section_start), indent, " ");

    entry = (unsigned long) bfd_get_32(abfd, data);

    if (is_name) {
        bfd_byte *name;
        if (HighBitSet(entry))
            name = regions->section_start + WithoutHighBit(entry);
        else
            name = regions->section_start + entry - rva_bias;

        if (name + 2 < regions->section_end && name > regions->section_start) {
            unsigned int len;
            if (regions->strings_start == NULL)
                regions->strings_start = name;

            len = bfd_get_16(abfd, name);
            fprintf(file, _("name: [val: %08lx len %d]: "), entry, len);

            if (name + 2 + (size_t)len * 2 < regions->section_end) {
                unsigned int i;
                for (i = 0; i < len; ++i) {
                    char c;
                    name += 2;
                    c = *name;
                    if (c > 0 && c < 32)
                        fprintf(file, "^%c", c + 64);
                    else
                        fprintf(file, "%.1s", name);
                }
            } else {
                fprintf(file, _("<corrupt string length: %#x>\n"), len);
                return regions->section_end + 1;
            }
        } else {
            fprintf(file, _("<corrupt string offset: %#lx>\n"), entry);
            return regions->section_end + 1;
        }
    } else {
        fprintf(file, _("ID: %#08lx"), entry);
    }

    entry = (unsigned long) bfd_get_32(abfd, data + 4);
    fprintf(file, _(", Value: %#08lx\n"), entry);

    if (HighBitSet(entry)) {
        bfd_byte *nextdata = regions->section_start + WithoutHighBit(entry);
        if (nextdata <= regions->section_start || nextdata > regions->section_end)
            return regions->section_end + 1;
        return rsrc_print_resource_directory(file, abfd, indent + 1, nextdata, regions, rva_bias);
    }

    leaf = regions->section_start + entry;
    if (leaf + 16 >= regions->section_end || leaf < regions->section_start)
        return regions->section_end + 1;

    addr = (unsigned long) bfd_get_32(abfd, leaf);
    size = (unsigned long) bfd_get_32(abfd, leaf + 4);

    fprintf(file, _("%03x %*.s  Leaf: Addr: %#08lx, Size: %#08lx, Codepage: %d\n"),
            (int)(entry), indent, " ", addr, size, (int) bfd_get_32(abfd, leaf + 8));

    if (bfd_get_32(abfd, leaf + 12) != 0 ||
        (regions->section_start + (addr - rva_bias) + size > regions->section_end))
        return regions->section_end + 1;

    if (regions->resource_start == NULL)
        regions->resource_start = regions->section_start + (addr - rva_bias);

    return regions->section_start + (addr - rva_bias) + size;
}

#define max(a,b) ((a) > (b) ? (a) : (b))
#define min(a,b) ((a) < (b) ? (a) : (b))

static bfd_byte *
rsrc_print_resource_directory(FILE *file,
                             bfd *abfd,
                             unsigned int indent,
                             bfd_byte *data,
                             rsrc_regions *regions,
                             bfd_vma rva_bias)
{
    unsigned int num_names, num_ids;
    bfd_byte *highest_data;

    if (data + 16 >= regions->section_end)
        return regions->section_end + 1;

    highest_data = data;

    fprintf(file, "%03x %*.s ", (int)(data - regions->section_start), indent, " ");
    if (indent == 0)
        fprintf(file, "Type");
    else if (indent == 2)
        fprintf(file, "Name");
    else if (indent == 4)
        fprintf(file, "Language");
    else {
        fprintf(file, _("<unknown directory type: %d>\n"), indent);
        return regions->section_end + 1;
    }

    num_names = (unsigned int) bfd_get_16(abfd, data + 12);
    num_ids   = (unsigned int) bfd_get_16(abfd, data + 14);

    fprintf(file, _(" Table: Char: %d, Time: %08lx, Ver: %d/%d, Num Names: %d, IDs: %d\n"),
            (int) bfd_get_32(abfd, data),
            (long) bfd_get_32(abfd, data + 4),
            (int) bfd_get_16(abfd, data + 8),
            (int) bfd_get_16(abfd, data + 10),
            (int) num_names,
            (int) num_ids);
    data += 16;

    for (; num_names > 0; --num_names) {
        bfd_byte *entry_end;
        entry_end = rsrc_print_resource_entries(file, abfd, indent + 1, true, data, regions, rva_bias);
        data += 8;
        if (entry_end > highest_data)
            highest_data = entry_end;
        if (entry_end >= regions->section_end)
            return entry_end;
    }

    for (; num_ids > 0; --num_ids) {
        bfd_byte *entry_end;
        entry_end = rsrc_print_resource_entries(file, abfd, indent + 1, false, data, regions, rva_bias);
        data += 8;
        if (entry_end > highest_data)
            highest_data = entry_end;
        if (entry_end >= regions->section_end)
            return entry_end;
    }

    return (highest_data > data ? highest_data : data);
}

/* Display the contents of a .rsrc section.  We do not try to
   reproduce the resources, windres does that.  Instead we dump
   the tables in a human readable format.  */

static bool rsrc_print_section(bfd *abfd, void *vfile) {
    pe_data_type *pe = pe_data(abfd);
    if (pe == NULL)
        return true;

    asection *section = bfd_get_section_by_name(abfd, ".rsrc");
    if (section == NULL || !(section->flags & SEC_HAS_CONTENTS) || section->size == 0)
        return true;

    bfd_size_type datasize = section->size;
    bfd_vma rva_bias = section->vma - pe->pe_opthdr.ImageBase;
    bfd_byte *data = NULL;

    if (!bfd_malloc_and_get_section(abfd, section, &data)) {
        free(data);
        return false;
    }

    rsrc_regions regions = {0};
    regions.section_start = data;
    regions.section_end = data + datasize;

    FILE *file = (FILE *)vfile;
    fflush(file);
    fprintf(file, "\nThe .rsrc Resource Directory section:\n");

    bfd_byte *cur = data;
    while (cur < regions.section_end) {
        bfd_byte *prev = cur;
        cur = rsrc_print_resource_directory(file, abfd, 0, cur, &regions, rva_bias);

        if (cur == regions.section_end + 1) {
            fprintf(file, _("Corrupt .rsrc section detected!\n"));
            break;
        }

        int align = (1 << section->alignment_power) - 1;
        cur = (bfd_byte *)(((ptrdiff_t)(cur + align)) & ~align);
        rva_bias += cur - prev;

        if (cur == (regions.section_end - 4)) {
            cur = regions.section_end;
        } else if (cur < regions.section_end) {
            bfd_byte *pad = cur;
            while (++pad < regions.section_end) {
                if (*pad != 0)
                    break;
            }
            if (pad < regions.section_end) {
                fprintf(file, _("\nWARNING: Extra data in .rsrc section - it will be ignored by Windows:\n"));
            }
            cur = pad;
        }
    }

    if (regions.strings_start != NULL)
        fprintf(file, _(" String table starts at offset: %#03x\n"), (int)(regions.strings_start - regions.section_start));
    if (regions.resource_start != NULL)
        fprintf(file, _(" Resources start at offset: %#03x\n"), (int)(regions.resource_start - regions.section_start));

    free(data);
    return true;
}

#define IMAGE_NUMBEROF_DEBUG_TYPES 17

static char * debug_type_names[IMAGE_NUMBEROF_DEBUG_TYPES] =
{
  "Unknown",
  "COFF",
  "CodeView",
  "FPO",
  "Misc",
  "Exception",
  "Fixup",
  "OMAP-to-SRC",
  "OMAP-from-SRC",
  "Borland",
  "Reserved",
  "CLSID",
  "Feature",
  "CoffGrp",
  "ILTCG",
  "MPX",
  "Repro",
};

static bool
pe_print_debugdata(bfd *abfd, void *vfile)
{
  FILE *file = (FILE *)vfile;
  pe_data_type *pe = pe_data(abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
  asection *section = NULL;
  bfd_byte *data = NULL;
  bfd_size_type dataoff;
  unsigned int i, j;
  bfd_vma addr = extra->DataDirectory[PE_DEBUG_DATA].VirtualAddress;
  bfd_size_type size = extra->DataDirectory[PE_DEBUG_DATA].Size;

  if (size == 0)
    return true;

  addr += extra->ImageBase;

  for (section = abfd->sections; section != NULL; section = section->next) {
    if ((addr >= section->vma) && (addr < (section->vma + section->size)))
      break;
  }

  if (section == NULL) {
    fprintf(file, _("\nThere is a debug directory, but the section containing it could not be found\n"));
    return true;
  }

  if (!(section->flags & SEC_HAS_CONTENTS)) {
    fprintf(file, _("\nThere is a debug directory in %s, but that section has no contents\n"), section->name);
    return true;
  }

  if (section->size < size) {
    fprintf(file, _("\nError: section %s contains the debug data starting address but it is too small\n"), section->name);
    return false;
  }

  fprintf(file, _("\nThere is a debug directory in %s at 0x%lx\n\n"), section->name, (unsigned long)addr);

  dataoff = addr - section->vma;

  if (size > (section->size - dataoff)) {
    fprintf(file, _("The debug data size field in the data directory is too big for the section"));
    return false;
  }

  fprintf(file, _("Type                Size     Rva      Offset\n"));

  if (!bfd_malloc_and_get_section(abfd, section, &data)) {
    return false;
  }

  for (i = 0; i + sizeof(struct external_IMAGE_DEBUG_DIRECTORY) <= size; i += sizeof(struct external_IMAGE_DEBUG_DIRECTORY)) {
    const char *type_name;
    struct external_IMAGE_DEBUG_DIRECTORY *ext =
      (struct external_IMAGE_DEBUG_DIRECTORY *)(data + dataoff + i);
    struct internal_IMAGE_DEBUG_DIRECTORY idd;

    _bfd_XXi_swap_debugdir_in(abfd, ext, &idd);

    type_name = (idd.Type < IMAGE_NUMBEROF_DEBUG_TYPES) ? debug_type_names[idd.Type] : debug_type_names[0];

    fprintf(file, " %2ld  %14s %08lx %08lx %08lx\n",
            idd.Type, type_name, idd.SizeOfData,
            idd.AddressOfRawData, idd.PointerToRawData);

    if (idd.Type == PE_IMAGE_DEBUG_TYPE_CODEVIEW) {
      char signature[CV_INFO_SIGNATURE_LENGTH * 2 + 1] = {0};
      char buffer[256 + 1] ATTRIBUTE_ALIGNED_ALIGNOF(CODEVIEW_INFO);
      char *pdb = NULL;
      CODEVIEW_INFO *cvinfo = (CODEVIEW_INFO *)buffer;

      if (!_bfd_XXi_slurp_codeview_record(abfd, (file_ptr)idd.PointerToRawData,
            idd.SizeOfData, cvinfo, &pdb)) {
        if (pdb)
          free(pdb);
        continue;
      }

      for (j = 0; j < cvinfo->SignatureLength && (j * 2 + 1) < sizeof(signature); j++)
        sprintf(&signature[j * 2], "%02x", cvinfo->Signature[j] & 0xff);

      fprintf(file, _("(format %c%c%c%c signature %s age %ld pdb %s)\n"),
               buffer[0], buffer[1], buffer[2], buffer[3],
               signature, cvinfo->Age, (pdb && pdb[0]) ? pdb : "(none)");

      if (pdb)
        free(pdb);
    }
  }

  free(data);

  if (size % sizeof(struct external_IMAGE_DEBUG_DIRECTORY) != 0) {
    fprintf(file,
         _("The debug directory size is not a multiple of the debug directory entry size\n"));
  }

  return true;
}

static bool pe_is_repro(bfd *abfd) {
    pe_data_type *pe = pe_data(abfd);
    struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
    asection *section = NULL;
    bfd_byte *data = NULL;
    bfd_size_type dataoff;
    unsigned int i;
    bfd_vma addr;
    bfd_size_type size;

    if (!pe || !extra)
        return false;

    if (PE_DEBUG_DATA >= ARRAY_SIZE(extra->DataDirectory))
        return false;

    addr = extra->DataDirectory[PE_DEBUG_DATA].VirtualAddress;
    size = extra->DataDirectory[PE_DEBUG_DATA].Size;

    if (size == 0)
        return false;

    addr += extra->ImageBase;

    for (section = abfd->sections; section != NULL; section = section->next) {
        if (addr >= section->vma && addr < (section->vma + section->size))
            break;
    }

    if (!section ||
        !(section->flags & SEC_HAS_CONTENTS) ||
        section->size < size)
        return false;

    dataoff = addr - section->vma;

    if (size > section->size || dataoff > section->size || size > section->size - dataoff)
        return false;

    if (!bfd_malloc_and_get_section(abfd, section, &data))
        return false;

    for (i = 0; i + sizeof(struct external_IMAGE_DEBUG_DIRECTORY) <= size;
         i += sizeof(struct external_IMAGE_DEBUG_DIRECTORY)) {
        struct external_IMAGE_DEBUG_DIRECTORY *ext =
            (struct external_IMAGE_DEBUG_DIRECTORY *)(data + dataoff + i);
        struct internal_IMAGE_DEBUG_DIRECTORY idd;

        _bfd_XXi_swap_debugdir_in(abfd, ext, &idd);

        if (idd.Type == PE_IMAGE_DEBUG_TYPE_REPRO) {
            free(data);
            return true;
        }
    }

    free(data);
    return false;
}

/* Print out the program headers.  */

bool
_bfd_XX_print_private_bfd_data_common(bfd *abfd, void *vfile)
{
    if (!abfd || !vfile)
        return false;

    FILE *file = (FILE *)vfile;
    int j;
    pe_data_type *pe = pe_data(abfd);
    if (!pe)
        return false;
    struct internal_extra_pe_aouthdr *i = &pe->pe_opthdr;
    const char *subsystem_name = NULL;
    const char *name = NULL;

    if (!file || !i)
        return false;

    if (fprintf(file, _("\nCharacteristics 0x%x\n"), pe->real_flags) < 0)
        return false;

#define PF(x, y) if (pe->real_flags & (x)) if (fprintf(file, "\t%s\n", (y)) < 0) return false;
    PF(IMAGE_FILE_RELOCS_STRIPPED, "relocations stripped");
    PF(IMAGE_FILE_EXECUTABLE_IMAGE, "executable");
    PF(IMAGE_FILE_LINE_NUMS_STRIPPED, "line numbers stripped");
    PF(IMAGE_FILE_LOCAL_SYMS_STRIPPED, "symbols stripped");
    PF(IMAGE_FILE_LARGE_ADDRESS_AWARE, "large address aware");
    PF(IMAGE_FILE_BYTES_REVERSED_LO, "little endian");
    PF(IMAGE_FILE_32BIT_MACHINE, "32 bit words");
    PF(IMAGE_FILE_DEBUG_STRIPPED, "debugging information removed");
    PF(IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "copy to swap file if on removable media");
    PF(IMAGE_FILE_NET_RUN_FROM_SWAP, "copy to swap file if on network media");
    PF(IMAGE_FILE_SYSTEM, "system file");
    PF(IMAGE_FILE_DLL, "DLL");
    PF(IMAGE_FILE_UP_SYSTEM_ONLY, "run only on uniprocessor machine");
    PF(IMAGE_FILE_BYTES_REVERSED_HI, "big endian");
#undef PF

    if (pe_is_repro(abfd)) {
        if (fprintf(file, "\nTime/Date\t\t%08lx", pe->coff.timestamp) < 0 ||
            fprintf(file, "\t(This is a reproducible build file hash, not a timestamp)\n") < 0)
            return false;
    } else {
        time_t t = pe->coff.timestamp;
        char *timestr = ctime(&t);
        if (timestr) {
            if (fprintf(file, "\nTime/Date\t\t%s", timestr) < 0)
                return false;
        } else {
            if (fprintf(file, "\nTime/Date\t\t[ctime error]\n") < 0)
                return false;
        }
    }

#ifndef IMAGE_NT_OPTIONAL_HDR_MAGIC
# define IMAGE_NT_OPTIONAL_HDR_MAGIC 0x10b
#endif
#ifndef IMAGE_NT_OPTIONAL_HDR64_MAGIC
# define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#endif
#ifndef IMAGE_NT_OPTIONAL_HDRROM_MAGIC
# define IMAGE_NT_OPTIONAL_HDRROM_MAGIC 0x107
#endif

    switch (i->Magic) {
        case IMAGE_NT_OPTIONAL_HDR_MAGIC: name = "PE32"; break;
        case IMAGE_NT_OPTIONAL_HDR64_MAGIC: name = "PE32+"; break;
        case IMAGE_NT_OPTIONAL_HDRROM_MAGIC: name = "ROM"; break;
        default: name = NULL; break;
    }
    if (fprintf(file, "Magic\t\t\t%04x", i->Magic) < 0)
        return false;
    if (name && fprintf(file, "\t(%s)", name) < 0)
        return false;
    if (fprintf(file, "\nMajorLinkerVersion\t%d\n", i->MajorLinkerVersion) < 0)
        return false;
    if (fprintf(file, "MinorLinkerVersion\t%d\n", i->MinorLinkerVersion) < 0)
        return false;
    if (fprintf(file, "SizeOfCode\t\t") < 0)
        return false;
    bfd_fprintf_vma(abfd, file, i->SizeOfCode);
    if (fprintf(file, "\nSizeOfInitializedData\t") < 0)
        return false;
    bfd_fprintf_vma(abfd, file, i->SizeOfInitializedData);
    if (fprintf(file, "\nSizeOfUninitializedData\t") < 0)
        return false;
    bfd_fprintf_vma(abfd, file, i->SizeOfUninitializedData);
    if (fprintf(file, "\nAddressOfEntryPoint\t") < 0)
        return false;
    bfd_fprintf_vma(abfd, file, i->AddressOfEntryPoint);
    if (fprintf(file, "\nBaseOfCode\t\t") < 0)
        return false;
    bfd_fprintf_vma(abfd, file, i->BaseOfCode);
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
    if (fprintf(file, "\nBaseOfData\t\t") < 0)
        return false;
    bfd_fprintf_vma(abfd, file, i->BaseOfData);
#endif

    if (fprintf(file, "\nImageBase\t\t") < 0)
        return false;
    bfd_fprintf_vma(abfd, file, i->ImageBase);
    if (fprintf(file, "\nSectionAlignment\t%08x\n", i->SectionAlignment) < 0)
        return false;
    if (fprintf(file, "FileAlignment\t\t%08x\n", i->FileAlignment) < 0)
        return false;
    if (fprintf(file, "MajorOSystemVersion\t%d\n", i->MajorOperatingSystemVersion) < 0)
        return false;
    if (fprintf(file, "MinorOSystemVersion\t%d\n", i->MinorOperatingSystemVersion) < 0)
        return false;
    if (fprintf(file, "MajorImageVersion\t%d\n", i->MajorImageVersion) < 0)
        return false;
    if (fprintf(file, "MinorImageVersion\t%d\n", i->MinorImageVersion) < 0)
        return false;
    if (fprintf(file, "MajorSubsystemVersion\t%d\n", i->MajorSubsystemVersion) < 0)
        return false;
    if (fprintf(file, "MinorSubsystemVersion\t%d\n", i->MinorSubsystemVersion) < 0)
        return false;
    if (fprintf(file, "Win32Version\t\t%08x\n", i->Win32Version) < 0)
        return false;
    if (fprintf(file, "SizeOfImage\t\t%08x\n", i->SizeOfImage) < 0)
        return false;
    if (fprintf(file, "SizeOfHeaders\t\t%08x\n", i->SizeOfHeaders) < 0)
        return false;
    if (fprintf(file, "CheckSum\t\t%08x\n", i->CheckSum) < 0)
        return false;

    switch (i->Subsystem) {
        case IMAGE_SUBSYSTEM_UNKNOWN: subsystem_name = "unspecified"; break;
        case IMAGE_SUBSYSTEM_NATIVE: subsystem_name = "NT native"; break;
        case IMAGE_SUBSYSTEM_WINDOWS_GUI: subsystem_name = "Windows GUI"; break;
        case IMAGE_SUBSYSTEM_WINDOWS_CUI: subsystem_name = "Windows CUI"; break;
        case IMAGE_SUBSYSTEM_POSIX_CUI: subsystem_name = "POSIX CUI"; break;
        case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: subsystem_name = "Wince CUI"; break;
        case IMAGE_SUBSYSTEM_EFI_APPLICATION: subsystem_name = "EFI application"; break;
        case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: subsystem_name = "EFI boot service driver"; break;
        case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: subsystem_name = "EFI runtime driver"; break;
        case IMAGE_SUBSYSTEM_SAL_RUNTIME_DRIVER: subsystem_name = "SAL runtime driver"; break;
        case IMAGE_SUBSYSTEM_XBOX: subsystem_name = "XBOX"; break;
        default: subsystem_name = NULL; break;
    }
    if (fprintf(file, "Subsystem\t\t%08x", i->Subsystem) < 0)
        return false;
    if (subsystem_name && fprintf(file, "\t(%s)", subsystem_name) < 0)
        return false;
    if (fprintf(file, "\nDllCharacteristics\t%08x\n", i->DllCharacteristics) < 0)
        return false;

    if (i->DllCharacteristics) {
        unsigned short dllch = i->DllCharacteristics;
        const char *indent = "\t\t\t\t\t";
        struct {
            unsigned short flag;
            const char *desc;
        } dll_flags[] = {
            { IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA, "HIGH_ENTROPY_VA" },
            { IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE, "DYNAMIC_BASE" },
            { IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY, "FORCE_INTEGRITY" },
            { IMAGE_DLL_CHARACTERISTICS_NX_COMPAT, "NX_COMPAT" },
            { IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, "NO_ISOLATION" },
            { IMAGE_DLLCHARACTERISTICS_NO_SEH, "NO_SEH" },
            { IMAGE_DLLCHARACTERISTICS_NO_BIND, "NO_BIND" },
            { IMAGE_DLLCHARACTERISTICS_APPCONTAINER, "APPCONTAINER" },
            { IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, "WDM_DRIVER" },
            { IMAGE_DLLCHARACTERISTICS_GUARD_CF, "GUARD_CF" },
            { IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, "TERMINAL_SERVICE_AWARE" }
        };
        size_t k;
        for (k = 0; k < sizeof(dll_flags) / sizeof(dll_flags[0]); ++k) {
            if (dllch & dll_flags[k].flag) {
                if (fprintf(file, "%s%s\n", indent, dll_flags[k].desc) < 0)
                    return false;
            }
        }
    }

    if (fprintf(file, "SizeOfStackReserve\t") < 0)
        return false;
    bfd_fprintf_vma(abfd, file, i->SizeOfStackReserve);
    if (fprintf(file, "\nSizeOfStackCommit\t") < 0)
        return false;
    bfd_fprintf_vma(abfd, file, i->SizeOfStackCommit);
    if (fprintf(file, "\nSizeOfHeapReserve\t") < 0)
        return false;
    bfd_fprintf_vma(abfd, file, i->SizeOfHeapReserve);
    if (fprintf(file, "\nSizeOfHeapCommit\t") < 0)
        return false;
    bfd_fprintf_vma(abfd, file, i->SizeOfHeapCommit);
    if (fprintf(file, "\nLoaderFlags\t\t%08lx\n", (unsigned long)i->LoaderFlags) < 0)
        return false;
    if (fprintf(file, "NumberOfRvaAndSizes\t%08lx\n", (unsigned long)i->NumberOfRvaAndSizes) < 0)
        return false;

    if (fprintf(file, "\nThe Data Directory\n") < 0)
        return false;
    for (j = 0; j < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; j++) {
        if (fprintf(file, "Entry %1x ", j) < 0)
            return false;
        bfd_fprintf_vma(abfd, file, i->DataDirectory[j].VirtualAddress);
        if (fprintf(file, " %08lx ", (unsigned long)i->DataDirectory[j].Size) < 0)
            return false;
        if (fprintf(file, "%s\n", dir_names[j]) < 0)
            return false;
    }

    pe_print_idata(abfd, vfile);
    pe_print_edata(abfd, vfile);
    if (bfd_coff_have_print_pdata(abfd))
        bfd_coff_print_pdata(abfd, vfile);
    else
        pe_print_pdata(abfd, vfile);
    pe_print_reloc(abfd, vfile);
    pe_print_debugdata(abfd, file);

    rsrc_print_section(abfd, vfile);

    return true;
}

static bool is_vma_in_section(bfd *abfd, asection *sect, void *obj) {
    if (!sect || !obj) {
        return false;
    }
    bfd_vma addr = *(const bfd_vma *)obj;
    if (sect->size == 0) {
        return false;
    }
    if (addr < sect->vma) {
        return false;
    }
    if (addr - sect->vma >= sect->size) {
        return false;
    }
    return true;
}

static asection *
find_section_by_vma(bfd *abfd, bfd_vma addr)
{
    if (abfd == NULL)
        return NULL;

    return bfd_sections_find_if(abfd, is_vma_in_section, (void *)&addr);
}

/* Copy any private info we understand from the input bfd
   to the output bfd.  */

bool _bfd_XX_bfd_copy_private_bfd_data_common(bfd *ibfd, bfd *obfd)
{
  pe_data_type *ipe, *ope;
  bfd_size_type size;

  if (ibfd == NULL || obfd == NULL)
    return false;

  if (ibfd->xvec == NULL || obfd->xvec == NULL)
    return false;

  if (ibfd->xvec->flavour != bfd_target_coff_flavour ||
      obfd->xvec->flavour != bfd_target_coff_flavour)
    return true;

  ipe = pe_data(ibfd);
  ope = pe_data(obfd);

  if (ipe == NULL || ope == NULL)
    return false;

  ope->dll = ipe->dll;

  if (obfd->xvec != ibfd->xvec)
    ope->pe_opthdr.Subsystem = IMAGE_SUBSYSTEM_UNKNOWN;

  if (!ope->has_reloc_section) {
    ope->pe_opthdr.DataDirectory[PE_BASE_RELOCATION_TABLE].VirtualAddress = 0;
    ope->pe_opthdr.DataDirectory[PE_BASE_RELOCATION_TABLE].Size = 0;
  }

  if (!ipe->has_reloc_section &&
      !(ipe->real_flags & IMAGE_FILE_RELOCS_STRIPPED))
    ope->dont_strip_reloc = 1;

  memcpy(ope->dos_message, ipe->dos_message, sizeof(ope->dos_message));

  size = ope->pe_opthdr.DataDirectory[PE_DEBUG_DATA].Size;
  if (size != 0) {
    bfd_vma addr = ope->pe_opthdr.DataDirectory[PE_DEBUG_DATA].VirtualAddress +
                   ope->pe_opthdr.ImageBase;
    bfd_vma last = addr + size - 1;
    asection *section = find_section_by_vma(obfd, last);

    if (section != NULL) {
      bfd_byte *data = NULL;
      bfd_vma dataoff = addr - section->vma;
      if (addr < section->vma ||
          section->size < dataoff ||
          section->size - dataoff < size)
      {
        _bfd_error_handler(
          _("%pB: Data Directory (%lx bytes at %" PRIx64 ") "
            "extends across section boundary at %" PRIx64),
          obfd,
          ope->pe_opthdr.DataDirectory[PE_DEBUG_DATA].Size,
          (uint64_t) addr,
          (uint64_t) section->vma
        );
        return false;
      }

      if ((section->flags & SEC_HAS_CONTENTS) &&
          bfd_malloc_and_get_section(obfd, section, &data) && data != NULL)
      {
        unsigned int i, num_dirs;
        struct external_IMAGE_DEBUG_DIRECTORY *dd =
          (struct external_IMAGE_DEBUG_DIRECTORY *)(data + dataoff);

        num_dirs = size / sizeof(struct external_IMAGE_DEBUG_DIRECTORY);

        for (i = 0; i < num_dirs; i++) {
          asection *ddsection;
          struct external_IMAGE_DEBUG_DIRECTORY *edd = &dd[i];
          struct internal_IMAGE_DEBUG_DIRECTORY idd;
          bfd_vma idd_vma;

          _bfd_XXi_swap_debugdir_in(obfd, edd, &idd);

          if (idd.AddressOfRawData == 0)
            continue;

          idd_vma = idd.AddressOfRawData + ope->pe_opthdr.ImageBase;
          ddsection = find_section_by_vma(obfd, idd_vma);
          if (ddsection == NULL)
            continue;

          idd.PointerToRawData = ddsection->filepos + idd_vma - ddsection->vma;
          _bfd_XXi_swap_debugdir_out(obfd, &idd, edd);
        }

        if (!bfd_set_section_contents(obfd, section, data, 0, section->size)) {
          _bfd_error_handler(
            _("failed to update file offsets in debug directory")
          );
          free(data);
          return false;
        }
        free(data);
      } else {
        _bfd_error_handler(
          _("%pB: failed to read debug data section"), obfd
        );
        if (data)
          free(data);
        return false;
      }
    }
  }

  return true;
}


/* Copy private section data.  */

bool _bfd_XX_bfd_copy_private_section_data(bfd *ibfd,
                                           asection *isec,
                                           bfd *obfd,
                                           asection *osec,
                                           struct bfd_link_info *link_info) {
    if (link_info != NULL ||
        bfd_get_flavour(ibfd) != bfd_target_coff_flavour ||
        bfd_get_flavour(obfd) != bfd_target_coff_flavour) {
        return true;
    }

    struct coff_section_tdata *icoff = coff_section_data(ibfd, isec);
    struct pei_section_tdata *ipei = pei_section_data(ibfd, isec);

    if (icoff && ipei) {
        struct coff_section_tdata *ocoff = coff_section_data(obfd, osec);
        if (!ocoff) {
            osec->used_by_bfd = bfd_zalloc(obfd, sizeof(struct coff_section_tdata));
            if (!osec->used_by_bfd)
                return false;
            ocoff = coff_section_data(obfd, osec);
        }
        if (!pei_section_data(obfd, osec)) {
            ocoff->tdata = bfd_zalloc(obfd, sizeof(struct pei_section_tdata));
            if (!ocoff->tdata)
                return false;
        }

        struct pei_section_tdata *opei = pei_section_data(obfd, osec);
        opei->virt_size = ipei->virt_size;
        opei->pe_flags = ipei->pe_flags;
    }
    return true;
}

void _bfd_XX_get_symbol_info(bfd *abfd, asymbol *symbol, symbol_info *ret) {
    if (!abfd || !symbol || !ret) {
        return;
    }
    coff_get_symbol_info(abfd, symbol, ret);
}

#if !defined(COFF_WITH_pep) && (defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined (COFF_WITH_peRiscV64))
static int
sort_x64_pdata (const void *l, const void *r)
{
  const char *lp = (const char *) l;
  const char *rp = (const char *) r;
  bfd_vma vl, vr;
  vl = bfd_getl32 (lp); vr = bfd_getl32 (rp);
  if (vl != vr)
    return (vl < vr ? -1 : 1);
  /* We compare just begin address.  */
  return 0;
}
#endif

/* Functions to process a .rsrc section.  */

static unsigned int sizeof_leaves;
static unsigned int sizeof_strings;
static unsigned int sizeof_tables_and_entries;

static bfd_byte *
rsrc_count_directory (bfd *, bfd_byte *, bfd_byte *, bfd_byte *, bfd_vma);

static bfd_byte *
rsrc_count_entries (bfd *abfd,
                   bool is_name,
                   bfd_byte *datastart,
                   bfd_byte *data,
                   bfd_byte *dataend,
                   bfd_vma rva_bias)
{
    unsigned long entry, addr, size;

    if (data + 8 >= dataend)
        return dataend + 1;

    if (is_name)
    {
        bfd_byte *name;
        unsigned int len;

        entry = (unsigned long) bfd_get_32 (abfd, data);

        if (HighBitSet(entry))
            name = datastart + WithoutHighBit(entry);
        else
            name = datastart + entry - rva_bias;

        if (name < datastart || name + 2 >= dataend)
            return dataend + 1;

        len = bfd_get_16(abfd, name);
        if (len == 0 || len > 256)
            return dataend + 1;
    }

    entry = (unsigned long) bfd_get_32 (abfd, data + 4);

    if (HighBitSet(entry))
    {
        bfd_byte *dir_data = datastart + WithoutHighBit(entry);

        if (dir_data <= datastart || dir_data >= dataend)
            return dataend + 1;

        return rsrc_count_directory (abfd, datastart, dir_data, dataend, rva_bias);
    }

    if (entry > (unsigned long)(dataend - datastart - 16))
        return dataend + 1;

    addr = (unsigned long) bfd_get_32 (abfd, datastart + entry);
    size = (unsigned long) bfd_get_32 (abfd, datastart + entry + 4);

    if (addr < rva_bias || (datastart + addr - rva_bias + size) > dataend)
        return dataend + 1;

    return datastart + addr - rva_bias + size;
}

static bfd_byte *
rsrc_count_directory(bfd *abfd,
                    bfd_byte *datastart,
                    bfd_byte *data,
                    bfd_byte *dataend,
                    bfd_vma rva_bias)
{
    unsigned int num_named, num_ids, total_entries, i;
    bfd_byte *highest_data = data;

    if (!abfd || !datastart || !data || !dataend || data + 16 >= dataend)
        return dataend + 1;

    num_named = (unsigned int) bfd_get_16(abfd, data + 12);
    num_ids = (unsigned int) bfd_get_16(abfd, data + 14);
    total_entries = num_named + num_ids;

    data += 16;

    for (i = 0; i < total_entries; i++) {
        int is_id_entry = (i >= num_named);
        bfd_byte *entry_end = rsrc_count_entries(abfd, is_id_entry, datastart, data, dataend, rva_bias);

        if (!entry_end)
            return dataend + 1;

        highest_data = (highest_data > entry_end) ? highest_data : entry_end;
        data += 8;

        if (entry_end >= dataend)
            break;
    }

    return (highest_data > data) ? highest_data : data;
}

typedef struct rsrc_dir_chain
{
  unsigned int	       num_entries;
  struct rsrc_entry *  first_entry;
  struct rsrc_entry *  last_entry;
} rsrc_dir_chain;

typedef struct rsrc_directory
{
  unsigned int characteristics;
  unsigned int time;
  unsigned int major;
  unsigned int minor;

  rsrc_dir_chain names;
  rsrc_dir_chain ids;

  struct rsrc_entry * entry;
} rsrc_directory;

typedef struct rsrc_string
{
  unsigned int	len;
  bfd_byte *	string;
} rsrc_string;

typedef struct rsrc_leaf
{
  unsigned int	size;
  unsigned int	codepage;
  bfd_byte *	data;
} rsrc_leaf;

typedef struct rsrc_entry
{
  bool is_name;
  union
  {
    unsigned int	  id;
    struct rsrc_string	  name;
  } name_id;

  bool is_dir;
  union
  {
    struct rsrc_directory * directory;
    struct rsrc_leaf *	    leaf;
  } value;

  struct rsrc_entry *	  next_entry;
  struct rsrc_directory * parent;
} rsrc_entry;

static bfd_byte *
rsrc_parse_directory (bfd *, rsrc_directory *, bfd_byte *,
		      bfd_byte *, bfd_byte *, bfd_vma, rsrc_entry *);

static bfd_byte *
rsrc_parse_entry(bfd *abfd,
                 bool is_name,
                 rsrc_entry *entry,
                 bfd_byte *datastart,
                 bfd_byte *data,
                 bfd_byte *dataend,
                 bfd_vma rva_bias,
                 rsrc_directory *parent)
{
    unsigned long val, addr, size;
    bfd_byte *address;

    if (!abfd || !entry || !datastart || !data || !dataend)
        return dataend;

    if (data + 8 > dataend)
        return dataend;

    val = bfd_get_32(abfd, data);

    entry->parent = parent;
    entry->is_name = is_name;

    if (is_name) {
        if (HighBitSet(val)) {
            val = WithoutHighBit(val);
            address = datastart + val;
        } else {
            address = datastart + val - rva_bias;
        }

        if (address + 3 > dataend || address < datastart)
            return dataend;

        entry->name_id.name.len = bfd_get_16(abfd, address);
        entry->name_id.name.string = address + 2;
    } else {
        entry->name_id.id = val;
    }

    val = bfd_get_32(abfd, data + 4);

    if (HighBitSet(val)) {
        entry->is_dir = true;
        entry->value.directory = bfd_malloc(sizeof(*entry->value.directory));
        if (!entry->value.directory)
            return dataend;

        bfd_byte *dir_result = rsrc_parse_directory(
            abfd, entry->value.directory,
            datastart,
            datastart + WithoutHighBit(val),
            dataend, rva_bias, entry);
        if (!dir_result)
            return dataend;
        return dir_result;
    }

    entry->is_dir = false;
    entry->value.leaf = bfd_malloc(sizeof(*entry->value.leaf));
    if (!entry->value.leaf)
        return dataend;

    data = datastart + val;
    if (data < datastart || data + 12 > dataend)
        return dataend;

    addr = bfd_get_32(abfd, data);
    size = bfd_get_32(abfd, data + 4);
    entry->value.leaf->size = size;
    entry->value.leaf->codepage = bfd_get_32(abfd, data + 8);

    if (size == 0 || addr < rva_bias)
        return dataend;
    if ((datastart + (addr - rva_bias)) < datastart)
        return dataend;
    if ((size > (unsigned long)(dataend - (datastart + (addr - rva_bias)))))
        return dataend;

    entry->value.leaf->data = bfd_malloc(size);
    if (!entry->value.leaf->data)
        return dataend;

    memcpy(entry->value.leaf->data, datastart + (addr - rva_bias), size);
    return datastart + (addr - rva_bias) + size;
}


static bfd_byte *
rsrc_parse_entries(bfd *abfd,
                  rsrc_dir_chain *chain,
                  bool is_name,
                  bfd_byte *highest_data,
                  bfd_byte *datastart,
                  bfd_byte *data,
                  bfd_byte *dataend,
                  bfd_vma rva_bias,
                  rsrc_directory *parent)
{
    unsigned int idx;
    rsrc_entry *entry = NULL;
    rsrc_entry *prev_entry = NULL;

    if (chain->num_entries == 0) {
        chain->first_entry = NULL;
        chain->last_entry = NULL;
        return highest_data;
    }

    for (idx = 0; idx < chain->num_entries; ++idx) {
        entry = bfd_malloc(sizeof(*entry));
        if (!entry) {
            if (idx == 0)
                chain->first_entry = NULL;
            chain->last_entry = prev_entry;
            return dataend;
        }

        if (idx == 0)
            chain->first_entry = entry;
        else
            prev_entry->next_entry = entry;

        bfd_byte *entry_end = rsrc_parse_entry(abfd, is_name, entry, datastart, data, dataend, rva_bias, parent);
        highest_data = max(entry_end, highest_data);
        if (entry_end > dataend) {
            entry->next_entry = NULL;
            chain->last_entry = entry;
            return dataend;
        }
        data += 8;

        prev_entry = entry;
    }

    if (entry)
        entry->next_entry = NULL;

    chain->last_entry = entry;

    return highest_data;
}

static bfd_byte *
rsrc_parse_directory(bfd *abfd,
                    rsrc_directory *table,
                    bfd_byte *datastart,
                    bfd_byte *data,
                    bfd_byte *dataend,
                    bfd_vma rva_bias,
                    rsrc_entry *entry)
{
    if (table == NULL || abfd == NULL || datastart == NULL || data == NULL || dataend == NULL || entry == NULL)
        return dataend;

    if (data + 16 > dataend)
        return dataend;

    table->characteristics = bfd_get_32(abfd, data);
    table->time            = bfd_get_32(abfd, data + 4);
    table->major           = bfd_get_16(abfd, data + 8);
    table->minor           = bfd_get_16(abfd, data + 10);
    table->names.num_entries = bfd_get_16(abfd, data + 12);
    table->ids.num_entries   = bfd_get_16(abfd, data + 14);
    table->entry = entry;

    data += 16;

    size_t name_count = table->names.num_entries;
    size_t id_count = table->ids.num_entries;

    if (data + name_count * 8 > dataend)
        return dataend;

    bfd_byte *highest_data = rsrc_parse_entries(abfd, &table->names, true, data,
                                                datastart, data, dataend, rva_bias, table);

    data += name_count * 8;

    if (data + id_count * 8 > dataend)
        return dataend;

    bfd_byte *new_highest = rsrc_parse_entries(abfd, &table->ids, false, highest_data,
                                               datastart, data, dataend, rva_bias, table);

    if (new_highest > highest_data)
        highest_data = new_highest;

    data += id_count * 8;

    return (highest_data > data) ? highest_data : data;
}

typedef struct rsrc_write_data
{
  bfd *      abfd;
  bfd_byte * datastart;
  bfd_byte * next_table;
  bfd_byte * next_leaf;
  bfd_byte * next_string;
  bfd_byte * next_data;
  bfd_vma    rva_bias;
} rsrc_write_data;

static void rsrc_write_string(rsrc_write_data *data, rsrc_string *string) {
  if (!data || !string || !data->abfd || !data->next_string || !string->string) {
    return;
  }
  bfd_put_16(data->abfd, string->len, data->next_string);
  size_t bytes_to_copy = (size_t)string->len * 2;
  memcpy(data->next_string + 2, string->string, bytes_to_copy);
  data->next_string += ((size_t)string->len + 1) * 2;
}

static inline unsigned int rsrc_compute_rva(const rsrc_write_data *data, const bfd_byte *addr) {
    if (data == NULL || data->datastart == NULL || addr == NULL) {
        return 0;
    }
    if (addr < data->datastart) {
        return 0;
    }
    return (unsigned int)(addr - data->datastart) + data->rva_bias;
}

static void rsrc_write_leaf(rsrc_write_data *data, rsrc_leaf *leaf)
{
    if (!data || !leaf || !data->abfd || !data->next_leaf || !data->next_data || !leaf->data)
        return;

    uint32_t rva = rsrc_compute_rva(data, data->next_data);
    bfd_put_32(data->abfd, rva, data->next_leaf);
    bfd_put_32(data->abfd, leaf->size, data->next_leaf + 4);
    bfd_put_32(data->abfd, leaf->codepage, data->next_leaf + 8);
    bfd_put_32(data->abfd, 0, data->next_leaf + 12);
    data->next_leaf += 16;

    memcpy(data->next_data, leaf->data, leaf->size);

    size_t aligned_size = ((leaf->size + 7) & ~((size_t)7));
    data->next_data += aligned_size;
}

static void rsrc_write_directory (rsrc_write_data *, rsrc_directory *);

static void rsrc_write_entry(rsrc_write_data *data, bfd_byte *where, rsrc_entry *entry) {
    if (entry == NULL || data == NULL || where == NULL)
        return;

    if (entry->is_name) {
        bfd_vma offset = data->next_string - data->datastart;
        bfd_put_32(data->abfd, SetHighBit(offset), where);
        rsrc_write_string(data, &entry->name_id.name);
    } else {
        bfd_put_32(data->abfd, entry->name_id.id, where);
    }

    if (entry->is_dir) {
        bfd_vma offset = data->next_table - data->datastart;
        bfd_put_32(data->abfd, SetHighBit(offset), where + 4);
        rsrc_write_directory(data, entry->value.directory);
    } else {
        bfd_vma offset = data->next_leaf - data->datastart;
        bfd_put_32(data->abfd, offset, where + 4);
        rsrc_write_leaf(data, entry->value.leaf);
    }
}

static void rsrc_compute_region_sizes(rsrc_directory *dir) {
    if (dir == NULL)
        return;

    sizeof_tables_and_entries += 16;

    for (struct rsrc_entry *entry = dir->names.first_entry; entry != NULL; entry = entry->next_entry) {
        sizeof_tables_and_entries += 8;
        if (&entry->name_id && entry->name_id.name.len > 0)
            sizeof_strings += ((size_t)entry->name_id.name.len + 1) * 2;
        if (entry->is_dir) {
            rsrc_compute_region_sizes(entry->value.directory);
        } else {
            sizeof_leaves += 16;
        }
    }

    for (struct rsrc_entry *entry = dir->ids.first_entry; entry != NULL; entry = entry->next_entry) {
        sizeof_tables_and_entries += 8;
        if (entry->is_dir) {
            rsrc_compute_region_sizes(entry->value.directory);
        } else {
            sizeof_leaves += 16;
        }
    }
}

static void rsrc_write_directory(rsrc_write_data *data, rsrc_directory *dir)
{
    if (!data || !dir)
        return;

    bfd_put_32(data->abfd, dir->characteristics, data->next_table);
    bfd_put_32(data->abfd, 0, data->next_table + 4);
    bfd_put_16(data->abfd, dir->major, data->next_table + 8);
    bfd_put_16(data->abfd, dir->minor, data->next_table + 10);
    bfd_put_16(data->abfd, dir->names.num_entries, data->next_table + 12);
    bfd_put_16(data->abfd, dir->ids.num_entries, data->next_table + 14);

    unsigned int total_name_entries = dir->names.num_entries;
    unsigned int total_id_entries = dir->ids.num_entries;
    bfd_byte *next_entry = data->next_table + 16;
    bfd_byte *expected_next = next_entry + (total_name_entries + total_id_entries) * 8;
    data->next_table = expected_next;

    rsrc_entry *entry = dir->names.first_entry;
    for (unsigned int i = 0; i < total_name_entries; ++i) {
        if (!entry || !entry->is_name)
            return;
        rsrc_write_entry(data, next_entry, entry);
        next_entry += 8;
        entry = entry->next_entry;
    }
    if (entry != NULL)
        return;

    entry = dir->ids.first_entry;
    for (unsigned int i = 0; i < total_id_entries; ++i) {
        if (!entry || entry->is_name)
            return;
        rsrc_write_entry(data, next_entry, entry);
        next_entry += 8;
        entry = entry->next_entry;
    }
    if (entry != NULL)
        return;

    if (expected_next != next_entry)
        return;
}

#if ! defined __CYGWIN__ && ! defined __MINGW32__
/* Return the length (number of units) of the first character in S,
   putting its 'ucs4_t' representation in *PUC.  */

static unsigned int u16_mbtouc(wint_t *puc, const unsigned short *s, unsigned int n) {
    if (!puc || !s || n == 0) {
        return 0;
    }

    unsigned short c = s[0];

    if (c < 0xd800 || c >= 0xe000) {
        *puc = c;
        return 1;
    }

    if (c >= 0xd800 && c < 0xdc00) {
        if (n < 2) {
            *puc = 0xfffd;
            return n;
        }
        unsigned short c2 = s[1];
        if (c2 >= 0xdc00 && c2 < 0xe000) {
            *puc = 0x10000 + (((unsigned int)c - 0xd800) << 10) + (c2 - 0xdc00);
            return 2;
        }
    }

    *puc = 0xfffd;
    return 1;
}
#endif /* not Cygwin/Mingw */

/* Perform a comparison of two entries.  */
static signed int rsrc_cmp(bool is_name, rsrc_entry *a, rsrc_entry *b) {
    if (!is_name) {
        return a->name_id.id - b->name_id.id;
    }

    bfd_byte *astring = a->name_id.name.string;
    unsigned int alen = a->name_id.name.len;
    bfd_byte *bstring = b->name_id.name.string;
    unsigned int blen = b->name_id.name.len;

#if defined(__CYGWIN__) || defined(__MINGW32__)
    size_t cmp_len = (alen < blen) ? alen : blen;
    signed int res;
    #undef rscpcmp
    #ifdef __CYGWIN__
        #define rscpcmp wcsncasecmp
    #endif
    #ifdef __MINGW32__
        #define rscpcmp wcsnicmp
    #endif

    if (!astring || !bstring) {
        return (astring == bstring) ? 0 : (astring ? 1 : -1);
    }
    res = rscpcmp((const wchar_t *)astring, (const wchar_t *)bstring, cmp_len);

#else
    unsigned int i;
    signed int res = 0;
    unsigned int cmp_len = (alen < blen) ? alen : blen;

    if (!astring || !bstring) {
        return (astring == bstring) ? 0 : (astring ? 1 : -1);
    }

    for (i = 0; i < cmp_len; i += 2) {
        wint_t awc = 0, bwc = 0;
        if (u16_mbtouc(&awc, (const unsigned short *)(astring + i), 2) != 2 ||
            u16_mbtouc(&bwc, (const unsigned short *)(bstring + i), 2) != 2) {
            return (int)alen - (int)blen;
        }
        awc = towlower(awc);
        bwc = towlower(bwc);
        res = (int)awc - (int)bwc;
        if (res != 0) {
            break;
        }
    }
#endif

    if (
#if defined(__CYGWIN__) || defined(__MINGW32__)
        res == 0
#else
        !res
#endif
    ) {
        return (int)alen - (int)blen;
    }

    return res;
}

static void rsrc_print_name(char *buffer, const rsrc_string string) {
    unsigned int i;
    const bfd_byte *name = string.string;
    size_t buf_len = strlen(buffer);

    for (i = 0; i < string.len; i++, name += 2) {
        if (buf_len + 1 < RSRC_MAX_NAME_LEN) {  // Assume RSRC_MAX_NAME_LEN is defined elsewhere
            buffer[buf_len++] = (char)name[0];
            buffer[buf_len] = '\0';
        } else {
            break;
        }
    }
}

static const char *
rsrc_resource_name(rsrc_entry *entry, rsrc_directory *dir, char *buffer)
{
    bool is_string = false;
    unsigned int id = 0;

    if (!buffer)
        return NULL;
    buffer[0] = '\0';

    if (dir && dir->entry && dir->entry->parent && dir->entry->parent->entry) {
        strcat(buffer, "type: ");
        if (dir->entry->parent->entry->is_name) {
            rsrc_print_name(buffer + strlen(buffer), dir->entry->parent->entry->name_id.name);
        } else {
            id = dir->entry->parent->entry->name_id.id;
            size_t len = strlen(buffer);
            snprintf(buffer + len, 64, "%x", id);

            switch (id) {
                case 1:  strcat(buffer, " (CURSOR)"); break;
                case 2:  strcat(buffer, " (BITMAP)"); break;
                case 3:  strcat(buffer, " (ICON)"); break;
                case 4:  strcat(buffer, " (MENU)"); break;
                case 5:  strcat(buffer, " (DIALOG)"); break;
                case 6:  strcat(buffer, " (STRING)"); is_string = true; break;
                case 7:  strcat(buffer, " (FONTDIR)"); break;
                case 8:  strcat(buffer, " (FONT)"); break;
                case 9:  strcat(buffer, " (ACCELERATOR)"); break;
                case 10: strcat(buffer, " (RCDATA)"); break;
                case 11: strcat(buffer, " (MESSAGETABLE)"); break;
                case 12: strcat(buffer, " (GROUP_CURSOR)"); break;
                case 14: strcat(buffer, " (GROUP_ICON)"); break;
                case 16: strcat(buffer, " (VERSION)"); break;
                case 17: strcat(buffer, " (DLGINCLUDE)"); break;
                case 19: strcat(buffer, " (PLUGPLAY)"); break;
                case 20: strcat(buffer, " (VXD)"); break;
                case 21: strcat(buffer, " (ANICURSOR)"); break;
                case 22: strcat(buffer, " (ANIICON)"); break;
                case 23: strcat(buffer, " (HTML)"); break;
                case 24: strcat(buffer, " (MANIFEST)"); break;
                case 240: strcat(buffer, " (DLGINIT)"); break;
                case 241: strcat(buffer, " (TOOLBAR)"); break;
                default: break;
            }
        }
    }

    if (dir && dir->entry) {
        strcat(buffer, " name: ");
        if (dir->entry->is_name) {
            rsrc_print_name(buffer + strlen(buffer), dir->entry->name_id.name);
        } else {
            id = dir->entry->name_id.id;
            size_t len = strlen(buffer);
            snprintf(buffer + len, 64, "%x", id);

            if (is_string) {
                len = strlen(buffer);
                snprintf(buffer + len, 128, " (resource id range: %d - %d)", (id - 1) << 4, (id << 4) - 1);
            }
        }
    }

    if (entry) {
        strcat(buffer, " lang: ");
        if (entry->is_name) {
            rsrc_print_name(buffer + strlen(buffer), entry->name_id.name);
        } else {
            size_t len = strlen(buffer);
            snprintf(buffer + len, 64, "%x", entry->name_id.id);
        }
    }

    return buffer;
}

/* *sigh* Windows resource strings are special.  Only the top 28-bits of
   their ID is stored in the NAME entry.  The bottom four bits are used as
   an index into unicode string table that makes up the data of the leaf.
   So identical type-name-lang string resources may not actually be
   identical at all.

   This function is called when we have detected two string resources with
   match top-28-bit IDs.  We have to scan the string tables inside the leaves
   and discover if there are any real collisions.  If there are then we report
   them and return FALSE.  Otherwise we copy any strings from B into A and
   then return TRUE.  */

static bool rsrc_merge_string_entries(rsrc_entry *a, rsrc_entry *b) {
    unsigned int copy_needed = 0;
    unsigned int i;
    bfd_byte *astring;
    bfd_byte *bstring;
    bfd_byte *new_data;
    bfd_byte *nstring;

    if (a == NULL || b == NULL || a->is_dir || b->is_dir || a->value.leaf == NULL || b->value.leaf == NULL || a->value.leaf->data == NULL || b->value.leaf->data == NULL)
        return false;

    astring = a->value.leaf->data;
    bstring = b->value.leaf->data;

    for (i = 0; i < 16; i++) {
        unsigned int alen = astring[0] + (astring[1] << 8);
        unsigned int blen = bstring[0] + (bstring[1] << 8);

        if (alen == 0) {
            copy_needed += blen * 2;
        } else if (blen == 0) {
            /* nothing to do */
        } else if (alen != blen) {
            break;
        } else if (memcmp(astring + 2, bstring + 2, alen * 2) != 0) {
            break;
        }

        astring += (alen + 1) * 2;
        bstring += (blen + 1) * 2;
    }

    if (i != 16) {
        if (a->parent && a->parent->entry && !a->parent->entry->is_name) {
            _bfd_error_handler(_(".rsrc merge failure: duplicate string resource: %d"),
                               ((a->parent->entry->name_id.id - 1) << 4) + i);
        }
        return false;
    }

    if (copy_needed == 0)
        return true;

    new_data = bfd_malloc(a->value.leaf->size + copy_needed);
    if (new_data == NULL)
        return false;

    nstring = new_data;
    astring = a->value.leaf->data;
    bstring = b->value.leaf->data;

    for (i = 0; i < 16; i++) {
        unsigned int alen = astring[0] + (astring[1] << 8);
        unsigned int blen = bstring[0] + (bstring[1] << 8);

        if (alen != 0) {
            memcpy(nstring, astring, (alen + 1) * 2);
            nstring += (alen + 1) * 2;
        } else if (blen != 0) {
            memcpy(nstring, bstring, (blen + 1) * 2);
            nstring += (blen + 1) * 2;
        } else {
            *nstring++ = 0;
            *nstring++ = 0;
        }

        astring += (alen + 1) * 2;
        bstring += (blen + 1) * 2;
    }

    if ((size_t)(nstring - new_data) != (a->value.leaf->size + copy_needed)) {
        free(new_data);
        return false;
    }

    free(a->value.leaf->data);
    a->value.leaf->data = new_data;
    a->value.leaf->size += copy_needed;

    return true;
}

static void rsrc_merge (rsrc_entry *, rsrc_entry *);

/* Sort the entries in given part of the directory.
   We use an old fashioned bubble sort because we are dealing
   with lists and we want to handle matches specially.  */

static void rsrc_sort_entries(rsrc_dir_chain *chain, bool is_name, rsrc_directory *dir) {
    if (chain->num_entries < 2)
        return;

    bool swapped;
    do {
        swapped = false;
        rsrc_entry **points_to_entry = &chain->first_entry;
        rsrc_entry *entry = *points_to_entry;
        rsrc_entry *next = entry->next_entry;

        while (next) {
            int cmp = rsrc_cmp(is_name, entry, next);

            if (cmp > 0) {
                entry->next_entry = next->next_entry;
                next->next_entry = entry;
                *points_to_entry = next;
                points_to_entry = &next->next_entry;
                next = entry->next_entry;
                swapped = true;
            } else if (cmp == 0) {
                if (entry->is_dir && next->is_dir) {
                    bool is_manifest_merge = !entry->is_name
                        && entry->name_id.id == 1
                        && dir && dir->entry
                        && !dir->entry->is_name
                        && dir->entry->name_id.id == 0x18;

                    if (is_manifest_merge) {
                        bool next_is_default_manifest =
                            next->value.directory->names.num_entries == 0 &&
                            next->value.directory->ids.num_entries == 1 &&
                            !next->value.directory->ids.first_entry->is_name &&
                            next->value.directory->ids.first_entry->name_id.id == 0;
                        bool entry_is_default_manifest =
                            entry->value.directory->names.num_entries == 0 &&
                            entry->value.directory->ids.num_entries == 1 &&
                            !entry->value.directory->ids.first_entry->is_name &&
                            entry->value.directory->ids.first_entry->name_id.id == 0;

                        if (next_is_default_manifest) {
                            // Fall through to drop NEXT
                        } else if (entry_is_default_manifest) {
                            entry->next_entry = next->next_entry;
                            next->next_entry = entry;
                            *points_to_entry = next;
                            points_to_entry = &next->next_entry;
                            next = entry->next_entry;
                            swapped = true;
                        } else {
                            _bfd_error_handler(_(".rsrc merge failure: multiple non-default manifests"));
                            bfd_set_error(bfd_error_file_truncated);
                            return;
                        }

                        entry->next_entry = next->next_entry;
                        chain->num_entries--;
                        if (chain->num_entries < 2)
                            return;
                        next = next->next_entry;
                        continue;
                    } else {
                        rsrc_merge(entry, next);
                    }
                } else if (entry->is_dir != next->is_dir) {
                    _bfd_error_handler(_(".rsrc merge failure: a directory matches a leaf"));
                    bfd_set_error(bfd_error_file_truncated);
                    return;
                } else {
                    bool is_manifest_leaf_drop = !entry->is_name
                        && entry->name_id.id == 0
                        && dir && dir->entry
                        && !dir->entry->is_name
                        && dir->entry->name_id.id == 1
                        && dir->entry->parent
                        && dir->entry->parent->entry
                        && !dir->entry->parent->entry->is_name
                        && dir->entry->parent->entry->name_id.id == 0x18;

                    bool is_string_type = dir
                        && dir->entry
                        && dir->entry->parent
                        && dir->entry->parent->entry
                        && !dir->entry->parent->entry->is_name
                        && dir->entry->parent->entry->name_id.id == 0x6;

                    if (is_manifest_leaf_drop) {
                        // Drop default manifest leaf
                    } else if (is_string_type) {
                        if (!rsrc_merge_string_entries(entry, next)) {
                            bfd_set_error(bfd_error_file_truncated);
                            return;
                        }
                    } else {
                        if (!dir || !dir->entry || !dir->entry->parent || !dir->entry->parent->entry) {
                            _bfd_error_handler(_(".rsrc merge failure: duplicate leaf"));
                        } else {
                            char buff[256];
                            _bfd_error_handler(_(".rsrc merge failure: duplicate leaf: %s"), rsrc_resource_name(entry, dir, buff));
                        }
                        bfd_set_error(bfd_error_file_truncated);
                        return;
                    }
                }

                entry->next_entry = next->next_entry;
                chain->num_entries--;
                if (chain->num_entries < 2)
                    return;
                next = next->next_entry;
            } else {
                points_to_entry = &entry->next_entry;
                entry = next;
                next = next->next_entry;
            }
        }
        chain->last_entry = entry;
    } while (swapped);
}

/* Attach B's chain onto A.  */
static void rsrc_attach_chain(rsrc_dir_chain *achain, rsrc_dir_chain *bchain) {
    if (!achain || !bchain)
        return;

    if (bchain->num_entries == 0)
        return;

    if (!achain->first_entry) {
        achain->first_entry = bchain->first_entry;
        achain->last_entry = bchain->last_entry;
    } else if (achain->last_entry) {
        achain->last_entry->next_entry = bchain->first_entry;
        achain->last_entry = bchain->last_entry;
    }

    achain->num_entries += bchain->num_entries;
    bchain->num_entries = 0;
    bchain->first_entry = NULL;
    bchain->last_entry = NULL;
}

static void rsrc_merge(struct rsrc_entry *a, struct rsrc_entry *b)
{
    if (!a || !b || !a->is_dir || !b->is_dir) {
        _bfd_error_handler(_("Invalid resource entries for merge."));
        bfd_set_error(bfd_error_file_truncated);
        return;
    }

    rsrc_directory *adir = a->value.directory;
    rsrc_directory *bdir = b->value.directory;

    if (!adir || !bdir) {
        _bfd_error_handler(_("Resource directory is NULL."));
        bfd_set_error(bfd_error_file_truncated);
        return;
    }

    if (adir->characteristics != bdir->characteristics) {
        _bfd_error_handler(_(".rsrc merge failure: dirs with differing characteristics"));
        bfd_set_error(bfd_error_file_truncated);
        return;
    }

    if (adir->major != bdir->major || adir->minor != bdir->minor) {
        _bfd_error_handler(_(".rsrc merge failure: differing directory versions"));
        bfd_set_error(bfd_error_file_truncated);
        return;
    }

    rsrc_attach_chain(&adir->names, &bdir->names);
    rsrc_attach_chain(&adir->ids, &bdir->ids);

    rsrc_sort_entries(&adir->names, true, adir);
    rsrc_sort_entries(&adir->ids, false, adir);
}

/* Check the .rsrc section.  If it contains multiple concatenated
   resources then we must merge them properly.  Otherwise Windows
   will ignore all but the first set.  */

static void
rsrc_process_section(bfd *abfd, struct coff_final_link_info *pfinfo)
{
    rsrc_directory new_table;
    bfd_size_type size;
    asection *sec;
    pe_data_type *pe;
    bfd_vma rva_bias;
    bfd_byte *data;
    bfd_byte *datastart = NULL;
    bfd_byte *dataend;
    bfd_byte *new_data = NULL;
    unsigned int num_resource_sets = 0;
    rsrc_directory *type_tables = NULL;
    rsrc_write_data write_data;
    unsigned int indx = 0;
    bfd *input;
    unsigned int num_input_rsrc = 0;
    unsigned int max_num_input_rsrc = 4;
    ptrdiff_t *rsrc_sizes = NULL;
    bfd_size_type sizeof_leaves = 0;
    bfd_size_type sizeof_strings = 0;
    bfd_size_type sizeof_tables_and_entries = 0;

    new_table.names.num_entries = 0;
    new_table.ids.num_entries = 0;

    sec = bfd_get_section_by_name(abfd, ".rsrc");
    if (!sec)
        return;

    size = sec->rawsize;
    if (size == 0)
        return;

    pe = pe_data(abfd);
    if (!pe)
        return;

    rva_bias = sec->vma - pe->pe_opthdr.ImageBase;

    if (!bfd_malloc_and_get_section(abfd, sec, &datastart))
        goto cleanup;

    data = datastart;
    rsrc_sizes = bfd_malloc(max_num_input_rsrc * sizeof(*rsrc_sizes));
    if (!rsrc_sizes)
        goto cleanup;

    for (input = pfinfo->info->input_bfds; input != NULL; input = input->link.next) {
        asection *rsrc_sec = bfd_get_section_by_name(input, ".rsrc");
        if (rsrc_sec && !discarded_section(rsrc_sec)) {
            if (num_input_rsrc == max_num_input_rsrc) {
                unsigned int new_max = max_num_input_rsrc + 10;
                ptrdiff_t *tmp_rsrc_sizes = bfd_realloc(rsrc_sizes, new_max * sizeof(*rsrc_sizes));
                if (!tmp_rsrc_sizes)
                    goto cleanup;
                rsrc_sizes = tmp_rsrc_sizes;
                max_num_input_rsrc = new_max;
            }
            if (rsrc_sec->size == 0)
                continue;
            rsrc_sizes[num_input_rsrc++] = rsrc_sec->size;
        }
    }

    if (num_input_rsrc < 2)
        goto cleanup;

    dataend = data + size;
    num_resource_sets = 0;

    while (data < dataend) {
        bfd_byte *p = data;
        data = rsrc_count_directory(abfd, data, data, dataend, rva_bias);
        if (data > dataend) {
            _bfd_error_handler(_("%pB: .rsrc merge failure: corrupt .rsrc section"), abfd);
            bfd_set_error(bfd_error_file_truncated);
            goto cleanup;
        }
        if ((bfd_size_type)(data - p) > (bfd_size_type)rsrc_sizes[num_resource_sets]) {
            _bfd_error_handler(_("%pB: .rsrc merge failure: unexpected .rsrc size"), abfd);
            bfd_set_error(bfd_error_file_truncated);
            goto cleanup;
        }
        data = p + rsrc_sizes[num_resource_sets];
        rva_bias += data - p;
        num_resource_sets++;
        if (num_resource_sets > num_input_rsrc)
            goto cleanup;
    }

    if (num_resource_sets != num_input_rsrc)
        goto cleanup;

    data = datastart;
    rva_bias = sec->vma - pe->pe_opthdr.ImageBase;

    type_tables = bfd_malloc(num_resource_sets * sizeof(*type_tables));
    if (!type_tables)
        goto cleanup;

    indx = 0;
    while (indx < num_resource_sets && data < dataend) {
        bfd_byte *p = data;
        rsrc_parse_directory(abfd, &type_tables[indx], data, data, dataend, rva_bias, NULL);
        data = p + rsrc_sizes[indx];
        rva_bias += data - p;
        indx++;
    }

    if (indx != num_resource_sets)
        goto cleanup;

    new_table.characteristics = type_tables[0].characteristics;
    new_table.time = type_tables[0].time;
    new_table.major = type_tables[0].major;
    new_table.minor = type_tables[0].minor;

    new_table.names.first_entry = NULL;
    new_table.names.last_entry = NULL;
    for (indx = 0; indx < num_resource_sets; indx++)
        rsrc_attach_chain(&new_table.names, &type_tables[indx].names);
    rsrc_sort_entries(&new_table.names, true, &new_table);

    new_table.ids.first_entry = NULL;
    new_table.ids.last_entry = NULL;
    for (indx = 0; indx < num_resource_sets; indx++)
        rsrc_attach_chain(&new_table.ids, &type_tables[indx].ids);
    rsrc_sort_entries(&new_table.ids, false, &new_table);

    sizeof_leaves = 0;
    sizeof_strings = 0;
    sizeof_tables_and_entries = 0;
    rsrc_compute_region_sizes(&new_table);
    sizeof_strings = (sizeof_strings + 7) & ~((bfd_size_type)7);

    new_data = bfd_zalloc(abfd, size);
    if (!new_data)
        goto cleanup;

    write_data.abfd = abfd;
    write_data.datastart = new_data;
    write_data.next_table = new_data;
    write_data.next_leaf = new_data + sizeof_tables_and_entries;
    write_data.next_string = write_data.next_leaf + sizeof_leaves;
    write_data.next_data = write_data.next_string + sizeof_strings;
    write_data.rva_bias = sec->vma - pe->pe_opthdr.ImageBase;

    rsrc_write_directory(&write_data, &new_table);

    bfd_set_section_contents(pfinfo->output_bfd, sec, new_data, 0, size);
    sec->size = sec->rawsize = size;

cleanup:
    if (datastart)
        free(datastart);
    if (rsrc_sizes)
        free(rsrc_sizes);
    if (type_tables)
        free(type_tables);
    if (new_data)
        free(new_data);
}

/* Handle the .idata section and other things that need symbol table
   access.  */

bool _bfd_XXi_final_link_postscript(bfd *abfd, struct coff_final_link_info *pfinfo) {
    struct coff_link_hash_entry *h1;
    struct bfd_link_info *info = pfinfo->info;
    bool result = true;
    char name[32];

    struct {
        const char *start;
        const char *end;
        int dir;
        const char *missing;
    } import_dirs[] = {
        { ".idata$2", ".idata$4", PE_IMPORT_TABLE, ".idata$2" },
        { ".idata$5", ".idata$6", PE_IMPORT_ADDRESS_TABLE, ".idata$5" }
    };

    for (int i = 0; i < 2; ++i) {
        bfd_vma vaddr = 0;
        h1 = coff_link_hash_lookup(coff_hash_table(info), import_dirs[i].start, false, false, true);
        if (h1 && (h1->root.type == bfd_link_hash_defined || h1->root.type == bfd_link_hash_defweak)
            && h1->root.u.def.section && h1->root.u.def.section->output_section) {
            vaddr = h1->root.u.def.value
                  + h1->root.u.def.section->output_section->vma
                  + h1->root.u.def.section->output_offset;
            pe_data(abfd)->pe_opthdr.DataDirectory[import_dirs[i].dir].VirtualAddress = vaddr;
        } else {
            _bfd_error_handler(_("%pB: unable to fill in DataDirectory[%d]: %s is missing"),
                              abfd, import_dirs[i].dir, import_dirs[i].missing);
            result = false;
        }

        h1 = coff_link_hash_lookup(coff_hash_table(info), import_dirs[i].end, false, false, true);
        if (h1 && (h1->root.type == bfd_link_hash_defined || h1->root.type == bfd_link_hash_defweak)
            && h1->root.u.def.section && h1->root.u.def.section->output_section) {
            bfd_vma sz = h1->root.u.def.value
                       + h1->root.u.def.section->output_section->vma
                       + h1->root.u.def.section->output_offset;
            pe_data(abfd)->pe_opthdr.DataDirectory[import_dirs[i].dir].Size =
                sz - pe_data(abfd)->pe_opthdr.DataDirectory[import_dirs[i].dir].VirtualAddress;
        } else {
            _bfd_error_handler(_("%pB: unable to fill in DataDirectory[%d]: %s is missing"),
                              abfd, import_dirs[i].dir, import_dirs[i].end);
            result = false;
        }
    }

    h1 = coff_link_hash_lookup(coff_hash_table(info), "__IAT_start__", false, false, true);
    if (h1 && (h1->root.type == bfd_link_hash_defined || h1->root.type == bfd_link_hash_defweak)
        && h1->root.u.def.section && h1->root.u.def.section->output_section) {
        bfd_vma iat_va = h1->root.u.def.value
                       + h1->root.u.def.section->output_section->vma
                       + h1->root.u.def.section->output_offset;

        h1 = coff_link_hash_lookup(coff_hash_table(info), "__IAT_end__", false, false, true);
        if (h1 && (h1->root.type == bfd_link_hash_defined || h1->root.type == bfd_link_hash_defweak)
            && h1->root.u.def.section && h1->root.u.def.section->output_section) {
            pe_data(abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].Size =
                (h1->root.u.def.value
                 + h1->root.u.def.section->output_section->vma
                 + h1->root.u.def.section->output_offset) - iat_va;
            if (pe_data(abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].Size != 0)
                pe_data(abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].VirtualAddress =
                    iat_va - pe_data(abfd)->pe_opthdr.ImageBase;
        } else {
            _bfd_error_handler(_("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
                              abfd, PE_IMPORT_ADDRESS_TABLE, "__IAT_end__");
            result = false;
        }
    }

    h1 = coff_link_hash_lookup(coff_hash_table(info), "__DELAY_IMPORT_DIRECTORY_start__", false, false, true);
    if (h1 && (h1->root.type == bfd_link_hash_defined || h1->root.type == bfd_link_hash_defweak)
        && h1->root.u.def.section && h1->root.u.def.section->output_section) {
        bfd_vma delay_va = h1->root.u.def.value
                         + h1->root.u.def.section->output_section->vma
                         + h1->root.u.def.section->output_offset;

        h1 = coff_link_hash_lookup(coff_hash_table(info), "__DELAY_IMPORT_DIRECTORY_end__", false, false, true);
        if (h1 && (h1->root.type == bfd_link_hash_defined || h1->root.type == bfd_link_hash_defweak)
            && h1->root.u.def.section && h1->root.u.def.section->output_section) {
            pe_data(abfd)->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR].Size =
                (h1->root.u.def.value
                 + h1->root.u.def.section->output_section->vma
                 + h1->root.u.def.section->output_offset) - delay_va;
            if (pe_data(abfd)->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR].Size != 0)
                pe_data(abfd)->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR].VirtualAddress =
                    delay_va - pe_data(abfd)->pe_opthdr.ImageBase;
        } else {
            _bfd_error_handler(_("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
                              abfd, PE_DELAY_IMPORT_DESCRIPTOR, "__DELAY_IMPORT_DIRECTORY_end__");
            result = false;
        }
    }

    memset(name, 0, sizeof(name));
    name[0] = bfd_get_symbol_leading_char(abfd);
    strcpy(name + !!name[0], "_tls_used");
    h1 = coff_link_hash_lookup(coff_hash_table(info), name, false, false, true);
    if (h1) {
        if ((h1->root.type == bfd_link_hash_defined || h1->root.type == bfd_link_hash_defweak)
            && h1->root.u.def.section && h1->root.u.def.section->output_section) {
            pe_data(abfd)->pe_opthdr.DataDirectory[PE_TLS_TABLE].VirtualAddress =
                h1->root.u.def.value
                + h1->root.u.def.section->output_section->vma
                + h1->root.u.def.section->output_offset
                - pe_data(abfd)->pe_opthdr.ImageBase;
        } else {
            _bfd_error_handler(_("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
                              abfd, PE_TLS_TABLE, name);
            result = false;
        }
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined(COFF_WITH_peRiscV64)
        pe_data(abfd)->pe_opthdr.DataDirectory[PE_TLS_TABLE].Size = 0x18;
#else
        pe_data(abfd)->pe_opthdr.DataDirectory[PE_TLS_TABLE].Size = 0x28;
#endif
    }

    memset(name, 0, sizeof(name));
    name[0] = bfd_get_symbol_leading_char(abfd);
    strcpy(name + !!name[0], "_load_config_used");
    h1 = coff_link_hash_lookup(coff_hash_table(info), name, false, false, true);
    if (h1) {
        char data[4] = {0, 0, 0, 0};
        if ((h1->root.type == bfd_link_hash_defined || h1->root.type == bfd_link_hash_defweak)
            && h1->root.u.def.section && h1->root.u.def.section->output_section) {
            bfd_vma va = h1->root.u.def.value
                       + h1->root.u.def.section->output_section->vma
                       + h1->root.u.def.section->output_offset
                       - pe_data(abfd)->pe_opthdr.ImageBase;
            pe_data(abfd)->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].VirtualAddress = va;

            if (pe_data(abfd)->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].VirtualAddress &
                    (bfd_arch_bits_per_address(abfd) / bfd_arch_bits_per_byte(abfd) - 1)) {
                _bfd_error_handler(_("%pB: unable to fill in DataDirectory[%d]: %s not properly aligned"),
                                   abfd, PE_LOAD_CONFIG_TABLE, name);
                result = false;
            }

            bfd_boolean ok = bfd_get_section_contents(abfd,
                h1->root.u.def.section->output_section, data,
                h1->root.u.def.section->output_offset + h1->root.u.def.value, 4);
            if (ok) {
                uint32_t size = bfd_get_32(abfd, data);
                pe_data(abfd)->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].Size =
                    (bfd_get_arch(abfd) == bfd_arch_i386
                     && ((bfd_get_mach(abfd) & ~bfd_mach_i386_intel_syntax) == bfd_mach_i386_i386)
                     && ((pe_data(abfd)->pe_opthdr.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI)
                         || (pe_data(abfd)->pe_opthdr.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI))
                     && (pe_data(abfd)->pe_opthdr.MajorSubsystemVersion * 256
                         + pe_data(abfd)->pe_opthdr.MinorSubsystemVersion <= 0x0501))
                    ? 64 : size;

                if (size > h1->root.u.def.section->size - h1->root.u.def.value) {
                    _bfd_error_handler(_("%pB: unable to fill in DataDirectory[%d]: size too large for the containing section"),
                                      abfd, PE_LOAD_CONFIG_TABLE);
                    result = false;
                }
            } else {
                _bfd_error_handler(_("%pB: unable to fill in DataDirectory[%d]: size can't be read from %s"),
                                   abfd, PE_LOAD_CONFIG_TABLE, name);
                result = false;
            }
        } else {
            _bfd_error_handler(_("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
                              abfd, PE_LOAD_CONFIG_TABLE, name);
            result = false;
        }
    }

#if !defined(COFF_WITH_pep) && (defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined(COFF_WITH_peRiscV64))
    {
        asection *sec = bfd_get_section_by_name(abfd, ".pdata");
        if (sec) {
            bfd_size_type x = sec->rawsize;
            bfd_byte *tmp_data = NULL;
            if (bfd_malloc_and_get_section(abfd, sec, &tmp_data) && tmp_data) {
                qsort(tmp_data, (size_t)(x / 12), 12, sort_x64_pdata);
                bfd_set_section_contents(pfinfo->output_bfd, sec, tmp_data, 0, x);
                free(tmp_data);
            } else {
                result = false;
            }
        }
    }
#endif

    rsrc_process_section(abfd, pfinfo);

    return result;
}
