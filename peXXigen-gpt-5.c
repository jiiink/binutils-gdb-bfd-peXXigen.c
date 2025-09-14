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

void
_bfd_XXi_swap_sym_in (bfd *abfd, void *ext1, void *in1)
{
  if (abfd == NULL || ext1 == NULL || in1 == NULL)
    {
      if (abfd != NULL)
        bfd_set_error (bfd_error_invalid_operation);
      return;
    }

  const SYMENT *ext = (const SYMENT *) ext1;
  struct internal_syment *in = (struct internal_syment *) in1;

  if (ext->e.e_name[0] == 0)
    {
      in->_n._n_n._n_zeroes = 0;
      in->_n._n_n._n_offset = H_GET_32 (abfd, ext->e.e.e_offset);
    }
  else
    {
      memcpy (in->_n._n_name, ext->e.e_name, SYMNMLEN);
    }

  in->n_value = H_GET_32 (abfd, ext->e_value);
  in->n_scnum = (short) H_GET_16 (abfd, ext->e_scnum);
  in->n_type = (sizeof (ext->e_type) == 2)
                 ? H_GET_16 (abfd, ext->e_type)
                 : H_GET_32 (abfd, ext->e_type);
  in->n_sclass = H_GET_8 (abfd, ext->e_sclass);
  in->n_numaux = H_GET_8 (abfd, ext->e_numaux);

#ifndef STRICT_PE_FORMAT
  if (in->n_sclass == C_SECTION)
    {
      char namebuf[SYMNMLEN + 1];
      const char *name = NULL;

      in->n_value = 0;

      if (in->n_scnum == 0)
        {
          asection *sec;

          name = _bfd_coff_internal_syment_name (abfd, in, namebuf);
          if (name == NULL)
            {
              _bfd_error_handler (_("%pB: unable to find name for empty section"), abfd);
              bfd_set_error (bfd_error_invalid_target);
              return;
            }

          sec = bfd_get_section_by_name (abfd, name);
          if (sec != NULL)
            in->n_scnum = sec->target_index;
        }

      if (in->n_scnum == 0)
        {
          int unused_section_number = 0;
          asection *sec;
          flagword flags;
          size_t name_len;
          char *sec_name;

          for (sec = abfd->sections; sec != NULL; sec = sec->next)
            if (unused_section_number <= sec->target_index)
              unused_section_number = sec->target_index + 1;

          name_len = strlen (name) + 1;
          sec_name = (char *) bfd_alloc (abfd, name_len);
          if (sec_name == NULL)
            {
              _bfd_error_handler (_("%pB: out of memory creating name for empty section"), abfd);
              return;
            }
          memcpy (sec_name, name, name_len);

          flags = (SEC_HAS_CONTENTS | SEC_ALLOC | SEC_DATA | SEC_LOAD | SEC_LINKER_CREATED);
          sec = bfd_make_section_anyway_with_flags (abfd, sec_name, flags);
          if (sec == NULL)
            {
              _bfd_error_handler (_("%pB: unable to create fake empty section"), abfd);
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

static bool
abs_finder (bfd * abfd ATTRIBUTE_UNUSED, asection * sec, void * data)
{
  if (sec == NULL || data == NULL)
    return false;

  const bfd_vma * val_ptr = (const bfd_vma *) data;
  const bfd_vma abs_val = *val_ptr;
  const bfd_vma base = sec->vma;
  const bfd_vma range = ((bfd_vma) 1) << 32;

  if (abs_val < base)
    return false;

  return (abs_val - base) < range;
}

unsigned int
_bfd_XXi_swap_sym_out (bfd *abfd, void *inp, void *extp)
{
  if (abfd == NULL || inp == NULL || extp == NULL)
    return 0;

  struct internal_syment *in = (struct internal_syment *) inp;
  SYMENT *ext = (SYMENT *) extp;

  if (in->_n._n_name[0] == 0)
    {
      H_PUT_32 (abfd, 0, ext->e.e.e_zeroes);
      H_PUT_32 (abfd, in->_n._n_n._n_offset, ext->e.e.e_offset);
    }
  else
    {
      memcpy (ext->e.e_name, in->_n._n_name, SYMNMLEN);
    }

  {
    unsigned long long limit = (1ULL << (sizeof (in->n_value) > 4 ? 32 : 31)) - 1ULL;
    if (sizeof (in->n_value) > 4
        && in->n_value > limit
        && in->n_scnum == N_ABS)
      {
        asection *sec = bfd_sections_find_if (abfd, abs_finder, &in->n_value);
        if (sec != NULL)
          {
            in->n_value -= sec->vma;
            in->n_scnum = sec->target_index;
          }
      }
  }

  H_PUT_32 (abfd, in->n_value, ext->e_value);
  H_PUT_16 (abfd, in->n_scnum, ext->e_scnum);

  if (sizeof (ext->e_type) == 2)
    H_PUT_16 (abfd, in->n_type, ext->e_type);
  else
    H_PUT_32 (abfd, in->n_type, ext->e_type);

  H_PUT_8 (abfd, in->n_sclass, ext->e_sclass);
  H_PUT_8 (abfd, in->n_numaux, ext->e_numaux);

  return SYMESZ;
}

void
_bfd_XXi_swap_aux_in (bfd *abfd,
                      void *ext1,
                      int type,
                      int in_class,
                      int indx ATTRIBUTE_UNUSED,
                      int numaux ATTRIBUTE_UNUSED,
                      void *in1)
{
  if (abfd == NULL || ext1 == NULL || in1 == NULL)
    return;

  const AUXENT *ext = (const AUXENT *) ext1;
  union internal_auxent *in = (union internal_auxent *) in1;

  memset (in, 0, sizeof (*in));

  switch (in_class)
    {
    case C_FILE:
      if (ext->x_file.x_fname[0] == 0)
        {
          in->x_file.x_n.x_n.x_zeroes = 0;
          in->x_file.x_n.x_n.x_offset = H_GET_32 (abfd, ext->x_file.x_n.x_offset);
        }
      else
#if FILNMLEN != E_FILNMLEN
#error we need to cope with truncating or extending x_fname
#endif
        memcpy (in->x_file.x_n.x_fname, ext->x_file.x_fname, FILNMLEN);
      return;

    case C_STAT:
    case C_LEAFSTAT:
    case C_HIDDEN:
      if (type == T_NULL)
        {
          in->x_scn.x_scnlen = GET_SCN_SCNLEN (abfd, ext);
          in->x_scn.x_nreloc = GET_SCN_NRELOC (abfd, ext);
          in->x_scn.x_nlinno = GET_SCN_NLINNO (abfd, ext);
          in->x_scn.x_checksum = H_GET_32 (abfd, ext->x_scn.x_checksum);
          in->x_scn.x_associated = H_GET_16 (abfd, ext->x_scn.x_associated);
          in->x_scn.x_comdat = H_GET_8 (abfd, ext->x_scn.x_comdat);
          return;
        }
      break;

    default:
      break;
    }

  in->x_sym.x_tagndx.u32 = H_GET_32 (abfd, ext->x_sym.x_tagndx);
  in->x_sym.x_tvndx = H_GET_16 (abfd, ext->x_sym.x_tvndx);

  if (in_class == C_BLOCK || in_class == C_FCN || ISFCN (type) || ISTAG (in_class))
    {
      in->x_sym.x_fcnary.x_fcn.x_lnnoptr = GET_FCN_LNNOPTR (abfd, ext);
      in->x_sym.x_fcnary.x_fcn.x_endndx.u32 = GET_FCN_ENDNDX (abfd, ext);
    }
  else
    {
      for (int i = 0; i < 4; i++)
        in->x_sym.x_fcnary.x_ary.x_dimen[i] =
          H_GET_16 (abfd, ext->x_sym.x_fcnary.x_ary.x_dimen[i]);
    }

  if (ISFCN (type))
    {
      in->x_sym.x_misc.x_fsize = H_GET_32 (abfd, ext->x_sym.x_misc.x_fsize);
    }
  else
    {
      in->x_sym.x_misc.x_lnsz.x_lnno = GET_LNSZ_LNNO (abfd, ext);
      in->x_sym.x_misc.x_lnsz.x_size = GET_LNSZ_SIZE (abfd, ext);
    }
}

unsigned int
_bfd_XXi_swap_aux_out (bfd *abfd,
                       void *inp,
                       int type,
                       int in_class,
                       int indx ATTRIBUTE_UNUSED,
                       int numaux ATTRIBUTE_UNUSED,
                       void *extp)
{
  const union internal_auxent *in = (const union internal_auxent *) inp;
  AUXENT *ext = (AUXENT *) extp;

  if (abfd == NULL || in == NULL || ext == NULL)
    return 0;

  memset (ext, 0, AUXESZ);

  switch (in_class)
    {
    case C_FILE:
      if (in->x_file.x_n.x_fname[0] == 0)
        {
          H_PUT_32 (abfd, 0, ext->x_file.x_n.x_zeroes);
          H_PUT_32 (abfd, in->x_file.x_n.x_n.x_offset, ext->x_file.x_n.x_offset);
        }
      else
#if FILNMLEN != E_FILNMLEN
#error we need to cope with truncating or extending x_fname
#endif
        {
          memcpy (ext->x_file.x_fname, in->x_file.x_n.x_fname, E_FILNMLEN);
        }
      return AUXESZ;

    case C_STAT:
    case C_LEAFSTAT:
    case C_HIDDEN:
      if (type == T_NULL)
        {
          PUT_SCN_SCNLEN (abfd, in->x_scn.x_scnlen, ext);
          PUT_SCN_NRELOC (abfd, in->x_scn.x_nreloc, ext);
          PUT_SCN_NLINNO (abfd, in->x_scn.x_nlinno, ext);
          H_PUT_32 (abfd, in->x_scn.x_checksum, ext->x_scn.x_checksum);
          H_PUT_16 (abfd, in->x_scn.x_associated, ext->x_scn.x_associated);
          H_PUT_8 (abfd, in->x_scn.x_comdat, ext->x_scn.x_comdat);
          return AUXESZ;
        }
      break;

    default:
      break;
    }

  H_PUT_32 (abfd, in->x_sym.x_tagndx.u32, ext->x_sym.x_tagndx);
  H_PUT_16 (abfd, in->x_sym.x_tvndx, ext->x_sym.x_tvndx);

  {
    int needs_fcn_fields = (in_class == C_BLOCK) || (in_class == C_FCN) || ISFCN (type) || ISTAG (in_class);
    if (needs_fcn_fields)
      {
        PUT_FCN_LNNOPTR (abfd, in->x_sym.x_fcnary.x_fcn.x_lnnoptr, ext);
        PUT_FCN_ENDNDX (abfd, in->x_sym.x_fcnary.x_fcn.x_endndx.u32, ext);
      }
    else
      {
        int i;
        for (i = 0; i < 4; ++i)
          H_PUT_16 (abfd, in->x_sym.x_fcnary.x_ary.x_dimen[i], ext->x_sym.x_fcnary.x_ary.x_dimen[i]);
      }
  }

  if (ISFCN (type))
    H_PUT_32 (abfd, in->x_sym.x_misc.x_fsize, ext->x_sym.x_misc.x_fsize);
  else
    {
      PUT_LNSZ_LNNO (abfd, in->x_sym.x_misc.x_lnsz.x_lnno, ext);
      PUT_LNSZ_SIZE (abfd, in->x_sym.x_misc.x_lnsz.x_size, ext);
    }

  return AUXESZ;
}

void
_bfd_XXi_swap_lineno_in(bfd *abfd, void *ext1, void *in1)
{
  if (abfd == NULL || ext1 == NULL || in1 == NULL)
    return;

  const LINENO *src = ext1;
  struct internal_lineno *dst = in1;

  dst->l_addr.l_symndx = H_GET_32(abfd, src->l_addr.l_symndx);
  dst->l_lnno = GET_LINENO_LNNO(abfd, src);
}

unsigned int
_bfd_XXi_swap_lineno_out (bfd *abfd, void *inp, void *outp)
{
  if (abfd == NULL || inp == NULL || outp == NULL)
    return 0;

  const struct internal_lineno *inl = (const struct internal_lineno *) inp;
  struct external_lineno *ext = (struct external_lineno *) outp;

  unsigned int symndx = (unsigned int) inl->l_addr.l_symndx;
  unsigned int lnno = (unsigned int) inl->l_lnno;

  H_PUT_32 (abfd, symndx, ext->l_addr.l_symndx);
  PUT_LINENO_LNNO (abfd, lnno, ext);
  return LINESZ;
}

void
_bfd_XXi_swap_aouthdr_in(bfd *abfd, void *aouthdr_ext1, void *aouthdr_int1)
{
  if (abfd == NULL || aouthdr_ext1 == NULL || aouthdr_int1 == NULL)
    return;

  const PEAOUTHDR *src = (const PEAOUTHDR *) aouthdr_ext1;
  const AOUTHDR *aouthdr_ext = (const AOUTHDR *) aouthdr_ext1;
  struct internal_aouthdr *aouthdr_int = (struct internal_aouthdr *) aouthdr_int1;
  struct internal_extra_pe_aouthdr *a = &aouthdr_int->pe;

  aouthdr_int->magic = H_GET_16 (abfd, aouthdr_ext->magic);
  aouthdr_int->vstamp = H_GET_16 (abfd, aouthdr_ext->vstamp);
  aouthdr_int->tsize = GET_AOUTHDR_TSIZE (abfd, aouthdr_ext->tsize);
  aouthdr_int->dsize = GET_AOUTHDR_DSIZE (abfd, aouthdr_ext->dsize);
  aouthdr_int->bsize = GET_AOUTHDR_BSIZE (abfd, aouthdr_ext->bsize);
  aouthdr_int->entry = GET_AOUTHDR_ENTRY (abfd, aouthdr_ext->entry);
  aouthdr_int->text_start = GET_AOUTHDR_TEXT_START (abfd, aouthdr_ext->text_start);

#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
  aouthdr_int->data_start = GET_AOUTHDR_DATA_START (abfd, aouthdr_ext->data_start);
  a->BaseOfData = aouthdr_int->data_start;
#endif

  a->Magic = aouthdr_int->magic;
  a->MajorLinkerVersion = H_GET_8 (abfd, aouthdr_ext->vstamp);
  a->MinorLinkerVersion = H_GET_8 (abfd, aouthdr_ext->vstamp + 1);
  a->SizeOfCode = aouthdr_int->tsize;
  a->SizeOfInitializedData = aouthdr_int->dsize;
  a->SizeOfUninitializedData = aouthdr_int->bsize;
  a->AddressOfEntryPoint = aouthdr_int->entry;
  a->BaseOfCode = aouthdr_int->text_start;
  a->ImageBase = GET_OPTHDR_IMAGE_BASE (abfd, src->ImageBase);
  a->SectionAlignment = H_GET_32 (abfd, src->SectionAlignment);
  a->FileAlignment = H_GET_32 (abfd, src->FileAlignment);
  a->MajorOperatingSystemVersion = H_GET_16 (abfd, src->MajorOperatingSystemVersion);
  a->MinorOperatingSystemVersion = H_GET_16 (abfd, src->MinorOperatingSystemVersion);
  a->MajorImageVersion = H_GET_16 (abfd, src->MajorImageVersion);
  a->MinorImageVersion = H_GET_16 (abfd, src->MinorImageVersion);
  a->MajorSubsystemVersion = H_GET_16 (abfd, src->MajorSubsystemVersion);
  a->MinorSubsystemVersion = H_GET_16 (abfd, src->MinorSubsystemVersion);
  a->Win32Version = H_GET_32 (abfd, src->Win32Version);
  a->SizeOfImage = H_GET_32 (abfd, src->SizeOfImage);
  a->SizeOfHeaders = H_GET_32 (abfd, src->SizeOfHeaders);
  a->CheckSum = H_GET_32 (abfd, src->CheckSum);
  a->Subsystem = H_GET_16 (abfd, src->Subsystem);
  a->DllCharacteristics = H_GET_16 (abfd, src->DllCharacteristics);
  a->SizeOfStackReserve = GET_OPTHDR_SIZE_OF_STACK_RESERVE (abfd, src->SizeOfStackReserve);
  a->SizeOfStackCommit = GET_OPTHDR_SIZE_OF_STACK_COMMIT (abfd, src->SizeOfStackCommit);
  a->SizeOfHeapReserve = GET_OPTHDR_SIZE_OF_HEAP_RESERVE (abfd, src->SizeOfHeapReserve);
  a->SizeOfHeapCommit = GET_OPTHDR_SIZE_OF_HEAP_COMMIT (abfd, src->SizeOfHeapCommit);
  a->LoaderFlags = H_GET_32 (abfd, src->LoaderFlags);
  a->NumberOfRvaAndSizes = H_GET_32 (abfd, src->NumberOfRvaAndSizes);

  {
    unsigned int dir_count = a->NumberOfRvaAndSizes;
    if (dir_count > IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
      dir_count = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    for (unsigned int idx = 0; idx < dir_count; idx++)
      {
        unsigned int size = H_GET_32 (abfd, src->DataDirectory[idx][1]);
        unsigned int vma = size ? H_GET_32 (abfd, src->DataDirectory[idx][0]) : 0U;
        a->DataDirectory[idx].Size = size;
        a->DataDirectory[idx].VirtualAddress = vma;
      }

    for (unsigned int idx = dir_count; idx < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; idx++)
      {
        a->DataDirectory[idx].Size = 0;
        a->DataDirectory[idx].VirtualAddress = 0;
      }
  }

  if (aouthdr_int->entry)
    {
      aouthdr_int->entry += a->ImageBase;
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
      aouthdr_int->entry &= 0xffffffff;
#endif
    }

  if (aouthdr_int->tsize)
    {
      aouthdr_int->text_start += a->ImageBase;
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
      aouthdr_int->text_start &= 0xffffffff;
#endif
    }

#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
  if (aouthdr_int->dsize)
    {
      aouthdr_int->data_start += a->ImageBase;
      aouthdr_int->data_start &= 0xffffffff;
    }
#endif
}

/* A support function for below.  */

static void
add_data_entry (bfd *abfd,
                struct internal_extra_pe_aouthdr *aout,
                int idx,
                char *name,
                bfd_vma base)
{
  asection *sec;

  if (abfd == NULL || aout == NULL || name == NULL || idx < 0)
    return;

  sec = bfd_get_section_by_name (abfd, name);
  if (sec == NULL)
    return;

  if (coff_section_data (abfd, sec) == NULL)
    return;

  if (pei_section_data (abfd, sec) == NULL)
    return;

  {
    unsigned int size = pei_section_data (abfd, sec)->virt_size;
    aout->DataDirectory[idx].Size = size;
    if (size != 0)
      {
        aout->DataDirectory[idx].VirtualAddress =
          (sec->vma - base) & 0xffffffff;
        sec->flags |= SEC_DATA;
      }
  }
}

unsigned int
_bfd_XXi_swap_aouthdr_out (bfd * abfd, void * in, void * out)
{
  struct internal_aouthdr *aouthdr_in = (struct internal_aouthdr *) in;
  pe_data_type *pe = pe_data (abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
  PEAOUTHDR *aouthdr_out = (PEAOUTHDR *) out;
  bfd_vma sa = extra->SectionAlignment;
  bfd_vma fa = extra->FileAlignment;
  bfd_vma ib = extra->ImageBase;
  IMAGE_DATA_DIRECTORY idata2 = pe->pe_opthdr.DataDirectory[PE_IMPORT_TABLE];
  IMAGE_DATA_DIRECTORY idata5 = pe->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE];
  IMAGE_DATA_DIRECTORY didat2 = pe->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR];
  IMAGE_DATA_DIRECTORY tls = pe->pe_opthdr.DataDirectory[PE_TLS_TABLE];
  IMAGE_DATA_DIRECTORY loadcfg = pe->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE];

  if (aouthdr_in->tsize)
    {
      aouthdr_in->text_start -= ib;
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
      aouthdr_in->text_start &= 0xffffffff;
#endif
    }

  if (aouthdr_in->dsize)
    {
      aouthdr_in->data_start -= ib;
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
      aouthdr_in->data_start &= 0xffffffff;
#endif
    }

  if (aouthdr_in->entry)
    {
      aouthdr_in->entry -= ib;
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
      aouthdr_in->entry &= 0xffffffff;
#endif
    }

  {
    bfd_vma align_up_bsize = fa ? ((aouthdr_in->bsize + fa - 1) & ~(fa - 1)) : aouthdr_in->bsize;
    aouthdr_in->bsize = align_up_bsize;
  }

  extra->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

  add_data_entry (abfd, extra, PE_EXPORT_TABLE, ".edata", ib);
  add_data_entry (abfd, extra, PE_RESOURCE_TABLE, ".rsrc", ib);
  add_data_entry (abfd, extra, PE_EXCEPTION_TABLE, ".pdata", ib);

  extra->DataDirectory[PE_IMPORT_TABLE]  = idata2;
  extra->DataDirectory[PE_IMPORT_ADDRESS_TABLE] = idata5;
  extra->DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR] = didat2;
  extra->DataDirectory[PE_TLS_TABLE] = tls;
  extra->DataDirectory[PE_LOAD_CONFIG_TABLE] = loadcfg;

  if (extra->DataDirectory[PE_IMPORT_TABLE].VirtualAddress == 0)
    add_data_entry (abfd, extra, PE_IMPORT_TABLE, ".idata", ib);

  if (pe->has_reloc_section)
    add_data_entry (abfd, extra, PE_BASE_RELOCATION_TABLE, ".reloc", ib);

  {
    asection *sec;
    bfd_vma hsize = 0;
    bfd_vma dsize = 0;
    bfd_vma isize = 0;
    bfd_vma tsize = 0;

    for (sec = abfd->sections; sec; sec = sec->next)
      {
        bfd_vma rounded = fa ? ((sec->size + fa - 1) & ~(fa - 1)) : sec->size;

        if (rounded == 0)
          continue;

        if (hsize == 0)
          hsize = sec->filepos;

        if (sec->flags & SEC_DATA)
          dsize += rounded;

        if (sec->flags & SEC_CODE)
          tsize += rounded;

        if (coff_section_data (abfd, sec) != NULL
            && pei_section_data (abfd, sec) != NULL)
          {
            bfd_vma vsz = pei_section_data (abfd, sec)->virt_size;
            bfd_vma vsz_aligned = fa ? ((vsz + fa - 1) & ~(fa - 1)) : vsz;
            bfd_vma sum = sec->vma - extra->ImageBase + vsz_aligned;
            isize = sa ? ((sum + sa - 1) & ~(sa - 1)) : sum;
          }
      }

    aouthdr_in->dsize = dsize;
    aouthdr_in->tsize = tsize;
    extra->SizeOfHeaders = hsize;
    extra->SizeOfImage = isize;
  }

  H_PUT_16 (abfd, aouthdr_in->magic, aouthdr_out->standard.magic);

  if (extra->MajorLinkerVersion || extra->MinorLinkerVersion)
    {
      H_PUT_8 (abfd, extra->MajorLinkerVersion,
               aouthdr_out->standard.vstamp);
      H_PUT_8 (abfd, extra->MinorLinkerVersion,
               aouthdr_out->standard.vstamp + 1);
    }
  else
    {
      short linker_version = (short) (BFD_VERSION / 1000000);
      unsigned short vs = (unsigned short) (linker_version / 100
                           + (linker_version % 100) * 256);
      H_PUT_16 (abfd, vs, aouthdr_out->standard.vstamp);
    }

  PUT_AOUTHDR_TSIZE (abfd, aouthdr_in->tsize, aouthdr_out->standard.tsize);
  PUT_AOUTHDR_DSIZE (abfd, aouthdr_in->dsize, aouthdr_out->standard.dsize);
  PUT_AOUTHDR_BSIZE (abfd, aouthdr_in->bsize, aouthdr_out->standard.bsize);
  PUT_AOUTHDR_ENTRY (abfd, aouthdr_in->entry, aouthdr_out->standard.entry);
  PUT_AOUTHDR_TEXT_START (abfd, aouthdr_in->text_start,
                          aouthdr_out->standard.text_start);

#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
  PUT_AOUTHDR_DATA_START (abfd, aouthdr_in->data_start,
                          aouthdr_out->standard.data_start);
#endif

  PUT_OPTHDR_IMAGE_BASE (abfd, extra->ImageBase, aouthdr_out->ImageBase);
  H_PUT_32 (abfd, extra->SectionAlignment, aouthdr_out->SectionAlignment);
  H_PUT_32 (abfd, extra->FileAlignment, aouthdr_out->FileAlignment);
  H_PUT_16 (abfd, extra->MajorOperatingSystemVersion,
            aouthdr_out->MajorOperatingSystemVersion);
  H_PUT_16 (abfd, extra->MinorOperatingSystemVersion,
            aouthdr_out->MinorOperatingSystemVersion);
  H_PUT_16 (abfd, extra->MajorImageVersion, aouthdr_out->MajorImageVersion);
  H_PUT_16 (abfd, extra->MinorImageVersion, aouthdr_out->MinorImageVersion);
  H_PUT_16 (abfd, extra->MajorSubsystemVersion,
            aouthdr_out->MajorSubsystemVersion);
  H_PUT_16 (abfd, extra->MinorSubsystemVersion,
            aouthdr_out->MinorSubsystemVersion);
  H_PUT_32 (abfd, extra->Win32Version, aouthdr_out->Win32Version);
  H_PUT_32 (abfd, extra->SizeOfImage, aouthdr_out->SizeOfImage);
  H_PUT_32 (abfd, extra->SizeOfHeaders, aouthdr_out->SizeOfHeaders);
  H_PUT_32 (abfd, extra->CheckSum, aouthdr_out->CheckSum);
  H_PUT_16 (abfd, extra->Subsystem, aouthdr_out->Subsystem);
  H_PUT_16 (abfd, extra->DllCharacteristics, aouthdr_out->DllCharacteristics);
  PUT_OPTHDR_SIZE_OF_STACK_RESERVE (abfd, extra->SizeOfStackReserve,
                                    aouthdr_out->SizeOfStackReserve);
  PUT_OPTHDR_SIZE_OF_STACK_COMMIT (abfd, extra->SizeOfStackCommit,
                                   aouthdr_out->SizeOfStackCommit);
  PUT_OPTHDR_SIZE_OF_HEAP_RESERVE (abfd, extra->SizeOfHeapReserve,
                                   aouthdr_out->SizeOfHeapReserve);
  PUT_OPTHDR_SIZE_OF_HEAP_COMMIT (abfd, extra->SizeOfHeapCommit,
                                  aouthdr_out->SizeOfHeapCommit);
  H_PUT_32 (abfd, extra->LoaderFlags, aouthdr_out->LoaderFlags);
  H_PUT_32 (abfd, extra->NumberOfRvaAndSizes,
            aouthdr_out->NumberOfRvaAndSizes);

  {
    int idx;
    for (idx = 0; idx < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; idx++)
      {
        H_PUT_32 (abfd, extra->DataDirectory[idx].VirtualAddress,
                  aouthdr_out->DataDirectory[idx][0]);
        H_PUT_32 (abfd, extra->DataDirectory[idx].Size,
                  aouthdr_out->DataDirectory[idx][1]);
      }
  }

  return AOUTSZ;
}

unsigned int
_bfd_XXi_only_swap_filehdr_out (bfd *abfd, void *in, void *out)
{
  struct internal_filehdr *filehdr_in = (struct internal_filehdr *) in;
  struct external_PEI_filehdr *filehdr_out = (struct external_PEI_filehdr *) out;
  size_t i;

  if (abfd == NULL || filehdr_in == NULL || filehdr_out == NULL || pe_data (abfd) == NULL)
    return 0;

  if (pe_data (abfd)->has_reloc_section || pe_data (abfd)->dont_strip_reloc)
    filehdr_in->f_flags &= ~F_RELFLG;

  if (pe_data (abfd)->dll)
    filehdr_in->f_flags |= F_DLL;

  filehdr_in->pe.e_magic    = IMAGE_DOS_SIGNATURE;
  filehdr_in->pe.e_cblp     = 0x90;
  filehdr_in->pe.e_cp       = 0x3;
  filehdr_in->pe.e_crlc     = 0x0;
  filehdr_in->pe.e_cparhdr  = 0x4;
  filehdr_in->pe.e_minalloc = 0x0;
  filehdr_in->pe.e_maxalloc = 0xffff;
  filehdr_in->pe.e_ss       = 0x0;
  filehdr_in->pe.e_sp       = 0xb8;
  filehdr_in->pe.e_csum     = 0x0;
  filehdr_in->pe.e_ip       = 0x0;
  filehdr_in->pe.e_cs       = 0x0;
  filehdr_in->pe.e_lfarlc   = 0x40;
  filehdr_in->pe.e_ovno     = 0x0;

  memset (filehdr_in->pe.e_res, 0, sizeof (filehdr_in->pe.e_res));

  filehdr_in->pe.e_oemid   = 0x0;
  filehdr_in->pe.e_oeminfo = 0x0;

  memset (filehdr_in->pe.e_res2, 0, sizeof (filehdr_in->pe.e_res2));

  filehdr_in->pe.e_lfanew = 0x80;

  memcpy (filehdr_in->pe.dos_message, pe_data (abfd)->dos_message,
          sizeof (filehdr_in->pe.dos_message));

  filehdr_in->pe.nt_signature = IMAGE_NT_SIGNATURE;

  H_PUT_16 (abfd, filehdr_in->f_magic, filehdr_out->f_magic);
  H_PUT_16 (abfd, filehdr_in->f_nscns, filehdr_out->f_nscns);

  {
    time_t ts = (pe_data (abfd)->timestamp == -1)
                ? bfd_get_current_time (0)
                : pe_data (abfd)->timestamp;
    H_PUT_32 (abfd, ts, filehdr_out->f_timdat);
  }

  PUT_FILEHDR_SYMPTR (abfd, filehdr_in->f_symptr, filehdr_out->f_symptr);
  H_PUT_32 (abfd, filehdr_in->f_nsyms, filehdr_out->f_nsyms);
  H_PUT_16 (abfd, filehdr_in->f_opthdr, filehdr_out->f_opthdr);
  H_PUT_16 (abfd, filehdr_in->f_flags, filehdr_out->f_flags);

  H_PUT_16 (abfd, filehdr_in->pe.e_magic,    filehdr_out->e_magic);
  H_PUT_16 (abfd, filehdr_in->pe.e_cblp,     filehdr_out->e_cblp);
  H_PUT_16 (abfd, filehdr_in->pe.e_cp,       filehdr_out->e_cp);
  H_PUT_16 (abfd, filehdr_in->pe.e_crlc,     filehdr_out->e_crlc);
  H_PUT_16 (abfd, filehdr_in->pe.e_cparhdr,  filehdr_out->e_cparhdr);
  H_PUT_16 (abfd, filehdr_in->pe.e_minalloc, filehdr_out->e_minalloc);
  H_PUT_16 (abfd, filehdr_in->pe.e_maxalloc, filehdr_out->e_maxalloc);
  H_PUT_16 (abfd, filehdr_in->pe.e_ss,       filehdr_out->e_ss);
  H_PUT_16 (abfd, filehdr_in->pe.e_sp,       filehdr_out->e_sp);
  H_PUT_16 (abfd, filehdr_in->pe.e_csum,     filehdr_out->e_csum);
  H_PUT_16 (abfd, filehdr_in->pe.e_ip,       filehdr_out->e_ip);
  H_PUT_16 (abfd, filehdr_in->pe.e_cs,       filehdr_out->e_cs);
  H_PUT_16 (abfd, filehdr_in->pe.e_lfarlc,   filehdr_out->e_lfarlc);
  H_PUT_16 (abfd, filehdr_in->pe.e_ovno,     filehdr_out->e_ovno);

  {
    size_t in_count = sizeof filehdr_in->pe.e_res / sizeof filehdr_in->pe.e_res[0];
    size_t out_count = sizeof filehdr_out->e_res / sizeof filehdr_out->e_res[0];
    size_t count = in_count < out_count ? in_count : out_count;
    for (i = 0; i < count; ++i)
      H_PUT_16 (abfd, filehdr_in->pe.e_res[i], filehdr_out->e_res[i]);
  }

  H_PUT_16 (abfd, filehdr_in->pe.e_oemid,   filehdr_out->e_oemid);
  H_PUT_16 (abfd, filehdr_in->pe.e_oeminfo, filehdr_out->e_oeminfo);

  {
    size_t in_count = sizeof filehdr_in->pe.e_res2 / sizeof filehdr_in->pe.e_res2[0];
    size_t out_count = sizeof filehdr_out->e_res2 / sizeof filehdr_out->e_res2[0];
    size_t count = in_count < out_count ? in_count : out_count;
    for (i = 0; i < count; ++i)
      H_PUT_16 (abfd, filehdr_in->pe.e_res2[i], filehdr_out->e_res2[i]);
  }

  H_PUT_32 (abfd, filehdr_in->pe.e_lfanew, filehdr_out->e_lfanew);

  memcpy (filehdr_out->dos_message, filehdr_in->pe.dos_message,
          sizeof (filehdr_out->dos_message));

  H_PUT_32 (abfd, filehdr_in->pe.nt_signature, filehdr_out->nt_signature);

  return FILHSZ;
}

unsigned int
_bfd_XX_only_swap_filehdr_out (bfd * abfd, void * in, void * out)
{
  if (abfd == NULL || in == NULL || out == NULL)
    {
      bfd_set_error (bfd_error_invalid_operation);
      return 0;
    }

  const struct internal_filehdr *filehdr_in = (const struct internal_filehdr *) in;
  FILHDR *filehdr_out = (FILHDR *) out;

  H_PUT_16 (abfd, filehdr_in->f_magic, filehdr_out->f_magic);
  H_PUT_16 (abfd, filehdr_in->f_nscns, filehdr_out->f_nscns);
  H_PUT_32 (abfd, filehdr_in->f_timdat, filehdr_out->f_timdat);
  PUT_FILEHDR_SYMPTR (abfd, filehdr_in->f_symptr, filehdr_out->f_symptr);
  H_PUT_32 (abfd, filehdr_in->f_nsyms, filehdr_out->f_nsyms);
  H_PUT_16 (abfd, filehdr_in->f_opthdr, filehdr_out->f_opthdr);
  H_PUT_16 (abfd, filehdr_in->f_flags, filehdr_out->f_flags);

  return FILHSZ;
}

unsigned int
_bfd_XXi_swap_scnhdr_out (bfd *abfd, void *in, void *out)
{
  struct internal_scnhdr *scnhdr_int = (struct internal_scnhdr *) in;
  SCNHDR *scnhdr_ext = (SCNHDR *) out;
  unsigned int ret = SCNHSZ;
  bfd_vma ps = 0;
  bfd_vma ss = 0;

  if (abfd == NULL || scnhdr_int == NULL || scnhdr_ext == NULL)
    {
      if (abfd != NULL)
        bfd_set_error (bfd_error_invalid_operation);
      return 0;
    }

  memcpy (scnhdr_ext->s_name, scnhdr_int->s_name, sizeof (scnhdr_int->s_name));

  {
    bfd_vma image_base = pe_data (abfd)->pe_opthdr.ImageBase;
    if (scnhdr_int->s_vaddr < image_base)
      {
        _bfd_error_handler (_("%pB:%.8s: section below image base"),
                            abfd, scnhdr_int->s_name);
        ss = 0;
      }
    else
      {
        ss = scnhdr_int->s_vaddr - image_base;
      }

#if !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
    if (scnhdr_int->s_vaddr >= image_base)
      {
        if (ss != (ss & 0xffffffff))
          _bfd_error_handler (_("%pB:%.8s: RVA truncated"), abfd, scnhdr_int->s_name);
        PUT_SCNHDR_VADDR (abfd, ss & 0xffffffff, scnhdr_ext->s_vaddr);
      }
    else
      {
        PUT_SCNHDR_VADDR (abfd, ss & 0xffffffff, scnhdr_ext->s_vaddr);
      }
#else
    PUT_SCNHDR_VADDR (abfd, ss, scnhdr_ext->s_vaddr);
#endif
  }

  if ((scnhdr_int->s_flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0)
    {
      if (bfd_pei_p (abfd))
        {
          ps = scnhdr_int->s_size;
          ss = 0;
        }
      else
        {
          ps = 0;
          ss = scnhdr_int->s_size;
        }
    }
  else
    {
      ps = bfd_pei_p (abfd) ? scnhdr_int->s_paddr : 0;
      ss = scnhdr_int->s_size;
    }

  PUT_SCNHDR_SIZE (abfd, ss, scnhdr_ext->s_size);
  PUT_SCNHDR_PADDR (abfd, ps, scnhdr_ext->s_paddr);

  PUT_SCNHDR_SCNPTR (abfd, scnhdr_int->s_scnptr, scnhdr_ext->s_scnptr);
  PUT_SCNHDR_RELPTR (abfd, scnhdr_int->s_relptr, scnhdr_ext->s_relptr);
  PUT_SCNHDR_LNNOPTR (abfd, scnhdr_int->s_lnnoptr, scnhdr_ext->s_lnnoptr);

  {
    typedef struct
    {
      char section_name[SCNNMLEN];
      unsigned long must_have;
    } pe_required_section_flags;

    static const pe_required_section_flags known_sections[] =
      {
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
        { ".xdata", IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA },
      };

    int i;
    int is_text = (memcmp (scnhdr_int->s_name, ".text", sizeof ".text") == 0);

    for (i = 0; i < (int) ARRAY_SIZE (known_sections); i++)
      {
        if (memcmp (scnhdr_int->s_name, known_sections[i].section_name, SCNNMLEN) == 0)
          {
            if (!is_text || (bfd_get_file_flags (abfd) & WP_TEXT))
              scnhdr_int->s_flags &= ~IMAGE_SCN_MEM_WRITE;

            scnhdr_int->s_flags |= known_sections[i].must_have;
            break;
          }
      }

    H_PUT_32 (abfd, scnhdr_int->s_flags, scnhdr_ext->s_flags);
  }

  {
    struct bfd_link_info *link_info = coff_data (abfd) ? coff_data (abfd)->link_info : NULL;
    int is_text = (memcmp (scnhdr_int->s_name, ".text", sizeof ".text") == 0);

    if (link_info
        && !bfd_link_relocatable (link_info)
        && !bfd_link_pic (link_info)
        && is_text)
      {
        H_PUT_16 (abfd, (scnhdr_int->s_nlnno & 0xffff), scnhdr_ext->s_nlnno);
        H_PUT_16 (abfd, (scnhdr_int->s_nlnno >> 16), scnhdr_ext->s_nreloc);
      }
    else
      {
        if (scnhdr_int->s_nlnno <= 0xffff)
          {
            H_PUT_16 (abfd, scnhdr_int->s_nlnno, scnhdr_ext->s_nlnno);
          }
        else
          {
            _bfd_error_handler (_("%pB: line number overflow: 0x%lx > 0xffff"),
                                abfd, scnhdr_int->s_nlnno);
            bfd_set_error (bfd_error_file_truncated);
            H_PUT_16 (abfd, 0xffff, scnhdr_ext->s_nlnno);
            ret = 0;
          }

        if (scnhdr_int->s_nreloc < 0xffff)
          {
            H_PUT_16 (abfd, scnhdr_int->s_nreloc, scnhdr_ext->s_nreloc);
          }
        else
          {
            H_PUT_16 (abfd, 0xffff, scnhdr_ext->s_nreloc);
            scnhdr_int->s_flags |= IMAGE_SCN_LNK_NRELOC_OVFL;
            H_PUT_32 (abfd, scnhdr_int->s_flags, scnhdr_ext->s_flags);
          }
      }
  }

  return ret;
}

void
_bfd_XXi_swap_debugdir_in(bfd *abfd, void *ext1, void *in1)
{
  if (abfd == NULL || ext1 == NULL || in1 == NULL)
    return;

  const struct external_IMAGE_DEBUG_DIRECTORY *ext =
    (const struct external_IMAGE_DEBUG_DIRECTORY *) ext1;
  struct internal_IMAGE_DEBUG_DIRECTORY *in =
    (struct internal_IMAGE_DEBUG_DIRECTORY *) in1;

  in->Characteristics = H_GET_32(abfd, ext->Characteristics);
  in->TimeDateStamp = H_GET_32(abfd, ext->TimeDateStamp);
  in->MajorVersion = H_GET_16(abfd, ext->MajorVersion);
  in->MinorVersion = H_GET_16(abfd, ext->MinorVersion);
  in->Type = H_GET_32(abfd, ext->Type);
  in->SizeOfData = H_GET_32(abfd, ext->SizeOfData);
  in->AddressOfRawData = H_GET_32(abfd, ext->AddressOfRawData);
  in->PointerToRawData = H_GET_32(abfd, ext->PointerToRawData);
}

unsigned int
_bfd_XXi_swap_debugdir_out(bfd *abfd, void *inp, void *extp)
{
  if (abfd == NULL || inp == NULL || extp == NULL)
    return 0;

  const struct internal_IMAGE_DEBUG_DIRECTORY *in = inp;
  struct external_IMAGE_DEBUG_DIRECTORY *ext = extp;

  H_PUT_32(abfd, in->Characteristics, ext->Characteristics);
  H_PUT_32(abfd, in->TimeDateStamp, ext->TimeDateStamp);
  H_PUT_16(abfd, in->MajorVersion, ext->MajorVersion);
  H_PUT_16(abfd, in->MinorVersion, ext->MinorVersion);
  H_PUT_32(abfd, in->Type, ext->Type);
  H_PUT_32(abfd, in->SizeOfData, ext->SizeOfData);
  H_PUT_32(abfd, in->AddressOfRawData, ext->AddressOfRawData);
  H_PUT_32(abfd, in->PointerToRawData, ext->PointerToRawData);

  return (unsigned int) sizeof(*ext);
}

CODEVIEW_INFO *
_bfd_XXi_slurp_codeview_record (bfd *abfd, file_ptr where, unsigned long length, CODEVIEW_INFO *cvinfo, char **pdb)
{
  char buffer[256 + 1];
  bfd_size_type nread;
  unsigned long min_size;

  if (abfd == NULL || cvinfo == NULL)
    return NULL;

  if (bfd_seek (abfd, where, SEEK_SET) != 0)
    return NULL;

  min_size = (sizeof (CV_INFO_PDB70) < sizeof (CV_INFO_PDB20))
             ? (unsigned long) sizeof (CV_INFO_PDB70)
             : (unsigned long) sizeof (CV_INFO_PDB20);
  if (length <= min_size)
    return NULL;

  if (length > 256)
    length = 256;

  nread = bfd_read (buffer, length, abfd);
  if (nread != length)
    return NULL;

  if ((size_t) nread < sizeof (buffer))
    memset (buffer + nread, 0, sizeof (buffer) - nread);

  cvinfo->CVSignature = H_GET_32 (abfd, buffer);
  cvinfo->Age = 0;

  if ((cvinfo->CVSignature == CVINFO_PDB70_CVSIGNATURE)
      && (length > sizeof (CV_INFO_PDB70)))
    {
      CV_INFO_PDB70 *cvinfo70 = (CV_INFO_PDB70 *) (void *) buffer;

      cvinfo->Age = H_GET_32 (abfd, cvinfo70->Age);
      bfd_putb32 (bfd_getl32 (cvinfo70->Signature), cvinfo->Signature);
      bfd_putb16 (bfd_getl16 (&(cvinfo70->Signature[4])), &(cvinfo->Signature[4]));
      bfd_putb16 (bfd_getl16 (&(cvinfo70->Signature[6])), &(cvinfo->Signature[6]));
      memcpy (&(cvinfo->Signature[8]), &(cvinfo70->Signature[8]), 8);

      cvinfo->SignatureLength = CV_INFO_SIGNATURE_LENGTH;

      if (pdb)
        *pdb = xstrdup (cvinfo70->PdbFileName);

      return cvinfo;
    }
  else if ((cvinfo->CVSignature == CVINFO_PDB20_CVSIGNATURE)
           && (length > sizeof (CV_INFO_PDB20)))
    {
      CV_INFO_PDB20 *cvinfo20 = (CV_INFO_PDB20 *) (void *) buffer;

      cvinfo->Age = H_GET_32 (abfd, cvinfo20->Age);
      memcpy (cvinfo->Signature, cvinfo20->Signature, 4);
      cvinfo->SignatureLength = 4;

      if (pdb)
        *pdb = xstrdup (cvinfo20->PdbFileName);

      return cvinfo;
    }

  return NULL;
}

unsigned int
_bfd_XXi_write_codeview_record (bfd *abfd, file_ptr where, CODEVIEW_INFO *cvinfo, const char *pdb)
{
  if (abfd == NULL || cvinfo == NULL)
    return 0;

  if (bfd_seek (abfd, where, SEEK_SET) != 0)
    return 0;

  size_t pdb_len = 0;
  if (pdb != NULL)
    pdb_len = strlen (pdb);

  const size_t base = sizeof (CV_INFO_PDB70) + 1U;
  if (pdb_len > (size_t) -1 - base)
    return 0;

  size_t total = base + pdb_len;
  bfd_size_type size = (bfd_size_type) total;
  if ((size_t) size != total)
    return 0;

  char *buffer = bfd_malloc (size);
  if (buffer == NULL)
    return 0;

  CV_INFO_PDB70 *cvinfo70 = (CV_INFO_PDB70 *) buffer;
  H_PUT_32 (abfd, CVINFO_PDB70_CVSIGNATURE, cvinfo70->CvSignature);

  bfd_putl32 (bfd_getb32 (cvinfo->Signature), cvinfo70->Signature);
  bfd_putl16 (bfd_getb16 (&cvinfo->Signature[4]), &cvinfo70->Signature[4]);
  bfd_putl16 (bfd_getb16 (&cvinfo->Signature[6]), &cvinfo70->Signature[6]);
  memcpy (&cvinfo70->Signature[8], &cvinfo->Signature[8], 8);

  H_PUT_32 (abfd, cvinfo->Age, cvinfo70->Age);

  if (pdb == NULL)
    cvinfo70->PdbFileName[0] = '\0';
  else
    memcpy (cvinfo70->PdbFileName, pdb, pdb_len + 1U);

  bfd_size_type written = bfd_write (buffer, size, abfd);
  free (buffer);

  return written == size ? (unsigned int) size : 0;
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

static bool
get_contents_sanity_check (bfd *abfd, asection *section,
                           bfd_size_type dataoff, bfd_size_type datasize)
{
  const flagword flags = section->flags;
  const bfd_size_type sec_size = section->size;

  if ((flags & SEC_HAS_CONTENTS) == 0)
    return false;

  if (dataoff > sec_size)
    return false;

  if (datasize > sec_size - dataoff)
    return false;

  {
    const ufile_ptr filesize = bfd_get_file_size (abfd);
    if (filesize != 0)
      {
        const ufile_ptr fpos = (ufile_ptr) section->filepos;
        if (fpos > filesize)
          return false;

        const ufile_ptr avail = filesize - fpos;

        if ((ufile_ptr) dataoff > avail)
          return false;

        if ((ufile_ptr) datasize > (avail - (ufile_ptr) dataoff))
          return false;
      }
  }

  return true;
}

static bool
pe_print_idata (bfd * abfd, void * vfile)
{
  FILE *file = (FILE *) vfile;
  bfd_byte *data = NULL;
  asection *section = NULL;
  bfd_signed_vma adj;
  bfd_size_type datasize = 0;
  bfd_size_type dataoff;
  bfd_size_type i;
  const int onaline = 20;

  pe_data_type *pe = pe_data (abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;

  bfd_vma addr = extra->DataDirectory[PE_IMPORT_TABLE].VirtualAddress;

  if (addr == 0 && extra->DataDirectory[PE_IMPORT_TABLE].Size == 0)
    {
      section = bfd_get_section_by_name (abfd, ".idata");
      if (section == NULL || (section->flags & SEC_HAS_CONTENTS) == 0)
        return true;

      addr = section->vma;
      datasize = section->size;
      if (datasize == 0)
        return true;
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
          fprintf (file,
                   _("\nThere is an import table, but the section containing it could not be found\n"));
          return true;
        }

      if ((section->flags & SEC_HAS_CONTENTS) == 0)
        {
          fprintf (file,
                   _("\nThere is an import table in %s, but that section has no contents\n"),
                   section->name);
          return true;
        }
    }

  fprintf (file, _("\nThere is an import table in %s at 0x%lx\n"),
           section->name, (unsigned long) addr);

  dataoff = addr - section->vma;

  fprintf (file,
           _("\nThe Import Tables (interpreted %s section contents)\n"),
           section->name);
  fprintf (file,
           _("\
 vma:            Hint    Time      Forward  DLL       First\n\
                 Table   Stamp     Chain    Name      Thunk\n"));

  if (!bfd_malloc_and_get_section (abfd, section, &data))
    {
      free (data);
      return false;
    }

  adj = section->vma - extra->ImageBase;

  for (i = dataoff; i + onaline <= datasize; i += onaline)
    {
      bfd_vma hint_addr = bfd_get_32 (abfd, data + i);
      bfd_vma time_stamp = bfd_get_32 (abfd, data + i + 4);
      bfd_vma forward_chain = bfd_get_32 (abfd, data + i + 8);
      bfd_vma dll_name = bfd_get_32 (abfd, data + i + 12);
      bfd_vma first_thunk = bfd_get_32 (abfd, data + i + 16);
      bfd_size_type idx = 0;
      bfd_size_type j;
      char *dll;

      fprintf (file, " %08lx\t", (unsigned long) (i + adj));

      fprintf (file, "%08lx %08lx %08lx %08lx %08lx\n",
               (unsigned long) hint_addr,
               (unsigned long) time_stamp,
               (unsigned long) forward_chain,
               (unsigned long) dll_name,
               (unsigned long) first_thunk);

      if (hint_addr == 0 && first_thunk == 0)
        break;

      if (dll_name < adj || dll_name - adj >= datasize)
        break;

      dll = (char *) data + dll_name - adj;

      {
        bfd_size_type remaining = datasize - (bfd_size_type) ((bfd_byte *) dll - data);
        if (remaining > 0)
          remaining--;
        else
          remaining = 0;
        int maxlen = remaining > (bfd_size_type) INT_MAX ? INT_MAX : (int) remaining;
        fprintf (file, _("\n\tDLL Name: %.*s\n"), maxlen, dll);
      }

      if (hint_addr == 0)
        hint_addr = first_thunk;

      if (hint_addr != 0 && hint_addr >= adj && hint_addr - adj < datasize)
        {
          bfd_byte *ft_data;
          asection *ft_section;
          bfd_vma ft_addr;
          bfd_size_type ft_datasize;
          bfd_size_type ft_idx;
          bool ft_allocated = false;

          fprintf (file, _("\tvma:     Ordinal  Hint  Member-Name  Bound-To\n"));

          idx = hint_addr - adj;

          ft_addr = first_thunk + extra->ImageBase;
          ft_idx = first_thunk - adj;
          ft_data = data + ft_idx;
          ft_datasize = (ft_idx <= datasize) ? (datasize - ft_idx) : 0;

          if (first_thunk != hint_addr)
            {
              for (ft_section = abfd->sections;
                   ft_section != NULL;
                   ft_section = ft_section->next)
                {
                  if (ft_addr >= ft_section->vma
                      && ft_addr < ft_section->vma + ft_section->size)
                    break;
                }

              if (ft_section == NULL)
                {
                  fprintf (file,
                           _("\nThere is a first thunk, but the section containing it could not be found\n"));
                  goto after_print_entries;
                }

              if (ft_section != section)
                {
                  ft_idx = first_thunk - (ft_section->vma - extra->ImageBase);
                  if (ft_idx > ft_section->size)
                    goto after_print_entries;

                  ft_datasize = ft_section->size - ft_idx;

                  if (!get_contents_sanity_check (abfd, ft_section, ft_idx, ft_datasize))
                    goto after_print_entries;

                  ft_data = (bfd_byte *) bfd_malloc (ft_datasize);
                  if (ft_data == NULL)
                    goto after_print_entries;

                  if (!bfd_get_section_contents (abfd, ft_section, ft_data,
                                                 (bfd_vma) ft_idx, ft_datasize))
                    {
                      free (ft_data);
                      goto after_print_entries;
                    }
                  ft_allocated = true;
                }
            }

#ifdef COFF_WITH_pex64
          for (j = 0; idx + j + 8 <= datasize; j += 8)
            {
              bfd_size_type amt;
              unsigned long member = bfd_get_32 (abfd, data + idx + j);
              unsigned long member_high = bfd_get_32 (abfd, data + idx + j + 4);

              if (!member && !member_high)
                break;

              amt = (bfd_size_type) member - adj;

              if (HighBitSet (member_high))
                {
                  unsigned int ordinal = member & 0xffff;
                  fprintf (file, "\t%08lx  %5u  <none> <none>",
                           (unsigned long)(first_thunk + j), ordinal);
                }
              else if (amt >= datasize || amt + 2 >= datasize)
                fprintf (file, _("\t<corrupt: 0x%08lx>"), member);
              else
                {
                  unsigned int hint = bfd_get_16 (abfd, data + amt);
                  char *member_name = (char *) data + amt + 2;
                  fprintf (file, "\t%08lx  <none>  %04x  %.*s",
                           (unsigned long)(first_thunk + j), hint,
                           (int) (datasize - (amt + 2)), member_name);
                }

              if (time_stamp != 0
                  && first_thunk != 0
                  && first_thunk != hint_addr
                  && j + 4 <= ft_datasize)
                fprintf (file, "\t%08lx",
                         (unsigned long) bfd_get_32 (abfd, ft_data + j));

              fprintf (file, "\n");
            }
#else
          for (j = 0; idx + j + 4 <= datasize; j += 4)
            {
              bfd_size_type amt;
              unsigned long member = bfd_get_32 (abfd, data + idx + j);

              if (member == 0)
                break;

              amt = (bfd_size_type) member - adj;

              if (HighBitSet (member))
                {
                  unsigned int ordinal = member & 0xffff;
                  fprintf (file, "\t%08lx  %5u  <none> <none>",
                           (unsigned long)(first_thunk + j), ordinal);
                }
              else if (amt >= datasize || amt + 2 >= datasize)
                fprintf (file, _("\t<corrupt: 0x%08lx>"), member);
              else
                {
                  unsigned int hint = bfd_get_16 (abfd, data + amt);
                  char *member_name = (char *) data + amt + 2;
                  fprintf (file, "\t%08lx  <none>  %04x  %.*s",
                           (unsigned long)(first_thunk + j), hint,
                           (int) (datasize - (amt + 2)), member_name);
                }

              if (time_stamp != 0
                  && first_thunk != 0
                  && first_thunk != hint_addr
                  && j + 4 <= ft_datasize)
                fprintf (file, "\t%08lx",
                         (unsigned long) bfd_get_32 (abfd, ft_data + j));

              fprintf (file, "\n");
            }
#endif
          if (ft_allocated)
            free (ft_data);

after_print_entries:
          ;
        }

      fprintf (file, "\n");
    }

  free (data);
  return true;
}

static bool
pe_print_edata (bfd * abfd, void * vfile)
{
  FILE *file = (FILE *) vfile;
  bfd_byte *data = NULL;
  asection *section = NULL;
  bfd_size_type datasize = 0;
  bfd_size_type dataoff = 0;
  bfd_size_type i;
  bfd_vma adj;
  struct EDT_type
  {
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

  pe_data_type *pe = pe_data (abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
  bfd_vma addr = extra->DataDirectory[PE_EXPORT_TABLE].VirtualAddress;
  bfd_size_type dd_size = extra->DataDirectory[PE_EXPORT_TABLE].Size;
  bool result = true;

  if (addr == 0 && dd_size == 0)
    {
      section = bfd_get_section_by_name (abfd, ".edata");
      if (section == NULL)
        goto done;

      addr = section->vma;
      dataoff = 0;
      datasize = section->size;
      if (datasize == 0)
        goto done;
    }
  else
    {
      addr += extra->ImageBase;

      for (section = abfd->sections; section != NULL; section = section->next)
        if (addr >= section->vma && addr < section->vma + section->size)
          break;

      if (section == NULL)
        {
          fprintf (file,
                   _("\nThere is an export table, but the section containing it could not be found\n"));
          goto done;
        }

      dataoff = addr - section->vma;
      datasize = dd_size;
    }

  if (datasize < 40)
    {
      fprintf (file,
               _("\nThere is an export table in %s, but it is too small (%d)\n"),
               section->name, (int) datasize);
      goto done;
    }

  if (!get_contents_sanity_check (abfd, section, dataoff, datasize))
    {
      fprintf (file,
               _("\nThere is an export table in %s, but contents cannot be read\n"),
               section->name);
      goto done;
    }

  fprintf (file, _("\nThere is an export table in %s at 0x%lx\n"),
           section->name, (unsigned long) addr);

  data = (bfd_byte *) bfd_malloc (datasize);
  if (data == NULL)
    {
      result = false;
      goto done;
    }

  if (! bfd_get_section_contents (abfd, section, data,
                                  (file_ptr) dataoff, datasize))
    {
      result = false;
      goto done;
    }

  edt.export_flags   = bfd_get_32 (abfd, data +  0);
  edt.time_stamp     = bfd_get_32 (abfd, data +  4);
  edt.major_ver      = bfd_get_16 (abfd, data +  8);
  edt.minor_ver      = bfd_get_16 (abfd, data + 10);
  edt.name           = bfd_get_32 (abfd, data + 12);
  edt.base           = bfd_get_32 (abfd, data + 16);
  edt.num_functions  = bfd_get_32 (abfd, data + 20);
  edt.num_names      = bfd_get_32 (abfd, data + 24);
  edt.eat_addr       = bfd_get_32 (abfd, data + 28);
  edt.npt_addr       = bfd_get_32 (abfd, data + 32);
  edt.ot_addr        = bfd_get_32 (abfd, data + 36);

  adj = section->vma - extra->ImageBase + dataoff;

  fprintf (file,
           _("\nThe Export Tables (interpreted %s section contents)\n\n"),
           section->name);

  fprintf (file, _("Export Flags \t\t\t%lx\n"), (unsigned long) edt.export_flags);
  fprintf (file, _("Time/Date stamp \t\t%lx\n"), (unsigned long) edt.time_stamp);
  fprintf (file, _("Major/Minor \t\t\t%d/%d\n"), edt.major_ver, edt.minor_ver);

  fprintf (file, _("Name \t\t\t\t"));
  bfd_fprintf_vma (abfd, file, edt.name);

  if ((edt.name >= adj) && ((bfd_size_type)(edt.name - adj) < datasize))
    fprintf (file, " %.*s\n",
             (int) (datasize - (bfd_size_type)(edt.name - adj)),
             data + (bfd_size_type)(edt.name - adj));
  else
    fprintf (file, "(outside .edata section)\n");

  fprintf (file, _("Ordinal Base \t\t\t%ld\n"), edt.base);

  fprintf (file, _("Number in:\n"));
  fprintf (file, _("\tExport Address Table \t\t%08lx\n"), edt.num_functions);
  fprintf (file, _("\t[Name Pointer/Ordinal] Table\t%08lx\n"), edt.num_names);

  fprintf (file, _("Table Addresses\n"));

  fprintf (file, _("\tExport Address Table \t\t"));
  bfd_fprintf_vma (abfd, file, edt.eat_addr);
  fprintf (file, "\n");

  fprintf (file, _("\tName Pointer Table \t\t"));
  bfd_fprintf_vma (abfd, file, edt.npt_addr);
  fprintf (file, "\n");

  fprintf (file, _("\tOrdinal Table \t\t\t"));
  bfd_fprintf_vma (abfd, file, edt.ot_addr);
  fprintf (file, "\n");

  fprintf (file, _("\nExport Address Table -- Ordinal Base %ld\n"), edt.base);
  fprintf (file, "\t          Ordinal  Address  Type\n");

  if (edt.eat_addr - adj >= datasize
      || (edt.num_functions + 1) * 4 < edt.num_functions
      || edt.eat_addr - adj + (edt.num_functions + 1) * 4 > datasize)
    fprintf (file, _("\tInvalid Export Address Table rva (0x%lx) or entry count (0x%lx)\n"),
             (long) edt.eat_addr, (long) edt.num_functions);
  else
    for (i = 0; i < edt.num_functions; ++i)
      {
        bfd_vma eat_member = bfd_get_32 (abfd,
                                         data + edt.eat_addr + (i * 4) - adj);
        if (eat_member == 0)
          continue;

        if (eat_member - adj <= datasize)
          {
            fprintf (file,
                     "\t[%4ld] +base[%4ld] %08lx %s -- %.*s\n",
                     (long) i,
                     (long) (i + edt.base),
                     (unsigned long) eat_member,
                     _("Forwarder RVA"),
                     (int)(datasize - (bfd_size_type)(eat_member - adj)),
                     data + (bfd_size_type)(eat_member - adj));
          }
        else
          {
            fprintf (file,
                     "\t[%4ld] +base[%4ld] %08lx %s\n",
                     (long) i,
                     (long) (i + edt.base),
                     (unsigned long) eat_member,
                     _("Export RVA"));
          }
      }

  fprintf (file, _("\n[Ordinal/Name Pointer] Table -- Ordinal Base %ld\n"),
           edt.base);
  fprintf (file, "\t          Ordinal   Hint Name\n");

  if (edt.npt_addr + (edt.num_names * 4) - adj >= datasize
      || edt.num_names * 4 < edt.num_names
      || (data + edt.npt_addr - adj) < data)
    fprintf (file, _("\tInvalid Name Pointer Table rva (0x%lx) or entry count (0x%lx)\n"),
             (long) edt.npt_addr, (long) edt.num_names);
  else if (edt.ot_addr + (edt.num_names * 2) - adj >= datasize
           || data + edt.ot_addr - adj < data)
    fprintf (file, _("\tInvalid Ordinal Table rva (0x%lx) or entry count (0x%lx)\n"),
             (long) edt.ot_addr, (long) edt.num_names);
  else
    for (i = 0; i < edt.num_names; ++i)
      {
        bfd_vma ord = bfd_get_16 (abfd, data + edt.ot_addr + (i * 2) - adj);
        bfd_vma name_ptr = bfd_get_32 (abfd, data + edt.npt_addr + (i * 4) - adj);

        if ((name_ptr - adj) >= datasize)
          {
            fprintf (file, _("\t[%4ld] +base[%4ld]  %04lx <corrupt offset: %lx>\n"),
                     (long) ord, (long) (ord + edt.base), (long) i, (long) name_ptr);
          }
        else
          {
            char *name = (char *) data + (bfd_size_type)(name_ptr - adj);
            fprintf (file,
                     "\t[%4ld] +base[%4ld]  %04lx %.*s\n",
                     (long) ord, (long) (ord + edt.base), (long) i,
                     (int)((char *)(data + datasize) - name), name);
          }
      }

done:
  free (data);
  return result;
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
pe_print_pdata (bfd *abfd, void *vfile)
{
#if defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
# define PDATA_ROW_SIZE (3 * 8)
#else
# define PDATA_ROW_SIZE (5 * 4)
#endif
  FILE *file = (FILE *) vfile;
  bfd_byte *data = NULL;
  asection *section = bfd_get_section_by_name (abfd, ".pdata");
  bfd_size_type datasize;
  bfd_size_type stop;
  bfd_size_type i;
  int row_size = PDATA_ROW_SIZE;

  if (section == NULL
      || (section->flags & SEC_HAS_CONTENTS) == 0
      || coff_section_data (abfd, section) == NULL
      || pei_section_data (abfd, section) == NULL)
    return true;

  stop = pei_section_data (abfd, section)->virt_size;
  if ((stop % row_size) != 0)
    fprintf (file,
	     _("warning, .pdata section size (%ld) is not a multiple of %d\n"),
	     (long) stop, row_size);

  fprintf (file,
	   _("\nThe Function Table (interpreted .pdata section contents)\n"));
#if defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
  fprintf (file,
	   _(" vma:\t\t\tBegin Address    End Address      Unwind Info\n"));
#else
  fprintf (file, _("\
 vma:\t\tBegin    End      EH       EH       PrologEnd  Exception\n\
     \t\tAddress  Address  Handler  Data     Address    Mask\n"));
#endif

  datasize = section->size;
  if (datasize == 0)
    return true;

  if (datasize < stop)
    {
      fprintf (file, _("Virtual size of .pdata section (%ld) larger than real size (%ld)\n"),
	       (long) stop, (long) datasize);
      return false;
    }

  if (! bfd_malloc_and_get_section (abfd, section, &data))
    {
      free (data);
      return false;
    }

  for (i = 0; i + (bfd_size_type) row_size <= stop; i += row_size)
    {
      const bfd_byte *p = data + i;
      bfd_vma begin_addr = GET_PDATA_ENTRY (abfd, p);
      bfd_vma end_addr = GET_PDATA_ENTRY (abfd, p + 4);
      bfd_vma eh_handler = GET_PDATA_ENTRY (abfd, p + 8);
      bfd_vma eh_data = GET_PDATA_ENTRY (abfd, p + 12);
      bfd_vma prolog_end_addr = GET_PDATA_ENTRY (abfd, p + 16);
#if !defined(COFF_WITH_pep) || defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined (COFF_WITH_peRiscV64)
      int em_data = ((eh_handler & 0x1) << 2) | (prolog_end_addr & 0x3);
#endif

      if (begin_addr == 0 && end_addr == 0 && eh_handler == 0
	  && eh_data == 0 && prolog_end_addr == 0)
	break;

      eh_handler &= ~(bfd_vma) 0x3;
      prolog_end_addr &= ~(bfd_vma) 0x3;

      fputc (' ', file);
      bfd_fprintf_vma (abfd, file, i + section->vma);
      fputc ('\t', file);
      bfd_fprintf_vma (abfd, file, begin_addr);
      fputc (' ', file);
      bfd_fprintf_vma (abfd, file, end_addr);
      fputc (' ', file);
      bfd_fprintf_vma (abfd, file, eh_handler);
#if !defined(COFF_WITH_pep) || defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined (COFF_WITH_peRiscV64)
      fputc (' ', file);
      bfd_fprintf_vma (abfd, file, eh_data);
      fputc (' ', file);
      bfd_fprintf_vma (abfd, file, prolog_end_addr);
      fprintf (file, "   %x", em_data);
#endif
      fprintf (file, "\n");
    }

  free (data);
  return true;
#undef PDATA_ROW_SIZE
}

typedef struct sym_cache
{
  int	     symcount;
  asymbol ** syms;
} sym_cache;

static asymbol **
slurp_symtab (bfd *abfd, sym_cache *psc)
{
  asymbol **sy = NULL;
  long storage;

  if (abfd == NULL || psc == NULL)
    return NULL;

  if ((bfd_get_file_flags (abfd) & HAS_SYMS) == 0)
    {
      psc->symcount = 0;
      return NULL;
    }

  storage = bfd_get_symtab_upper_bound (abfd);
  if (storage < 0)
    return NULL;

  if (storage > 0)
    {
      size_t size = (size_t) storage;
      if (storage != (long) size)
        return NULL;

      sy = (asymbol **) bfd_malloc (size);
      if (sy == NULL)
        return NULL;
    }

  psc->symcount = bfd_canonicalize_symtab (abfd, sy);
  if (psc->symcount < 0)
    {
      if (sy != NULL)
        free (sy);
      return NULL;
    }

  return sy;
}

static const char *
my_symbol_for_address (bfd *abfd, bfd_vma func, sym_cache *psc)
{
  int i;

  if (psc == NULL)
    return NULL;

  if (psc->syms == 0)
    {
      if (abfd == NULL)
        return NULL;
      psc->syms = slurp_symtab (abfd, psc);
    }

  if (psc->syms == NULL || psc->symcount <= 0)
    return NULL;

  for (i = 0; i < psc->symcount; i++)
    {
      if (psc->syms[i] == NULL || psc->syms[i]->section == NULL)
        continue;

      if ((bfd_vma) (psc->syms[i]->section->vma + psc->syms[i]->value) == func)
        return psc->syms[i]->name;
    }

  return NULL;
}

static void
cleanup_syms (sym_cache *psc)
{
  if (psc == NULL)
    return;

  psc->symcount = 0;
  free (psc->syms);
  psc->syms = NULL;
}

/* This is the version for "compressed" pdata.  */

bool
_bfd_XX_print_ce_compressed_pdata (bfd * abfd, void * vfile)
{
  FILE *file = (FILE *) vfile;
  const bfd_size_type row_size = 8;
  bfd_byte *data = NULL;
  asection *section = bfd_get_section_by_name (abfd, ".pdata");
  bfd_size_type datasize = 0;
  bfd_size_type i;
  bfd_size_type stop;
  struct sym_cache cache = {0, 0};

  if (file == NULL)
    return false;

  if (section == NULL
      || (section->flags & SEC_HAS_CONTENTS) == 0
      || coff_section_data (abfd, section) == NULL
      || pei_section_data (abfd, section) == NULL)
    return true;

  stop = pei_section_data (abfd, section)->virt_size;
  if ((stop % row_size) != 0)
    fprintf (file,
	     /* xgettext:c-format */
	     _("warning, .pdata section size (%ld) is not a multiple of %d\n"),
	     (long) stop, (int) row_size);

  fprintf (file,
	   _("\nThe Function Table (interpreted .pdata section contents)\n"));

  fprintf (file, _("\
 vma:\t\tBegin    Prolog   Function Flags    Exception EH\n\
     \t\tAddress  Length   Length   32b exc  Handler   Data\n"));

  datasize = section->size;
  if (datasize == 0)
    return true;

  if (! bfd_malloc_and_get_section (abfd, section, &data))
    {
      free (data);
      return false;
    }

  if (stop > datasize)
    stop = datasize;

  asection *tsection = bfd_get_section_by_name (abfd, ".text");
  int have_text = (tsection != NULL
                   && coff_section_data (abfd, tsection) != NULL
                   && pei_section_data (abfd, tsection) != NULL);

  for (i = 0; i + row_size <= stop; i += row_size)
    {
      bfd_vma begin_addr;
      bfd_vma other_data;
      bfd_vma prolog_length, function_length;
      int flag32bit, exception_flag;

      begin_addr = GET_PDATA_ENTRY (abfd, data + i     );
      other_data = GET_PDATA_ENTRY (abfd, data + i +  4);

      if (begin_addr == 0 && other_data == 0)
	break;

      prolog_length = (other_data & 0x000000FF);
      function_length = (other_data & 0x3FFFFF00) >> 8;
      flag32bit = (int)((other_data & 0x40000000) >> 30);
      exception_flag = (int)((other_data & 0x80000000) >> 31);

      fputc (' ', file);
      bfd_fprintf_vma (abfd, file, i + section->vma); fputc ('\t', file);
      bfd_fprintf_vma (abfd, file, begin_addr); fputc (' ', file);
      bfd_fprintf_vma (abfd, file, prolog_length); fputc (' ', file);
      bfd_fprintf_vma (abfd, file, function_length); fputc (' ', file);
      fprintf (file, "%2d  %2d   ", flag32bit, exception_flag);

      if (have_text)
	{
	  bfd_vma min_begin = tsection->vma + 8;
	  if (begin_addr >= min_begin && tsection->size >= 8)
	    {
	      bfd_vma eh_off_vma = begin_addr - 8 - tsection->vma;
	      if (eh_off_vma <= (bfd_vma) (tsection->size - 8))
		{
		  bfd_byte *tdata = (bfd_byte *) bfd_malloc (8);
		  if (tdata)
		    {
		      if (bfd_get_section_contents (abfd, tsection, tdata,
						    (file_ptr) eh_off_vma, 8))
			{
			  bfd_vma eh = bfd_get_32 (abfd, tdata);
			  bfd_vma eh_data = bfd_get_32 (abfd, tdata + 4);
			  fprintf (file, "%08x  ", (unsigned int) eh);
			  fprintf (file, "%08x", (unsigned int) eh_data);
			  if (eh != 0)
			    {
			      const char *s = my_symbol_for_address (abfd, eh, &cache);
			      if (s)
				fprintf (file, " (%s) ", s);
			    }
			}
		      free (tdata);
		    }
		}
	    }
	}

      fprintf (file, "\n");
    }

  free (data);
  cleanup_syms (&cache);
  return true;
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
pe_print_reloc (bfd * abfd, void * vfile)
{
  FILE *file = (FILE *) vfile;
  bfd_byte *data = NULL;
  asection *section = bfd_get_section_by_name (abfd, ".reloc");
  bfd_byte *p, *end;

  if (section == NULL || section->size == 0 || (section->flags & SEC_HAS_CONTENTS) == 0)
    return true;

  fprintf (file,
           _("\n\nPE File Base Relocations (interpreted .reloc section contents)\n"));

  if (! bfd_malloc_and_get_section (abfd, section, &data))
    {
      free (data);
      return false;
    }

  p = data;
  end = data + section->size;

  enum { HEADER_SIZE = 8, ENTRY_SIZE = 2, TYPE_SHIFT = 12 };
  const unsigned int TYPE_MASK = 0xF000;
  const unsigned int OFFSET_MASK = 0x0FFF;
  const size_t tbl_count = sizeof (tbl) / sizeof (tbl[0]);

  while (p + HEADER_SIZE <= end)
    {
      bfd_vma virtual_address;
      unsigned long size;
      unsigned long number;
      bfd_byte *chunk_end;
      bfd_byte *header_start = p;

      virtual_address = bfd_get_32 (abfd, p);
      size = bfd_get_32 (abfd, p + 4);
      p += HEADER_SIZE;

      if (size == 0)
        break;

      if (size < HEADER_SIZE)
        break;

      number = (size - HEADER_SIZE) / ENTRY_SIZE;

      fprintf (file,
               _("\nVirtual Address: %08lx Chunk size %lu (0x%lx) Number of fixups %lu\n"),
               (unsigned long) virtual_address, size, size, number);

      chunk_end = header_start + size;
      if (chunk_end > end)
        chunk_end = end;

      int j = 0;
      while (p + ENTRY_SIZE <= chunk_end)
        {
          unsigned short e = bfd_get_16 (abfd, p);
          unsigned int t = (e & TYPE_MASK) >> TYPE_SHIFT;
          int off = e & OFFSET_MASK;

          if (t >= tbl_count)
            t = (unsigned int) (tbl_count - 1);

          fprintf (file,
                   _("\treloc %4d offset %4x [%4lx] %s"),
                   j, off, (unsigned long) (off + virtual_address), tbl[t]);

          p += ENTRY_SIZE;
          j++;

          if (t == IMAGE_REL_BASED_HIGHADJ && p + ENTRY_SIZE <= chunk_end)
            {
              fprintf (file, " (%4x)", (unsigned int) bfd_get_16 (abfd, p));
              p += ENTRY_SIZE;
              j++;
            }

          fprintf (file, "\n");
        }

      if (p < chunk_end)
        p = chunk_end;
    }

  free (data);

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
rsrc_print_resource_entries (FILE *file,
			     bfd *abfd,
			     unsigned int indent,
			     bool is_name,
			     bfd_byte *data,
			     rsrc_regions *regions,
			     bfd_vma rva_bias)
{
  const size_t MIN_ENTRY_BYTES = 8;
  const size_t LEAF_HEADER_SIZE = 16;
  const size_t WCHAR_SIZE = 2;

  if (data + MIN_ENTRY_BYTES >= regions->section_end)
    return regions->section_end + 1;

  fprintf (file, _("%03x %*.s Entry: "), (int)(data - regions->section_start), indent, " ");

  {
    unsigned long first = (unsigned long) bfd_get_32 (abfd, data);

    if (is_name)
      {
        bfd_byte *name = NULL;
        bfd_vma offset;

        if (HighBitSet (first))
          offset = WithoutHighBit (first);
        else
          {
            bfd_vma first_vma = (bfd_vma) first;
            if (first_vma < rva_bias)
              {
                fprintf (file, _("<corrupt string offset: %#lx>\n"), first);
                return regions->section_end + 1;
              }
            offset = first_vma - rva_bias;
          }

        name = regions->section_start + offset;

        if (name + WCHAR_SIZE < regions->section_end && name > regions->section_start)
          {
            unsigned int len = bfd_get_16 (abfd, name);

            if (regions->strings_start == NULL)
              regions->strings_start = name;

            fprintf (file, _("name: [val: %08lx len %d]: "), first, len);

            {
              bfd_byte *content = name + WCHAR_SIZE;
              size_t remaining = (size_t) (regions->section_end - content);
              if ((size_t) len > (remaining / WCHAR_SIZE))
                {
                  fprintf (file, _("<corrupt string length: %#x>\n"), len);
                  return regions->section_end + 1;
                }

              for (unsigned int i = 0; i < len; i++)
                {
                  char c;
                  content += WCHAR_SIZE;
                  c = *content;
                  if (c > 0 && c < 32)
                    fprintf (file, "^%c", (char) (c + 64));
                  else
                    fprintf (file, "%.1s", content);
                }
            }
          }
        else
          {
            fprintf (file, _("<corrupt string offset: %#lx>\n"), first);
            return regions->section_end + 1;
          }
      }
    else
      {
        fprintf (file, _("ID: %#08lx"), first);
      }

    {
      unsigned long value = (unsigned long) bfd_get_32 (abfd, data + 4);
      fprintf (file, _(", Value: %#08lx\n"), value);

      if (HighBitSet (value))
        {
          bfd_byte *dir_ptr = regions->section_start + WithoutHighBit (value);
          if (dir_ptr <= regions->section_start || dir_ptr > regions->section_end)
            return regions->section_end + 1;

          return rsrc_print_resource_directory (file, abfd, indent + 1, dir_ptr, regions, rva_bias);
        }

      {
        bfd_byte *leaf = regions->section_start + value;

        if (leaf + LEAF_HEADER_SIZE >= regions->section_end || leaf < regions->section_start)
          return regions->section_end + 1;

        {
          unsigned long addr = (unsigned long) bfd_get_32 (abfd, leaf);
          unsigned long size = (unsigned long) bfd_get_32 (abfd, leaf + 4);
          int codepage = (int) bfd_get_32 (abfd, leaf + 8);

          fprintf (file, _("%03x %*.s  Leaf: Addr: %#08lx, Size: %#08lx, Codepage: %d\n"),
                   (int) value, indent, " ", addr, size, codepage);

          if (bfd_get_32 (abfd, leaf + 12) != 0)
            return regions->section_end + 1;

          if ((bfd_vma) addr < rva_bias)
            return regions->section_end + 1;

          {
            bfd_byte *data_start = regions->section_start + (addr - rva_bias);

            if (data_start < regions->section_start)
              return regions->section_end + 1;

            if (data_start + size > regions->section_end)
              return regions->section_end + 1;

            if (regions->resource_start == NULL)
              regions->resource_start = data_start;

            return data_start + size;
          }
        }
      }
    }
  }
}

#define max(a,b) ((a) > (b) ? (a) : (b))
#define min(a,b) ((a) < (b) ? (a) : (b))

static bfd_byte *
rsrc_print_resource_directory (FILE *file,
                               bfd *abfd,
                               unsigned int indent,
                               bfd_byte *data,
                               rsrc_regions *regions,
                               bfd_vma rva_bias)
{
  unsigned int num_names, num_ids;
  bfd_byte *highest_data = data;

  if (data + 16 >= regions->section_end)
    return regions->section_end + 1;

  fprintf (file, "%03x %*.s ", (int) (data - regions->section_start), (int) indent, " ");
  switch (indent)
    {
    case 0:
      fprintf (file, "Type");
      break;
    case 2:
      fprintf (file, "Name");
      break;
    case 4:
      fprintf (file, "Language");
      break;
    default:
      fprintf (file, _("<unknown directory type: %d>\n"), indent);
      return regions->section_end + 1;
    }

  {
    int characteristics = (int) bfd_get_32 (abfd, data);
    long time_stamp = (long) bfd_get_32 (abfd, data + 4);
    int ver_major = (int) bfd_get_16 (abfd, data + 8);
    int ver_minor = (int) bfd_get_16 (abfd, data + 10);
    num_names = (unsigned int) bfd_get_16 (abfd, data + 12);
    num_ids = (unsigned int) bfd_get_16 (abfd, data + 14);

    fprintf (file, _(" Table: Char: %d, Time: %08lx, Ver: %d/%d, Num Names: %d, IDs: %d\n"),
             characteristics, time_stamp, ver_major, ver_minor,
             (int) num_names, (int) num_ids);
  }

  data += 16;

  for (unsigned int i = 0; i < num_names; i++)
    {
      bfd_byte *entry_end = rsrc_print_resource_entries (file, abfd, indent + 1, true,
                                                         data, regions, rva_bias);
      data += 8;
      if (entry_end > highest_data)
        highest_data = entry_end;
      if (entry_end >= regions->section_end)
        return entry_end;
    }

  for (unsigned int i = 0; i < num_ids; i++)
    {
      bfd_byte *entry_end = rsrc_print_resource_entries (file, abfd, indent + 1, false,
                                                         data, regions, rva_bias);
      data += 8;
      if (entry_end > highest_data)
        highest_data = entry_end;
      if (entry_end >= regions->section_end)
        return entry_end;
    }

  return highest_data > data ? highest_data : data;
}

/* Display the contents of a .rsrc section.  We do not try to
   reproduce the resources, windres does that.  Instead we dump
   the tables in a human readable format.  */

static bool
rsrc_print_section (bfd * abfd, void * vfile)
{
  bfd_vma rva_bias;
  pe_data_type * pe;
  FILE * file = (FILE *) vfile;
  bfd_size_type datasize;
  asection * section;
  bfd_byte * data = NULL;
  rsrc_regions regions;

  pe = pe_data (abfd);
  if (pe == NULL)
    return true;

  section = bfd_get_section_by_name (abfd, ".rsrc");
  if (section == NULL)
    return true;
  if (!(section->flags & SEC_HAS_CONTENTS))
    return true;

  datasize = section->size;
  if (datasize == 0)
    return true;

  rva_bias = section->vma - pe->pe_opthdr.ImageBase;

  if (! bfd_malloc_and_get_section (abfd, section, & data))
    {
      free (data);
      return false;
    }

  regions.section_start = data;
  regions.section_end = data + datasize;
  regions.strings_start = NULL;
  regions.resource_start = NULL;

  fflush (file);
  fprintf (file, "\nThe .rsrc Resource Directory section:\n");

  {
    size_t align_mask = ((size_t)1 << section->alignment_power) - 1;

    while (data < regions.section_end)
      {
        bfd_byte * p = data;

        data = rsrc_print_resource_directory (file, abfd, 0, data, & regions, rva_bias);

        if (data == regions.section_end + 1)
          {
            fprintf (file, _("Corrupt .rsrc section detected!\n"));
          }
        else
          {
            size_t offset = (size_t) (data - regions.section_start);
            size_t aligned_offset = (offset + align_mask) & ~align_mask;

            if (aligned_offset > (size_t) datasize)
              aligned_offset = (size_t) datasize;

            data = regions.section_start + aligned_offset;
            rva_bias += (bfd_vma) (data - p);

            {
              size_t remaining = (size_t) (regions.section_end - data);

              if (remaining == 4)
                {
                  data = regions.section_end;
                }
              else if (data < regions.section_end)
                {
                  bfd_byte * t = data;

                  while (++ t < regions.section_end)
                    if (* t != 0)
                      break;

                  if (t < regions.section_end)
                    fprintf (file, _("\nWARNING: Extra data in .rsrc section - it will be ignored by Windows:\n"));

                  data = t;
                }
            }
          }
      }
  }

  if (regions.strings_start != NULL)
    fprintf (file, _(" String table starts at offset: %#03x\n"),
             (int) (regions.strings_start - regions.section_start));
  if (regions.resource_start != NULL)
    fprintf (file, _(" Resources start at offset: %#03x\n"),
             (int) (regions.resource_start - regions.section_start));

  free (regions.section_start);
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
pe_print_debugdata (bfd *abfd, void *vfile)
{
  FILE *file = (FILE *) vfile;
  pe_data_type *pe;
  struct internal_extra_pe_aouthdr *extra;
  asection *section;
  bfd_byte *data = NULL;
  bfd_size_type dataoff;
  unsigned int i;

  bfd_vma addr;
  bfd_size_type size;

  if (abfd == NULL || file == NULL)
    return false;

  pe = pe_data (abfd);
  extra = &pe->pe_opthdr;

  addr = extra->DataDirectory[PE_DEBUG_DATA].VirtualAddress;
  size = extra->DataDirectory[PE_DEBUG_DATA].Size;

  if (size == 0)
    return true;

  addr += extra->ImageBase;

  for (section = abfd->sections; section != NULL; section = section->next)
    {
      if (addr >= section->vma && addr < section->vma + section->size)
        break;
    }

  if (section == NULL)
    {
      fprintf (file,
               _("\nThere is a debug directory, but the section containing it could not be found\n"));
      return true;
    }

  if ((section->flags & SEC_HAS_CONTENTS) == 0)
    {
      fprintf (file,
               _("\nThere is a debug directory in %s, but that section has no contents\n"),
               section->name);
      return true;
    }

  if (section->size < size)
    {
      fprintf (file,
               _("\nError: section %s contains the debug data starting address but it is too small\n"),
               section->name);
      return false;
    }

  fprintf (file, _("\nThere is a debug directory in %s at 0x%lx\n\n"),
           section->name, (unsigned long) addr);

  dataoff = addr - section->vma;

  if (size > section->size - dataoff)
    {
      fprintf (file, _("The debug data size field in the data directory is too big for the section"));
      return false;
    }

  fprintf (file, _("Type                Size     Rva      Offset\n"));

  if (!bfd_malloc_and_get_section (abfd, section, &data))
    {
      if (data != NULL)
        free (data);
      return false;
    }

  {
    bfd_size_type dir_count = size / sizeof (struct external_IMAGE_DEBUG_DIRECTORY);
    struct external_IMAGE_DEBUG_DIRECTORY *base =
      (struct external_IMAGE_DEBUG_DIRECTORY *) (data + dataoff);

    for (i = 0; i < dir_count; i++)
      {
        const char *type_name;
        struct external_IMAGE_DEBUG_DIRECTORY *ext = &base[i];
        struct internal_IMAGE_DEBUG_DIRECTORY idd;

        _bfd_XXi_swap_debugdir_in (abfd, ext, &idd);

        if (idd.Type >= IMAGE_NUMBEROF_DEBUG_TYPES)
          type_name = debug_type_names[0];
        else
          type_name = debug_type_names[idd.Type];

        fprintf (file, " %2ld  %14s %08lx %08lx %08lx\n",
                 idd.Type, type_name, idd.SizeOfData,
                 idd.AddressOfRawData, idd.PointerToRawData);

        if (idd.Type == PE_IMAGE_DEBUG_TYPE_CODEVIEW)
          {
            char signature[CV_INFO_SIGNATURE_LENGTH * 2 + 1];
            char buffer[256 + 1] ATTRIBUTE_ALIGNED_ALIGNOF (CODEVIEW_INFO);
            char *pdb = NULL;
            CODEVIEW_INFO *cvinfo = (CODEVIEW_INFO *) buffer;

            if (!_bfd_XXi_slurp_codeview_record (abfd, (file_ptr) idd.PointerToRawData,
                                                 idd.SizeOfData, cvinfo, &pdb))
              continue;

            {
              unsigned int j;
              unsigned int max_pairs = CV_INFO_SIGNATURE_LENGTH;
              unsigned int pairs = cvinfo->SignatureLength < max_pairs
                                   ? cvinfo->SignatureLength
                                   : max_pairs;
              unsigned int pos = 0;

              signature[0] = '\0';
              for (j = 0; j < pairs; j++)
                {
                  if (pos + 3 > sizeof (signature))
                    break;
                  snprintf (&signature[pos], sizeof (signature) - pos, "%02x",
                            cvinfo->Signature[j] & 0xff);
                  pos += 2;
                }
                signature[sizeof (signature) - 1] = '\0';
            }

            fprintf (file, _("(format %c%c%c%c signature %s age %ld pdb %s)\n"),
                     buffer[0], buffer[1], buffer[2], buffer[3],
                     signature, cvinfo->Age, (pdb && pdb[0]) ? pdb : "(none)");

            free (pdb);
          }
      }
  }

  free (data);

  if (size % sizeof (struct external_IMAGE_DEBUG_DIRECTORY) != 0)
    fprintf (file,
             _("The debug directory size is not a multiple of the debug directory entry size\n"));

  return true;
}

static bool
pe_is_repro (bfd *abfd)
{
  pe_data_type *pe = pe_data (abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
  asection *section = NULL;
  asection *s;
  bfd_byte *data = NULL;
  bfd_vma va = extra->DataDirectory[PE_DEBUG_DATA].VirtualAddress;
  bfd_size_type size = extra->DataDirectory[PE_DEBUG_DATA].Size;
  bfd_size_type dataoff;
  bfd_size_type num_entries;
  bool found = false;

  if (size == 0)
    return false;

  va += extra->ImageBase;

  for (s = abfd->sections; s != NULL; s = s->next)
    {
      bfd_size_type off;

      if ((s->flags & SEC_HAS_CONTENTS) == 0)
        continue;
      if (va < s->vma)
        continue;

      off = (bfd_size_type) (va - s->vma);
      if (off < s->size)
        {
          section = s;
          break;
        }
    }

  if (section == NULL)
    return false;

  dataoff = (bfd_size_type) (va - section->vma);

  if (size > section->size - dataoff)
    return false;

  if (size < (bfd_size_type) sizeof (struct external_IMAGE_DEBUG_DIRECTORY))
    return false;

  if (!bfd_malloc_and_get_section (abfd, section, &data))
    {
      if (data != NULL)
        free (data);
      return false;
    }

  num_entries = size / sizeof (struct external_IMAGE_DEBUG_DIRECTORY);

  if (num_entries != 0)
    {
      struct external_IMAGE_DEBUG_DIRECTORY *ext =
        (struct external_IMAGE_DEBUG_DIRECTORY *) (data + dataoff);
      unsigned int i;

      for (i = 0; i < num_entries; i++)
        {
          struct internal_IMAGE_DEBUG_DIRECTORY idd;
          _bfd_XXi_swap_debugdir_in (abfd, &ext[i], &idd);
          if (idd.Type == PE_IMAGE_DEBUG_TYPE_REPRO)
            {
              found = true;
              break;
            }
        }
    }

  free (data);
  return found;
}

/* Print out the program headers.  */

bool
_bfd_XX_print_private_bfd_data_common (bfd * abfd, void * vfile)
{
  FILE *file = (FILE *) vfile;
  int j;
  pe_data_type *pe = pe_data (abfd);
  struct internal_extra_pe_aouthdr *i = &pe->pe_opthdr;
  const char *subsystem_name = NULL;
  const char *name;

  typedef struct { unsigned long flag; const char *name; } named_flag_t;

  static const char *
  get_magic_name (unsigned short magic)
  {
    switch (magic)
      {
      case IMAGE_NT_OPTIONAL_HDR_MAGIC: return "PE32";
      case IMAGE_NT_OPTIONAL_HDR64_MAGIC: return "PE32+";
      case IMAGE_NT_OPTIONAL_HDRROM_MAGIC: return "ROM";
      default: return NULL;
      }
  }

  static const char *
  get_subsystem_name (unsigned short subsystem)
  {
    switch (subsystem)
      {
      case IMAGE_SUBSYSTEM_UNKNOWN: return "unspecified";
      case IMAGE_SUBSYSTEM_NATIVE: return "NT native";
      case IMAGE_SUBSYSTEM_WINDOWS_GUI: return "Windows GUI";
      case IMAGE_SUBSYSTEM_WINDOWS_CUI: return "Windows CUI";
      case IMAGE_SUBSYSTEM_POSIX_CUI: return "POSIX CUI";
      case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: return "Wince CUI";
      case IMAGE_SUBSYSTEM_EFI_APPLICATION: return "EFI application";
      case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return "EFI boot service driver";
      case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: return "EFI runtime driver";
      case IMAGE_SUBSYSTEM_SAL_RUNTIME_DRIVER: return "SAL runtime driver";
      case IMAGE_SUBSYSTEM_XBOX: return "XBOX";
      default: return NULL;
      }
  }

  static void
  print_characteristics (FILE *file, unsigned long flags)
  {
    static const named_flag_t table[] = {
      { IMAGE_FILE_RELOCS_STRIPPED, "relocations stripped" },
      { IMAGE_FILE_EXECUTABLE_IMAGE, "executable" },
      { IMAGE_FILE_LINE_NUMS_STRIPPED, "line numbers stripped" },
      { IMAGE_FILE_LOCAL_SYMS_STRIPPED, "symbols stripped" },
      { IMAGE_FILE_LARGE_ADDRESS_AWARE, "large address aware" },
      { IMAGE_FILE_BYTES_REVERSED_LO, "little endian" },
      { IMAGE_FILE_32BIT_MACHINE, "32 bit words" },
      { IMAGE_FILE_DEBUG_STRIPPED, "debugging information removed" },
      { IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "copy to swap file if on removable media" },
      { IMAGE_FILE_NET_RUN_FROM_SWAP, "copy to swap file if on network media" },
      { IMAGE_FILE_SYSTEM, "system file" },
      { IMAGE_FILE_DLL, "DLL" },
      { IMAGE_FILE_UP_SYSTEM_ONLY, "run only on uniprocessor machine" },
      { IMAGE_FILE_BYTES_REVERSED_HI, "big endian" }
    };
    for (size_t k = 0; k < sizeof (table) / sizeof (table[0]); ++k)
      if (flags & table[k].flag)
        fprintf (file, "\t%s\n", table[k].name);
  }

  static void
  print_dll_characteristics (FILE *file, unsigned short dllch)
  {
    if (!dllch)
      return;

    static const named_flag_t table[] = {
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

    const char *indent = "\t\t\t\t\t";
    for (size_t k = 0; k < sizeof (table) / sizeof (table[0]); ++k)
      if (dllch & (unsigned short) table[k].flag)
        fprintf (file, "%s%s\n", indent, table[k].name);
  }

  fprintf (file, _("\nCharacteristics 0x%x\n"), pe->real_flags);
  print_characteristics (file, pe->real_flags);

  if (pe_is_repro (abfd))
    {
      fprintf (file, "\nTime/Date\t\t%08lx", pe->coff.timestamp);
      fprintf (file, "\t(This is a reproducible build file hash, not a timestamp)\n");
    }
  else
    {
      time_t t = pe->coff.timestamp;
      char *ts = ctime (&t);
      if (ts)
        fprintf (file, "\nTime/Date\t\t%s", ts);
      else
        fprintf (file, "\nTime/Date\t\t<unknown>\n");
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

  name = get_magic_name (i->Magic);
  fprintf (file, "Magic\t\t\t%04x", i->Magic);
  if (name)
    fprintf (file, "\t(%s)", name);
  fprintf (file, "\nMajorLinkerVersion\t%d\n", i->MajorLinkerVersion);
  fprintf (file, "MinorLinkerVersion\t%d\n", i->MinorLinkerVersion);
  fprintf (file, "SizeOfCode\t\t");
  bfd_fprintf_vma (abfd, file, i->SizeOfCode);
  fprintf (file, "\nSizeOfInitializedData\t");
  bfd_fprintf_vma (abfd, file, i->SizeOfInitializedData);
  fprintf (file, "\nSizeOfUninitializedData\t");
  bfd_fprintf_vma (abfd, file, i->SizeOfUninitializedData);
  fprintf (file, "\nAddressOfEntryPoint\t");
  bfd_fprintf_vma (abfd, file, i->AddressOfEntryPoint);
  fprintf (file, "\nBaseOfCode\t\t");
  bfd_fprintf_vma (abfd, file, i->BaseOfCode);
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
  fprintf (file, "\nBaseOfData\t\t");
  bfd_fprintf_vma (abfd, file, i->BaseOfData);
#endif

  fprintf (file, "\nImageBase\t\t");
  bfd_fprintf_vma (abfd, file, i->ImageBase);
  fprintf (file, "\nSectionAlignment\t%08x\n", i->SectionAlignment);
  fprintf (file, "FileAlignment\t\t%08x\n", i->FileAlignment);
  fprintf (file, "MajorOSystemVersion\t%d\n", i->MajorOperatingSystemVersion);
  fprintf (file, "MinorOSystemVersion\t%d\n", i->MinorOperatingSystemVersion);
  fprintf (file, "MajorImageVersion\t%d\n", i->MajorImageVersion);
  fprintf (file, "MinorImageVersion\t%d\n", i->MinorImageVersion);
  fprintf (file, "MajorSubsystemVersion\t%d\n", i->MajorSubsystemVersion);
  fprintf (file, "MinorSubsystemVersion\t%d\n", i->MinorSubsystemVersion);
  fprintf (file, "Win32Version\t\t%08x\n", i->Win32Version);
  fprintf (file, "SizeOfImage\t\t%08x\n", i->SizeOfImage);
  fprintf (file, "SizeOfHeaders\t\t%08x\n", i->SizeOfHeaders);
  fprintf (file, "CheckSum\t\t%08x\n", i->CheckSum);

  subsystem_name = get_subsystem_name (i->Subsystem);

  fprintf (file, "Subsystem\t\t%08x", i->Subsystem);
  if (subsystem_name)
    fprintf (file, "\t(%s)", subsystem_name);
  fprintf (file, "\nDllCharacteristics\t%08x\n", i->DllCharacteristics);
  print_dll_characteristics (file, i->DllCharacteristics);

  fprintf (file, "SizeOfStackReserve\t");
  bfd_fprintf_vma (abfd, file, i->SizeOfStackReserve);
  fprintf (file, "\nSizeOfStackCommit\t");
  bfd_fprintf_vma (abfd, file, i->SizeOfStackCommit);
  fprintf (file, "\nSizeOfHeapReserve\t");
  bfd_fprintf_vma (abfd, file, i->SizeOfHeapReserve);
  fprintf (file, "\nSizeOfHeapCommit\t");
  bfd_fprintf_vma (abfd, file, i->SizeOfHeapCommit);
  fprintf (file, "\nLoaderFlags\t\t%08lx\n", (unsigned long) i->LoaderFlags);
  fprintf (file, "NumberOfRvaAndSizes\t%08lx\n",
	   (unsigned long) i->NumberOfRvaAndSizes);

  fprintf (file, "\nThe Data Directory\n");
  for (j = 0; j < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; j++)
    {
      fprintf (file, "Entry %1x ", j);
      bfd_fprintf_vma (abfd, file, i->DataDirectory[j].VirtualAddress);
      fprintf (file, " %08lx ", (unsigned long) i->DataDirectory[j].Size);
      fprintf (file, "%s\n", dir_names[j]);
    }

  pe_print_idata (abfd, vfile);
  pe_print_edata (abfd, vfile);
  if (bfd_coff_have_print_pdata (abfd))
    bfd_coff_print_pdata (abfd, vfile);
  else
    pe_print_pdata (abfd, vfile);
  pe_print_reloc (abfd, vfile);
  pe_print_debugdata (abfd, file);

  rsrc_print_section (abfd, vfile);

  return true;
}

static bool
is_vma_in_section (bfd *abfd ATTRIBUTE_UNUSED, asection *sect, void *obj)
{
  if (sect == NULL || obj == NULL)
    return false;

  const bfd_vma *addr_ptr = (const bfd_vma *) obj;
  const bfd_vma addr = *addr_ptr;
  const bfd_vma vma = sect->vma;

  if (addr < vma)
    return false;

  const bfd_vma delta = addr - vma;
  return delta < (bfd_vma) sect->size;
}

static asection *
find_section_by_vma (bfd *abfd, bfd_vma addr)
{
  if (abfd == NULL)
    return NULL;

  return bfd_sections_find_if (abfd, is_vma_in_section, &addr);
}

/* Copy any private info we understand from the input bfd
   to the output bfd.  */

bool
_bfd_XX_bfd_copy_private_bfd_data_common (bfd * ibfd, bfd * obfd)
{
  pe_data_type *ipe, *ope;
  bfd_size_type size;

  if (ibfd->xvec->flavour != bfd_target_coff_flavour
      || obfd->xvec->flavour != bfd_target_coff_flavour)
    return true;

  ipe = pe_data (ibfd);
  ope = pe_data (obfd);

  ope->dll = ipe->dll;

  if (obfd->xvec != ibfd->xvec)
    ope->pe_opthdr.Subsystem = IMAGE_SUBSYSTEM_UNKNOWN;

  if (!ope->has_reloc_section)
    {
      ope->pe_opthdr.DataDirectory[PE_BASE_RELOCATION_TABLE].VirtualAddress = 0;
      ope->pe_opthdr.DataDirectory[PE_BASE_RELOCATION_TABLE].Size = 0;
    }

  if (!ipe->has_reloc_section
      && ! (ipe->real_flags & IMAGE_FILE_RELOCS_STRIPPED))
    ope->dont_strip_reloc = 1;

  memcpy (ope->dos_message, ipe->dos_message, sizeof (ope->dos_message));

  size = ope->pe_opthdr.DataDirectory[PE_DEBUG_DATA].Size;
  if (size == 0)
    return true;

  {
    bfd_vma addr = ope->pe_opthdr.DataDirectory[PE_DEBUG_DATA].VirtualAddress
      + ope->pe_opthdr.ImageBase;
    bfd_vma last = addr + size - 1;
    asection *section = find_section_by_vma (obfd, last);

    if (section == NULL)
      return true;

    {
      bfd_vma dataoff = addr - section->vma;

      if (addr < section->vma
          || section->size < dataoff
          || section->size - dataoff < size)
        {
          _bfd_error_handler
            (_("%pB: Data Directory (%lx bytes at %" PRIx64 ") "
               "extends across section boundary at %" PRIx64),
             obfd, ope->pe_opthdr.DataDirectory[PE_DEBUG_DATA].Size,
             (uint64_t) addr, (uint64_t) section->vma);
          return false;
        }

      if ((section->flags & SEC_HAS_CONTENTS) == 0)
        {
          _bfd_error_handler (_("%pB: failed to read "
                                "debug data section"), obfd);
          return false;
        }

      {
        bfd_byte *data = NULL;

        if (!bfd_malloc_and_get_section (obfd, section, &data))
          {
            _bfd_error_handler (_("%pB: failed to read "
                                  "debug data section"), obfd);
            return false;
          }

        {
          struct external_IMAGE_DEBUG_DIRECTORY *dd =
            (struct external_IMAGE_DEBUG_DIRECTORY *)(data + dataoff);
          bfd_size_type directory_size =
            ope->pe_opthdr.DataDirectory[PE_DEBUG_DATA].Size;
          bfd_size_type entry_size =
            (bfd_size_type) sizeof (struct external_IMAGE_DEBUG_DIRECTORY);
          bfd_size_type dd_count = directory_size / entry_size;

          for (bfd_size_type i = 0; i < dd_count; i++)
            {
              struct external_IMAGE_DEBUG_DIRECTORY *edd = &dd[i];
              struct internal_IMAGE_DEBUG_DIRECTORY idd;

              _bfd_XXi_swap_debugdir_in (obfd, edd, &idd);

              if (idd.AddressOfRawData == 0)
                continue;

              {
                bfd_vma idd_vma = idd.AddressOfRawData + ope->pe_opthdr.ImageBase;
                asection *ddsection = find_section_by_vma (obfd, idd_vma);

                if (!ddsection)
                  continue;

                idd.PointerToRawData
                  = ddsection->filepos + idd_vma - ddsection->vma;
                _bfd_XXi_swap_debugdir_out (obfd, &idd, edd);
              }
            }
        }

        {
          bool ok = bfd_set_section_contents (obfd, section, data, 0,
                                              section->size);
          free (data);
          if (!ok)
            {
              _bfd_error_handler (_("failed to update file offsets"
                                    " in debug directory"));
              return false;
            }
        }
      }
    }
  }

  return true;
}

/* Copy private section data.  */

bool
_bfd_XX_bfd_copy_private_section_data (bfd *ibfd,
                                       asection *isec,
                                       bfd *obfd,
                                       asection *osec,
                                       struct bfd_link_info *link_info)
{
  if (link_info != NULL
      || bfd_get_flavour (ibfd) != bfd_target_coff_flavour
      || bfd_get_flavour (obfd) != bfd_target_coff_flavour)
    return true;

  {
    struct coff_section_tdata *icoff = coff_section_data (ibfd, isec);
    struct pei_section_tdata *ipei = pei_section_data (ibfd, isec);

    if (icoff == NULL || ipei == NULL)
      return true;

    {
      struct coff_section_tdata *ocoff = coff_section_data (obfd, osec);
      if (ocoff == NULL)
        {
          osec->used_by_bfd = bfd_zalloc (obfd, sizeof (struct coff_section_tdata));
          if (osec->used_by_bfd == NULL)
            return false;
          ocoff = coff_section_data (obfd, osec);
          if (ocoff == NULL)
            return false;
        }

      {
        struct pei_section_tdata *opei = pei_section_data (obfd, osec);
        if (opei == NULL)
          {
            ocoff->tdata = bfd_zalloc (obfd, sizeof (struct pei_section_tdata));
            if (ocoff->tdata == NULL)
              return false;
            opei = pei_section_data (obfd, osec);
            if (opei == NULL)
              return false;
          }

        opei->virt_size = ipei->virt_size;
        opei->pe_flags = ipei->pe_flags;
      }
    }
  }

  return true;
}

void _bfd_XX_get_symbol_info(bfd *abfd, asymbol *symbol, symbol_info *ret)
{
    if (abfd == NULL || symbol == NULL || ret == NULL) {
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
  enum { ENTRY_PAIR_BYTES = 8, NAME_LEN_BYTES = 2, ENTRY_INFO_BYTES = 16 };
  bfd_byte *const invalid = dataend + 1;

  if (data > dataend || datastart > dataend)
    return invalid;

  bfd_byte *const after_pair = data + ENTRY_PAIR_BYTES;
  if (after_pair >= dataend)
    return invalid;

  if (is_name)
    {
      bfd_vma name_entry = bfd_get_32 (abfd, data);
      bfd_byte *name_ptr;

      if (HighBitSet (name_entry))
        name_ptr = datastart + WithoutHighBit (name_entry);
      else
        name_ptr = datastart + name_entry - rva_bias;

      if (name_ptr < datastart)
        return invalid;

      bfd_byte *const after_name_len = name_ptr + NAME_LEN_BYTES;
      if (after_name_len >= dataend)
        return invalid;

      unsigned int len = bfd_get_16 (abfd, name_ptr);
      if (len == 0 || len > 256)
        return invalid;
    }

  bfd_vma entry = bfd_get_32 (abfd, data + 4);

  if (HighBitSet (entry))
    {
      bfd_byte *dirptr = datastart + WithoutHighBit (entry);

      if (dirptr <= datastart || dirptr >= dataend)
        return invalid;

      return rsrc_count_directory (abfd, datastart, dirptr, dataend, rva_bias);
    }

  bfd_byte *entry_ptr = datastart + entry;
  bfd_byte *const after_entry_info = entry_ptr + ENTRY_INFO_BYTES;
  if (after_entry_info >= dataend)
    return invalid;

  bfd_vma addr = bfd_get_32 (abfd, entry_ptr);
  bfd_vma size = bfd_get_32 (abfd, entry_ptr + 4);

  return datastart + addr - rva_bias + size;
}

static bfd_byte *
rsrc_count_directory (bfd *abfd,
                      bfd_byte *datastart,
                      bfd_byte *data,
                      bfd_byte *dataend,
                      bfd_vma rva_bias)
{
  unsigned int num_named, num_ids, total_entries;
  bfd_byte *highest_data = data;

  ptrdiff_t avail = dataend - data;
  if (avail <= 16)
    return dataend + 1;

  num_named = (unsigned int) bfd_get_16 (abfd, data + 12);
  num_ids = (unsigned int) bfd_get_16 (abfd, data + 14);
  total_entries = num_named + num_ids;

  data += 16;

  while (total_entries-- != 0)
    {
      bfd_byte *entry_end = rsrc_count_entries (abfd, total_entries >= num_ids,
                                                datastart, data, dataend, rva_bias);
      data += 8;
      if (entry_end > highest_data)
        highest_data = entry_end;
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
rsrc_parse_entry (bfd *abfd,
                  bool is_name,
                  rsrc_entry *entry,
                  bfd_byte *datastart,
                  bfd_byte *data,
                  bfd_byte *dataend,
                  bfd_vma rva_bias,
                  rsrc_directory *parent)
{
  size_t total_len;
  size_t avail;
  bfd_vma first_val;
  bfd_vma second_val;

  entry->parent = parent;
  entry->is_name = is_name;

  if (data < datastart || data > dataend)
    return dataend;

  total_len = (size_t) (dataend - datastart);
  avail = (size_t) (dataend - data);
  if (avail < 8)
    return dataend;

  first_val = bfd_get_32 (abfd, data);

  if (is_name)
    {
      bfd_vma offset;

      if (HighBitSet (first_val))
        {
          offset = WithoutHighBit (first_val);
        }
      else
        {
          if (first_val < rva_bias)
            return dataend;
          offset = first_val - rva_bias;
        }

      if (offset > total_len || total_len - offset < 4)
        return dataend;

      {
        bfd_byte *address = datastart + offset;
        entry->name_id.name.len = bfd_get_16 (abfd, address);
        entry->name_id.name.string = address + 2;
      }
    }
  else
    {
      entry->name_id.id = first_val;
    }

  second_val = bfd_get_32 (abfd, data + 4);

  if (HighBitSet (second_val))
    {
      size_t dir_off = (size_t) WithoutHighBit (second_val);
      if (dir_off > total_len)
        return dataend;

      entry->is_dir = true;
      entry->value.directory = bfd_malloc (sizeof (*entry->value.directory));
      if (entry->value.directory == NULL)
        return dataend;

      return rsrc_parse_directory (abfd, entry->value.directory,
                                   datastart,
                                   datastart + dir_off,
                                   dataend, rva_bias, entry);
    }

  entry->is_dir = false;
  entry->value.leaf = bfd_malloc (sizeof (*entry->value.leaf));
  if (entry->value.leaf == NULL)
    return dataend;

  {
    size_t entry_off = (size_t) second_val;
    if (entry_off > total_len || total_len - entry_off < 12)
      return dataend;

    bfd_byte *desc = datastart + entry_off;
    bfd_vma addr = bfd_get_32 (abfd, desc);
    unsigned long leaf_size_ul = bfd_get_32 (abfd, desc + 4);
    size_t leaf_size = (size_t) leaf_size_ul;
    entry->value.leaf->size = leaf_size_ul;
    entry->value.leaf->codepage = bfd_get_32 (abfd, desc + 8);

    if (addr < rva_bias)
      return dataend;

    {
      size_t payload_off = (size_t) (addr - rva_bias);
      if (payload_off > total_len || leaf_size > total_len - payload_off)
        return dataend;

      entry->value.leaf->data = bfd_malloc (leaf_size);
      if (entry->value.leaf->data == NULL)
        return dataend;

      if (leaf_size != 0)
        memcpy (entry->value.leaf->data, datastart + payload_off, leaf_size);

      return datastart + payload_off + leaf_size;
    }
  }
}

static bfd_byte *
rsrc_parse_entries (bfd *abfd,
                    rsrc_dir_chain *chain,
                    bool is_name,
                    bfd_byte *highest_data,
                    bfd_byte *datastart,
                    bfd_byte *data,
                    bfd_byte *dataend,
                    bfd_vma rva_bias,
                    rsrc_directory *parent)
{
  unsigned int i;
  rsrc_entry *entry = NULL;
  rsrc_entry *prev = NULL;

  if (chain->num_entries == 0)
    {
      chain->first_entry = NULL;
      chain->last_entry = NULL;
      return highest_data;
    }

  for (i = 0; i < chain->num_entries; ++i)
    {
      bfd_byte *entry_end;

      entry = bfd_malloc (sizeof (*entry));
      if (entry == NULL)
        return dataend;

      entry->next_entry = NULL;

      if (i == 0)
        chain->first_entry = entry;
      else
        prev->next_entry = entry;

      entry_end = rsrc_parse_entry (abfd, is_name, entry, datastart,
                                    data, dataend, rva_bias, parent);

      if (entry_end > highest_data)
        highest_data = entry_end;

      if (entry_end > dataend)
        return dataend;

      data += 8;
      prev = entry;
    }

  chain->last_entry = entry;

  return highest_data;
}

static bfd_byte *
rsrc_parse_directory (bfd *           abfd,
                      rsrc_directory * table,
                      bfd_byte *       datastart,
                      bfd_byte *       data,
                      bfd_byte *       dataend,
                      bfd_vma          rva_bias,
                      rsrc_entry *     entry)
{
  bfd_byte *highest_data = data;

  if (table == NULL)
    return dataend;

  if (data == NULL || dataend == NULL || data > dataend)
    return dataend;

  if ((size_t) (dataend - data) < 16)
    return dataend;

  table->characteristics = bfd_get_32 (abfd, data);
  table->time = bfd_get_32 (abfd, data + 4);
  table->major = bfd_get_16 (abfd, data + 8);
  table->minor = bfd_get_16 (abfd, data + 10);
  table->names.num_entries = bfd_get_16 (abfd, data + 12);
  table->ids.num_entries = bfd_get_16 (abfd, data + 14);
  table->entry = entry;

  data += 16;

  highest_data = rsrc_parse_entries (abfd, &table->names, true, data,
                                     datastart, data, dataend, rva_bias, table);

  {
    size_t names_bytes = (size_t) table->names.num_entries * 8u;
    if ((size_t) (dataend - data) < names_bytes)
      return dataend;
    data += names_bytes;
  }

  highest_data = rsrc_parse_entries (abfd, &table->ids, false, highest_data,
                                     datastart, data, dataend, rva_bias, table);

  {
    size_t ids_bytes = (size_t) table->ids.num_entries * 8u;
    if ((size_t) (dataend - data) < ids_bytes)
      return dataend;
    data += ids_bytes;
  }

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

static void
rsrc_write_string(rsrc_write_data *data, rsrc_string *string)
{
  if (data == NULL || string == NULL || data->next_string == NULL || string->string == NULL)
    return;

  unsigned short len16 = (unsigned short) string->len;
  size_t bytes_to_copy = (size_t) len16 * 2u;
  size_t total_advance = bytes_to_copy + 2u;

  bfd_put_16(data->abfd, len16, data->next_string);
  memcpy(data->next_string + 2, string->string, bytes_to_copy);
  data->next_string += total_advance;
}

static inline unsigned int
rsrc_compute_rva (const rsrc_write_data * data,
                  const bfd_byte *       addr)
{
  if (data == NULL || data->datastart == NULL || addr == NULL)
    return 0U;

  long long diff = addr - data->datastart;

  if (diff <= 0)
    return data->rva_bias;

  unsigned long long udiff = (unsigned long long) diff;
  unsigned long long max_uint = (unsigned long long) (~(unsigned int) 0U);

  if (udiff > max_uint - (unsigned long long) data->rva_bias)
    return (unsigned int) ~0U;

  return (unsigned int) udiff + data->rva_bias;
}

static void
rsrc_write_leaf(rsrc_write_data *data, rsrc_leaf *leaf)
{
  if (data == NULL || leaf == NULL || data->abfd == NULL
      || data->next_leaf == NULL || data->next_data == NULL)
    return;

  size_t offset = 0;
  const size_t field_size = 4;
  const size_t header_size = 4 * field_size;
  const size_t align = 8;

  bfd_put_32(data->abfd, rsrc_compute_rva(data, data->next_data), data->next_leaf + offset);
  offset += field_size;
  bfd_put_32(data->abfd, leaf->size, data->next_leaf + offset);
  offset += field_size;
  bfd_put_32(data->abfd, leaf->codepage, data->next_leaf + offset);
  offset += field_size;
  bfd_put_32(data->abfd, 0, data->next_leaf + offset);
  data->next_leaf += header_size;

  if (leaf->size > 0 && leaf->data != NULL)
    memcpy(data->next_data, leaf->data, leaf->size);

  {
    size_t s = (size_t) leaf->size;
    size_t aligned = (s + (align - 1)) & ~(align - 1);
    data->next_data += aligned;
  }
}

static void rsrc_write_directory (rsrc_write_data *, rsrc_directory *);

static void
rsrc_write_entry(rsrc_write_data *data, bfd_byte *where, rsrc_entry *entry)
{
  if (data == NULL || where == NULL || entry == NULL || data->abfd == NULL)
    return;

  bfd *abfd = data->abfd;
  bfd_byte *const where_value = where + 4;

  if (entry->is_name)
    {
      ptrdiff_t off = data->next_string - data->datastart;
      if (off < 0 || off > 0x7FFFFFFF)
        return;
      bfd_put_32(abfd, SetHighBit((unsigned int) off), where);
      rsrc_write_string(data, &entry->name_id.name);
    }
  else
    {
      bfd_put_32(abfd, entry->name_id.id, where);
    }

  if (entry->is_dir)
    {
      ptrdiff_t off = data->next_table - data->datastart;
      if (off < 0 || off > 0x7FFFFFFF)
        return;
      bfd_put_32(abfd, SetHighBit((unsigned int) off), where_value);
      rsrc_write_directory(data, entry->value.directory);
    }
  else
    {
      ptrdiff_t off = data->next_leaf - data->datastart;
      if (off < 0 || off > 0x7FFFFFFF)
        return;
      bfd_put_32(abfd, (unsigned int) off, where_value);
      rsrc_write_leaf(data, entry->value.leaf);
    }
}

static void rsrc_compute_region_sizes(rsrc_directory *dir);

static void rsrc_process_entry_list(struct rsrc_entry *entry, int include_strings)
{
  for (; entry != NULL; entry = entry->next_entry)
    {
      sizeof_tables_and_entries += 8;

      if (include_strings)
        sizeof_strings += (entry->name_id.name.len + 1) * 2;

      if (entry->is_dir)
        rsrc_compute_region_sizes(entry->value.directory);
      else
        sizeof_leaves += 16;
    }
}

static void
rsrc_compute_region_sizes (rsrc_directory * dir)
{
  if (dir == NULL)
    return;

  sizeof_tables_and_entries += 16;

  rsrc_process_entry_list(dir->names.first_entry, 1);
  rsrc_process_entry_list(dir->ids.first_entry, 0);
}

static void rsrc_write_entries(rsrc_write_data *data, bfd_byte **pnext, unsigned int count, rsrc_entry *entry, int expect_name, size_t entry_size)
{
  unsigned int i = count;
  bfd_byte *next = *pnext;

  while (i > 0 && entry != NULL)
    {
      BFD_ASSERT(!!entry->is_name == !!expect_name);
      rsrc_write_entry(data, next, entry);
      next += entry_size;
      i--;
      entry = entry->next_entry;
    }

  BFD_ASSERT(i == 0);
  BFD_ASSERT(entry == NULL);

  *pnext = next;
}

static void
rsrc_write_directory (rsrc_write_data * data,
		      rsrc_directory *  dir)
{
  const size_t dir_header_size = 16u;
  const size_t entry_size = 8u;
  unsigned int names_count;
  unsigned int ids_count;
  size_t total_entries;
  size_t entries_bytes;
  bfd_byte * next_entry;
  bfd_byte * nt;

  BFD_ASSERT (data != NULL);
  BFD_ASSERT (dir != NULL);
  BFD_ASSERT (data->abfd != NULL);
  BFD_ASSERT (data->next_table != NULL);

  bfd_put_32 (data->abfd, dir->characteristics, data->next_table);
  bfd_put_32 (data->abfd, 0, data->next_table + 4);
  bfd_put_16 (data->abfd, dir->major, data->next_table + 8);
  bfd_put_16 (data->abfd, dir->minor, data->next_table + 10);
  bfd_put_16 (data->abfd, dir->names.num_entries, data->next_table + 12);
  bfd_put_16 (data->abfd, dir->ids.num_entries, data->next_table + 14);

  next_entry = data->next_table + dir_header_size;

  names_count = dir->names.num_entries;
  ids_count = dir->ids.num_entries;
  total_entries = (size_t) names_count + (size_t) ids_count;
  entries_bytes = total_entries * entry_size;

  BFD_ASSERT (total_entries >= names_count);
  BFD_ASSERT (entries_bytes / entry_size == total_entries);

  data->next_table = next_entry + entries_bytes;
  nt = data->next_table;

  rsrc_write_entries (data, &next_entry, names_count, dir->names.first_entry, 1, entry_size);
  rsrc_write_entries (data, &next_entry, ids_count, dir->ids.first_entry, 0, entry_size);

  BFD_ASSERT (nt == next_entry);
}

#if ! defined __CYGWIN__ && ! defined __MINGW32__
/* Return the length (number of units) of the first character in S,
   putting its 'ucs4_t' representation in *PUC.  */

static unsigned int
u16_mbtouc(wint_t *puc, const unsigned short *s, unsigned int n)
{
  unsigned int c1;
  unsigned int c2;

  if (puc == NULL || s == NULL)
    return 0;

  if (n == 0)
    {
      *puc = 0xfffd;
      return 0;
    }

  c1 = s[0];

  if (c1 < 0xd800 || c1 >= 0xe000)
    {
      *puc = (wint_t)c1;
      return 1;
    }

  if (c1 >= 0xdc00)
    {
      *puc = 0xfffd;
      return 1;
    }

  if (n < 2)
    {
      *puc = 0xfffd;
      return n;
    }

  c2 = s[1];

  if (c2 >= 0xdc00 && c2 < 0xe000)
    {
      *puc = (wint_t)(0x10000 + ((c1 - 0xd800) << 10) + (c2 - 0xdc00));
      return 2;
    }

  *puc = 0xfffd;
  return 1;
}
#endif /* not Cygwin/Mingw */

/* Perform a comparison of two entries.  */
static signed int
rsrc_cmp (bool is_name, rsrc_entry *a, rsrc_entry *b)
{
  if (!is_name)
    return a->name_id.id - b->name_id.id;

  const bfd_byte *astring = a->name_id.name.string;
  unsigned int alen = a->name_id.name.len;
  const bfd_byte *bstring = b->name_id.name.string;
  unsigned int blen = b->name_id.name.len;

#if defined(__CYGWIN__) || defined(__MINGW32__)
  size_t n = (alen < blen) ? (size_t) alen : (size_t) blen;
# ifdef __CYGWIN__
  int res = wcsncasecmp((const wchar_t *) astring, (const wchar_t *) bstring, n);
# else
  int res = wcsnicmp((const wchar_t *) astring, (const wchar_t *) bstring, n);
# endif
  if (res != 0)
    return (signed int) res;
  return (signed int) (alen - blen);
#else
  const unsigned short *ap = (const unsigned short *) astring;
  const unsigned short *bp = (const unsigned short *) bstring;
  unsigned int ai = 0, bi = 0;

  while (ai < alen && bi < blen)
    {
      wint_t awc = 0, bwc = 0;
      unsigned int arem = alen - ai;
      unsigned int brem = blen - bi;

      unsigned int acons = u16_mbtouc(&awc, ap + ai, arem);
      unsigned int bcons = u16_mbtouc(&bwc, bp + bi, brem);

      if (acons == 0) { awc = (wint_t) ap[ai]; acons = 1; }
      if (bcons == 0) { bwc = (wint_t) bp[bi]; bcons = 1; }

      if (acons != bcons)
        return (signed int) acons - (signed int) bcons;

      awc = towlower(awc);
      bwc = towlower(bwc);

      if (awc != bwc)
        return (awc < bwc) ? -1 : 1;

      ai += acons;
      bi += bcons;
    }

  return (signed int) (alen - blen);
#endif
}

static void
rsrc_print_name(char *buffer, rsrc_string string)
{
  if (buffer == NULL || string.string == NULL)
    return;

  const bfd_byte *name = string.string;
  char *out = buffer + strlen(buffer);
  unsigned int i;

  for (i = 0; i < string.len; ++i, name += 2)
    {
      char ch = (char) name[0];
      if (ch != '\0')
        {
          *out++ = ch;
        }
    }
  *out = '\0';
}

static const char *
resource_type_desc(unsigned int id, bool *is_string)
{
  if (is_string != NULL)
    *is_string = false;

  switch (id)
    {
    case 1: return " (CURSOR)";
    case 2: return " (BITMAP)";
    case 3: return " (ICON)";
    case 4: return " (MENU)";
    case 5: return " (DIALOG)";
    case 6:
      if (is_string != NULL)
        *is_string = true;
      return " (STRING)";
    case 7: return " (FONTDIR)";
    case 8: return " (FONT)";
    case 9: return " (ACCELERATOR)";
    case 10: return " (RCDATA)";
    case 11: return " (MESSAGETABLE)";
    case 12: return " (GROUP_CURSOR)";
    case 14: return " (GROUP_ICON)";
    case 16: return " (VERSION)";
    case 17: return " (DLGINCLUDE)";
    case 19: return " (PLUGPLAY)";
    case 20: return " (VXD)";
    case 21: return " (ANICURSOR)";
    case 22: return " (ANIICON)";
    case 23: return " (HTML)";
    case 24: return " (MANIFEST)";
    case 240: return " (DLGINIT)";
    case 241: return " (TOOLBAR)";
    default: return NULL;
    }
}

static const char *
rsrc_resource_name (rsrc_entry *entry, rsrc_directory *dir, char *buffer)
{
  bool is_string = false;
  rsrc_entry *dir_entry = NULL;
  rsrc_entry *parent_entry = NULL;
  char *p;

  if (buffer == NULL)
    return NULL;

  buffer[0] = '\0';
  p = buffer;

  if (dir != NULL && dir->entry != NULL)
    {
      dir_entry = dir->entry;
      if (dir_entry->parent != NULL)
        parent_entry = dir_entry->parent->entry;
    }

  if (parent_entry != NULL)
    {
      strcpy (p, "type: ");
      p += strlen (p);

      if (parent_entry->is_name)
        {
          rsrc_print_name (p, parent_entry->name_id.name);
          p += strlen (p);
        }
      else
        {
          unsigned int id = parent_entry->name_id.id;
          const char *desc;

          sprintf (p, "%x", id);
          p += strlen (p);

          desc = resource_type_desc (id, &is_string);
          if (desc != NULL)
            {
              strcpy (p, desc);
              p += strlen (p);
            }
        }
    }

  if (dir_entry != NULL)
    {
      strcpy (p, " name: ");
      p += strlen (p);

      if (dir_entry->is_name)
        {
          rsrc_print_name (p, dir_entry->name_id.name);
          p += strlen (p);
        }
      else
        {
          unsigned int id = dir_entry->name_id.id;

          sprintf (p, "%x", id);
          p += strlen (p);

          if (is_string)
            {
              sprintf (p, " (resource id range: %d - %d)",
                       (id - 1) << 4, (id << 4) - 1);
              p += strlen (p);
            }
        }
    }

  if (entry != NULL)
    {
      strcpy (p, " lang: ");
      p += strlen (p);

      if (entry->is_name)
        rsrc_print_name (p, entry->name_id.name);
      else
        sprintf (p, "%x", entry->name_id.id);
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

static bool
rsrc_merge_string_entries (rsrc_entry * a ATTRIBUTE_UNUSED,
			   rsrc_entry * b ATTRIBUTE_UNUSED)
{
  size_t copy_needed = 0;
  unsigned int i;
  const bfd_byte * astring;
  const bfd_byte * bstring;
  bfd_byte * new_data;
  bfd_byte * nstring;

  BFD_ASSERT (a && b);
  BFD_ASSERT (! a->is_dir);
  astring = a->value.leaf->data;

  BFD_ASSERT (! b->is_dir);
  bstring = b->value.leaf->data;

  for (i = 0; i < 16; i++)
    {
      unsigned int alen = (unsigned int) astring[0] | ((unsigned int) astring[1] << 8);
      unsigned int blen = (unsigned int) bstring[0] | ((unsigned int) bstring[1] << 8);

      if (alen == 0 && blen != 0)
	{
	  copy_needed += (size_t) blen * 2u;
	}
      else if (blen == 0)
	{
	  /* Nothing to do.  */
	}
      else if (alen != blen
	       || memcmp (astring + 2, bstring + 2, (size_t) alen * 2u) != 0)
	{
	  break;
	}

      astring += ((size_t) alen + 1u) * 2u;
      bstring += ((size_t) blen + 1u) * 2u;
    }

  if (i != 16)
    {
      if (a->parent != NULL
	  && a->parent->entry != NULL
	  && !a->parent->entry->is_name)
	_bfd_error_handler (_(".rsrc merge failure: duplicate string resource: %d"),
			    ((a->parent->entry->name_id.id - 1) << 4) + i);
      return false;
    }

  if (copy_needed == 0)
    return true;

  {
    size_t a_size = (size_t) a->value.leaf->size;
    if (copy_needed > SIZE_MAX - a_size)
      return false;

    new_data = bfd_malloc (a_size + copy_needed);
  }
  if (new_data == NULL)
    return false;

  nstring = new_data;
  astring = a->value.leaf->data;
  bstring = b->value.leaf->data;

  for (i = 0; i < 16; i++)
    {
      unsigned int alen = (unsigned int) astring[0] | ((unsigned int) astring[1] << 8);
      unsigned int blen = (unsigned int) bstring[0] | ((unsigned int) bstring[1] << 8);

      if (alen != 0)
	{
	  size_t sz = ((size_t) alen + 1u) * 2u;
	  memcpy (nstring, astring, sz);
	  nstring += sz;
	}
      else if (blen != 0)
	{
	  size_t sz = ((size_t) blen + 1u) * 2u;
	  memcpy (nstring, bstring, sz);
	  nstring += sz;
	}
      else
	{
	  * nstring++ = 0;
	  * nstring++ = 0;
	}

      astring += ((size_t) alen + 1u) * 2u;
      bstring += ((size_t) blen + 1u) * 2u;
    }

  BFD_ASSERT ((size_t) (nstring - new_data) == (size_t) a->value.leaf->size + copy_needed);

  free (a->value.leaf->data);
  a->value.leaf->data = new_data;
  a->value.leaf->size += copy_needed;

  return true;
}

static void rsrc_merge (rsrc_entry *, rsrc_entry *);

/* Sort the entries in given part of the directory.
   We use an old fashioned bubble sort because we are dealing
   with lists and we want to handle matches specially.  */

static void
rsrc_sort_entries (rsrc_dir_chain *chain, bool is_name, rsrc_directory *dir)
{
  rsrc_entry *entry;
  rsrc_entry *next;
  rsrc_entry **points_to_entry;
  bool swapped;

  if (chain == NULL || chain->num_entries < 2 || chain->first_entry == NULL)
    return;

  do
    {
      swapped = false;
      points_to_entry = &chain->first_entry;
      entry = *points_to_entry;
      if (entry == NULL || entry->next_entry == NULL)
        {
          chain->last_entry = entry;
          return;
        }
      next  = entry->next_entry;

      do
        {
          int cmp = rsrc_cmp (is_name, entry, next);

          if (cmp > 0)
            {
              entry->next_entry = next->next_entry;
              next->next_entry = entry;
              *points_to_entry = next;
              points_to_entry = &next->next_entry;
              next = entry->next_entry;
              swapped = true;
              continue;
            }

          if (cmp == 0)
            {
              bool both_dirs = entry->is_dir && next->is_dir;
              bool mixed_dir = entry->is_dir != next->is_dir;
              rsrc_entry *dir_entry = dir ? dir->entry : NULL;
              rsrc_entry *parent_entry = (dir_entry && dir_entry->parent) ? dir_entry->parent->entry : NULL;

              if (both_dirs)
                {
                  bool in_manifest_type = dir_entry && !dir_entry->is_name && dir_entry->name_id.id == 0x18;
                  bool entry_is_manifest_name1 = !entry->is_name && entry->name_id.id == 1 && in_manifest_type;

                  if (entry_is_manifest_name1)
                    {
                      bool next_is_default =
                        next->value.directory
                        && next->value.directory->names.num_entries == 0
                        && next->value.directory->ids.num_entries == 1
                        && next->value.directory->ids.first_entry
                        && !next->value.directory->ids.first_entry->is_name
                        && next->value.directory->ids.first_entry->name_id.id == 0;

                      bool entry_is_default =
                        entry->value.directory
                        && entry->value.directory->names.num_entries == 0
                        && entry->value.directory->ids.num_entries == 1
                        && entry->value.directory->ids.first_entry
                        && !entry->value.directory->ids.first_entry->is_name
                        && entry->value.directory->ids.first_entry->name_id.id == 0;

                      if (!next_is_default && !entry_is_default)
                        {
                          _bfd_error_handler (_(".rsrc merge failure: multiple non-default manifests"));
                          bfd_set_error (bfd_error_file_truncated);
                          return;
                        }

                      if (entry_is_default && !next_is_default)
                        {
                          entry->next_entry = next->next_entry;
                          next->next_entry = entry;
                          *points_to_entry = next;
                          points_to_entry = &next->next_entry;
                          next = entry->next_entry;
                          swapped = true;
                        }

                      entry->next_entry = next->next_entry;
                      chain->num_entries--;
                      if (chain->num_entries < 2)
                        return;
                      next = next->next_entry;
                      continue;
                    }
                  else
                    {
                      rsrc_merge (entry, next);
                    }
                }
              else if (mixed_dir)
                {
                  _bfd_error_handler (_(".rsrc merge failure: a directory matches a leaf"));
                  bfd_set_error (bfd_error_file_truncated);
                  return;
                }
              else
                {
                  bool is_default_manifest_leaf =
                    (!entry->is_name && entry->name_id.id == 0)
                    && dir_entry && !dir_entry->is_name && dir_entry->name_id.id == 1
                    && parent_entry && !parent_entry->is_name && parent_entry->name_id.id == 0x18;

                  bool is_string_type =
                    parent_entry && !parent_entry->is_name && parent_entry->name_id.id == 0x6;

                  if (!is_default_manifest_leaf)
                    {
                      if (is_string_type)
                        {
                          if (! rsrc_merge_string_entries (entry, next))
                            {
                              bfd_set_error (bfd_error_file_truncated);
                              return;
                            }
                        }
                      else
                        {
                          if (!(dir_entry && parent_entry))
                            _bfd_error_handler (_(".rsrc merge failure: duplicate leaf"));
                          else
                            {
                              char buff[256];
                              _bfd_error_handler (_(".rsrc merge failure: duplicate leaf: %s"),
                                                  rsrc_resource_name (entry, dir, buff));
                            }
                          bfd_set_error (bfd_error_file_truncated);
                          return;
                        }
                    }
                }

              entry->next_entry = next->next_entry;
              chain->num_entries--;
              if (chain->num_entries < 2)
                return;
              next = next->next_entry;
            }
          else
            {
              points_to_entry = &entry->next_entry;
              entry = next;
              next = next ? next->next_entry : NULL;
            }
        }
      while (next);

      chain->last_entry = entry;
    }
  while (swapped);
}

/* Attach B's chain onto A.  */
static void
rsrc_attach_chain (rsrc_dir_chain * achain, rsrc_dir_chain * bchain)
{
  if (achain == NULL || bchain == NULL || achain == bchain)
    return;

  if (bchain->num_entries == 0 || bchain->first_entry == NULL || bchain->last_entry == NULL)
    return;

  if (achain->first_entry == NULL || achain->last_entry == NULL)
    {
      achain->first_entry = bchain->first_entry;
      achain->last_entry  = bchain->last_entry;
    }
  else
    {
      achain->last_entry->next_entry = bchain->first_entry;
      achain->last_entry = bchain->last_entry;
    }

  achain->num_entries += bchain->num_entries;

  bchain->num_entries = 0;
  bchain->first_entry = NULL;
  bchain->last_entry = NULL;
}

static inline void
rsrc_merge_error (const char *msg)
{
  _bfd_error_handler (_(msg));
  bfd_set_error (bfd_error_file_truncated);
}

static void
rsrc_merge (struct rsrc_entry *a, struct rsrc_entry *b)
{
  rsrc_directory *adir;
  rsrc_directory *bdir;

  BFD_ASSERT (a != NULL);
  BFD_ASSERT (b != NULL);
  BFD_ASSERT (a->is_dir);
  BFD_ASSERT (b->is_dir);

  if (a == NULL || b == NULL || !a->is_dir || !b->is_dir)
    {
      rsrc_merge_error (".rsrc merge failure: invalid resource directories");
      return;
    }

  adir = a->value.directory;
  bdir = b->value.directory;

  if (adir == NULL || bdir == NULL)
    {
      rsrc_merge_error (".rsrc merge failure: missing directory data");
      return;
    }

  if (adir->characteristics != bdir->characteristics)
    {
      rsrc_merge_error (".rsrc merge failure: dirs with differing characteristics");
      return;
    }

  if (adir->major != bdir->major || adir->minor != bdir->minor)
    {
      rsrc_merge_error (".rsrc merge failure: differing directory versions");
      return;
    }

  rsrc_attach_chain (&adir->names, &bdir->names);
  rsrc_attach_chain (&adir->ids, &bdir->ids);

  rsrc_sort_entries (&adir->names, true, adir);
  rsrc_sort_entries (&adir->ids, false, adir);
}

/* Check the .rsrc section.  If it contains multiple concatenated
   resources then we must merge them properly.  Otherwise Windows
   will ignore all but the first set.  */

static void
rsrc_process_section (bfd * abfd,
		      struct coff_final_link_info * pfinfo)
{
  rsrc_directory    new_table;
  bfd_size_type	    size;
  asection *	    sec;
  pe_data_type *    pe;
  bfd_vma	    rva_bias;
  bfd_byte *	    data = NULL;
  bfd_byte *	    datastart = NULL;
  bfd_byte *	    dataend = NULL;
  bfd_byte *	    new_data = NULL;
  unsigned int	    num_resource_sets = 0;
  rsrc_directory *  type_tables = NULL;
  rsrc_write_data   write_data;
  unsigned int	    indx;
  bfd *		    input;
  unsigned int	    num_input_rsrc = 0;
  unsigned int	    max_num_input_rsrc = 4;
  ptrdiff_t *	    rsrc_sizes = NULL;

  new_table.names.num_entries = 0;
  new_table.ids.num_entries = 0;

  sec = bfd_get_section_by_name (abfd, ".rsrc");
  if (sec == NULL || (size = sec->rawsize) == 0)
    return;

  pe = pe_data (abfd);
  if (pe == NULL)
    return;

  rva_bias = sec->vma - pe->pe_opthdr.ImageBase;

  if (! bfd_malloc_and_get_section (abfd, sec, &datastart))
    goto end;

  data = datastart;
  dataend = datastart + size;

  rsrc_sizes = bfd_malloc (max_num_input_rsrc * sizeof (*rsrc_sizes));
  if (rsrc_sizes == NULL)
    goto end;

  for (input = pfinfo->info->input_bfds;
       input != NULL;
       input = input->link.next)
    {
      asection * rsrc_sec = bfd_get_section_by_name (input, ".rsrc");

      if (rsrc_sec != NULL && !discarded_section (rsrc_sec))
	{
	  if (num_input_rsrc == max_num_input_rsrc)
	    {
	      unsigned int new_cap = max_num_input_rsrc + 10;
	      ptrdiff_t *new_rsrc_sizes = bfd_realloc (rsrc_sizes, new_cap * sizeof (*rsrc_sizes));
	      if (new_rsrc_sizes == NULL)
		goto end;
	      rsrc_sizes = new_rsrc_sizes;
	      max_num_input_rsrc = new_cap;
	    }

	  BFD_ASSERT (rsrc_sec->size > 0);
	  rsrc_sizes[num_input_rsrc++] = (ptrdiff_t) rsrc_sec->size;
	}
    }

  if (num_input_rsrc < 2)
    goto end;

  num_resource_sets = 0;
  data = datastart;
  rva_bias = sec->vma - pe->pe_opthdr.ImageBase;

  while (data < dataend)
    {
      bfd_byte * p = data;

      if (num_resource_sets >= num_input_rsrc)
	{
	  _bfd_error_handler (_("%pB: .rsrc merge failure: unexpected number of .rsrc sections"),
			      abfd);
	  bfd_set_error (bfd_error_file_truncated);
	  goto end;
	}

      data = rsrc_count_directory (abfd, data, data, dataend, rva_bias);

      if (data > dataend)
	{
	  _bfd_error_handler (_("%pB: .rsrc merge failure: corrupt .rsrc section"),
			      abfd);
	  bfd_set_error (bfd_error_file_truncated);
	  goto end;
	}

      if ((ptrdiff_t)(data - p) > rsrc_sizes[num_resource_sets])
	{
	  _bfd_error_handler (_("%pB: .rsrc merge failure: unexpected .rsrc size"),
			      abfd);
	  bfd_set_error (bfd_error_file_truncated);
	  goto end;
	}

      if ((bfd_size_type) rsrc_sizes[num_resource_sets] > (bfd_size_type) (dataend - p))
	{
	  _bfd_error_handler (_("%pB: .rsrc merge failure: corrupt .rsrc section"),
			      abfd);
	  bfd_set_error (bfd_error_file_truncated);
	  goto end;
	}

      data = p + rsrc_sizes[num_resource_sets];
      rva_bias += (bfd_vma) (data - p);
      ++num_resource_sets;
    }
  BFD_ASSERT (num_resource_sets == num_input_rsrc);

  data = datastart;
  rva_bias = sec->vma - pe->pe_opthdr.ImageBase;

  type_tables = bfd_malloc (num_resource_sets * sizeof (*type_tables));
  if (type_tables == NULL)
    goto end;

  indx = 0;
  while (data < dataend)
    {
      bfd_byte * p = data;

      if (indx >= num_resource_sets)
	{
	  _bfd_error_handler (_("%pB: .rsrc merge failure: corrupt .rsrc section"),
			      abfd);
	  bfd_set_error (bfd_error_file_truncated);
	  goto end;
	}

      (void) rsrc_parse_directory (abfd, type_tables + indx, data, data,
				   dataend, rva_bias, NULL);
      data = p + rsrc_sizes[indx];
      rva_bias += (bfd_vma) (data - p);
      ++indx;
    }
  BFD_ASSERT (indx == num_resource_sets);

  new_table.characteristics = type_tables[0].characteristics;
  new_table.time	    = type_tables[0].time;
  new_table.major	    = type_tables[0].major;
  new_table.minor	    = type_tables[0].minor;

  new_table.names.first_entry = NULL;
  new_table.names.last_entry = NULL;

  for (indx = 0; indx < num_resource_sets; indx++)
    rsrc_attach_chain (&new_table.names, &type_tables[indx].names);

  rsrc_sort_entries (&new_table.names, true, &new_table);

  new_table.ids.first_entry = NULL;
  new_table.ids.last_entry = NULL;

  for (indx = 0; indx < num_resource_sets; indx++)
    rsrc_attach_chain (&new_table.ids, &type_tables[indx].ids);

  rsrc_sort_entries (&new_table.ids, false, &new_table);

  sizeof_leaves = sizeof_strings = sizeof_tables_and_entries = 0;
  rsrc_compute_region_sizes (&new_table);
  sizeof_strings = (sizeof_strings + 7) & ~7;

  new_data = bfd_zalloc (abfd, size);
  if (new_data == NULL)
    goto end;

  write_data.abfd	 = abfd;
  write_data.datastart	 = new_data;
  write_data.next_table	 = new_data;
  write_data.next_leaf	 = new_data + sizeof_tables_and_entries;
  write_data.next_string = write_data.next_leaf + sizeof_leaves;
  write_data.next_data	 = write_data.next_string + sizeof_strings;
  write_data.rva_bias	 = sec->vma - pe->pe_opthdr.ImageBase;

  rsrc_write_directory (&write_data, &new_table);

  bfd_set_section_contents (pfinfo->output_bfd, sec, new_data, 0, size);
  sec->size = sec->rawsize = size;

 end:
  free (datastart);
  free (rsrc_sizes);
  free (type_tables);
}

/* Handle the .idata section and other things that need symbol table
   access.  */

static inline bool coff_sym_is_valid(const struct coff_link_hash_entry *h)
{
  return h != NULL
      && (h->root.type == bfd_link_hash_defined || h->root.type == bfd_link_hash_defweak)
      && h->root.u.def.section != NULL
      && h->root.u.def.section->output_section != NULL;
}

static inline bfd_vma coff_sym_vma(const struct coff_link_hash_entry *h)
{
  return h->root.u.def.value
       + h->root.u.def.section->output_section->vma
       + h->root.u.def.section->output_offset;
}

static inline struct coff_link_hash_entry *coff_lookup(struct bfd_link_info *info, const char *name)
{
  return coff_link_hash_lookup(coff_hash_table(info), name, false, false, true);
}

static inline void build_sym_name(bfd *abfd, const char *base, char *out, size_t outsz)
{
  int lead = bfd_get_symbol_leading_char(abfd);
  if (lead)
    snprintf(out, outsz, "%c%s", lead, base);
  else
    snprintf(out, outsz, "%s", base);
  if (outsz) out[outsz - 1] = '\0';
}

bool
_bfd_XXi_final_link_postscript (bfd * abfd, struct coff_final_link_info *pfinfo)
{
  struct coff_link_hash_entry *h1;
  struct bfd_link_info *info = pfinfo->info;
  bool result = true;
  char name[32];

  h1 = coff_lookup(info, ".idata$2");
  if (h1 != NULL)
    {
      if (coff_sym_is_valid(h1))
        pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_TABLE].VirtualAddress = coff_sym_vma(h1);
      else
        {
          _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: %s is missing"),
                              abfd, PE_IMPORT_TABLE, ".idata$2");
          result = false;
        }

      h1 = coff_lookup(info, ".idata$4");
      if (coff_sym_is_valid(h1))
        pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_TABLE].Size =
          (coff_sym_vma(h1)
           - pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_TABLE].VirtualAddress);
      else
        {
          _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: %s is missing"),
                              abfd, PE_IMPORT_TABLE, ".idata$4");
          result = false;
        }

      h1 = coff_lookup(info, ".idata$5");
      if (coff_sym_is_valid(h1))
        pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].VirtualAddress = coff_sym_vma(h1);
      else
        {
          _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: %s is missing"),
                              abfd, PE_IMPORT_ADDRESS_TABLE, ".idata$5");
          result = false;
        }

      h1 = coff_lookup(info, ".idata$6");
      if (coff_sym_is_valid(h1))
        pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].Size =
          (coff_sym_vma(h1)
           - pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].VirtualAddress);
      else
        {
          _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: %s is missing"),
                              abfd, PE_IMPORT_ADDRESS_TABLE, ".idata$6");
          result = false;
        }
    }
  else
    {
      h1 = coff_lookup(info, "__IAT_start__");
      if (coff_sym_is_valid(h1))
        {
          bfd_vma iat_va = coff_sym_vma(h1);
          h1 = coff_lookup(info, "__IAT_end__");
          if (coff_sym_is_valid(h1))
            {
              pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].Size =
                (coff_sym_vma(h1) - iat_va);
              if (pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].Size != 0)
                pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].VirtualAddress =
                  iat_va - pe_data (abfd)->pe_opthdr.ImageBase;
            }
          else
            {
              _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
                                  abfd, PE_IMPORT_ADDRESS_TABLE, "__IAT_end__");
              result = false;
            }
        }
    }

  h1 = coff_lookup(info, "__DELAY_IMPORT_DIRECTORY_start__");
  if (coff_sym_is_valid(h1))
    {
      bfd_vma delay_va = coff_sym_vma(h1);
      h1 = coff_lookup(info, "__DELAY_IMPORT_DIRECTORY_end__");
      if (coff_sym_is_valid(h1))
        {
          pe_data (abfd)->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR].Size =
            (coff_sym_vma(h1) - delay_va);
          if (pe_data (abfd)->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR].Size != 0)
            pe_data (abfd)->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR].VirtualAddress =
              delay_va - pe_data (abfd)->pe_opthdr.ImageBase;
        }
      else
        {
          _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
                              abfd, PE_DELAY_IMPORT_DESCRIPTOR, "__DELAY_IMPORT_DIRECTORY_end__");
          result = false;
        }
    }

  build_sym_name(abfd, "_tls_used", name, sizeof(name));
  h1 = coff_lookup(info, name);
  if (h1 != NULL)
    {
      if (coff_sym_is_valid(h1))
        pe_data (abfd)->pe_opthdr.DataDirectory[PE_TLS_TABLE].VirtualAddress =
          (coff_sym_vma(h1) - pe_data (abfd)->pe_opthdr.ImageBase);
      else
        {
          _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
                              abfd, PE_TLS_TABLE, name);
          result = false;
        }
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
      pe_data (abfd)->pe_opthdr.DataDirectory[PE_TLS_TABLE].Size = 0x18;
#else
      pe_data (abfd)->pe_opthdr.DataDirectory[PE_TLS_TABLE].Size = 0x28;
#endif
    }

  build_sym_name(abfd, "_load_config_used", name, sizeof(name));
  h1 = coff_lookup(info, name);
  if (h1 != NULL)
    {
      char data[4];
      if (coff_sym_is_valid(h1))
        {
          pe_data (abfd)->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].VirtualAddress =
            (coff_sym_vma(h1) - pe_data (abfd)->pe_opthdr.ImageBase);

          if (pe_data (abfd)->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].VirtualAddress
              & (bfd_arch_bits_per_address (abfd) / bfd_arch_bits_per_byte (abfd) - 1))
            {
              _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: %s not properly aligned"),
                                  abfd, PE_LOAD_CONFIG_TABLE, name);
              result = false;
            }

          if (bfd_get_section_contents (abfd,
                                        h1->root.u.def.section->output_section,
                                        data,
                                        h1->root.u.def.section->output_offset + h1->root.u.def.value,
                                        sizeof(data)))
            {
              uint32_t size = bfd_get_32 (abfd, data);
              pe_data (abfd)->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].Size =
                (bfd_get_arch (abfd) == bfd_arch_i386
                 && ((bfd_get_mach (abfd) & ~bfd_mach_i386_intel_syntax) == bfd_mach_i386_i386)
                 && ((pe_data (abfd)->pe_opthdr.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI)
                     || (pe_data (abfd)->pe_opthdr.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI))
                 && (pe_data (abfd)->pe_opthdr.MajorSubsystemVersion * 256
                     + pe_data (abfd)->pe_opthdr.MinorSubsystemVersion <= 0x0501))
                ? 64 : size;

              if (size > h1->root.u.def.section->size - h1->root.u.def.value)
                {
                  _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: size too large for the containing section"),
                                      abfd, PE_LOAD_CONFIG_TABLE);
                  result = false;
                }
            }
          else
            {
              _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: size can't be read from %s"),
                                  abfd, PE_LOAD_CONFIG_TABLE, name);
              result = false;
            }
        }
      else
        {
          _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
                              abfd, PE_LOAD_CONFIG_TABLE, name);
          result = false;
        }
    }

#if !defined(COFF_WITH_pep) && (defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined (COFF_WITH_peRiscV64))
  {
    asection *sec = bfd_get_section_by_name (abfd, ".pdata");
    if (sec)
      {
        bfd_size_type x = sec->rawsize;
        bfd_byte *tmp_data = NULL;
        if (bfd_malloc_and_get_section (abfd, sec, &tmp_data))
          {
            qsort (tmp_data, (size_t) (x / 12), 12, sort_x64_pdata);
            if (!bfd_set_section_contents (pfinfo->output_bfd, sec, tmp_data, 0, x))
              result = false;
            free (tmp_data);
          }
        else
          result = false;
      }
  }
#endif

  rsrc_process_section (abfd, pfinfo);
  return result;
}
