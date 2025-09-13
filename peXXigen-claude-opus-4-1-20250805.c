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
_bfd_XXi_swap_sym_in (bfd * abfd, void * ext1, void * in1)
{
  SYMENT *ext = (SYMENT *) ext1;
  struct internal_syment *in = (struct internal_syment *) in1;

  if (ext->e.e_name[0] == 0)
    {
      in->_n._n_n._n_zeroes = 0;
      in->_n._n_n._n_offset = H_GET_32 (abfd, ext->e.e.e_offset);
    }
  else
    memcpy (in->_n._n_name, ext->e.e_name, SYMNMLEN);

  in->n_value = H_GET_32 (abfd, ext->e_value);
  in->n_scnum = (short) H_GET_16 (abfd, ext->e_scnum);

  if (sizeof (ext->e_type) == 2)
    in->n_type = H_GET_16 (abfd, ext->e_type);
  else
    in->n_type = H_GET_32 (abfd, ext->e_type);

  in->n_sclass = H_GET_8 (abfd, ext->e_sclass);
  in->n_numaux = H_GET_8 (abfd, ext->e_numaux);

#ifndef STRICT_PE_FORMAT
  if (in->n_sclass != C_SECTION)
    return;

  in->n_value = 0x0;

  if (in->n_scnum != 0)
    {
      in->n_sclass = C_STAT;
      return;
    }

  char namebuf[SYMNMLEN + 1];
  const char *name = _bfd_coff_internal_syment_name (abfd, in, namebuf);
  if (name == NULL)
    {
      _bfd_error_handler (_("%pB: unable to find name for empty section"), abfd);
      bfd_set_error (bfd_error_invalid_target);
      return;
    }

  asection *sec = bfd_get_section_by_name (abfd, name);
  if (sec != NULL)
    {
      in->n_scnum = sec->target_index;
      in->n_sclass = C_STAT;
      return;
    }

  int unused_section_number = 0;
  for (sec = abfd->sections; sec; sec = sec->next)
    if (unused_section_number <= sec->target_index)
      unused_section_number = sec->target_index + 1;

  size_t name_len = strlen (name) + 1;
  char *sec_name = bfd_alloc (abfd, name_len);
  if (sec_name == NULL)
    {
      _bfd_error_handler (_("%pB: out of memory creating name for empty section"), abfd);
      return;
    }
  memcpy (sec_name, name, name_len);

  flagword flags = SEC_HAS_CONTENTS | SEC_ALLOC | SEC_DATA | SEC_LOAD | SEC_LINKER_CREATED;
  sec = bfd_make_section_anyway_with_flags (abfd, sec_name, flags);
  if (sec == NULL)
    {
      _bfd_error_handler (_("%pB: unable to create fake empty section"), abfd);
      return;
    }

  sec->alignment_power = 2;
  sec->target_index = unused_section_number;
  in->n_scnum = unused_section_number;
  in->n_sclass = C_STAT;
#endif
}

static bool
abs_finder(bfd *abfd ATTRIBUTE_UNUSED, asection *sec, void *data)
{
  if (sec == NULL || data == NULL) {
    return false;
  }
  
  bfd_vma abs_val = *(bfd_vma *)data;
  bfd_vma section_end = sec->vma + (1ULL << 32);
  
  if (section_end < sec->vma) {
    return false;
  }
  
  return sec->vma <= abs_val && section_end > abs_val;
}

unsigned int
_bfd_XXi_swap_sym_out (bfd * abfd, void * inp, void * extp)
{
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

  if (sizeof (in->n_value) > 4)
    {
      const unsigned int shift = 32;
      const unsigned long long max_value = (1ULL << shift) - 1;
      
      if (in->n_value > max_value && in->n_scnum == N_ABS)
        {
          asection * sec = bfd_sections_find_if (abfd, abs_finder, &in->n_value);
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
    {
      H_PUT_16 (abfd, in->n_type, ext->e_type);
    }
  else
    {
      H_PUT_32 (abfd, in->n_type, ext->e_type);
    }

  H_PUT_8 (abfd, in->n_sclass, ext->e_sclass);
  H_PUT_8 (abfd, in->n_numaux, ext->e_numaux);

  return SYMESZ;
}

void
_bfd_XXi_swap_aux_in (bfd *	abfd,
		      void *	ext1,
		      int       type,
		      int       in_class,
		      int	indx ATTRIBUTE_UNUSED,
		      int	numaux ATTRIBUTE_UNUSED,
		      void *	in1)
{
  AUXENT *ext = (AUXENT *) ext1;
  union internal_auxent *in = (union internal_auxent *) in1;

  memset (in, 0, sizeof (*in));
  
  if (in_class == C_FILE)
    {
      if (ext->x_file.x_fname[0] == 0)
	{
	  in->x_file.x_n.x_n.x_zeroes = 0;
	  in->x_file.x_n.x_n.x_offset = H_GET_32 (abfd, ext->x_file.x_n.x_offset);
	}
      else
	{
#if FILNMLEN != E_FILNMLEN
#error we need to cope with truncating or extending x_fname
#endif
	  memcpy (in->x_file.x_n.x_fname, ext->x_file.x_fname, FILNMLEN);
	}
      return;
    }

  if ((in_class == C_STAT || in_class == C_LEAFSTAT || in_class == C_HIDDEN) 
      && type == T_NULL)
    {
      in->x_scn.x_scnlen = GET_SCN_SCNLEN (abfd, ext);
      in->x_scn.x_nreloc = GET_SCN_NRELOC (abfd, ext);
      in->x_scn.x_nlinno = GET_SCN_NLINNO (abfd, ext);
      in->x_scn.x_checksum = H_GET_32 (abfd, ext->x_scn.x_checksum);
      in->x_scn.x_associated = H_GET_16 (abfd, ext->x_scn.x_associated);
      in->x_scn.x_comdat = H_GET_8 (abfd, ext->x_scn.x_comdat);
      return;
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
      in->x_sym.x_fcnary.x_ary.x_dimen[0] = H_GET_16 (abfd, ext->x_sym.x_fcnary.x_ary.x_dimen[0]);
      in->x_sym.x_fcnary.x_ary.x_dimen[1] = H_GET_16 (abfd, ext->x_sym.x_fcnary.x_ary.x_dimen[1]);
      in->x_sym.x_fcnary.x_ary.x_dimen[2] = H_GET_16 (abfd, ext->x_sym.x_fcnary.x_ary.x_dimen[2]);
      in->x_sym.x_fcnary.x_ary.x_dimen[3] = H_GET_16 (abfd, ext->x_sym.x_fcnary.x_ary.x_dimen[3]);
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
_bfd_XXi_swap_aux_out (bfd *  abfd,
		       void * inp,
		       int    type,
		       int    in_class,
		       int    indx ATTRIBUTE_UNUSED,
		       int    numaux ATTRIBUTE_UNUSED,
		       void * extp)
{
  union internal_auxent *in = (union internal_auxent *) inp;
  AUXENT *ext = (AUXENT *) extp;

  if (in == NULL || ext == NULL || abfd == NULL)
    return 0;

  memset (ext, 0, AUXESZ);

  if (in_class == C_FILE)
    {
      if (in->x_file.x_n.x_fname[0] == 0)
        {
          H_PUT_32 (abfd, 0, ext->x_file.x_n.x_zeroes);
          H_PUT_32 (abfd, in->x_file.x_n.x_n.x_offset, ext->x_file.x_n.x_offset);
        }
      else
        {
#if FILNMLEN != E_FILNMLEN
#error we need to cope with truncating or extending x_fname
#endif
          memcpy (ext->x_file.x_fname, in->x_file.x_n.x_fname, E_FILNMLEN);
        }
      return AUXESZ;
    }

  if ((in_class == C_STAT || in_class == C_LEAFSTAT || in_class == C_HIDDEN) && type == T_NULL)
    {
      PUT_SCN_SCNLEN (abfd, in->x_scn.x_scnlen, ext);
      PUT_SCN_NRELOC (abfd, in->x_scn.x_nreloc, ext);
      PUT_SCN_NLINNO (abfd, in->x_scn.x_nlinno, ext);
      H_PUT_32 (abfd, in->x_scn.x_checksum, ext->x_scn.x_checksum);
      H_PUT_16 (abfd, in->x_scn.x_associated, ext->x_scn.x_associated);
      H_PUT_8 (abfd, in->x_scn.x_comdat, ext->x_scn.x_comdat);
      return AUXESZ;
    }

  H_PUT_32 (abfd, in->x_sym.x_tagndx.u32, ext->x_sym.x_tagndx);
  H_PUT_16 (abfd, in->x_sym.x_tvndx, ext->x_sym.x_tvndx);

  if (in_class == C_BLOCK || in_class == C_FCN || ISFCN (type) || ISTAG (in_class))
    {
      PUT_FCN_LNNOPTR (abfd, in->x_sym.x_fcnary.x_fcn.x_lnnoptr, ext);
      PUT_FCN_ENDNDX (abfd, in->x_sym.x_fcnary.x_fcn.x_endndx.u32, ext);
    }
  else
    {
      H_PUT_16 (abfd, in->x_sym.x_fcnary.x_ary.x_dimen[0], ext->x_sym.x_fcnary.x_ary.x_dimen[0]);
      H_PUT_16 (abfd, in->x_sym.x_fcnary.x_ary.x_dimen[1], ext->x_sym.x_fcnary.x_ary.x_dimen[1]);
      H_PUT_16 (abfd, in->x_sym.x_fcnary.x_ary.x_dimen[2], ext->x_sym.x_fcnary.x_ary.x_dimen[2]);
      H_PUT_16 (abfd, in->x_sym.x_fcnary.x_ary.x_dimen[3], ext->x_sym.x_fcnary.x_ary.x_dimen[3]);
    }

  if (ISFCN (type))
    {
      H_PUT_32 (abfd, in->x_sym.x_misc.x_fsize, ext->x_sym.x_misc.x_fsize);
    }
  else
    {
      PUT_LNSZ_LNNO (abfd, in->x_sym.x_misc.x_lnsz.x_lnno, ext);
      PUT_LNSZ_SIZE (abfd, in->x_sym.x_misc.x_lnsz.x_size, ext);
    }

  return AUXESZ;
}

void
_bfd_XXi_swap_lineno_in (bfd * abfd, void * ext1, void * in1)
{
  if (abfd == NULL || ext1 == NULL || in1 == NULL)
    return;

  LINENO *ext = (LINENO *) ext1;
  struct internal_lineno *in = (struct internal_lineno *) in1;

  in->l_addr.l_symndx = H_GET_32 (abfd, ext->l_addr.l_symndx);
  in->l_lnno = GET_LINENO_LNNO (abfd, ext);
}

unsigned int
_bfd_XXi_swap_lineno_out (bfd * abfd, void * inp, void * outp)
{
  if (abfd == NULL || inp == NULL || outp == NULL)
    return 0;

  struct internal_lineno *in = (struct internal_lineno *) inp;
  struct external_lineno *ext = (struct external_lineno *) outp;
  
  H_PUT_32 (abfd, in->l_addr.l_symndx, ext->l_addr.l_symndx);
  PUT_LINENO_LNNO (abfd, in->l_lnno, ext);
  
  return LINESZ;
}

void
_bfd_XXi_swap_aouthdr_in (bfd * abfd,
			  void * aouthdr_ext1,
			  void * aouthdr_int1)
{
  PEAOUTHDR * src = (PEAOUTHDR *) aouthdr_ext1;
  AOUTHDR * aouthdr_ext = (AOUTHDR *) aouthdr_ext1;
  struct internal_aouthdr *aouthdr_int
    = (struct internal_aouthdr *) aouthdr_int1;
  struct internal_extra_pe_aouthdr *a = &aouthdr_int->pe;

  aouthdr_int->magic = H_GET_16 (abfd, aouthdr_ext->magic);
  aouthdr_int->vstamp = H_GET_16 (abfd, aouthdr_ext->vstamp);
  aouthdr_int->tsize = GET_AOUTHDR_TSIZE (abfd, aouthdr_ext->tsize);
  aouthdr_int->dsize = GET_AOUTHDR_DSIZE (abfd, aouthdr_ext->dsize);
  aouthdr_int->bsize = GET_AOUTHDR_BSIZE (abfd, aouthdr_ext->bsize);
  aouthdr_int->entry = GET_AOUTHDR_ENTRY (abfd, aouthdr_ext->entry);
  aouthdr_int->text_start =
    GET_AOUTHDR_TEXT_START (abfd, aouthdr_ext->text_start);

#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
  aouthdr_int->data_start =
    GET_AOUTHDR_DATA_START (abfd, aouthdr_ext->data_start);
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
  a->MajorOperatingSystemVersion =
    H_GET_16 (abfd, src->MajorOperatingSystemVersion);
  a->MinorOperatingSystemVersion =
    H_GET_16 (abfd, src->MinorOperatingSystemVersion);
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
  a->SizeOfStackReserve =
    GET_OPTHDR_SIZE_OF_STACK_RESERVE (abfd, src->SizeOfStackReserve);
  a->SizeOfStackCommit =
    GET_OPTHDR_SIZE_OF_STACK_COMMIT (abfd, src->SizeOfStackCommit);
  a->SizeOfHeapReserve =
    GET_OPTHDR_SIZE_OF_HEAP_RESERVE (abfd, src->SizeOfHeapReserve);
  a->SizeOfHeapCommit =
    GET_OPTHDR_SIZE_OF_HEAP_COMMIT (abfd, src->SizeOfHeapCommit);
  a->LoaderFlags = H_GET_32 (abfd, src->LoaderFlags);
  a->NumberOfRvaAndSizes = H_GET_32 (abfd, src->NumberOfRvaAndSizes);

  unsigned idx;
  unsigned num_entries = a->NumberOfRvaAndSizes;
  if (num_entries > IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
    num_entries = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

  for (idx = 0; idx < num_entries; idx++)
    {
      int size = H_GET_32 (abfd, src->DataDirectory[idx][1]);
      int vma = (size != 0) ? H_GET_32 (abfd, src->DataDirectory[idx][0]) : 0;

      a->DataDirectory[idx].Size = size;
      a->DataDirectory[idx].VirtualAddress = vma;
    }

  for (; idx < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; idx++)
    {
      a->DataDirectory[idx].Size = 0;
      a->DataDirectory[idx].VirtualAddress = 0;
    }

  if (aouthdr_int->entry != 0)
    {
      aouthdr_int->entry += a->ImageBase;
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
      aouthdr_int->entry &= 0xffffffff;
#endif
    }

  if (aouthdr_int->tsize != 0)
    {
      aouthdr_int->text_start += a->ImageBase;
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
      aouthdr_int->text_start &= 0xffffffff;
#endif
    }

#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
  if (aouthdr_int->dsize != 0)
    {
      aouthdr_int->data_start += a->ImageBase;
      aouthdr_int->data_start &= 0xffffffff;
    }
#endif
}

/* A support function for below.  */

static void
add_data_entry (bfd * abfd,
		struct internal_extra_pe_aouthdr *aout,
		int idx,
		char *name,
		bfd_vma base)
{
  asection *sec;
  int size;

  if (abfd == NULL || aout == NULL || name == NULL)
    return;

  sec = bfd_get_section_by_name (abfd, name);
  if (sec == NULL)
    return;

  if (coff_section_data (abfd, sec) == NULL)
    return;

  if (pei_section_data (abfd, sec) == NULL)
    return;

  size = pei_section_data (abfd, sec)->virt_size;
  aout->DataDirectory[idx].Size = size;

  if (size == 0)
    return;

  aout->DataDirectory[idx].VirtualAddress = (sec->vma - base) & 0xffffffff;
  sec->flags |= SEC_DATA;
}

unsigned int
_bfd_XXi_swap_aouthdr_out (bfd * abfd, void * in, void * out)
{
  struct internal_aouthdr *aouthdr_in = (struct internal_aouthdr *) in;
  pe_data_type *pe = pe_data (abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
  PEAOUTHDR *aouthdr_out = (PEAOUTHDR *) out;
  bfd_vma sa, fa, ib;

  sa = extra->SectionAlignment;
  fa = extra->FileAlignment;
  ib = extra->ImageBase;

  IMAGE_DATA_DIRECTORY saved_dirs[5];
  saved_dirs[0] = pe->pe_opthdr.DataDirectory[PE_IMPORT_TABLE];
  saved_dirs[1] = pe->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE];
  saved_dirs[2] = pe->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR];
  saved_dirs[3] = pe->pe_opthdr.DataDirectory[PE_TLS_TABLE];
  saved_dirs[4] = pe->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE];

#define IS_32BIT_PE (!defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined(COFF_WITH_peRiscV64))

  if (aouthdr_in->tsize)
    {
      aouthdr_in->text_start -= ib;
#if IS_32BIT_PE
      aouthdr_in->text_start &= 0xffffffff;
#endif
    }

  if (aouthdr_in->dsize)
    {
      aouthdr_in->data_start -= ib;
#if IS_32BIT_PE
      aouthdr_in->data_start &= 0xffffffff;
#endif
    }

  if (aouthdr_in->entry)
    {
      aouthdr_in->entry -= ib;
#if IS_32BIT_PE
      aouthdr_in->entry &= 0xffffffff;
#endif
    }

#define FA(x) (((x) + fa -1 ) & (- fa))
#define SA(x) (((x) + sa -1 ) & (- sa))

  aouthdr_in->bsize = FA (aouthdr_in->bsize);

  extra->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

  add_data_entry (abfd, extra, PE_EXPORT_TABLE, ".edata", ib);
  add_data_entry (abfd, extra, PE_RESOURCE_TABLE, ".rsrc", ib);
  add_data_entry (abfd, extra, PE_EXCEPTION_TABLE, ".pdata", ib);

  extra->DataDirectory[PE_IMPORT_TABLE] = saved_dirs[0];
  extra->DataDirectory[PE_IMPORT_ADDRESS_TABLE] = saved_dirs[1];
  extra->DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR] = saved_dirs[2];
  extra->DataDirectory[PE_TLS_TABLE] = saved_dirs[3];
  extra->DataDirectory[PE_LOAD_CONFIG_TABLE] = saved_dirs[4];

  if (extra->DataDirectory[PE_IMPORT_TABLE].VirtualAddress == 0)
    add_data_entry (abfd, extra, PE_IMPORT_TABLE, ".idata", ib);

  if (pe->has_reloc_section)
    add_data_entry (abfd, extra, PE_BASE_RELOCATION_TABLE, ".reloc", ib);

  asection *sec;
  bfd_vma hsize = 0;
  bfd_vma dsize = 0;
  bfd_vma isize = 0;
  bfd_vma tsize = 0;

  for (sec = abfd->sections; sec; sec = sec->next)
    {
      int rounded = FA (sec->size);

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
        isize = SA (sec->vma - extra->ImageBase
                    + FA (pei_section_data (abfd, sec)->virt_size));
    }

  aouthdr_in->dsize = dsize;
  aouthdr_in->tsize = tsize;
  extra->SizeOfHeaders = hsize;
  extra->SizeOfImage = isize;

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
#define LINKER_VERSION ((short) (BFD_VERSION / 1000000))
      H_PUT_16 (abfd, (LINKER_VERSION / 100 + (LINKER_VERSION % 100) * 256),
                aouthdr_out->standard.vstamp);
    }

  PUT_AOUTHDR_TSIZE (abfd, aouthdr_in->tsize, aouthdr_out->standard.tsize);
  PUT_AOUTHDR_DSIZE (abfd, aouthdr_in->dsize, aouthdr_out->standard.dsize);
  PUT_AOUTHDR_BSIZE (abfd, aouthdr_in->bsize, aouthdr_out->standard.bsize);
  PUT_AOUTHDR_ENTRY (abfd, aouthdr_in->entry, aouthdr_out->standard.entry);
  PUT_AOUTHDR_TEXT_START (abfd, aouthdr_in->text_start,
                          aouthdr_out->standard.text_start);

#if IS_32BIT_PE
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

  int idx;
  for (idx = 0; idx < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; idx++)
    {
      H_PUT_32 (abfd, extra->DataDirectory[idx].VirtualAddress,
                aouthdr_out->DataDirectory[idx][0]);
      H_PUT_32 (abfd, extra->DataDirectory[idx].Size,
                aouthdr_out->DataDirectory[idx][1]);
    }

  return AOUTSZ;
}

unsigned int
_bfd_XXi_only_swap_filehdr_out (bfd * abfd, void * in, void * out)
{
  struct internal_filehdr *filehdr_in = (struct internal_filehdr *) in;
  struct external_PEI_filehdr *filehdr_out = (struct external_PEI_filehdr *) out;

  if (filehdr_in == NULL || filehdr_out == NULL || abfd == NULL)
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

  memset(filehdr_in->pe.e_res, 0, sizeof(filehdr_in->pe.e_res));
  
  filehdr_in->pe.e_oemid   = 0x0;
  filehdr_in->pe.e_oeminfo = 0x0;

  memset(filehdr_in->pe.e_res2, 0, sizeof(filehdr_in->pe.e_res2));

  filehdr_in->pe.e_lfanew = 0x80;

  memcpy (filehdr_in->pe.dos_message, pe_data (abfd)->dos_message,
	  sizeof (filehdr_in->pe.dos_message));

  filehdr_in->pe.nt_signature = IMAGE_NT_SIGNATURE;

  H_PUT_16 (abfd, filehdr_in->f_magic, filehdr_out->f_magic);
  H_PUT_16 (abfd, filehdr_in->f_nscns, filehdr_out->f_nscns);

  if ((pe_data (abfd)->timestamp) == -1)
    {
      time_t now = bfd_get_current_time (0);
      H_PUT_32 (abfd, now, filehdr_out->f_timdat);
    }
  else
    {
      H_PUT_32 (abfd, pe_data (abfd)->timestamp, filehdr_out->f_timdat);
    }

  PUT_FILEHDR_SYMPTR (abfd, filehdr_in->f_symptr, filehdr_out->f_symptr);
  H_PUT_32 (abfd, filehdr_in->f_nsyms, filehdr_out->f_nsyms);
  H_PUT_16 (abfd, filehdr_in->f_opthdr, filehdr_out->f_opthdr);
  H_PUT_16 (abfd, filehdr_in->f_flags, filehdr_out->f_flags);

  H_PUT_16 (abfd, filehdr_in->pe.e_magic, filehdr_out->e_magic);
  H_PUT_16 (abfd, filehdr_in->pe.e_cblp, filehdr_out->e_cblp);
  H_PUT_16 (abfd, filehdr_in->pe.e_cp, filehdr_out->e_cp);
  H_PUT_16 (abfd, filehdr_in->pe.e_crlc, filehdr_out->e_crlc);
  H_PUT_16 (abfd, filehdr_in->pe.e_cparhdr, filehdr_out->e_cparhdr);
  H_PUT_16 (abfd, filehdr_in->pe.e_minalloc, filehdr_out->e_minalloc);
  H_PUT_16 (abfd, filehdr_in->pe.e_maxalloc, filehdr_out->e_maxalloc);
  H_PUT_16 (abfd, filehdr_in->pe.e_ss, filehdr_out->e_ss);
  H_PUT_16 (abfd, filehdr_in->pe.e_sp, filehdr_out->e_sp);
  H_PUT_16 (abfd, filehdr_in->pe.e_csum, filehdr_out->e_csum);
  H_PUT_16 (abfd, filehdr_in->pe.e_ip, filehdr_out->e_ip);
  H_PUT_16 (abfd, filehdr_in->pe.e_cs, filehdr_out->e_cs);
  H_PUT_16 (abfd, filehdr_in->pe.e_lfarlc, filehdr_out->e_lfarlc);
  H_PUT_16 (abfd, filehdr_in->pe.e_ovno, filehdr_out->e_ovno);

  for (int idx = 0; idx < 4; idx++)
    H_PUT_16 (abfd, filehdr_in->pe.e_res[idx], filehdr_out->e_res[idx]);

  H_PUT_16 (abfd, filehdr_in->pe.e_oemid, filehdr_out->e_oemid);
  H_PUT_16 (abfd, filehdr_in->pe.e_oeminfo, filehdr_out->e_oeminfo);

  for (int idx = 0; idx < 10; idx++)
    H_PUT_16 (abfd, filehdr_in->pe.e_res2[idx], filehdr_out->e_res2[idx]);

  H_PUT_32 (abfd, filehdr_in->pe.e_lfanew, filehdr_out->e_lfanew);

  memcpy (filehdr_out->dos_message, filehdr_in->pe.dos_message,
	  sizeof (filehdr_out->dos_message));

  H_PUT_32 (abfd, filehdr_in->pe.nt_signature, filehdr_out->nt_signature);

  return FILHSZ;
}

unsigned int
_bfd_XX_only_swap_filehdr_out (bfd * abfd, void * in, void * out)
{
  if (abfd == NULL || in == NULL || out == NULL) {
    return 0;
  }

  struct internal_filehdr *filehdr_in = (struct internal_filehdr *) in;
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
_bfd_XXi_swap_scnhdr_out (bfd * abfd, void * in, void * out)
{
  struct internal_scnhdr *scnhdr_int = (struct internal_scnhdr *) in;
  SCNHDR *scnhdr_ext = (SCNHDR *) out;
  unsigned int ret = SCNHSZ;
  bfd_vma ps;
  bfd_vma ss;

  memcpy (scnhdr_ext->s_name, scnhdr_int->s_name, sizeof (scnhdr_int->s_name));

  ss = scnhdr_int->s_vaddr - pe_data (abfd)->pe_opthdr.ImageBase;
  if (scnhdr_int->s_vaddr < pe_data (abfd)->pe_opthdr.ImageBase)
    _bfd_error_handler (_("%pB:%.8s: section below image base"),
                        abfd, scnhdr_int->s_name);
#if !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
  else if(ss != (ss & 0xffffffff))
    _bfd_error_handler (_("%pB:%.8s: RVA truncated"), abfd, scnhdr_int->s_name);
  PUT_SCNHDR_VADDR (abfd, ss & 0xffffffff, scnhdr_ext->s_vaddr);
#else
  PUT_SCNHDR_VADDR (abfd, ss, scnhdr_ext->s_vaddr);
#endif

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

  static const struct {
    char section_name[SCNNMLEN];
    unsigned long must_have;
  } known_sections[] = {
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
    { ".text" , IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE },
    { ".tls",   IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_WRITE },
    { ".xdata", IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA },
  };

  for (size_t i = 0; i < ARRAY_SIZE (known_sections); i++)
    {
      if (memcmp (scnhdr_int->s_name, known_sections[i].section_name, SCNNMLEN) == 0)
        {
          if (memcmp (scnhdr_int->s_name, ".text", sizeof ".text")
              || (bfd_get_file_flags (abfd) & WP_TEXT))
            scnhdr_int->s_flags &= ~IMAGE_SCN_MEM_WRITE;
          scnhdr_int->s_flags |= known_sections[i].must_have;
          break;
        }
    }

  H_PUT_32 (abfd, scnhdr_int->s_flags, scnhdr_ext->s_flags);

  if (coff_data (abfd)->link_info
      && ! bfd_link_relocatable (coff_data (abfd)->link_info)
      && ! bfd_link_pic (coff_data (abfd)->link_info)
      && memcmp (scnhdr_int->s_name, ".text", sizeof ".text") == 0)
    {
      H_PUT_16 (abfd, (scnhdr_int->s_nlnno & 0xffff), scnhdr_ext->s_nlnno);
      H_PUT_16 (abfd, (scnhdr_int->s_nlnno >> 16), scnhdr_ext->s_nreloc);
    }
  else
    {
      if (scnhdr_int->s_nlnno <= 0xffff)
	H_PUT_16 (abfd, scnhdr_int->s_nlnno, scnhdr_ext->s_nlnno);
      else
	{
	  _bfd_error_handler (_("%pB: line number overflow: 0x%lx > 0xffff"),
			      abfd, scnhdr_int->s_nlnno);
	  bfd_set_error (bfd_error_file_truncated);
	  H_PUT_16 (abfd, 0xffff, scnhdr_ext->s_nlnno);
	  ret = 0;
	}

      if (scnhdr_int->s_nreloc < 0xffff)
	H_PUT_16 (abfd, scnhdr_int->s_nreloc, scnhdr_ext->s_nreloc);
      else
	{
	  H_PUT_16 (abfd, 0xffff, scnhdr_ext->s_nreloc);
	  scnhdr_int->s_flags |= IMAGE_SCN_LNK_NRELOC_OVFL;
	  H_PUT_32 (abfd, scnhdr_int->s_flags, scnhdr_ext->s_flags);
	}
    }
  return ret;
}

void
_bfd_XXi_swap_debugdir_in (bfd * abfd, void * ext1, void * in1)
{
  struct external_IMAGE_DEBUG_DIRECTORY *ext;
  struct internal_IMAGE_DEBUG_DIRECTORY *in;

  if (abfd == NULL || ext1 == NULL || in1 == NULL)
    return;

  ext = (struct external_IMAGE_DEBUG_DIRECTORY *) ext1;
  in = (struct internal_IMAGE_DEBUG_DIRECTORY *) in1;

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
_bfd_XXi_swap_debugdir_out (bfd * abfd, void * inp, void * extp)
{
  struct external_IMAGE_DEBUG_DIRECTORY *ext = extp;
  struct internal_IMAGE_DEBUG_DIRECTORY *in = inp;

  if (abfd == NULL || in == NULL || ext == NULL)
    return 0;

  H_PUT_32(abfd, in->Characteristics, ext->Characteristics);
  H_PUT_32(abfd, in->TimeDateStamp, ext->TimeDateStamp);
  H_PUT_16(abfd, in->MajorVersion, ext->MajorVersion);
  H_PUT_16(abfd, in->MinorVersion, ext->MinorVersion);
  H_PUT_32(abfd, in->Type, ext->Type);
  H_PUT_32(abfd, in->SizeOfData, ext->SizeOfData);
  H_PUT_32(abfd, in->AddressOfRawData, ext->AddressOfRawData);
  H_PUT_32(abfd, in->PointerToRawData, ext->PointerToRawData);

  return sizeof (struct external_IMAGE_DEBUG_DIRECTORY);
}

CODEVIEW_INFO *
_bfd_XXi_slurp_codeview_record (bfd * abfd, file_ptr where, unsigned long length, CODEVIEW_INFO *cvinfo,
				char **pdb)
{
  char buffer[256+1];
  bfd_size_type nread;

  if (!abfd || !cvinfo)
    return NULL;

  if (bfd_seek (abfd, where, SEEK_SET) != 0)
    return NULL;

  if (length <= sizeof (CV_INFO_PDB70) && length <= sizeof (CV_INFO_PDB20))
    return NULL;

  if (length > 256)
    length = 256;

  nread = bfd_read (buffer, length, abfd);
  if (length != nread)
    return NULL;

  memset (buffer + nread, 0, sizeof (buffer) - nread);

  cvinfo->CVSignature = H_GET_32 (abfd, buffer);
  cvinfo->Age = 0;

  if (cvinfo->CVSignature == CVINFO_PDB70_CVSIGNATURE)
    {
      if (length <= sizeof (CV_INFO_PDB70))
        return NULL;

      CV_INFO_PDB70 *cvinfo70 = (CV_INFO_PDB70 *)(buffer);

      cvinfo->Age = H_GET_32(abfd, cvinfo70->Age);

      bfd_putb32 (bfd_getl32 (cvinfo70->Signature), cvinfo->Signature);
      bfd_putb16 (bfd_getl16 (&(cvinfo70->Signature[4])), &(cvinfo->Signature[4]));
      bfd_putb16 (bfd_getl16 (&(cvinfo70->Signature[6])), &(cvinfo->Signature[6]));
      memcpy (&(cvinfo->Signature[8]), &(cvinfo70->Signature[8]), 8);

      cvinfo->SignatureLength = CV_INFO_SIGNATURE_LENGTH;

      if (pdb)
        *pdb = xstrdup (cvinfo70->PdbFileName);

      return cvinfo;
    }

  if (cvinfo->CVSignature == CVINFO_PDB20_CVSIGNATURE)
    {
      if (length <= sizeof (CV_INFO_PDB20))
        return NULL;

      CV_INFO_PDB20 *cvinfo20 = (CV_INFO_PDB20 *)(buffer);
      
      cvinfo->Age = H_GET_32(abfd, cvinfo20->Age);
      memcpy (cvinfo->Signature, cvinfo20->Signature, 4);
      cvinfo->SignatureLength = 4;

      if (pdb)
        *pdb = xstrdup (cvinfo20->PdbFileName);

      return cvinfo;
    }

  return NULL;
}

unsigned int
_bfd_XXi_write_codeview_record (bfd * abfd, file_ptr where, CODEVIEW_INFO *cvinfo,
				const char *pdb)
{
  size_t pdb_len = 0;
  bfd_size_type size;
  bfd_size_type written;
  CV_INFO_PDB70 *cvinfo70;
  char * buffer;

  if (abfd == NULL || cvinfo == NULL)
    return 0;

  if (pdb != NULL)
    pdb_len = strlen (pdb);

  size = sizeof (CV_INFO_PDB70) + pdb_len + 1;

  if (bfd_seek (abfd, where, SEEK_SET) != 0)
    return 0;

  buffer = bfd_malloc (size);
  if (buffer == NULL)
    return 0;

  cvinfo70 = (CV_INFO_PDB70 *) buffer;
  H_PUT_32 (abfd, CVINFO_PDB70_CVSIGNATURE, cvinfo70->CvSignature);

  bfd_putl32 (bfd_getb32 (cvinfo->Signature), cvinfo70->Signature);
  bfd_putl16 (bfd_getb16 (&(cvinfo->Signature[4])), &(cvinfo70->Signature[4]));
  bfd_putl16 (bfd_getb16 (&(cvinfo->Signature[6])), &(cvinfo70->Signature[6]));
  memcpy (&(cvinfo70->Signature[8]), &(cvinfo->Signature[8]), 8);

  H_PUT_32 (abfd, cvinfo->Age, cvinfo70->Age);

  if (pdb == NULL)
    {
      cvinfo70->PdbFileName[0] = '\0';
    }
  else
    {
      memcpy (cvinfo70->PdbFileName, pdb, pdb_len);
      cvinfo70->PdbFileName[pdb_len] = '\0';
    }

  written = bfd_write (buffer, size, abfd);

  free (buffer);

  if (written != size)
    return 0;

  return size;
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
  if ((section->flags & SEC_HAS_CONTENTS) == 0)
    return false;
    
  if (dataoff > section->size)
    return false;
    
  if (datasize > section->size - dataoff)
    return false;
    
  ufile_ptr filesize = bfd_get_file_size (abfd);
  if (filesize == 0)
    return true;
    
  if ((ufile_ptr) section->filepos > filesize)
    return false;
    
  ufile_ptr remaining_from_filepos = filesize - section->filepos;
  
  if (dataoff > remaining_from_filepos)
    return false;
    
  if (datasize > remaining_from_filepos - dataoff)
    return false;
    
  return true;
}

static bool
pe_print_idata(bfd *abfd, void *vfile)
{
    FILE *file = (FILE *)vfile;
    bfd_byte *data = NULL;
    asection *section;
    bfd_signed_vma adj;
    bfd_size_type datasize = 0;
    bfd_size_type dataoff;
    bfd_size_type i;
    int onaline = 20;
    pe_data_type *pe = pe_data(abfd);
    struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
    bfd_vma addr;
    bool result = true;

    addr = extra->DataDirectory[PE_IMPORT_TABLE].VirtualAddress;

    if (addr == 0 && extra->DataDirectory[PE_IMPORT_TABLE].Size == 0) {
        section = bfd_get_section_by_name(abfd, ".idata");
        if (section == NULL || (section->flags & SEC_HAS_CONTENTS) == 0)
            return true;
        addr = section->vma;
        datasize = section->size;
        if (datasize == 0)
            return true;
    } else {
        addr += extra->ImageBase;
        for (section = abfd->sections; section != NULL; section = section->next) {
            datasize = section->size;
            if (addr >= section->vma && addr < section->vma + datasize)
                break;
        }
        if (section == NULL) {
            fprintf(file, _("\nThere is an import table, but the section containing it could not be found\n"));
            return true;
        }
        if (!(section->flags & SEC_HAS_CONTENTS)) {
            fprintf(file, _("\nThere is an import table in %s, but that section has no contents\n"), section->name);
            return true;
        }
    }

    fprintf(file, _("\nThere is an import table in %s at 0x%lx\n"), section->name, (unsigned long)addr);
    dataoff = addr - section->vma;
    fprintf(file, _("\nThe Import Tables (interpreted %s section contents)\n"), section->name);
    fprintf(file, _(" vma:            Hint    Time      Forward  DLL       First\n                 Table   Stamp     Chain    Name      Thunk\n"));

    if (!bfd_malloc_and_get_section(abfd, section, &data)) {
        free(data);
        return false;
    }

    adj = section->vma - extra->ImageBase;

    for (i = dataoff; i + onaline <= datasize; i += onaline) {
        bfd_vma hint_addr;
        bfd_vma time_stamp;
        bfd_vma forward_chain;
        bfd_vma dll_name;
        bfd_vma first_thunk;
        int idx = 0;
        bfd_size_type j;
        char *dll;

        fprintf(file, " %08lx\t", (unsigned long)(i + adj));
        hint_addr = bfd_get_32(abfd, data + i);
        time_stamp = bfd_get_32(abfd, data + i + 4);
        forward_chain = bfd_get_32(abfd, data + i + 8);
        dll_name = bfd_get_32(abfd, data + i + 12);
        first_thunk = bfd_get_32(abfd, data + i + 16);

        fprintf(file, "%08lx %08lx %08lx %08lx %08lx\n",
                (unsigned long)hint_addr, (unsigned long)time_stamp,
                (unsigned long)forward_chain, (unsigned long)dll_name,
                (unsigned long)first_thunk);

        if (hint_addr == 0 && first_thunk == 0)
            break;

        if (dll_name - adj >= section->size)
            break;

        dll = (char *)data + dll_name - adj;
        bfd_size_type maxlen = (char *)(data + datasize) - dll - 1;
        fprintf(file, _("\n\tDLL Name: %.*s\n"), (int)maxlen, dll);

        if (hint_addr == 0)
            hint_addr = first_thunk;

        if (hint_addr != 0 && hint_addr - adj < datasize) {
            bfd_byte *ft_data = NULL;
            asection *ft_section;
            bfd_vma ft_addr;
            bfd_size_type ft_datasize;
            int ft_idx;
            int ft_allocated = 0;

            fprintf(file, _("\tvma:     Ordinal  Hint  Member-Name  Bound-To\n"));
            idx = hint_addr - adj;
            ft_addr = first_thunk + extra->ImageBase;
            ft_idx = first_thunk - adj;
            ft_data = data + ft_idx;
            ft_datasize = datasize - ft_idx;

            if (first_thunk != hint_addr) {
                for (ft_section = abfd->sections; ft_section != NULL; ft_section = ft_section->next) {
                    if (ft_addr >= ft_section->vma && ft_addr < ft_section->vma + ft_section->size)
                        break;
                }
                if (ft_section == NULL) {
                    fprintf(file, _("\nThere is a first thunk, but the section containing it could not be found\n"));
                    continue;
                }
                if (ft_section != section) {
                    ft_idx = first_thunk - (ft_section->vma - extra->ImageBase);
                    ft_datasize = ft_section->size - ft_idx;
                    if (!get_contents_sanity_check(abfd, ft_section, ft_idx, ft_datasize))
                        continue;
                    ft_data = (bfd_byte *)bfd_malloc(ft_datasize);
                    if (ft_data == NULL)
                        continue;
                    if (!bfd_get_section_contents(abfd, ft_section, ft_data, (bfd_vma)ft_idx, ft_datasize)) {
                        free(ft_data);
                        continue;
                    }
                    ft_allocated = 1;
                }
            }

#ifdef COFF_WITH_pex64
            for (j = 0; idx + j + 8 <= datasize; j += 8) {
                bfd_size_type amt;
                unsigned long member = bfd_get_32(abfd, data + idx + j);
                unsigned long member_high = bfd_get_32(abfd, data + idx + j + 4);

                if (!member && !member_high)
                    break;

                amt = member - adj;

                if (HighBitSet(member_high)) {
                    unsigned int ordinal = member & 0xffff;
                    fprintf(file, "\t%08lx  %5u  <none> <none>", (unsigned long)(first_thunk + j), ordinal);
                } else if (amt >= datasize || amt + 2 >= datasize) {
                    fprintf(file, _("\t<corrupt: 0x%08lx>"), member);
                } else {
                    unsigned int hint = bfd_get_16(abfd, data + amt);
                    char *member_name = (char *)data + amt + 2;
                    fprintf(file, "\t%08lx  <none>  %04x  %.*s",
                            (unsigned long)(first_thunk + j), hint,
                            (int)(datasize - (amt + 2)), member_name);
                }

                if (time_stamp != 0 && first_thunk != 0 && first_thunk != hint_addr && j + 4 <= ft_datasize)
                    fprintf(file, "\t%08lx", (unsigned long)bfd_get_32(abfd, ft_data + j));

                fprintf(file, "\n");
            }
#else
            for (j = 0; idx + j + 4 <= datasize; j += 4) {
                bfd_size_type amt;
                unsigned long member = bfd_get_32(abfd, data + idx + j);

                if (member == 0)
                    break;

                amt = member - adj;

                if (HighBitSet(member)) {
                    unsigned int ordinal = member & 0xffff;
                    fprintf(file, "\t%08lx  %5u  <none> <none>", (unsigned long)(first_thunk + j), ordinal);
                } else if (amt >= datasize || amt + 2 >= datasize) {
                    fprintf(file, _("\t<corrupt: 0x%08lx>"), member);
                } else {
                    unsigned int hint = bfd_get_16(abfd, data + amt);
                    char *member_name = (char *)data + amt + 2;
                    fprintf(file, "\t%08lx  <none>  %04x  %.*s",
                            (unsigned long)(first_thunk + j), hint,
                            (int)(datasize - (amt + 2)), member_name);
                }

                if (time_stamp != 0 && first_thunk != 0 && first_thunk != hint_addr && j + 4 <= ft_datasize)
                    fprintf(file, "\t%08lx", (unsigned long)bfd_get_32(abfd, ft_data + j));

                fprintf(file, "\n");
            }
#endif
            if (ft_allocated)
                free(ft_data);
        }
        fprintf(file, "\n");
    }

    free(data);
    return result;
}

static bool
pe_print_edata (bfd * abfd, void * vfile)
{
  FILE *file = (FILE *) vfile;
  bfd_byte *data = NULL;
  asection *section;
  bfd_size_type datasize = 0;
  bfd_size_type dataoff;
  bfd_size_type i;
  bfd_vma adj;
  bool ret = true;
  
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
  bfd_vma addr;

  addr = extra->DataDirectory[PE_EXPORT_TABLE].VirtualAddress;

  if (addr == 0 && extra->DataDirectory[PE_EXPORT_TABLE].Size == 0)
    {
      section = bfd_get_section_by_name (abfd, ".edata");
      if (section == NULL)
        return true;

      addr = section->vma;
      dataoff = 0;
      datasize = section->size;
      if (datasize == 0)
        return true;
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
          return true;
        }

      dataoff = addr - section->vma;
      datasize = extra->DataDirectory[PE_EXPORT_TABLE].Size;
    }

  if (datasize < 40)
    {
      fprintf (file,
               _("\nThere is an export table in %s, but it is too small (%d)\n"),
               section->name, (int) datasize);
      return true;
    }

  if (!get_contents_sanity_check (abfd, section, dataoff, datasize))
    {
      fprintf (file,
               _("\nThere is an export table in %s, but contents cannot be read\n"),
               section->name);
      return true;
    }

  fprintf (file, _("\nThere is an export table in %s at 0x%lx\n"),
           section->name, (unsigned long) addr);

  data = (bfd_byte *) bfd_malloc (datasize);
  if (data == NULL)
    return false;

  if (!bfd_get_section_contents (abfd, section, data,
                                  (file_ptr) dataoff, datasize))
    {
      free (data);
      return false;
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

  fprintf (file,
           _("Export Flags \t\t\t%lx\n"), (unsigned long) edt.export_flags);

  fprintf (file,
           _("Time/Date stamp \t\t%lx\n"), (unsigned long) edt.time_stamp);

  fprintf (file,
           _("Major/Minor \t\t\t%d/%d\n"), edt.major_ver, edt.minor_ver);

  fprintf (file,
           _("Name \t\t\t\t"));
  bfd_fprintf_vma (abfd, file, edt.name);

  if ((edt.name >= adj) && (edt.name < adj + datasize))
    fprintf (file, " %.*s\n",
             (int) (datasize - (edt.name - adj)),
             data + edt.name - adj);
  else
    fprintf (file, "(outside .edata section)\n");

  fprintf (file,
           _("Ordinal Base \t\t\t%ld\n"), edt.base);

  fprintf (file,
           _("Number in:\n"));

  fprintf (file,
           _("\tExport Address Table \t\t%08lx\n"),
           edt.num_functions);

  fprintf (file,
           _("\t[Name Pointer/Ordinal] Table\t%08lx\n"), edt.num_names);

  fprintf (file,
           _("Table Addresses\n"));

  fprintf (file,
           _("\tExport Address Table \t\t"));
  bfd_fprintf_vma (abfd, file, edt.eat_addr);
  fprintf (file, "\n");

  fprintf (file,
           _("\tName Pointer Table \t\t"));
  bfd_fprintf_vma (abfd, file, edt.npt_addr);
  fprintf (file, "\n");

  fprintf (file,
           _("\tOrdinal Table \t\t\t"));
  bfd_fprintf_vma (abfd, file, edt.ot_addr);
  fprintf (file, "\n");

  fprintf (file,
          _("\nExport Address Table -- Ordinal Base %ld\n"),
          edt.base);
  fprintf (file, "\t          Ordinal  Address  Type\n");

  if (edt.eat_addr < adj || 
      edt.eat_addr - adj >= datasize ||
      (edt.num_functions + 1) * 4 < edt.num_functions ||
      edt.eat_addr - adj + (edt.num_functions + 1) * 4 > datasize)
    {
      fprintf (file, _("\tInvalid Export Address Table rva (0x%lx) or entry count (0x%lx)\n"),
               (long) edt.eat_addr,
               (long) edt.num_functions);
    }
  else
    {
      for (i = 0; i < edt.num_functions; ++i)
        {
          bfd_vma eat_member = bfd_get_32 (abfd,
                                           data + edt.eat_addr + (i * 4) - adj);
          if (eat_member == 0)
            continue;

          if (eat_member >= adj && eat_member - adj <= datasize)
            {
              fprintf (file,
                       "\t[%4ld] +base[%4ld] %08lx %s -- %.*s\n",
                       (long) i,
                       (long) (i + edt.base),
                       (unsigned long) eat_member,
                       _("Forwarder RVA"),
                       (int)(datasize - (eat_member - adj)),
                       data + eat_member - adj);
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
    }

  fprintf (file,
           _("\n[Ordinal/Name Pointer] Table -- Ordinal Base %ld\n"),
          edt.base);
  fprintf (file, "\t          Ordinal   Hint Name\n");

  if (edt.npt_addr < adj ||
      edt.npt_addr + (edt.num_names * 4) < edt.npt_addr ||
      edt.npt_addr + (edt.num_names * 4) - adj >= datasize ||
      edt.num_names * 4 < edt.num_names)
    {
      fprintf (file, _("\tInvalid Name Pointer Table rva (0x%lx) or entry count (0x%lx)\n"),
               (long) edt.npt_addr,
               (long) edt.num_names);
    }
  else if (edt.ot_addr < adj ||
           edt.ot_addr + (edt.num_names * 2) < edt.ot_addr ||
           edt.ot_addr + (edt.num_names * 2) - adj >= datasize)
    {
      fprintf (file, _("\tInvalid Ordinal Table rva (0x%lx) or entry count (0x%lx)\n"),
               (long) edt.ot_addr,
               (long) edt.num_names);
    }
  else
    {
      for (i = 0; i < edt.num_names; ++i)
        {
          bfd_vma name_ptr;
          bfd_vma ord;

          ord = bfd_get_16 (abfd, data + edt.ot_addr + (i * 2) - adj);
          name_ptr = bfd_get_32 (abfd, data + edt.npt_addr + (i * 4) - adj);

          if (name_ptr < adj || (name_ptr - adj) >= datasize)
            {
              fprintf (file, _("\t[%4ld] +base[%4ld]  %04lx <corrupt offset: %lx>\n"),
                       (long) ord, (long) (ord + edt.base), (long) i, (long) name_ptr);
            }
          else
            {
              char * name = (char *) data + name_ptr - adj;
              fprintf (file,
                       "\t[%4ld] +base[%4ld]  %04lx %.*s\n",
                       (long) ord, (long) (ord + edt.base), (long) i,
                       (int)((char *)(data + datasize) - name), name);
            }
        }
    }

  free (data);
  return ret;
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
pe_print_pdata (bfd * abfd, void * vfile)
{
#if defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
# define PDATA_ROW_SIZE	(3 * 8)
# define IS_PEP_ONLY 1
#else
# define PDATA_ROW_SIZE	(5 * 4)
# define IS_PEP_ONLY 0
#endif

  FILE *file = (FILE *) vfile;
  bfd_byte *data = NULL;
  asection *section = bfd_get_section_by_name (abfd, ".pdata");
  bfd_size_type datasize = 0;
  bfd_size_type i;
  bfd_size_type stop;

  if (section == NULL
      || (section->flags & SEC_HAS_CONTENTS) == 0
      || coff_section_data (abfd, section) == NULL
      || pei_section_data (abfd, section) == NULL)
    return true;

  stop = pei_section_data (abfd, section)->virt_size;
  if ((stop % PDATA_ROW_SIZE) != 0)
    fprintf (file,
	     _("warning, .pdata section size (%ld) is not a multiple of %d\n"),
	     (long) stop, PDATA_ROW_SIZE);

  fprintf (file,
	   _("\nThe Function Table (interpreted .pdata section contents)\n"));
  
  if (IS_PEP_ONLY)
    fprintf (file,
	     _(" vma:\t\t\tBegin Address    End Address      Unwind Info\n"));
  else
    fprintf (file, _("\
 vma:\t\tBegin    End      EH       EH       PrologEnd  Exception\n\
     \t\tAddress  Address  Handler  Data     Address    Mask\n"));

  datasize = section->size;
  if (datasize == 0)
    return true;

  if (datasize < stop)
    {
      fprintf (file, _("Virtual size of .pdata section (%ld) larger than real size (%ld)\n"),
	       (long) stop, (long) datasize);
      return false;
    }

  if (!bfd_malloc_and_get_section (abfd, section, &data))
    {
      free (data);
      return false;
    }

  for (i = 0; i < stop; i += PDATA_ROW_SIZE)
    {
      bfd_vma begin_addr;
      bfd_vma end_addr;
      bfd_vma eh_handler;
      bfd_vma eh_data;
      bfd_vma prolog_end_addr;
      int em_data;

      if (i + PDATA_ROW_SIZE > stop)
	break;

      begin_addr      = GET_PDATA_ENTRY (abfd, data + i);
      end_addr	      = GET_PDATA_ENTRY (abfd, data + i + 4);
      eh_handler      = GET_PDATA_ENTRY (abfd, data + i + 8);
      eh_data	      = GET_PDATA_ENTRY (abfd, data + i + 12);
      prolog_end_addr = GET_PDATA_ENTRY (abfd, data + i + 16);

      if (begin_addr == 0 && end_addr == 0 && eh_handler == 0
	  && eh_data == 0 && prolog_end_addr == 0)
	break;

      if (!IS_PEP_ONLY)
	em_data = ((eh_handler & 0x1) << 2) | (prolog_end_addr & 0x3);
      else
	em_data = 0;
      
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
      
      if (!IS_PEP_ONLY)
	{
	  fputc (' ', file);
	  bfd_fprintf_vma (abfd, file, eh_data);
	  fputc (' ', file);
	  bfd_fprintf_vma (abfd, file, prolog_end_addr);
	  fprintf (file, "   %x", em_data);
	}
      
      fprintf (file, "\n");
    }

  free (data);

  return true;
#undef PDATA_ROW_SIZE
#undef IS_PEP_ONLY
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
  long symcount;

  if (abfd == NULL || psc == NULL)
    {
      return NULL;
    }

  psc->symcount = 0;

  if (!(bfd_get_file_flags (abfd) & HAS_SYMS))
    {
      return NULL;
    }

  storage = bfd_get_symtab_upper_bound (abfd);
  if (storage <= 0)
    {
      return NULL;
    }

  sy = (asymbol **) bfd_malloc (storage);
  if (sy == NULL)
    {
      return NULL;
    }

  symcount = bfd_canonicalize_symtab (abfd, sy);
  if (symcount < 0)
    {
      free (sy);
      return NULL;
    }

  psc->symcount = symcount;
  return sy;
}

static const char *
my_symbol_for_address (bfd *abfd, bfd_vma func, sym_cache *psc)
{
  if (psc == NULL || abfd == NULL)
    return NULL;

  if (psc->syms == NULL)
    {
      psc->syms = slurp_symtab (abfd, psc);
      if (psc->syms == NULL)
        return NULL;
    }

  for (int i = 0; i < psc->symcount; i++)
    {
      if (psc->syms[i] == NULL || psc->syms[i]->section == NULL)
        continue;
      
      if (psc->syms[i]->section->vma + psc->syms[i]->value == func)
        return psc->syms[i]->name;
    }

  return NULL;
}

static void cleanup_syms(sym_cache *psc)
{
    if (psc == NULL) {
        return;
    }
    
    psc->symcount = 0;
    free(psc->syms);
    psc->syms = NULL;
}

/* This is the version for "compressed" pdata.  */

bool
_bfd_XX_print_ce_compressed_pdata (bfd * abfd, void * vfile)
{
  FILE *file = (FILE *) vfile;
  bfd_byte *data = NULL;
  asection *section = bfd_get_section_by_name (abfd, ".pdata");
  bfd_size_type datasize = 0;
  bfd_size_type i;
  bfd_size_type start, stop;
  int onaline = 8;
  struct sym_cache cache = {0, 0};
  bool result = true;

  if (section == NULL
      || (section->flags & SEC_HAS_CONTENTS) == 0
      || coff_section_data (abfd, section) == NULL
      || pei_section_data (abfd, section) == NULL)
    return true;

  stop = pei_section_data (abfd, section)->virt_size;
  if ((stop % onaline) != 0)
    fprintf (file,
	     _("warning, .pdata section size (%ld) is not a multiple of %d\n"),
	     (long) stop, onaline);

  fprintf (file,
	   _("\nThe Function Table (interpreted .pdata section contents)\n"));

  fprintf (file, _("\
 vma:\t\tBegin    Prolog   Function Flags    Exception EH\n\
     \t\tAddress  Length   Length   32b exc  Handler   Data\n"));

  datasize = section->size;
  if (datasize == 0)
    return true;

  if (!bfd_malloc_and_get_section (abfd, section, &data))
    {
      free (data);
      return false;
    }

  start = 0;
  if (stop > datasize)
    stop = datasize;

  for (i = start; i < stop; i += onaline)
    {
      bfd_vma begin_addr;
      bfd_vma other_data;
      bfd_vma prolog_length, function_length;
      int flag32bit, exception_flag;
      asection *tsection;

      if (i + onaline > stop)
	break;

      begin_addr = GET_PDATA_ENTRY (abfd, data + i);
      other_data = GET_PDATA_ENTRY (abfd, data + i + 4);

      if (begin_addr == 0 && other_data == 0)
	break;

      prolog_length = (other_data & 0x000000FF);
      function_length = (other_data & 0x3FFFFF00) >> 8;
      flag32bit = (int)((other_data & 0x40000000) >> 30);
      exception_flag = (int)((other_data & 0x80000000) >> 31);

      fputc (' ', file);
      bfd_fprintf_vma (abfd, file, i + section->vma);
      fputc ('\t', file);
      bfd_fprintf_vma (abfd, file, begin_addr);
      fputc (' ', file);
      bfd_fprintf_vma (abfd, file, prolog_length);
      fputc (' ', file);
      bfd_fprintf_vma (abfd, file, function_length);
      fputc (' ', file);
      fprintf (file, "%2d  %2d   ", flag32bit, exception_flag);

      tsection = bfd_get_section_by_name (abfd, ".text");
      if (tsection && coff_section_data (abfd, tsection)
	  && pei_section_data (abfd, tsection))
	{
	  bfd_vma eh_off = (begin_addr - 8) - tsection->vma;
	  bfd_byte *tdata = (bfd_byte *) bfd_malloc (8);
	  
	  if (tdata)
	    {
	      if (bfd_get_section_contents (abfd, tsection, tdata, eh_off, 8))
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

      fprintf (file, "\n");
    }

  free (data);
  cleanup_syms (&cache);

  return result;
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

  if (section == NULL || section->size == 0 || (section->flags & SEC_HAS_CONTENTS) == 0)
    return true;

  fprintf (file, _("\n\nPE File Base Relocations (interpreted .reloc section contents)\n"));

  if (!bfd_malloc_and_get_section (abfd, section, &data))
    {
      free (data);
      return false;
    }

  if (!process_reloc_blocks(abfd, file, data, section->size))
    {
      free (data);
      return false;
    }

  free (data);
  return true;
}

static bool
process_reloc_blocks(bfd *abfd, FILE *file, bfd_byte *data, bfd_size_type size)
{
  bfd_byte *p = data;
  bfd_byte *end = data + size;

  while (p + 8 <= end)
    {
      bfd_vma virtual_address = bfd_get_32 (abfd, p);
      unsigned long block_size = bfd_get_32 (abfd, p + 4);
      
      if (block_size == 0)
        break;

      if (block_size < 8)
        return false;

      unsigned long number = (block_size - 8) / 2;
      
      fprintf (file, _("\nVirtual Address: %08lx Chunk size %ld (0x%lx) Number of fixups %ld\n"),
               (unsigned long) virtual_address, block_size, block_size, number);

      p += 8;
      
      if (!process_reloc_entries(abfd, file, p, block_size - 8, end, virtual_address))
        return false;
        
      p += block_size - 8;
    }
  
  return true;
}

static bool
process_reloc_entries(bfd *abfd, FILE *file, bfd_byte *p, unsigned long entries_size, 
                      bfd_byte *end, bfd_vma virtual_address)
{
  bfd_byte *chunk_end = p + entries_size;
  
  if (chunk_end > end)
    chunk_end = end;
    
  int j = 0;
  
  while (p + 2 <= chunk_end)
    {
      unsigned short e = bfd_get_16 (abfd, p);
      unsigned int type = (e & 0xF000) >> 12;
      int offset = e & 0x0FFF;
      
      print_reloc_entry(file, j, offset, virtual_address, type);
      
      p += 2;
      j++;
      
      if (type == IMAGE_REL_BASED_HIGHADJ && p + 2 <= chunk_end)
        {
          fprintf (file, " (%4x)", (unsigned int) bfd_get_16 (abfd, p));
          p += 2;
          j++;
        }
        
      fprintf (file, "\n");
    }
    
  return true;
}

static void
print_reloc_entry(FILE *file, int index, int offset, bfd_vma virtual_address, unsigned int type)
{
  const size_t tbl_size = sizeof (tbl) / sizeof (tbl[0]);
  
  if (type >= tbl_size)
    type = tbl_size - 1;
    
  fprintf (file, _("\treloc %4d offset %4x [%4lx] %s"),
           index, offset, (unsigned long) (offset + virtual_address), tbl[type]);
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
  unsigned long entry, addr, size;
  bfd_byte *leaf;
  bfd_byte *error_return = regions->section_end + 1;

  if (data == NULL || regions == NULL || file == NULL || abfd == NULL)
    return error_return;

  if (data + 8 >= regions->section_end)
    return error_return;

  fprintf (file, _("%03x %*.s Entry: "), (int)(data - regions->section_start), indent, " ");

  entry = (unsigned long) bfd_get_32 (abfd, data);
  
  if (is_name)
    {
      bfd_byte *name;
      unsigned int len;

      if (HighBitSet (entry))
	name = regions->section_start + WithoutHighBit (entry);
      else
	name = regions->section_start + entry - rva_bias;

      if (name <= regions->section_start || name + 2 >= regions->section_end)
	{
	  fprintf (file, _("<corrupt string offset: %#lx>\n"), entry);
	  return error_return;
	}

      if (regions->strings_start == NULL)
	regions->strings_start = name;

      len = bfd_get_16 (abfd, name);
      fprintf (file, _("name: [val: %08lx len %d]: "), entry, len);

      if (name + 2 + len * 2 >= regions->section_end)
	{
	  fprintf (file, _("<corrupt string length: %#x>\n"), len);
	  return error_return;
	}

      name += 2;
      for (unsigned int i = 0; i < len; i++)
	{
	  char c = name[i * 2];
	  if (c > 0 && c < 32)
	    fprintf (file, "^%c", c + 64);
	  else
	    fprintf (file, "%.1s", &name[i * 2]);
	}
    }
  else
    {
      fprintf (file, _("ID: %#08lx"), entry);
    }

  entry = (unsigned long) bfd_get_32 (abfd, data + 4);
  fprintf (file, _(", Value: %#08lx\n"), entry);

  if (HighBitSet (entry))
    {
      bfd_byte *dir_data = regions->section_start + WithoutHighBit (entry);
      if (dir_data <= regions->section_start || dir_data > regions->section_end)
	return error_return;

      return rsrc_print_resource_directory (file, abfd, indent + 1, dir_data,
					    regions, rva_bias);
    }

  leaf = regions->section_start + entry;

  if (leaf < regions->section_start || leaf + 16 >= regions->section_end)
    return error_return;

  addr = (unsigned long) bfd_get_32 (abfd, leaf);
  size = (unsigned long) bfd_get_32 (abfd, leaf + 4);
  
  fprintf (file, _("%03x %*.s  Leaf: Addr: %#08lx, Size: %#08lx, Codepage: %d\n"),
	   (int) entry, indent, " ",
	   addr, size,
	   (int) bfd_get_32 (abfd, leaf + 8));

  if (bfd_get_32 (abfd, leaf + 12) != 0)
    return error_return;

  bfd_byte *resource_addr = regions->section_start + (addr - rva_bias);
  if (resource_addr + size > regions->section_end)
    return error_return;

  if (regions->resource_start == NULL)
    regions->resource_start = resource_addr;

  return resource_addr + size;
}

#define max(a,b) ((a) > (b) ? (a) : (b))
#define min(a,b) ((a) < (b) ? (a) : (b))

static bfd_byte *
rsrc_print_resource_directory (FILE *	      file,
			       bfd *	      abfd,
			       unsigned int   indent,
			       bfd_byte *     data,
			       rsrc_regions * regions,
			       bfd_vma	      rva_bias)
{
  unsigned int num_names, num_ids;
  bfd_byte * highest_data = data;
  bfd_byte * entry_end;
  const char * dir_type;

  if (data + 16 >= regions->section_end)
    return regions->section_end + 1;

  fprintf (file, "%03x %*.s ", (int)(data - regions->section_start), indent, " ");
  
  if (indent == 0)
    dir_type = "Type";
  else if (indent == 2)
    dir_type = "Name";
  else if (indent == 4)
    dir_type = "Language";
  else
    {
      fprintf (file, _("<unknown directory type: %d>\n"), indent);
      return regions->section_end + 1;
    }
  
  fprintf (file, "%s", dir_type);

  num_names = (int) bfd_get_16 (abfd, data + 12);
  num_ids = (int) bfd_get_16 (abfd, data + 14);
  
  fprintf (file, _(" Table: Char: %d, Time: %08lx, Ver: %d/%d, Num Names: %d, IDs: %d\n"),
	   (int) bfd_get_32 (abfd, data),
	   (long) bfd_get_32 (abfd, data + 4),
	   (int)  bfd_get_16 (abfd, data + 8),
	   (int)  bfd_get_16 (abfd, data + 10),
	   num_names,
	   num_ids);
  data += 16;

  while (num_names > 0)
    {
      entry_end = rsrc_print_resource_entries (file, abfd, indent + 1, true,
					       data, regions, rva_bias);
      data += 8;
      if (entry_end > highest_data)
        highest_data = entry_end;
      if (entry_end >= regions->section_end)
	return entry_end;
      num_names--;
    }

  while (num_ids > 0)
    {
      entry_end = rsrc_print_resource_entries (file, abfd, indent + 1, false,
					       data, regions, rva_bias);
      data += 8;
      if (entry_end > highest_data)
        highest_data = entry_end;
      if (entry_end >= regions->section_end)
	return entry_end;
      num_ids--;
    }

  return (highest_data > data) ? highest_data : data;
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
  bool result = true;

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

  if (!bfd_malloc_and_get_section (abfd, section, &data))
    {
      if (data != NULL)
        free (data);
      return false;
    }

  regions.section_start = data;
  regions.section_end = data + datasize;
  regions.strings_start = NULL;
  regions.resource_start = NULL;

  fflush (file);
  fprintf (file, "\nThe .rsrc Resource Directory section:\n");

  while (data < regions.section_end)
    {
      bfd_byte * p = data;
      
      data = rsrc_print_resource_directory (file, abfd, 0, data, &regions, rva_bias);

      if (data == regions.section_end + 1)
        {
          fprintf (file, _("Corrupt .rsrc section detected!\n"));
        }
      else if (data < regions.section_end)
        {
          int align = (1 << section->alignment_power) - 1;
          data = (bfd_byte *) (((ptrdiff_t) (data + align)) & ~align);
          rva_bias += data - p;

          if (data == (regions.section_end - 4))
            {
              data = regions.section_end;
            }
          else if (data < regions.section_end)
            {
              bfd_byte * check_data = data;
              while (++check_data < regions.section_end)
                {
                  if (*check_data != 0)
                    {
                      fprintf (file, _("\nWARNING: Extra data in .rsrc section - it will be ignored by Windows:\n"));
                      break;
                    }
                }
              data = regions.section_end;
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
  return result;
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
    asection *section;
    bfd_byte *data = NULL;
    bfd_size_type dataoff;
    unsigned int i, j;
    bool result = true;

    bfd_vma addr = extra->DataDirectory[PE_DEBUG_DATA].VirtualAddress;
    bfd_size_type size = extra->DataDirectory[PE_DEBUG_DATA].Size;

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
        fprintf(file, _("\nThere is a debug directory, but the section containing it could not be found\n"));
        return true;
    }
    
    if (!(section->flags & SEC_HAS_CONTENTS))
    {
        fprintf(file, _("\nThere is a debug directory in %s, but that section has no contents\n"), section->name);
        return true;
    }
    
    if (section->size < size)
    {
        fprintf(file, _("\nError: section %s contains the debug data starting address but it is too small\n"), section->name);
        return false;
    }

    fprintf(file, _("\nThere is a debug directory in %s at 0x%lx\n\n"), section->name, (unsigned long)addr);

    dataoff = addr - section->vma;

    if (size > section->size - dataoff)
    {
        fprintf(file, _("The debug data size field in the data directory is too big for the section"));
        return false;
    }

    fprintf(file, _("Type                Size     Rva      Offset\n"));

    if (!bfd_malloc_and_get_section(abfd, section, &data))
    {
        free(data);
        return false;
    }

    size_t entry_count = size / sizeof(struct external_IMAGE_DEBUG_DIRECTORY);
    
    for (i = 0; i < entry_count; i++)
    {
        const char *type_name;
        struct external_IMAGE_DEBUG_DIRECTORY *ext = &((struct external_IMAGE_DEBUG_DIRECTORY *)(data + dataoff))[i];
        struct internal_IMAGE_DEBUG_DIRECTORY idd;

        _bfd_XXi_swap_debugdir_in(abfd, ext, &idd);

        if (idd.Type >= IMAGE_NUMBEROF_DEBUG_TYPES)
            type_name = debug_type_names[0];
        else
            type_name = debug_type_names[idd.Type];

        fprintf(file, " %2ld  %14s %08lx %08lx %08lx\n", 
                idd.Type, type_name, idd.SizeOfData, 
                idd.AddressOfRawData, idd.PointerToRawData);

        if (idd.Type == PE_IMAGE_DEBUG_TYPE_CODEVIEW)
        {
            char signature[CV_INFO_SIGNATURE_LENGTH * 2 + 1];
            char buffer[256 + 1] ATTRIBUTE_ALIGNED_ALIGNOF(CODEVIEW_INFO);
            char *pdb = NULL;
            CODEVIEW_INFO *cvinfo = (CODEVIEW_INFO *)buffer;

            if (_bfd_XXi_slurp_codeview_record(abfd, (file_ptr)idd.PointerToRawData, 
                                              idd.SizeOfData, cvinfo, &pdb))
            {
                for (j = 0; j < cvinfo->SignatureLength; j++)
                    sprintf(&signature[j * 2], "%02x", cvinfo->Signature[j] & 0xff);

                fprintf(file, _("(format %c%c%c%c signature %s age %ld pdb %s)\n"),
                       buffer[0], buffer[1], buffer[2], buffer[3],
                       signature, cvinfo->Age, pdb && pdb[0] ? pdb : "(none)");

                free(pdb);
            }
        }
    }

    free(data);

    if (size % sizeof(struct external_IMAGE_DEBUG_DIRECTORY) != 0)
        fprintf(file, _("The debug directory size is not a multiple of the debug directory entry size\n"));

    return result;
}

static bool
pe_is_repro (bfd * abfd)
{
  pe_data_type *pe = pe_data (abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
  asection *section;
  bfd_byte *data = NULL;
  bfd_size_type dataoff;
  unsigned int i;
  bool res = false;

  bfd_vma addr = extra->DataDirectory[PE_DEBUG_DATA].VirtualAddress;
  bfd_size_type size = extra->DataDirectory[PE_DEBUG_DATA].Size;

  if (size == 0)
    return false;

  addr += extra->ImageBase;
  for (section = abfd->sections; section != NULL; section = section->next)
    {
      if ((addr >= section->vma) && (addr < (section->vma + section->size)))
        break;
    }

  if (section == NULL)
    return false;

  if (!(section->flags & SEC_HAS_CONTENTS))
    return false;

  if (section->size < size)
    return false;

  dataoff = addr - section->vma;

  if (size > (section->size - dataoff))
    return false;

  if (!bfd_malloc_and_get_section (abfd, section, &data))
    {
      if (data != NULL)
        free (data);
      return false;
    }

  for (i = 0; i < size / sizeof (struct external_IMAGE_DEBUG_DIRECTORY); i++)
    {
      struct external_IMAGE_DEBUG_DIRECTORY *ext
        = &((struct external_IMAGE_DEBUG_DIRECTORY *)(data + dataoff))[i];
      struct internal_IMAGE_DEBUG_DIRECTORY idd;

      _bfd_XXi_swap_debugdir_in (abfd, ext, &idd);

      if (idd.Type == PE_IMAGE_DEBUG_TYPE_REPRO)
        {
          res = true;
          break;
        }
    }

  free(data);

  return res;
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

  fprintf (file, _("\nCharacteristics 0x%x\n"), pe->real_flags);
  
  static const struct {
    unsigned int flag;
    const char *desc;
  } flag_descriptions[] = {
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
  
  for (size_t idx = 0; idx < sizeof(flag_descriptions) / sizeof(flag_descriptions[0]); idx++)
    {
      if (pe->real_flags & flag_descriptions[idx].flag)
        fprintf (file, "\t%s\n", flag_descriptions[idx].desc);
    }

  if (pe_is_repro (abfd))
    {
      fprintf (file, "\nTime/Date\t\t%08lx", pe->coff.timestamp);
      fprintf (file, "\t(This is a reproducible build file hash, not a timestamp)\n");
    }
  else
    {
      time_t t = pe->coff.timestamp;
      fprintf (file, "\nTime/Date\t\t%s", ctime (&t));
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

  switch (i->Magic)
    {
    case IMAGE_NT_OPTIONAL_HDR_MAGIC:
      name = "PE32";
      break;
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
      name = "PE32+";
      break;
    case IMAGE_NT_OPTIONAL_HDRROM_MAGIC:
      name = "ROM";
      break;
    default:
      name = NULL;
      break;
    }
  fprintf (file, "Magic\t\t\t%04x", i->Magic);
  if (name)
    fprintf (file, "\t(%s)",name);
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

  switch (i->Subsystem)
    {
    case IMAGE_SUBSYSTEM_UNKNOWN:
      subsystem_name = "unspecified";
      break;
    case IMAGE_SUBSYSTEM_NATIVE:
      subsystem_name = "NT native";
      break;
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
      subsystem_name = "Windows GUI";
      break;
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:
      subsystem_name = "Windows CUI";
      break;
    case IMAGE_SUBSYSTEM_POSIX_CUI:
      subsystem_name = "POSIX CUI";
      break;
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
      subsystem_name = "Wince CUI";
      break;
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:
      subsystem_name = "EFI application";
      break;
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
      subsystem_name = "EFI boot service driver";
      break;
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
      subsystem_name = "EFI runtime driver";
      break;
    case IMAGE_SUBSYSTEM_SAL_RUNTIME_DRIVER:
      subsystem_name = "SAL runtime driver";
      break;
    case IMAGE_SUBSYSTEM_XBOX:
      subsystem_name = "XBOX";
      break;
    default:
      subsystem_name = NULL;
    }

  fprintf (file, "Subsystem\t\t%08x", i->Subsystem);
  if (subsystem_name)
    fprintf (file, "\t(%s)", subsystem_name);
  fprintf (file, "\nDllCharacteristics\t%08x\n", i->DllCharacteristics);
  
  if (i->DllCharacteristics)
    {
      unsigned short dllch = i->DllCharacteristics;
      const char *indent = "\t\t\t\t\t";
      
      static const struct {
        unsigned short flag;
        const char *desc;
      } dll_characteristics[] = {
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
      
      for (size_t idx = 0; idx < sizeof(dll_characteristics) / sizeof(dll_characteristics[0]); idx++)
        {
          if (dllch & dll_characteristics[idx].flag)
            fprintf (file, "%s%s\n", indent, dll_characteristics[idx].desc);
        }
    }
    
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
  if (sect == NULL || obj == NULL) {
    return false;
  }
  
  bfd_vma addr = *(bfd_vma *)obj;
  
  if (sect->size == 0) {
    return addr == sect->vma;
  }
  
  bfd_vma section_end = sect->vma + sect->size;
  
  if (section_end < sect->vma) {
    return false;
  }
  
  return addr >= sect->vma && addr < section_end;
}

static asection *
find_section_by_vma (bfd *abfd, bfd_vma addr)
{
  if (abfd == NULL) {
    return NULL;
  }
  
  return bfd_sections_find_if (abfd, is_vma_in_section, &addr);
}

/* Copy any private info we understand from the input bfd
   to the output bfd.  */

bool
_bfd_XX_bfd_copy_private_bfd_data_common (bfd * ibfd, bfd * obfd)
{
  pe_data_type *ipe, *ope;

  if (ibfd->xvec->flavour != bfd_target_coff_flavour
      || obfd->xvec->flavour != bfd_target_coff_flavour)
    return true;

  ipe = pe_data (ibfd);
  ope = pe_data (obfd);

  ope->dll = ipe->dll;

  if (obfd->xvec != ibfd->xvec)
    ope->pe_opthdr.Subsystem = IMAGE_SUBSYSTEM_UNKNOWN;

  if (!pe_data (obfd)->has_reloc_section)
    {
      pe_data (obfd)->pe_opthdr.DataDirectory[PE_BASE_RELOCATION_TABLE].VirtualAddress = 0;
      pe_data (obfd)->pe_opthdr.DataDirectory[PE_BASE_RELOCATION_TABLE].Size = 0;
    }

  if (!pe_data (ibfd)->has_reloc_section
      && !(pe_data (ibfd)->real_flags & IMAGE_FILE_RELOCS_STRIPPED))
    pe_data (obfd)->dont_strip_reloc = 1;

  memcpy (ope->dos_message, ipe->dos_message, sizeof (ope->dos_message));

  return _bfd_XX_process_debug_directory (obfd, ope);
}

static bool
_bfd_XX_process_debug_directory (bfd * obfd, pe_data_type * ope)
{
  bfd_size_type size = ope->pe_opthdr.DataDirectory[PE_DEBUG_DATA].Size;
  
  if (size == 0)
    return true;

  bfd_vma addr = ope->pe_opthdr.DataDirectory[PE_DEBUG_DATA].VirtualAddress
                 + ope->pe_opthdr.ImageBase;
  bfd_vma last = addr + size - 1;
  asection *section = find_section_by_vma (obfd, last);

  if (section == NULL)
    return true;

  if (!_bfd_XX_validate_debug_section (obfd, section, addr, size, ope))
    return false;

  if ((section->flags & SEC_HAS_CONTENTS) == 0)
    {
      _bfd_error_handler (_("%pB: failed to read debug data section"), obfd);
      return false;
    }

  return _bfd_XX_update_debug_offsets (obfd, section, addr, size, ope);
}

static bool
_bfd_XX_validate_debug_section (bfd * obfd, asection * section, 
                                bfd_vma addr, bfd_size_type size,
                                pe_data_type * ope)
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
  return true;
}

static bool
_bfd_XX_update_debug_offsets (bfd * obfd, asection * section,
                              bfd_vma addr, bfd_size_type size,
                              pe_data_type * ope)
{
  bfd_byte *data = NULL;
  bfd_vma dataoff = addr - section->vma;
  bool result = false;

  if (!bfd_malloc_and_get_section (obfd, section, &data))
    {
      _bfd_error_handler (_("%pB: failed to read debug data section"), obfd);
      return false;
    }

  struct external_IMAGE_DEBUG_DIRECTORY *dd =
    (struct external_IMAGE_DEBUG_DIRECTORY *)(data + dataoff);

  unsigned int count = ope->pe_opthdr.DataDirectory[PE_DEBUG_DATA].Size
                      / sizeof (struct external_IMAGE_DEBUG_DIRECTORY);

  for (unsigned int i = 0; i < count; i++)
    {
      _bfd_XX_process_single_debug_entry (obfd, &dd[i], ope);
    }

  if (bfd_set_section_contents (obfd, section, data, 0, section->size))
    {
      result = true;
    }
  else
    {
      _bfd_error_handler (_("failed to update file offsets in debug directory"));
    }

  free (data);
  return result;
}

static void
_bfd_XX_process_single_debug_entry (bfd * obfd,
                                    struct external_IMAGE_DEBUG_DIRECTORY * edd,
                                    pe_data_type * ope)
{
  struct internal_IMAGE_DEBUG_DIRECTORY idd;
  _bfd_XXi_swap_debugdir_in (obfd, edd, &idd);

  if (idd.AddressOfRawData == 0)
    return;

  bfd_vma idd_vma = idd.AddressOfRawData + ope->pe_opthdr.ImageBase;
  asection *ddsection = find_section_by_vma (obfd, idd_vma);
  
  if (ddsection == NULL)
    return;

  idd.PointerToRawData = ddsection->filepos + idd_vma - ddsection->vma;
  _bfd_XXi_swap_debugdir_out (obfd, &idd, edd);
}

/* Copy private section data.  */

bool
_bfd_XX_bfd_copy_private_section_data (bfd *ibfd,
				       asection *isec,
				       bfd *obfd,
				       asection *osec,
				       struct bfd_link_info *link_info)
{
  if (link_info != NULL)
    return true;
    
  if (bfd_get_flavour (ibfd) != bfd_target_coff_flavour)
    return true;
    
  if (bfd_get_flavour (obfd) != bfd_target_coff_flavour)
    return true;

  if (coff_section_data (ibfd, isec) == NULL)
    return true;
    
  if (pei_section_data (ibfd, isec) == NULL)
    return true;

  if (coff_section_data (obfd, osec) == NULL)
    {
      size_t amt = sizeof (struct coff_section_tdata);
      osec->used_by_bfd = bfd_zalloc (obfd, amt);
      if (osec->used_by_bfd == NULL)
        return false;
    }

  if (pei_section_data (obfd, osec) == NULL)
    {
      size_t amt = sizeof (struct pei_section_tdata);
      coff_section_data (obfd, osec)->tdata = bfd_zalloc (obfd, amt);
      if (coff_section_data (obfd, osec)->tdata == NULL)
        return false;
    }

  pei_section_data (obfd, osec)->virt_size =
    pei_section_data (ibfd, isec)->virt_size;
  pei_section_data (obfd, osec)->pe_flags =
    pei_section_data (ibfd, isec)->pe_flags;

  return true;
}

void
_bfd_XX_get_symbol_info (bfd * abfd, asymbol *symbol, symbol_info *ret)
{
  if (abfd != NULL && symbol != NULL && ret != NULL)
  {
    coff_get_symbol_info (abfd, symbol, ret);
  }
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
  unsigned long entry;
  unsigned long addr;
  unsigned long size;
  bfd_byte *result;

  if (data == NULL || datastart == NULL || dataend == NULL)
    return dataend + 1;

  if (data + 8 > dataend)
    return dataend + 1;

  if (is_name)
    {
      bfd_byte *name;
      unsigned int len;

      entry = bfd_get_32 (abfd, data);

      if (HighBitSet (entry))
        {
          unsigned long offset = WithoutHighBit (entry);
          if (offset > (unsigned long)(dataend - datastart))
            return dataend + 1;
          name = datastart + offset;
        }
      else
        {
          if (entry < rva_bias)
            return dataend + 1;
          unsigned long offset = entry - rva_bias;
          if (offset > (unsigned long)(dataend - datastart))
            return dataend + 1;
          name = datastart + offset;
        }

      if (name < datastart || name + 2 > dataend)
        return dataend + 1;

      len = bfd_get_16 (abfd, name);
      if (len == 0 || len > 256)
        return dataend + 1;
    }

  entry = bfd_get_32 (abfd, data + 4);

  if (HighBitSet (entry))
    {
      unsigned long offset = WithoutHighBit (entry);
      if (offset > (unsigned long)(dataend - datastart))
        return dataend + 1;
      
      result = datastart + offset;

      if (result <= datastart || result >= dataend)
        return dataend + 1;

      return rsrc_count_directory (abfd, datastart, result, dataend, rva_bias);
    }

  if (entry > (unsigned long)(dataend - datastart - 16))
    return dataend + 1;

  bfd_byte *entry_ptr = datastart + entry;
  if (entry_ptr + 8 > dataend)
    return dataend + 1;

  addr = bfd_get_32 (abfd, entry_ptr);
  size = bfd_get_32 (abfd, entry_ptr + 4);

  if (addr < rva_bias)
    return dataend + 1;

  unsigned long offset = addr - rva_bias;
  if (offset > (unsigned long)(dataend - datastart))
    return dataend + 1;

  if (size > (unsigned long)(dataend - datastart - offset))
    return dataend + 1;

  return datastart + offset + size;
}

static bfd_byte *
rsrc_count_directory (bfd *abfd,
                     bfd_byte *datastart,
                     bfd_byte *data,
                     bfd_byte *dataend,
                     bfd_vma rva_bias)
{
  unsigned int num_entries;
  unsigned int num_ids;
  bfd_byte *highest_data;
  size_t required_size = 16;
  
  if (data == NULL || dataend == NULL || datastart == NULL || abfd == NULL)
    return dataend + 1;
  
  if (dataend < data || (size_t)(dataend - data) < required_size)
    return dataend + 1;
  
  num_entries = bfd_get_16 (abfd, data + 12);
  num_ids = bfd_get_16 (abfd, data + 14);
  
  if (num_entries > ((size_t)(dataend - data - 16) / 8))
    return dataend + 1;
  
  if (num_ids > num_entries)
    return dataend + 1;
  
  num_entries += num_ids;
  
  if (num_entries > ((size_t)(dataend - data - 16) / 8))
    return dataend + 1;
  
  highest_data = data;
  data += 16;
  
  for (unsigned int i = 0; i < num_entries; i++)
    {
      bfd_byte *entry_end;
      bfd_boolean is_name = (i < num_ids);
      
      if (data + 8 > dataend)
        break;
      
      entry_end = rsrc_count_entries (abfd, is_name, datastart, data, dataend, rva_bias);
      
      if (entry_end > highest_data)
        highest_data = entry_end;
      
      if (entry_end >= dataend)
        break;
      
      data += 8;
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
		  bfd_byte * data,
		  bfd_byte *dataend,
		  bfd_vma rva_bias,
		  rsrc_directory *parent)
{
  unsigned long val;

  if (data == NULL || datastart == NULL || dataend == NULL || entry == NULL)
    return dataend;
  
  if (data + 8 > dataend)
    return dataend;

  val = bfd_get_32 (abfd, data);
  entry->parent = parent;
  entry->is_name = is_name;

  if (is_name)
    {
      bfd_byte *address;
      unsigned long offset;

      if (HighBitSet (val))
        offset = WithoutHighBit (val);
      else
        offset = val - rva_bias;

      if (offset > (unsigned long)(dataend - datastart))
        return dataend;

      address = datastart + offset;
      if (address + 3 > dataend)
        return dataend;

      entry->name_id.name.len = bfd_get_16 (abfd, address);
      entry->name_id.name.string = address + 2;
    }
  else
    {
      entry->name_id.id = val;
    }

  val = bfd_get_32 (abfd, data + 4);

  if (HighBitSet (val))
    {
      unsigned long dir_offset = WithoutHighBit (val);
      
      if (dir_offset > (unsigned long)(dataend - datastart))
        return dataend;

      entry->is_dir = true;
      entry->value.directory = bfd_malloc (sizeof (*entry->value.directory));
      if (entry->value.directory == NULL)
        return dataend;

      return rsrc_parse_directory (abfd, entry->value.directory,
                                   datastart,
                                   datastart + dir_offset,
                                   dataend, rva_bias, entry);
    }

  if (val > (unsigned long)(dataend - datastart))
    return dataend;

  entry->is_dir = false;
  entry->value.leaf = bfd_malloc (sizeof (*entry->value.leaf));
  if (entry->value.leaf == NULL)
    return dataend;

  data = datastart + val;
  if (data + 12 > dataend)
    {
      free (entry->value.leaf);
      entry->value.leaf = NULL;
      return dataend;
    }

  unsigned long addr = bfd_get_32 (abfd, data);
  unsigned long size = bfd_get_32 (abfd, data + 4);
  
  if (addr < rva_bias)
    {
      free (entry->value.leaf);
      entry->value.leaf = NULL;
      return dataend;
    }
  
  unsigned long data_offset = addr - rva_bias;
  
  if (data_offset > (unsigned long)(dataend - datastart) || 
      size > (unsigned long)(dataend - datastart - data_offset))
    {
      free (entry->value.leaf);
      entry->value.leaf = NULL;
      return dataend;
    }

  entry->value.leaf->size = size;
  entry->value.leaf->codepage = bfd_get_32 (abfd, data + 8);
  entry->value.leaf->data = bfd_malloc (size);
  
  if (entry->value.leaf->data == NULL)
    {
      free (entry->value.leaf);
      entry->value.leaf = NULL;
      return dataend;
    }

  memcpy (entry->value.leaf->data, datastart + data_offset, size);
  return datastart + data_offset + size;
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
  rsrc_entry *entry;
  rsrc_entry *prev_entry = NULL;
  bfd_byte *current_data = data;
  bfd_byte *current_highest = highest_data;

  chain->first_entry = NULL;
  chain->last_entry = NULL;

  if (chain->num_entries == 0)
    return current_highest;

  for (i = 0; i < chain->num_entries; i++)
    {
      bfd_byte *entry_end;

      entry = bfd_malloc (sizeof (*entry));
      if (entry == NULL)
        return dataend;

      entry->next_entry = NULL;

      if (prev_entry == NULL)
        chain->first_entry = entry;
      else
        prev_entry->next_entry = entry;

      entry_end = rsrc_parse_entry (abfd, is_name, entry, datastart,
                                    current_data, dataend, rva_bias, parent);
      
      if (entry_end > dataend)
        return dataend;

      if (entry_end > current_highest)
        current_highest = entry_end;

      current_data += 8;
      prev_entry = entry;
    }

  chain->last_entry = entry;

  return current_highest;
}

static bfd_byte *
rsrc_parse_directory (bfd *abfd,
                     rsrc_directory *table,
                     bfd_byte *datastart,
                     bfd_byte *data,
                     bfd_byte *dataend,
                     bfd_vma rva_bias,
                     rsrc_entry *entry)
{
  bfd_byte *highest_data;
  bfd_byte *names_data;
  bfd_byte *ids_data;
  size_t names_size;
  size_t ids_size;
  
  if (table == NULL)
    return dataend;
  
  if (data == NULL || datastart == NULL || dataend == NULL)
    return dataend;
  
  if (data > dataend || (dataend - data) < 16)
    return dataend;
  
  table->characteristics = bfd_get_32 (abfd, data);
  table->time = bfd_get_32 (abfd, data + 4);
  table->major = bfd_get_16 (abfd, data + 8);
  table->minor = bfd_get_16 (abfd, data + 10);
  table->names.num_entries = bfd_get_16 (abfd, data + 12);
  table->ids.num_entries = bfd_get_16 (abfd, data + 14);
  table->entry = entry;
  
  names_size = (size_t)table->names.num_entries * 8;
  ids_size = (size_t)table->ids.num_entries * 8;
  
  names_data = data + 16;
  if (names_data > dataend || (dataend - names_data) < names_size)
    return dataend;
  
  ids_data = names_data + names_size;
  if (ids_data > dataend || (dataend - ids_data) < ids_size)
    return dataend;
  
  highest_data = rsrc_parse_entries (abfd, &table->names, true, names_data,
                                    datastart, names_data, dataend, rva_bias, table);
  
  highest_data = rsrc_parse_entries (abfd, &table->ids, false, highest_data,
                                    datastart, ids_data, dataend, rva_bias, table);
  
  data = ids_data + ids_size;
  
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
rsrc_write_string (rsrc_write_data * data,
		   rsrc_string *     string)
{
  if (data == NULL || string == NULL || data->abfd == NULL || data->next_string == NULL) {
    return;
  }
  
  if (string->len > 0 && string->string == NULL) {
    return;
  }
  
  size_t string_size = (size_t)string->len * 2;
  size_t total_size = ((size_t)string->len + 1) * 2;
  
  bfd_put_16 (data->abfd, string->len, data->next_string);
  
  if (string->len > 0) {
    memcpy (data->next_string + 2, string->string, string_size);
  }
  
  data->next_string += total_size;
}

static inline unsigned int
rsrc_compute_rva (const rsrc_write_data * data,
		  const bfd_byte * addr)
{
  if (data == NULL || addr == NULL || data->datastart == NULL)
    return 0;
  
  if (addr < data->datastart)
    return 0;
  
  ptrdiff_t offset = addr - data->datastart;
  
  if (offset > UINT_MAX - data->rva_bias)
    return 0;
  
  return (unsigned int)offset + data->rva_bias;
}

static void
rsrc_write_leaf (rsrc_write_data * data,
		 rsrc_leaf *	   leaf)
{
  if (data == NULL || leaf == NULL || data->abfd == NULL) {
    return;
  }

  if (data->next_leaf == NULL || data->next_data == NULL || leaf->data == NULL) {
    return;
  }

  const size_t LEAF_ENTRY_SIZE = 16;
  const size_t ALIGNMENT = 8;
  const uint32_t RESERVED_VALUE = 0;

  uint32_t rva = rsrc_compute_rva(data, data->next_data);
  
  bfd_put_32(data->abfd, rva, data->next_leaf);
  bfd_put_32(data->abfd, leaf->size, data->next_leaf + 4);
  bfd_put_32(data->abfd, leaf->codepage, data->next_leaf + 8);
  bfd_put_32(data->abfd, RESERVED_VALUE, data->next_leaf + 12);
  
  data->next_leaf += LEAF_ENTRY_SIZE;

  if (leaf->size > 0) {
    memcpy(data->next_data, leaf->data, leaf->size);
  }
  
  size_t aligned_size = (leaf->size + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1);
  data->next_data += aligned_size;
}

static void rsrc_write_directory (rsrc_write_data *, rsrc_directory *);

static void
rsrc_write_entry (rsrc_write_data *data,
                  bfd_byte *where,
                  rsrc_entry *entry)
{
  if (data == NULL || where == NULL || entry == NULL) {
    return;
  }

  bfd_vma name_offset;
  if (entry->is_name) {
    name_offset = SetHighBit (data->next_string - data->datastart);
    bfd_put_32 (data->abfd, name_offset, where);
    rsrc_write_string (data, &entry->name_id.name);
  } else {
    bfd_put_32 (data->abfd, entry->name_id.id, where);
  }

  bfd_vma value_offset;
  if (entry->is_dir) {
    value_offset = SetHighBit (data->next_table - data->datastart);
    bfd_put_32 (data->abfd, value_offset, where + 4);
    rsrc_write_directory (data, entry->value.directory);
  } else {
    value_offset = data->next_leaf - data->datastart;
    bfd_put_32 (data->abfd, value_offset, where + 4);
    rsrc_write_leaf (data, entry->value.leaf);
  }
}

static void
rsrc_compute_region_sizes (rsrc_directory * dir)
{
  struct rsrc_entry * entry;

  if (dir == NULL)
    return;

  sizeof_tables_and_entries += 16;

  entry = dir->names.first_entry;
  while (entry != NULL)
    {
      sizeof_tables_and_entries += 8;
      sizeof_strings += (entry->name_id.name.len + 1) * 2;

      if (entry->is_dir)
        rsrc_compute_region_sizes (entry->value.directory);
      else
        sizeof_leaves += 16;

      entry = entry->next_entry;
    }

  entry = dir->ids.first_entry;
  while (entry != NULL)
    {
      sizeof_tables_and_entries += 8;

      if (entry->is_dir)
        rsrc_compute_region_sizes (entry->value.directory);
      else
        sizeof_leaves += 16;

      entry = entry->next_entry;
    }
}

static void
rsrc_write_directory (rsrc_write_data * data,
		      rsrc_directory *  dir)
{
  if (data == NULL || dir == NULL || data->abfd == NULL || data->next_table == NULL) {
    return;
  }

  bfd_put_32 (data->abfd, dir->characteristics, data->next_table);
  bfd_put_32 (data->abfd, 0, data->next_table + 4);
  bfd_put_16 (data->abfd, dir->major, data->next_table + 8);
  bfd_put_16 (data->abfd, dir->minor, data->next_table + 10);
  bfd_put_16 (data->abfd, dir->names.num_entries, data->next_table + 12);
  bfd_put_16 (data->abfd, dir->ids.num_entries, data->next_table + 14);

  bfd_byte * next_entry = data->next_table + 16;
  data->next_table = next_entry + ((dir->names.num_entries + dir->ids.num_entries) * 8);
  bfd_byte * expected_end = data->next_table;

  if (!rsrc_write_entries(data, &next_entry, &dir->names, 1)) {
    return;
  }

  if (!rsrc_write_entries(data, &next_entry, &dir->ids, 0)) {
    return;
  }

  BFD_ASSERT (expected_end == next_entry);
}

static int
rsrc_write_entries(rsrc_write_data * data, bfd_byte ** next_entry, 
                   rsrc_entry_list * list, int check_is_name)
{
  if (data == NULL || next_entry == NULL || *next_entry == NULL || list == NULL) {
    return 0;
  }

  rsrc_entry * entry = list->first_entry;
  unsigned int remaining = list->num_entries;

  while (remaining > 0 && entry != NULL) {
    if (check_is_name) {
      BFD_ASSERT (entry->is_name);
    } else {
      BFD_ASSERT (!entry->is_name);
    }
    
    rsrc_write_entry (data, *next_entry, entry);
    *next_entry += 8;
    entry = entry->next_entry;
    remaining--;
  }

  BFD_ASSERT (remaining == 0);
  BFD_ASSERT (entry == NULL);
  
  return 1;
}

#if ! defined __CYGWIN__ && ! defined __MINGW32__
/* Return the length (number of units) of the first character in S,
   putting its 'ucs4_t' representation in *PUC.  */

static unsigned int u16_mbtouc(wint_t *puc, const unsigned short *s, unsigned int n)
{
    const unsigned short SURROGATE_HIGH_START = 0xd800;
    const unsigned short SURROGATE_HIGH_END = 0xdc00;
    const unsigned short SURROGATE_LOW_START = 0xdc00;
    const unsigned short SURROGATE_LOW_END = 0xe000;
    const wint_t REPLACEMENT_CHAR = 0xfffd;
    const wint_t SURROGATE_OFFSET = 0x10000;
    const unsigned int SURROGATE_SHIFT = 10;
    
    if (puc == NULL || s == NULL || n == 0) {
        return 0;
    }
    
    unsigned short first_unit = s[0];
    
    if (first_unit < SURROGATE_HIGH_START || first_unit >= SURROGATE_LOW_END) {
        *puc = first_unit;
        return 1;
    }
    
    if (first_unit >= SURROGATE_HIGH_START && first_unit < SURROGATE_HIGH_END) {
        if (n < 2) {
            *puc = REPLACEMENT_CHAR;
            return n;
        }
        
        unsigned short second_unit = s[1];
        if (second_unit >= SURROGATE_LOW_START && second_unit < SURROGATE_LOW_END) {
            *puc = SURROGATE_OFFSET + 
                   ((first_unit - SURROGATE_HIGH_START) << SURROGATE_SHIFT) + 
                   (second_unit - SURROGATE_LOW_START);
            return 2;
        }
    }
    
    *puc = REPLACEMENT_CHAR;
    return 1;
}
#endif /* not Cygwin/Mingw */

/* Perform a comparison of two entries.  */
static signed int
rsrc_cmp (bool is_name, rsrc_entry * a, rsrc_entry * b)
{
  if (!is_name)
    return a->name_id.id - b->name_id.id;

  if (!a || !b)
    return 0;

  bfd_byte *astring = a->name_id.name.string;
  unsigned int alen = a->name_id.name.len;
  bfd_byte *bstring = b->name_id.name.string;
  unsigned int blen = b->name_id.name.len;

  if (!astring || !bstring)
    return 0;

  unsigned int min_len = (alen < blen) ? alen : blen;
  signed int res = 0;

#if defined __CYGWIN__
  res = wcsncasecmp((const wchar_t *)astring, (const wchar_t *)bstring, min_len);
#elif defined __MINGW32__
  res = wcsnicmp((const wchar_t *)astring, (const wchar_t *)bstring, min_len);
#else
  for (unsigned int i = 0; i < min_len && res == 0; i++, astring += 2, bstring += 2)
  {
    wint_t awc;
    wint_t bwc;

    unsigned int Alen = u16_mbtouc(&awc, (const unsigned short *)astring, 2);
    unsigned int Blen = u16_mbtouc(&bwc, (const unsigned short *)bstring, 2);

    if (Alen != Blen)
      return Alen - Blen;

    awc = towlower(awc);
    bwc = towlower(bwc);

    res = awc - bwc;
  }
#endif

  if (res == 0)
    res = alen - blen;

  return res;
}

static void
rsrc_print_name (char * buffer, rsrc_string string)
{
  if (buffer == NULL || string.string == NULL || string.len == 0)
    return;

  size_t buffer_len = strlen(buffer);
  size_t max_append = 1024 - buffer_len;
  
  if (max_append == 0)
    return;

  unsigned int chars_to_copy = string.len;
  if (chars_to_copy > max_append)
    chars_to_copy = max_append;

  bfd_byte * name = string.string;
  char * dest = buffer + buffer_len;

  for (unsigned int i = 0; i < chars_to_copy; i++)
    {
      *dest++ = *name;
      name += 2;
    }
  
  *dest = '\0';
}

static const char *
rsrc_resource_name (rsrc_entry *entry, rsrc_directory *dir, char *buffer)
{
  bool is_string = false;
  size_t buf_len = 0;

  if (buffer == NULL)
    return NULL;

  buffer[0] = '\0';

  if (dir != NULL && dir->entry != NULL && dir->entry->parent != NULL
      && dir->entry->parent->entry != NULL)
    {
      buf_len = strlen("type: ");
      memcpy(buffer, "type: ", buf_len + 1);
      
      if (dir->entry->parent->entry->is_name)
        {
          rsrc_print_name(buffer + buf_len, dir->entry->parent->entry->name_id.name);
          buf_len = strlen(buffer);
        }
      else
        {
          unsigned int id = dir->entry->parent->entry->name_id.id;
          int written = snprintf(buffer + buf_len, 32, "%x", id);
          if (written > 0 && written < 32)
            buf_len += written;
          
          const char *type_name = NULL;
          switch (id)
            {
            case 1: type_name = " (CURSOR)"; break;
            case 2: type_name = " (BITMAP)"; break;
            case 3: type_name = " (ICON)"; break;
            case 4: type_name = " (MENU)"; break;
            case 5: type_name = " (DIALOG)"; break;
            case 6: type_name = " (STRING)"; is_string = true; break;
            case 7: type_name = " (FONTDIR)"; break;
            case 8: type_name = " (FONT)"; break;
            case 9: type_name = " (ACCELERATOR)"; break;
            case 10: type_name = " (RCDATA)"; break;
            case 11: type_name = " (MESSAGETABLE)"; break;
            case 12: type_name = " (GROUP_CURSOR)"; break;
            case 14: type_name = " (GROUP_ICON)"; break;
            case 16: type_name = " (VERSION)"; break;
            case 17: type_name = " (DLGINCLUDE)"; break;
            case 19: type_name = " (PLUGPLAY)"; break;
            case 20: type_name = " (VXD)"; break;
            case 21: type_name = " (ANICURSOR)"; break;
            case 22: type_name = " (ANIICON)"; break;
            case 23: type_name = " (HTML)"; break;
            case 24: type_name = " (MANIFEST)"; break;
            case 240: type_name = " (DLGINIT)"; break;
            case 241: type_name = " (TOOLBAR)"; break;
            default: break;
            }
          
          if (type_name != NULL)
            {
              size_t type_len = strlen(type_name);
              memcpy(buffer + buf_len, type_name, type_len + 1);
              buf_len += type_len;
            }
        }
    }

  if (dir != NULL && dir->entry != NULL)
    {
      const char *name_prefix = " name: ";
      size_t prefix_len = strlen(name_prefix);
      memcpy(buffer + buf_len, name_prefix, prefix_len + 1);
      buf_len += prefix_len;
      
      if (dir->entry->is_name)
        {
          rsrc_print_name(buffer + buf_len, dir->entry->name_id.name);
          buf_len = strlen(buffer);
        }
      else
        {
          unsigned int id = dir->entry->name_id.id;
          int written = snprintf(buffer + buf_len, 32, "%x", id);
          if (written > 0 && written < 32)
            buf_len += written;

          if (is_string)
            {
              written = snprintf(buffer + buf_len, 64, " (resource id range: %d - %d)",
                               (id - 1) << 4, (id << 4) - 1);
              if (written > 0 && written < 64)
                buf_len += written;
            }
        }
    }

  if (entry != NULL)
    {
      const char *lang_prefix = " lang: ";
      size_t prefix_len = strlen(lang_prefix);
      memcpy(buffer + buf_len, lang_prefix, prefix_len + 1);
      buf_len += prefix_len;

      if (entry->is_name)
        rsrc_print_name(buffer + buf_len, entry->name_id.name);
      else
        snprintf(buffer + buf_len, 32, "%x", entry->name_id.id);
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
  unsigned int copy_needed = 0;
  unsigned int i;
  bfd_byte * astring;
  bfd_byte * bstring;
  bfd_byte * new_data;
  bfd_byte * nstring;

  if (a == NULL || b == NULL || a->is_dir || b->is_dir || 
      a->value.leaf == NULL || b->value.leaf == NULL ||
      a->value.leaf->data == NULL || b->value.leaf->data == NULL)
    return false;

  astring = a->value.leaf->data;
  bstring = b->value.leaf->data;

  for (i = 0; i < 16; i++)
    {
      if (astring > a->value.leaf->data + a->value.leaf->size - 2 ||
          bstring > b->value.leaf->data + b->value.leaf->size - 2)
        return false;
        
      unsigned int alen = astring[0] + (astring[1] << 8);
      unsigned int blen = bstring[0] + (bstring[1] << 8);

      if (astring + (alen + 1) * 2 > a->value.leaf->data + a->value.leaf->size ||
          bstring + (blen + 1) * 2 > b->value.leaf->data + b->value.leaf->size)
        return false;

      if (alen == 0)
	{
	  copy_needed += blen * 2;
	}
      else if (blen != 0)
	{
	  if (alen != blen || memcmp (astring + 2, bstring + 2, alen * 2) != 0)
	    {
	      if (a->parent != NULL && a->parent->entry != NULL && !a->parent->entry->is_name)
		_bfd_error_handler (_(".rsrc merge failure: duplicate string resource: %d"),
				    ((a->parent->entry->name_id.id - 1) << 4) + i);
	      return false;
	    }
	}

      astring += (alen + 1) * 2;
      bstring += (blen + 1) * 2;
    }

  if (copy_needed == 0)
    return true;

  new_data = bfd_malloc (a->value.leaf->size + copy_needed);
  if (new_data == NULL)
    return false;

  nstring = new_data;
  astring = a->value.leaf->data;
  bstring = b->value.leaf->data;

  for (i = 0; i < 16; i++)
    {
      unsigned int alen = astring[0] + (astring[1] << 8);
      unsigned int blen = bstring[0] + (bstring[1] << 8);

      if (alen != 0)
	{
	  memcpy (nstring, astring, (alen + 1) * 2);
	  nstring += (alen + 1) * 2;
	}
      else if (blen != 0)
	{
	  memcpy (nstring, bstring, (blen + 1) * 2);
	  nstring += (blen + 1) * 2;
	}
      else
	{
	  nstring[0] = 0;
	  nstring[1] = 0;
	  nstring += 2;
	}

      astring += (alen + 1) * 2;
      bstring += (blen + 1) * 2;
    }

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
rsrc_sort_entries (rsrc_dir_chain *chain,
                   bool is_name,
                   rsrc_directory *dir)
{
  rsrc_entry *entry;
  rsrc_entry *next;
  rsrc_entry **points_to_entry;
  bool swapped;

  if (chain == NULL || chain->num_entries < 2)
    return;

  do
    {
      swapped = false;
      points_to_entry = &chain->first_entry;
      entry = *points_to_entry;
      next = entry->next_entry;

      while (next != NULL)
        {
          signed int cmp = rsrc_cmp (is_name, entry, next);

          if (cmp > 0)
            {
              entry->next_entry = next->next_entry;
              next->next_entry = entry;
              *points_to_entry = next;
              points_to_entry = &next->next_entry;
              next = entry->next_entry;
              swapped = true;
            }
          else if (cmp == 0)
            {
              if (!handle_duplicate_entries (chain, &entry, &next, points_to_entry, dir, &swapped))
                return;
              if (chain->num_entries < 2)
                return;
            }
          else
            {
              points_to_entry = &entry->next_entry;
              entry = next;
              next = next->next_entry;
            }
        }

      chain->last_entry = entry;
    }
  while (swapped);
}

static bool
handle_duplicate_entries (rsrc_dir_chain *chain,
                          rsrc_entry **entry,
                          rsrc_entry **next,
                          rsrc_entry ***points_to_entry,
                          rsrc_directory *dir,
                          bool *swapped)
{
  if ((*entry)->is_dir && (*next)->is_dir)
    {
      if (is_manifest_entry (*entry, dir))
        {
          if (!handle_manifest_merge (entry, next, points_to_entry, swapped))
            return false;
        }
      else
        {
          rsrc_merge (*entry, *next);
        }
    }
  else if ((*entry)->is_dir != (*next)->is_dir)
    {
      _bfd_error_handler (_(".rsrc merge failure: a directory matches a leaf"));
      bfd_set_error (bfd_error_file_truncated);
      return false;
    }
  else
    {
      if (!handle_duplicate_leaves (*entry, *next, dir))
        return false;
    }

  (*entry)->next_entry = (*next)->next_entry;
  chain->num_entries--;
  *next = (*next)->next_entry;
  return true;
}

static bool
is_manifest_entry (rsrc_entry *entry, rsrc_directory *dir)
{
  return !entry->is_name
         && entry->name_id.id == 1
         && dir != NULL
         && dir->entry != NULL
         && !dir->entry->is_name
         && dir->entry->name_id.id == 0x18;
}

static bool
handle_manifest_merge (rsrc_entry **entry,
                       rsrc_entry **next,
                       rsrc_entry ***points_to_entry,
                       bool *swapped)
{
  bool next_is_default = is_default_manifest (*next);
  bool entry_is_default = is_default_manifest (*entry);

  if (next_is_default)
    {
      return true;
    }
  
  if (entry_is_default)
    {
      (*entry)->next_entry = (*next)->next_entry;
      (*next)->next_entry = *entry;
      **points_to_entry = *next;
      *points_to_entry = &(*next)->next_entry;
      *next = (*entry)->next_entry;
      *swapped = true;
      return true;
    }

  _bfd_error_handler (_(".rsrc merge failure: multiple non-default manifests"));
  bfd_set_error (bfd_error_file_truncated);
  return false;
}

static bool
is_default_manifest (rsrc_entry *entry)
{
  return entry->value.directory->names.num_entries == 0
         && entry->value.directory->ids.num_entries == 1
         && !entry->value.directory->ids.first_entry->is_name
         && entry->value.directory->ids.first_entry->name_id.id == 0;
}

static bool
handle_duplicate_leaves (rsrc_entry *entry, rsrc_entry *next, rsrc_directory *dir)
{
  if (is_default_manifest_leaf (entry, dir))
    return true;

  if (is_string_resource (dir))
    {
      if (!rsrc_merge_string_entries (entry, next))
        {
          bfd_set_error (bfd_error_file_truncated);
          return false;
        }
      return true;
    }

  report_duplicate_leaf_error (entry, dir);
  bfd_set_error (bfd_error_file_truncated);
  return false;
}

static bool
is_default_manifest_leaf (rsrc_entry *entry, rsrc_directory *dir)
{
  return !entry->is_name
         && entry->name_id.id == 0
         && dir != NULL
         && dir->entry != NULL
         && !dir->entry->is_name
         && dir->entry->name_id.id == 1
         && dir->entry->parent != NULL
         && dir->entry->parent->entry != NULL
         && !dir->entry->parent->entry->is_name
         && dir->entry->parent->entry->name_id.id == 0x18;
}

static bool
is_string_resource (rsrc_directory *dir)
{
  return dir != NULL
         && dir->entry != NULL
         && dir->entry->parent != NULL
         && dir->entry->parent->entry != NULL
         && !dir->entry->parent->entry->is_name
         && dir->entry->parent->entry->name_id.id == 0x6;
}

static void
report_duplicate_leaf_error (rsrc_entry *entry, rsrc_directory *dir)
{
  if (dir == NULL
      || dir->entry == NULL
      || dir->entry->parent == NULL
      || dir->entry->parent->entry == NULL)
    {
      _bfd_error_handler (_(".rsrc merge failure: duplicate leaf"));
    }
  else
    {
      char buff[256];
      _bfd_error_handler (_(".rsrc merge failure: duplicate leaf: %s"),
                          rsrc_resource_name (entry, dir, buff));
    }
}

/* Attach B's chain onto A.  */
static void
rsrc_attach_chain (rsrc_dir_chain * achain, rsrc_dir_chain * bchain)
{
  if (achain == NULL || bchain == NULL)
    return;

  if (bchain->num_entries == 0)
    return;

  achain->num_entries += bchain->num_entries;

  if (achain->first_entry == NULL)
    {
      achain->first_entry = bchain->first_entry;
      achain->last_entry  = bchain->last_entry;
    }
  else
    {
      achain->last_entry->next_entry = bchain->first_entry;
      achain->last_entry = bchain->last_entry;
    }

  bchain->num_entries = 0;
  bchain->first_entry = NULL;
  bchain->last_entry = NULL;
}

static void
rsrc_merge (struct rsrc_entry * a, struct rsrc_entry * b)
{
  rsrc_directory * adir;
  rsrc_directory * bdir;

  if (a == NULL || b == NULL)
    {
      bfd_set_error (bfd_error_invalid_operation);
      return;
    }

  if (!a->is_dir || !b->is_dir)
    {
      bfd_set_error (bfd_error_invalid_operation);
      return;
    }

  adir = a->value.directory;
  bdir = b->value.directory;

  if (adir == NULL || bdir == NULL)
    {
      bfd_set_error (bfd_error_invalid_operation);
      return;
    }

  if (adir->characteristics != bdir->characteristics)
    {
      _bfd_error_handler (_(".rsrc merge failure: dirs with differing characteristics"));
      bfd_set_error (bfd_error_file_truncated);
      return;
    }

  if (adir->major != bdir->major || adir->minor != bdir->minor)
    {
      _bfd_error_handler (_(".rsrc merge failure: differing directory versions"));
      bfd_set_error (bfd_error_file_truncated);
      return;
    }

  rsrc_attach_chain (& adir->names, & bdir->names);
  rsrc_attach_chain (& adir->ids, & bdir->ids);
  rsrc_sort_entries (& adir->names, true, adir);
  rsrc_sort_entries (& adir->ids, false, adir);
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
  bfd_byte *	    dataend;
  bfd_byte *	    new_data = NULL;
  unsigned int	    num_resource_sets;
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
    return;

  data = datastart;
  rsrc_sizes = bfd_malloc (max_num_input_rsrc * sizeof (*rsrc_sizes));
  if (rsrc_sizes == NULL)
    goto cleanup;

  for (input = pfinfo->info->input_bfds;
       input != NULL;
       input = input->link.next)
    {
      asection * rsrc_sec = bfd_get_section_by_name (input, ".rsrc");

      if (rsrc_sec != NULL && !discarded_section (rsrc_sec))
	{
	  if (num_input_rsrc == max_num_input_rsrc)
	    {
	      ptrdiff_t * new_rsrc_sizes;
	      max_num_input_rsrc += 10;
	      new_rsrc_sizes = bfd_realloc (rsrc_sizes, max_num_input_rsrc
					     * sizeof (*rsrc_sizes));
	      if (new_rsrc_sizes == NULL)
		goto cleanup;
	      rsrc_sizes = new_rsrc_sizes;
	    }

	  BFD_ASSERT (rsrc_sec->size > 0);
	  rsrc_sizes [num_input_rsrc ++] = rsrc_sec->size;
	}
    }

  if (num_input_rsrc < 2)
    goto cleanup;

  dataend = data + size;
  num_resource_sets = 0;

  while (data < dataend)
    {
      bfd_byte * p = data;

      data = rsrc_count_directory (abfd, data, data, dataend, rva_bias);

      if (data > dataend)
	{
	  _bfd_error_handler (_("%pB: .rsrc merge failure: corrupt .rsrc section"),
			      abfd);
	  bfd_set_error (bfd_error_file_truncated);
	  goto cleanup;
	}

      if ((data - p) > rsrc_sizes [num_resource_sets])
	{
	  _bfd_error_handler (_("%pB: .rsrc merge failure: unexpected .rsrc size"),
			      abfd);
	  bfd_set_error (bfd_error_file_truncated);
	  goto cleanup;
	}

      data = p + rsrc_sizes[num_resource_sets];
      rva_bias += data - p;
      ++ num_resource_sets;
    }
  BFD_ASSERT (num_resource_sets == num_input_rsrc);

  data = datastart;
  rva_bias = sec->vma - pe->pe_opthdr.ImageBase;

  type_tables = bfd_malloc (num_resource_sets * sizeof (*type_tables));
  if (type_tables == NULL)
    goto cleanup;

  indx = 0;
  while (data < dataend)
    {
      bfd_byte * p = data;

      (void) rsrc_parse_directory (abfd, type_tables + indx, data, data,
				   dataend, rva_bias, NULL);
      data = p + rsrc_sizes[indx];
      rva_bias += data - p;
      ++ indx;
    }
  BFD_ASSERT (indx == num_resource_sets);

  new_table.characteristics = type_tables[0].characteristics;
  new_table.time	    = type_tables[0].time;
  new_table.major	    = type_tables[0].major;
  new_table.minor	    = type_tables[0].minor;

  new_table.names.first_entry = NULL;
  new_table.names.last_entry = NULL;

  for (indx = 0; indx < num_resource_sets; indx++)
    rsrc_attach_chain (& new_table.names, & type_tables[indx].names);

  rsrc_sort_entries (& new_table.names, true, & new_table);

  new_table.ids.first_entry = NULL;
  new_table.ids.last_entry = NULL;

  for (indx = 0; indx < num_resource_sets; indx++)
    rsrc_attach_chain (& new_table.ids, & type_tables[indx].ids);

  rsrc_sort_entries (& new_table.ids, false, & new_table);

  sizeof_leaves = sizeof_strings = sizeof_tables_and_entries = 0;
  rsrc_compute_region_sizes (& new_table);
  sizeof_strings = (sizeof_strings + 7) & ~ 7;

  new_data = bfd_zalloc (abfd, size);
  if (new_data == NULL)
    goto cleanup;

  write_data.abfd	 = abfd;
  write_data.datastart	 = new_data;
  write_data.next_table	 = new_data;
  write_data.next_leaf	 = new_data + sizeof_tables_and_entries;
  write_data.next_string = write_data.next_leaf + sizeof_leaves;
  write_data.next_data	 = write_data.next_string + sizeof_strings;
  write_data.rva_bias	 = sec->vma - pe->pe_opthdr.ImageBase;

  rsrc_write_directory (& write_data, & new_table);

  bfd_set_section_contents (pfinfo->output_bfd, sec, new_data, 0, size);
  sec->size = sec->rawsize = size;

 cleanup:
  free (datastart);
  free (rsrc_sizes);
  free (type_tables);
}

/* Handle the .idata section and other things that need symbol table
   access.  */

bool
_bfd_XXi_final_link_postscript (bfd * abfd, struct coff_final_link_info *pfinfo)
{
  struct bfd_link_info *info = pfinfo->info;
  bool result = true;
  char name[20];

  if (abfd == NULL || pfinfo == NULL || info == NULL)
    return false;

  static const struct {
    const char *idata_name;
    const char *missing_name;
    int directory_index;
    bool is_size;
  } idata_sections[] = {
    { ".idata$2", ".idata$2", PE_IMPORT_TABLE, false },
    { ".idata$4", ".idata$4", PE_IMPORT_TABLE, true },
    { ".idata$5", ".idata$5", PE_IMPORT_ADDRESS_TABLE, false },
    { ".idata$6", ".idata$6", PE_IMPORT_ADDRESS_TABLE, true }
  };

  struct coff_link_hash_entry *h_idata2 = coff_link_hash_lookup(
    coff_hash_table(info), ".idata$2", false, false, true);

  if (h_idata2 != NULL)
  {
    for (int i = 0; i < 4; i++)
    {
      struct coff_link_hash_entry *h = coff_link_hash_lookup(
        coff_hash_table(info), idata_sections[i].idata_name, false, false, true);

      if (h == NULL || 
          (h->root.type != bfd_link_hash_defined && h->root.type != bfd_link_hash_defweak) ||
          h->root.u.def.section == NULL ||
          h->root.u.def.section->output_section == NULL)
      {
        _bfd_error_handler(
          _("%pB: unable to fill in DataDirectory[%d]: %s is missing"),
          abfd, idata_sections[i].directory_index, idata_sections[i].missing_name);
        result = false;
        continue;
      }

      bfd_vma value = h->root.u.def.value +
                      h->root.u.def.section->output_section->vma +
                      h->root.u.def.section->output_offset;

      if (idata_sections[i].is_size)
      {
        pe_data(abfd)->pe_opthdr.DataDirectory[idata_sections[i].directory_index].Size =
          value - pe_data(abfd)->pe_opthdr.DataDirectory[idata_sections[i].directory_index].VirtualAddress;
      }
      else
      {
        pe_data(abfd)->pe_opthdr.DataDirectory[idata_sections[i].directory_index].VirtualAddress = value;
      }
    }
  }
  else
  {
    struct coff_link_hash_entry *h_iat_start = coff_link_hash_lookup(
      coff_hash_table(info), "__IAT_start__", false, false, true);

    if (h_iat_start != NULL &&
        (h_iat_start->root.type == bfd_link_hash_defined || 
         h_iat_start->root.type == bfd_link_hash_defweak) &&
        h_iat_start->root.u.def.section != NULL &&
        h_iat_start->root.u.def.section->output_section != NULL)
    {
      bfd_vma iat_va = h_iat_start->root.u.def.value +
                       h_iat_start->root.u.def.section->output_section->vma +
                       h_iat_start->root.u.def.section->output_offset;

      struct coff_link_hash_entry *h_iat_end = coff_link_hash_lookup(
        coff_hash_table(info), "__IAT_end__", false, false, true);

      if (h_iat_end != NULL &&
          (h_iat_end->root.type == bfd_link_hash_defined || 
           h_iat_end->root.type == bfd_link_hash_defweak) &&
          h_iat_end->root.u.def.section != NULL &&
          h_iat_end->root.u.def.section->output_section != NULL)
      {
        bfd_vma size = (h_iat_end->root.u.def.value +
                        h_iat_end->root.u.def.section->output_section->vma +
                        h_iat_end->root.u.def.section->output_offset) - iat_va;
        
        pe_data(abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].Size = size;
        if (size != 0)
          pe_data(abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].VirtualAddress =
            iat_va - pe_data(abfd)->pe_opthdr.ImageBase;
      }
      else
      {
        _bfd_error_handler(
          _("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
          abfd, PE_IMPORT_ADDRESS_TABLE, "__IAT_end__");
        result = false;
      }
    }
  }

  struct coff_link_hash_entry *h_delay_start = coff_link_hash_lookup(
    coff_hash_table(info), "__DELAY_IMPORT_DIRECTORY_start__", false, false, true);

  if (h_delay_start != NULL &&
      (h_delay_start->root.type == bfd_link_hash_defined || 
       h_delay_start->root.type == bfd_link_hash_defweak) &&
      h_delay_start->root.u.def.section != NULL &&
      h_delay_start->root.u.def.section->output_section != NULL)
  {
    bfd_vma delay_va = h_delay_start->root.u.def.value +
                       h_delay_start->root.u.def.section->output_section->vma +
                       h_delay_start->root.u.def.section->output_offset;

    struct coff_link_hash_entry *h_delay_end = coff_link_hash_lookup(
      coff_hash_table(info), "__DELAY_IMPORT_DIRECTORY_end__", false, false, true);

    if (h_delay_end != NULL &&
        (h_delay_end->root.type == bfd_link_hash_defined || 
         h_delay_end->root.type == bfd_link_hash_defweak) &&
        h_delay_end->root.u.def.section != NULL &&
        h_delay_end->root.u.def.section->output_section != NULL)
    {
      bfd_vma size = (h_delay_end->root.u.def.value +
                      h_delay_end->root.u.def.section->output_section->vma +
                      h_delay_end->root.u.def.section->output_offset) - delay_va;
      
      pe_data(abfd)->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR].Size = size;
      if (size != 0)
        pe_data(abfd)->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR].VirtualAddress =
          delay_va - pe_data(abfd)->pe_opthdr.ImageBase;
    }
    else
    {
      _bfd_error_handler(
        _("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
        abfd, PE_DELAY_IMPORT_DESCRIPTOR, "__DELAY_IMPORT_DIRECTORY_end__");
      result = false;
    }
  }

  name[0] = bfd_get_symbol_leading_char(abfd);
  strcpy(name + !!name[0], "_tls_used");
  
  struct coff_link_hash_entry *h_tls = coff_link_hash_lookup(
    coff_hash_table(info), name, false, false, true);

  if (h_tls != NULL)
  {
    if ((h_tls->root.type == bfd_link_hash_defined || 
         h_tls->root.type == bfd_link_hash_defweak) &&
        h_tls->root.u.def.section != NULL &&
        h_tls->root.u.def.section->output_section != NULL)
    {
      pe_data(abfd)->pe_opthdr.DataDirectory[PE_TLS_TABLE].VirtualAddress =
        h_tls->root.u.def.value +
        h_tls->root.u.def.section->output_section->vma +
        h_tls->root.u.def.section->output_offset -
        pe_data(abfd)->pe_opthdr.ImageBase;
    }
    else
    {
      _bfd_error_handler(
        _("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
        abfd, PE_TLS_TABLE, name);
      result = false;
    }

#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined(COFF_WITH_peRiscV64)
    pe_data(abfd)->pe_opthdr.DataDirectory[PE_TLS_TABLE].Size = 0x18;
#else
    pe_data(abfd)->pe_opthdr.DataDirectory[PE_TLS_TABLE].Size = 0x28;
#endif
  }

  name[0] = bfd_get_symbol_leading_char(abfd);
  strcpy(name + !!name[0], "_load_config_used");
  
  struct coff_link_hash_entry *h_load_config = coff_link_hash_lookup(
    coff_hash_table(info), name, false, false, true);

  if (h_load_config != NULL)
  {
    if ((h_load_config->root.type == bfd_link_hash_defined || 
         h_load_config->root.type == bfd_link_hash_defweak) &&
        h_load_config->root.u.def.section != NULL &&
        h_load_config->root.u.def.section->output_section != NULL)
    {
      bfd_vma virt_addr = h_load_config->root.u.def.value +
                          h_load_config->root.u.def.section->output_section->vma +
                          h_load_config->root.u.def.section->output_offset -
                          pe_data(abfd)->pe_opthdr.ImageBase;

      pe_data(abfd)->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].VirtualAddress = virt_addr;

      unsigned int alignment = bfd_arch_bits_per_address(abfd) / bfd_arch_bits_per_byte(abfd) - 1;
      if (virt_addr & alignment)
      {
        _bfd_error_handler(
          _("%pB: unable to fill in DataDirectory[%d]: %s not properly aligned"),
          abfd, PE_LOAD_CONFIG_TABLE, name);
        result = false;
      }

      char data[4];
      if (bfd_get_section_contents(abfd,
          h_load_config->root.u.def.section->output_section, data,
          h_load_config->root.u.def.section->output_offset + h_load_config->root.u.def.value, 4))
      {
        uint32_t size = bfd_get_32(abfd, data);
        
        bool is_x86_windows_xp_or_earlier = 
          (bfd_get_arch(abfd) == bfd_arch_i386) &&
          ((bfd_get_mach(abfd) & ~bfd_mach_i386_intel_syntax) == bfd_mach_i386_i386) &&
          ((pe_data(abfd)->pe_opthdr.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) ||
           (pe_data(abfd)->pe_opthdr.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI)) &&
          ((pe_data(abfd)->pe_opthdr.MajorSubsystemVersion * 256 +
            pe_data(abfd)->pe_opthdr.MinorSubsystemVersion) <= 0x0501);

        pe_data(abfd)->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].Size =
          is_x86_windows_xp_or_earlier ? 64 : size;

        if (size > h_load_config->root.u.def.section->size - h_load_config->root.u.def.value)
        {
          _bfd_error_handler(
            _("%pB: unable to fill in DataDirectory[%d]: size too large for the containing section"),
            abfd, PE_LOAD_CONFIG_TABLE);
          result = false;
        }
      }
      else
      {
        _bfd_error_handler(
          _("%pB: unable to fill in DataDirectory[%d]: size can't be read from %s"),
          abfd, PE_LOAD_CONFIG_TABLE, name);
        result = false;
      }
    }
    else
    {
      _bfd_error_handler(
        _("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
        abfd, PE_LOAD_CONFIG_TABLE, name);
      result = false;
    }
  }

#if !defined(COFF_WITH_pep) && (defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined(COFF_WITH_peRiscV64))
  {
    asection *sec = bfd_get_section_by_name(abfd, ".pdata");
    if (sec != NULL && sec->rawsize > 0)
    {
      bfd_byte *tmp_data = NULL;
      if (bfd_malloc_and_get_section(abfd, sec, &tmp_data))
      {
        qsort(tmp_data, (size_t)(sec->rawsize / 12), 12, sort_x64_pdata);
        bfd_set_section_contents(pfinfo->output_bfd, sec, tmp_data, 0, sec->rawsize);
        free(tmp_data);
      }
      else
      {
        result = false;
      }
    }
  }
#endif

  rsrc_process_section(abfd, pfinfo);

  return result;
}
