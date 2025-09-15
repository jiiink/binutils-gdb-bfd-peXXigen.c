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
  SYMENT *ext = (SYMENT *) ext1;
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

  if (sizeof (ext->e_type) == 2)
    {
      in->n_type = H_GET_16 (abfd, ext->e_type);
    }
  else
    {
      in->n_type = H_GET_32 (abfd, ext->e_type);
    }

  in->n_sclass = H_GET_8 (abfd, ext->e_sclass);
  in->n_numaux = H_GET_8 (abfd, ext->e_numaux);

#ifndef STRICT_PE_FORMAT
  if (in->n_sclass != C_SECTION)
    {
      return;
    }

  in->n_value = 0;

  if (in->n_scnum == 0)
    {
      char namebuf[SYMNMLEN + 1];
      const char *name = _bfd_coff_internal_syment_name (abfd, in, namebuf);
      if (name == NULL)
	{
	  _bfd_error_handler (_("%pB: unable to find name for empty section"),
				  abfd);
	  bfd_set_error (bfd_error_invalid_target);
	  return;
	}

      asection *found_sec = bfd_get_section_by_name (abfd, name);
      if (found_sec != NULL)
	{
	  in->n_scnum = found_sec->target_index;
	}
      else
	{
	  int unused_section_number = 0;
	  for (asection *iter_sec = abfd->sections; iter_sec;
	       iter_sec = iter_sec->next)
	    {
	      if (unused_section_number <= iter_sec->target_index)
		{
		  unused_section_number = iter_sec->target_index + 1;
		}
	    }

	  size_t name_len = strlen (name) + 1;
	  char *sec_name = bfd_alloc (abfd, name_len);
	  if (sec_name == NULL)
	    {
	      _bfd_error_handler (
		_("%pB: out of memory creating name for empty section"), abfd);
	      return;
	    }
	  memcpy (sec_name, name, name_len);

	  flagword flags = (SEC_HAS_CONTENTS | SEC_ALLOC | SEC_DATA | SEC_LOAD
			   | SEC_LINKER_CREATED);
	  asection *new_sec =
	    bfd_make_section_anyway_with_flags (abfd, sec_name, flags);
	  if (new_sec == NULL)
	    {
	      _bfd_error_handler (
		_("%pB: unable to create fake empty section"), abfd);
	      return;
	    }

	  new_sec->alignment_power = 2;
	  new_sec->target_index = unused_section_number;
	  in->n_scnum = unused_section_number;
	}
    }

  in->n_sclass = C_STAT;
#endif
}

static bool
abs_finder (bfd *abfd ATTRIBUTE_UNUSED, asection *sec, void *data)
{
  if (sec == NULL || data == NULL)
    {
      return false;
    }

  const bfd_vma address_space_size_32_bit = 1ULL << 32;
  const bfd_vma abs_val = *(const bfd_vma *) data;
  const bfd_vma section_start = sec->vma;
  const bfd_vma section_end = section_start + address_space_size_32_bit;

  return (abs_val >= section_start) && (abs_val < section_end);
}

unsigned int
_bfd_XXi_swap_sym_out (bfd *abfd, void *inp, void *extp)
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

  if (sizeof (in->n_value) > 4
      && in->n_scnum == N_ABS
      && in->n_value > 0xFFFFFFFFUL)
    {
      asection *sec = bfd_sections_find_if (abfd, abs_finder, &in->n_value);
      if (sec)
	{
	  in->n_value -= sec->vma;
	  in->n_scnum = sec->target_index;
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

static bfd_boolean
is_function_like (int in_class, int type)
{
  return in_class == C_BLOCK
	 || in_class == C_FCN
	 || ISFCN (type)
	 || ISTAG (in_class);
}

static void
swap_aux_file_in (bfd *abfd, union internal_auxent *in, const AUXENT *ext)
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
}

static void
swap_aux_scn_in (bfd *abfd, union internal_auxent *in, const AUXENT *ext)
{
  in->x_scn.x_scnlen = GET_SCN_SCNLEN (abfd, ext);
  in->x_scn.x_nreloc = GET_SCN_NRELOC (abfd, ext);
  in->x_scn.x_nlinno = GET_SCN_NLINNO (abfd, ext);
  in->x_scn.x_checksum = H_GET_32 (abfd, ext->x_scn.x_checksum);
  in->x_scn.x_associated = H_GET_16 (abfd, ext->x_scn.x_associated);
  in->x_scn.x_comdat = H_GET_8 (abfd, ext->x_scn.x_comdat);
}

static void
swap_aux_sym_in (bfd *abfd, union internal_auxent *in, const AUXENT *ext,
		 int in_class, int type)
{
  in->x_sym.x_tagndx.u32 = H_GET_32 (abfd, ext->x_sym.x_tagndx);
  in->x_sym.x_tvndx = H_GET_16 (abfd, ext->x_sym.x_tvndx);

  if (is_function_like (in_class, type))
    {
      in->x_sym.x_fcnary.x_fcn.x_lnnoptr = GET_FCN_LNNOPTR (abfd, ext);
      in->x_sym.x_fcnary.x_fcn.x_endndx.u32 = GET_FCN_ENDNDX (abfd, ext);
    }
  else
    {
      in->x_sym.x_fcnary.x_ary.x_dimen[0] =
	H_GET_16 (abfd, ext->x_sym.x_fcnary.x_ary.x_dimen[0]);
      in->x_sym.x_fcnary.x_ary.x_dimen[1] =
	H_GET_16 (abfd, ext->x_sym.x_fcnary.x_ary.x_dimen[1]);
      in->x_sym.x_fcnary.x_ary.x_dimen[2] =
	H_GET_16 (abfd, ext->x_sym.x_fcnary.x_ary.x_dimen[2]);
      in->x_sym.x_fcnary.x_ary.x_dimen[3] =
	H_GET_16 (abfd, ext->x_sym.x_fcnary.x_ary.x_dimen[3]);
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

void
_bfd_XXi_swap_aux_in (bfd *abfd,
		      void *ext1,
		      int type,
		      int in_class,
		      int indx ATTRIBUTE_UNUSED,
		      int numaux ATTRIBUTE_UNUSED,
		      void *in1)
{
  const AUXENT *ext = (const AUXENT *) ext1;
  union internal_auxent *in = (union internal_auxent *) in1;

  memset (in, 0, sizeof (*in));

  switch (in_class)
    {
    case C_FILE:
      swap_aux_file_in (abfd, in, ext);
      break;

    case C_STAT:
    case C_LEAFSTAT:
    case C_HIDDEN:
      if (type == T_NULL)
	{
	  swap_aux_scn_in (abfd, in, ext);
	  break;
	}
    default:
      swap_aux_sym_in (abfd, in, ext, in_class, type);
      break;
    }
}

unsigned int
_bfd_XXi_swap_aux_out (bfd *abfd, void *inp, int type, int in_class,
		       int indx ATTRIBUTE_UNUSED, int numaux ATTRIBUTE_UNUSED,
		       void *extp)
{
  const union internal_auxent *in = (const union internal_auxent *) inp;
  AUXENT *ext = (AUXENT *) extp;

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
	{
#if FILNMLEN != E_FILNMLEN
#error we need to cope with truncating or extending x_fname
#endif
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

  const int is_function_or_block = (in_class == C_BLOCK
				    || in_class == C_FCN
				    || ISFCN (type)
				    || ISTAG (in_class));
  if (is_function_or_block)
    {
      PUT_FCN_LNNOPTR (abfd, in->x_sym.x_fcnary.x_fcn.x_lnnoptr, ext);
      PUT_FCN_ENDNDX (abfd, in->x_sym.x_fcnary.x_fcn.x_endndx.u32, ext);
    }
  else
    {
      for (int i = 0; i < 4; ++i)
	{
	  H_PUT_16 (abfd, in->x_sym.x_fcnary.x_ary.x_dimen[i],
		    ext->x_sym.x_fcnary.x_ary.x_dimen[i]);
	}
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
_bfd_XXi_swap_lineno_in (bfd *abfd, void *ext_ptr, void *in_ptr)
{
  if (abfd == NULL || ext_ptr == NULL || in_ptr == NULL)
    {
      return;
    }

  const LINENO *ext = (const LINENO *) ext_ptr;
  struct internal_lineno *in = (struct internal_lineno *) in_ptr;

  in->l_addr.l_symndx = H_GET_32 (abfd, ext->l_addr.l_symndx);
  in->l_lnno = GET_LINENO_LNNO (abfd, ext);
}

unsigned int
_bfd_XXi_swap_lineno_out (bfd *abfd, const void *inp, void *outp)
{
  if (abfd == NULL || inp == NULL || outp == NULL)
    {
      return 0;
    }

  const struct internal_lineno *in = (const struct internal_lineno *) inp;
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
  const PEAOUTHDR *src = (const PEAOUTHDR *) aouthdr_ext1;
  const AOUTHDR *aouthdr_ext = (const AOUTHDR *) aouthdr_ext1;
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
  /* PE32+ does not have data_start member!  */
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

  /* PR 17512: Don't blindly trust NumberOfRvaAndSizes.  */
  const unsigned long rva_count = a->NumberOfRvaAndSizes;
  for (unsigned int idx = 0; idx < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++idx)
    {
      if (idx < rva_count)
	{
	  unsigned long size = H_GET_32 (abfd, src->DataDirectory[idx][1]);
	  a->DataDirectory[idx].Size = size;
	  /* If data directory is empty, rva also should be 0.  */
	  a->DataDirectory[idx].VirtualAddress =
	    size ? H_GET_32 (abfd, src->DataDirectory[idx][0]) : 0;
	}
      else
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
  /* PE32+ does not have data_start member!  */
  if (aouthdr_int->dsize)
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
  asection *sec = bfd_get_section_by_name (abfd, name);
  if (sec == NULL)
    return;

  struct pei_section_t *pei_sec = pei_section_data (abfd, sec);
  if (pei_sec == NULL || coff_section_data (abfd, sec) == NULL)
    return;

  int size = pei_sec->virt_size;
  aout->DataDirectory[idx].Size = size;

  if (size != 0)
    {
      aout->DataDirectory[idx].VirtualAddress =
	(sec->vma - base) & 0xffffffff;
      sec->flags |= SEC_DATA;
    }
}

#if defined(COFF_WITH_pep) || defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined(COFF_WITH_peRiscV64)
#define IS_PE32PLUS_FORMAT 1
#else
#define IS_PE32PLUS_FORMAT 0
#endif

static inline bfd_vma
align_up (bfd_vma val, bfd_vma alignment)
{
  return (val + alignment - 1) & ~(alignment - 1);
}

static inline bfd_vma
vma_to_rva (bfd_vma vma, bfd_vma image_base)
{
  bfd_vma rva = vma - image_base;
#if !IS_PE32PLUS_FORMAT
  rva &= 0xffffffff;
#endif
  return rva;
}

struct pe_image_sizes
{
  bfd_vma text_size;
  bfd_vma data_size;
  bfd_vma image_size;
  bfd_vma headers_size;
};

static void
calculate_pe_image_sizes (bfd *abfd,
			  bfd_vma file_align,
			  bfd_vma sect_align,
			  bfd_vma image_base,
			  struct pe_image_sizes *sizes)
{
  sizes->text_size = 0;
  sizes->data_size = 0;
  sizes->image_size = 0;
  sizes->headers_size = 0;

  for (asection *sec = abfd->sections; sec != NULL; sec = sec->next)
    {
      bfd_size_type rounded_size = align_up (sec->size, file_align);

      if (rounded_size == 0)
	continue;

      if (sizes->headers_size == 0 && sec->filepos != 0)
	sizes->headers_size = sec->filepos;

      if ((sec->flags & SEC_DATA) != 0)
	sizes->data_size += rounded_size;

      if ((sec->flags & SEC_CODE) != 0)
	sizes->text_size += rounded_size;

      if (coff_section_data (abfd, sec) != NULL
	  && pei_section_data (abfd, sec) != NULL)
	{
	  bfd_vma sec_virt_size = pei_section_data (abfd, sec)->virt_size;
	  bfd_vma end_rva = sec->vma - image_base + align_up (sec_virt_size, file_align);
	  sizes->image_size = align_up (end_rva, sect_align);
	}
    }
}

static void
set_linker_version_stamp (bfd *abfd,
			  const struct internal_extra_pe_aouthdr *extra,
			  PEAOUTHDR *aouthdr_out)
{
  if (extra->MajorLinkerVersion || extra->MinorLinkerVersion)
    {
      H_PUT_8 (abfd, extra->MajorLinkerVersion, aouthdr_out->standard.vstamp);
      H_PUT_8 (abfd, extra->MinorLinkerVersion, aouthdr_out->standard.vstamp + 1);
    }
  else
    {
      const unsigned int bfd_linker_version = BFD_VERSION / 1000000;
      const unsigned short major = (unsigned short) (bfd_linker_version / 100);
      const unsigned short minor = (unsigned short) (bfd_linker_version % 100);
      const unsigned short version_stamp = (unsigned short) ((minor << 8) | major);
      H_PUT_16 (abfd, version_stamp, aouthdr_out->standard.vstamp);
    }
}

unsigned int
_bfd_XXi_swap_aouthdr_out (bfd *abfd, void *in, void *out)
{
  struct internal_aouthdr *aouthdr_in = (struct internal_aouthdr *) in;
  PEAOUTHDR *aouthdr_out = (PEAOUTHDR *) out;
  pe_data_type *pe = pe_data (abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
  const bfd_vma image_base = extra->ImageBase;

  const IMAGE_DATA_DIRECTORY saved_import_table = extra->DataDirectory[PE_IMPORT_TABLE];
  const IMAGE_DATA_DIRECTORY saved_iat = extra->DataDirectory[PE_IMPORT_ADDRESS_TABLE];
  const IMAGE_DATA_DIRECTORY saved_delay_import_table = extra->DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR];
  const IMAGE_DATA_DIRECTORY saved_tls_table = extra->DataDirectory[PE_TLS_TABLE];
  const IMAGE_DATA_DIRECTORY saved_load_config_table = extra->DataDirectory[PE_LOAD_CONFIG_TABLE];

  if (aouthdr_in->tsize)
    aouthdr_in->text_start = vma_to_rva (aouthdr_in->text_start, image_base);

  if (aouthdr_in->dsize)
    aouthdr_in->data_start = vma_to_rva (aouthdr_in->data_start, image_base);

  if (aouthdr_in->entry)
    aouthdr_in->entry = vma_to_rva (aouthdr_in->entry, image_base);

  aouthdr_in->bsize = align_up (aouthdr_in->bsize, extra->FileAlignment);

  extra->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

  add_data_entry (abfd, extra, PE_EXPORT_TABLE, ".edata", image_base);
  add_data_entry (abfd, extra, PE_RESOURCE_TABLE, ".rsrc", image_base);
  add_data_entry (abfd, extra, PE_EXCEPTION_TABLE, ".pdata", image_base);

  extra->DataDirectory[PE_IMPORT_TABLE] = saved_import_table;
  extra->DataDirectory[PE_IMPORT_ADDRESS_TABLE] = saved_iat;
  extra->DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR] = saved_delay_import_table;
  extra->DataDirectory[PE_TLS_TABLE] = saved_tls_table;
  extra->DataDirectory[PE_LOAD_CONFIG_TABLE] = saved_load_config_table;

  if (extra->DataDirectory[PE_IMPORT_TABLE].VirtualAddress == 0)
    add_data_entry (abfd, extra, PE_IMPORT_TABLE, ".idata", image_base);

  if (pe->has_reloc_section)
    add_data_entry (abfd, extra, PE_BASE_RELOCATION_TABLE, ".reloc", image_base);

  struct pe_image_sizes sizes;
  calculate_pe_image_sizes (abfd, extra->FileAlignment, extra->SectionAlignment, image_base, &sizes);

  aouthdr_in->dsize = sizes.data_size;
  aouthdr_in->tsize = sizes.text_size;
  extra->SizeOfHeaders = sizes.headers_size;
  extra->SizeOfImage = sizes.image_size;

  H_PUT_16 (abfd, aouthdr_in->magic, aouthdr_out->standard.magic);
  set_linker_version_stamp (abfd, extra, aouthdr_out);

  PUT_AOUTHDR_TSIZE (abfd, aouthdr_in->tsize, aouthdr_out->standard.tsize);
  PUT_AOUTHDR_DSIZE (abfd, aouthdr_in->dsize, aouthdr_out->standard.dsize);
  PUT_AOUTHDR_BSIZE (abfd, aouthdr_in->bsize, aouthdr_out->standard.bsize);
  PUT_AOUTHDR_ENTRY (abfd, aouthdr_in->entry, aouthdr_out->standard.entry);
  PUT_AOUTHDR_TEXT_START (abfd, aouthdr_in->text_start,
			  aouthdr_out->standard.text_start);

#if !IS_PE32PLUS_FORMAT
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

  for (int idx = 0; idx < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; idx++)
    {
      H_PUT_32 (abfd, extra->DataDirectory[idx].VirtualAddress,
		aouthdr_out->DataDirectory[idx][0]);
      H_PUT_32 (abfd, extra->DataDirectory[idx].Size,
		aouthdr_out->DataDirectory[idx][1]);
    }

  return AOUTSZ;
}

static void
initialize_internal_pei_header (struct internal_filehdr *filehdr_in,
				const pe_data_struct * pe)
{
  filehdr_in->pe.e_magic = IMAGE_DOS_SIGNATURE;
  filehdr_in->pe.e_cblp = 0x90;
  filehdr_in->pe.e_cp = 0x3;
  filehdr_in->pe.e_crlc = 0x0;
  filehdr_in->pe.e_cparhdr = 0x4;
  filehdr_in->pe.e_minalloc = 0x0;
  filehdr_in->pe.e_maxalloc = 0xffff;
  filehdr_in->pe.e_ss = 0x0;
  filehdr_in->pe.e_sp = 0xb8;
  filehdr_in->pe.e_csum = 0x0;
  filehdr_in->pe.e_ip = 0x0;
  filehdr_in->pe.e_cs = 0x0;
  filehdr_in->pe.e_lfarlc = 0x40;
  filehdr_in->pe.e_ovno = 0x0;
  filehdr_in->pe.e_oemid = 0x0;
  filehdr_in->pe.e_oeminfo = 0x0;
  filehdr_in->pe.e_lfanew = 0x80;
  filehdr_in->pe.nt_signature = IMAGE_NT_SIGNATURE;

  memset (filehdr_in->pe.e_res, 0, sizeof (filehdr_in->pe.e_res));
  memset (filehdr_in->pe.e_res2, 0, sizeof (filehdr_in->pe.e_res2));

  memcpy (filehdr_in->pe.dos_message, pe->dos_message,
	  sizeof (filehdr_in->pe.dos_message));
}

static void
swap_filehdr_to_external (bfd * abfd,
			  const struct internal_filehdr * filehdr_in,
			  struct external_PEI_filehdr * filehdr_out,
			  const pe_data_struct * pe)
{
  time_t timestamp =
    (pe->timestamp == -1) ? bfd_get_current_time (0) : pe->timestamp;

  H_PUT_16 (abfd, filehdr_in->f_magic, filehdr_out->f_magic);
  H_PUT_16 (abfd, filehdr_in->f_nscns, filehdr_out->f_nscns);
  H_PUT_32 (abfd, timestamp, filehdr_out->f_timdat);
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
  H_PUT_16 (abfd, filehdr_in->pe.e_oemid, filehdr_out->e_oemid);
  H_PUT_16 (abfd, filehdr_in->pe.e_oeminfo, filehdr_out->e_oeminfo);

  for (int idx = 0; idx < 4; idx++)
    H_PUT_16 (abfd, filehdr_in->pe.e_res[idx], filehdr_out->e_res[idx]);

  for (int idx = 0; idx < 10; idx++)
    H_PUT_16 (abfd, filehdr_in->pe.e_res2[idx], filehdr_out->e_res2[idx]);

  H_PUT_32 (abfd, filehdr_in->pe.e_lfanew, filehdr_out->e_lfanew);

  memcpy (filehdr_out->dos_message, filehdr_in->pe.dos_message,
	  sizeof (filehdr_out->dos_message));

  H_PUT_32 (abfd, filehdr_in->pe.nt_signature, filehdr_out->nt_signature);
}

unsigned int
_bfd_XXi_only_swap_filehdr_out (bfd * abfd, void *in, void *out)
{
  if (abfd == NULL || in == NULL || out == NULL)
    {
      return 0;
    }

  struct internal_filehdr *filehdr_in = (struct internal_filehdr *) in;
  struct external_PEI_filehdr *filehdr_out =
    (struct external_PEI_filehdr *) out;
  const pe_data_struct *pe = pe_data (abfd);

  if (pe->has_reloc_section || pe->dont_strip_reloc)
    {
      filehdr_in->f_flags &= ~F_RELFLG;
    }

  if (pe->dll)
    {
      filehdr_in->f_flags |= F_DLL;
    }

  initialize_internal_pei_header (filehdr_in, pe);
  swap_filehdr_to_external (abfd, filehdr_in, filehdr_out, pe);

  return FILHSZ;
}

unsigned int
_bfd_XX_only_swap_filehdr_out (bfd *abfd, const void *in, void *out)
{
  if (abfd == NULL || in == NULL || out == NULL)
    {
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
  { ".text" , IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE },
  { ".tls",   IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_WRITE },
  { ".xdata", IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA },
};

unsigned int
_bfd_XXi_swap_scnhdr_out (bfd * abfd, const void * in, void * out)
{
  const struct internal_scnhdr *scnhdr_int = (const struct internal_scnhdr *) in;
  SCNHDR *scnhdr_ext = (SCNHDR *) out;
  unsigned int bytes_written = SCNHSZ;

  memcpy (scnhdr_ext->s_name, scnhdr_int->s_name, sizeof (scnhdr_int->s_name));

  const bfd_vma image_base = pe_data (abfd)->pe_opthdr.ImageBase;
  bfd_vma rva = scnhdr_int->s_vaddr - image_base;

  if (scnhdr_int->s_vaddr < image_base)
    _bfd_error_handler (_("%pB:%.8s: section below image base"),
                        abfd, scnhdr_int->s_name);
#if !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
  else if (rva != (rva & 0xffffffff))
    _bfd_error_handler (_("%pB:%.8s: RVA truncated"), abfd, scnhdr_int->s_name);
  PUT_SCNHDR_VADDR (abfd, rva & 0xffffffff, scnhdr_ext->s_vaddr);
#else
  PUT_SCNHDR_VADDR (abfd, rva, scnhdr_ext->s_vaddr);
#endif

  bfd_vma virtual_size;
  bfd_vma size_of_raw_data;
  const bool is_pei = bfd_pei_p (abfd);
  const bool is_uninitialized = (scnhdr_int->s_flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;

  if (is_uninitialized)
    {
      size_of_raw_data = is_pei ? 0 : scnhdr_int->s_size;
      virtual_size = is_pei ? scnhdr_int->s_size : 0;
    }
  else
    {
      size_of_raw_data = scnhdr_int->s_size;
      virtual_size = is_pei ? scnhdr_int->s_paddr : 0;
    }

  PUT_SCNHDR_SIZE (abfd, size_of_raw_data, scnhdr_ext->s_size);
  PUT_SCNHDR_PADDR (abfd, virtual_size, scnhdr_ext->s_paddr);
  PUT_SCNHDR_SCNPTR (abfd, scnhdr_int->s_scnptr, scnhdr_ext->s_scnptr);
  PUT_SCNHDR_RELPTR (abfd, scnhdr_int->s_relptr, scnhdr_ext->s_relptr);
  PUT_SCNHDR_LNNOPTR (abfd, scnhdr_int->s_lnnoptr, scnhdr_ext->s_lnnoptr);

  unsigned long flags = scnhdr_int->s_flags;
  const bool is_text_section = (memcmp (scnhdr_int->s_name, ".text", sizeof ".text") == 0);

  for (size_t i = 0; i < ARRAY_SIZE (known_sections); ++i)
    {
      if (memcmp (scnhdr_int->s_name, known_sections[i].section_name, SCNNMLEN) == 0)
        {
          if (!is_text_section || (bfd_get_file_flags (abfd) & WP_TEXT))
            flags &= ~IMAGE_SCN_MEM_WRITE;
          flags |= known_sections[i].must_have;
          break;
        }
    }

  const struct bfd_link_info *link_info = coff_data (abfd)->link_info;
  const bool is_final_link = link_info && !bfd_link_relocatable (link_info) && !bfd_link_pic (link_info);

  if (is_final_link && is_text_section)
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
          bytes_written = 0;
        }

      if (scnhdr_int->s_nreloc < 0xffff)
        H_PUT_16 (abfd, scnhdr_int->s_nreloc, scnhdr_ext->s_nreloc);
      else
        {
          H_PUT_16 (abfd, 0xffff, scnhdr_ext->s_nreloc);
          flags |= IMAGE_SCN_LNK_NRELOC_OVFL;
        }
    }

  H_PUT_32 (abfd, flags, scnhdr_ext->s_flags);

  return bytes_written;
}

void
_bfd_XXi_swap_debugdir_in (bfd *abfd, const void *ext1, void *in1)
{
  if (abfd == NULL || ext1 == NULL || in1 == NULL)
    {
      return;
    }

  const struct external_IMAGE_DEBUG_DIRECTORY *ext =
    (const struct external_IMAGE_DEBUG_DIRECTORY *) ext1;
  struct internal_IMAGE_DEBUG_DIRECTORY *in =
    (struct internal_IMAGE_DEBUG_DIRECTORY *) in1;

  in->Characteristics = H_GET_32 (abfd, ext->Characteristics);
  in->TimeDateStamp = H_GET_32 (abfd, ext->TimeDateStamp);
  in->MajorVersion = H_GET_16 (abfd, ext->MajorVersion);
  in->MinorVersion = H_GET_16 (abfd, ext->MinorVersion);
  in->Type = H_GET_32 (abfd, ext->Type);
  in->SizeOfData = H_GET_32 (abfd, ext->SizeOfData);
  in->AddressOfRawData = H_GET_32 (abfd, ext->AddressOfRawData);
  in->PointerToRawData = H_GET_32 (abfd, ext->PointerToRawData);
}

unsigned int
_bfd_XXi_swap_debugdir_out (bfd *abfd, const void *inp, void *extp)
{
  if (abfd == NULL || inp == NULL || extp == NULL)
    {
      return 0;
    }

  struct external_IMAGE_DEBUG_DIRECTORY *ext =
    (struct external_IMAGE_DEBUG_DIRECTORY *) extp;
  const struct internal_IMAGE_DEBUG_DIRECTORY *in =
    (const struct internal_IMAGE_DEBUG_DIRECTORY *) inp;

  H_PUT_32 (abfd, in->Characteristics, ext->Characteristics);
  H_PUT_32 (abfd, in->TimeDateStamp, ext->TimeDateStamp);
  H_PUT_16 (abfd, in->MajorVersion, ext->MajorVersion);
  H_PUT_16 (abfd, in->MinorVersion, ext->MinorVersion);
  H_PUT_32 (abfd, in->Type, ext->Type);
  H_PUT_32 (abfd, in->SizeOfData, ext->SizeOfData);
  H_PUT_32 (abfd, in->AddressOfRawData, ext->AddressOfRawData);
  H_PUT_32 (abfd, in->PointerToRawData, ext->PointerToRawData);

  return sizeof (struct external_IMAGE_DEBUG_DIRECTORY);
}

CODEVIEW_INFO *
_bfd_XXi_slurp_codeview_record (bfd *abfd, file_ptr where, unsigned long length, CODEVIEW_INFO *cvinfo,
                                char **pdb)
{
  char buffer[256 + 1];
  bfd_size_type nread;
  const char *pdb_filename_src = NULL;

  if (bfd_seek (abfd, where, SEEK_SET) != 0)
    {
      return NULL;
    }

  unsigned long capped_length = (length > 256) ? 256 : length;
  nread = bfd_read (buffer, capped_length, abfd);
  if (nread != capped_length)
    {
      return NULL;
    }

  buffer[nread] = '\0';

  cvinfo->CVSignature = H_GET_32 (abfd, buffer);
  cvinfo->Age = 0;

  if (cvinfo->CVSignature == CVINFO_PDB70_CVSIGNATURE
      && nread >= sizeof (CV_INFO_PDB70))
    {
      const CV_INFO_PDB70 *cvinfo70 = (const CV_INFO_PDB70 *) buffer;
      cvinfo->Age = H_GET_32 (abfd, cvinfo70->Age);

      bfd_putb32 (bfd_getl32 (cvinfo70->Signature), cvinfo->Signature);
      bfd_putb16 (bfd_getl16 (&(cvinfo70->Signature[4])), &(cvinfo->Signature[4]));
      bfd_putb16 (bfd_getl16 (&(cvinfo70->Signature[6])), &(cvinfo->Signature[6]));
      memcpy (&(cvinfo->Signature[8]), &(cvinfo70->Signature[8]), 8);

      cvinfo->SignatureLength = CV_INFO_SIGNATURE_LENGTH;
      pdb_filename_src = cvinfo70->PdbFileName;
    }
  else if (cvinfo->CVSignature == CVINFO_PDB20_CVSIGNATURE
           && nread >= sizeof (CV_INFO_PDB20))
    {
      const CV_INFO_PDB20 *cvinfo20 = (const CV_INFO_PDB20 *) buffer;
      cvinfo->Age = H_GET_32 (abfd, cvinfo20->Age);
      memcpy (cvinfo->Signature, cvinfo20->Signature, 4);
      cvinfo->SignatureLength = 4;
      pdb_filename_src = cvinfo20->PdbFileName;
    }
  else
    {
      return NULL;
    }

  if (pdb && pdb_filename_src)
    {
      *pdb = xstrdup (pdb_filename_src);
    }

  return cvinfo;
}

unsigned int
_bfd_XXi_write_codeview_record (bfd * abfd, file_ptr where, CODEVIEW_INFO *cvinfo,
				const char *pdb)
{
  if (cvinfo == NULL)
    return 0;

  const size_t pdb_len = pdb ? strlen (pdb) : 0;
  const bfd_size_type base_size = sizeof (CV_INFO_PDB70);
  bfd_size_type size;
  unsigned int result = 0;
  char *buffer = NULL;

  const bfd_size_type max_pdb_len = (bfd_size_type)-1 - base_size - 1;
  if (pdb_len > max_pdb_len)
    goto cleanup;

  size = base_size + (bfd_size_type)pdb_len + 1;

  if (bfd_seek (abfd, where, SEEK_SET) != 0)
    goto cleanup;

  buffer = bfd_malloc (size);
  if (buffer == NULL)
    goto cleanup;

  CV_INFO_PDB70 *cvinfo70 = (CV_INFO_PDB70 *) buffer;
  H_PUT_32 (abfd, CVINFO_PDB70_CVSIGNATURE, cvinfo70->CvSignature);

  const unsigned char *src_sig = cvinfo->Signature;
  unsigned char *dest_sig = cvinfo70->Signature;
  enum
  {
    DATA2_OFFSET = 4,
    DATA3_OFFSET = 6,
    DATA4_OFFSET = 8,
    DATA4_SIZE = 8
  };
  bfd_putl32 (bfd_getb32 (src_sig), dest_sig);
  bfd_putl16 (bfd_getb16 (src_sig + DATA2_OFFSET), dest_sig + DATA2_OFFSET);
  bfd_putl16 (bfd_getb16 (src_sig + DATA3_OFFSET), dest_sig + DATA3_OFFSET);
  memcpy (dest_sig + DATA4_OFFSET, src_sig + DATA4_OFFSET, DATA4_SIZE);

  H_PUT_32 (abfd, cvinfo->Age, cvinfo70->Age);

  if (pdb != NULL)
    memcpy (cvinfo70->PdbFileName, pdb, pdb_len + 1);
  else
    cvinfo70->PdbFileName[0] = '\0';

  if (bfd_write (buffer, size, abfd) == size)
    result = size;

cleanup:
  free (buffer);
  return result;
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

  if (dataoff > section->size || datasize > section->size - dataoff)
    return false;

  ufile_ptr filesize = bfd_get_file_size (abfd);
  if (filesize == 0)
    return true;

  if ((ufile_ptr) section->filepos > filesize)
    return false;

  ufile_ptr remaining_space = filesize - section->filepos;
  if (dataoff > remaining_space || datasize > remaining_space - dataoff)
    return false;

  return true;
}

static asection *
find_section_by_vma (bfd *abfd, bfd_vma vma)
{
  asection *sec;

  for (sec = abfd->sections; sec != NULL; sec = sec->next)
    {
      if (sec->size > 0
          && vma >= sec->vma
          && vma < sec->vma + sec->size)
        return sec;
    }
  return NULL;
}

static void
print_import_thunks (FILE *file, bfd *abfd, asection *section, bfd_byte *data,
                     bfd_size_type datasize, bfd_signed_vma adj,
                     bfd_vma hint_addr, bfd_vma first_thunk, bfd_vma time_stamp)
{
  pe_data_type *pe = pe_data (abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
  bfd_size_type hint_offset = hint_addr - adj;

  if (hint_offset >= datasize)
    return;

  bfd_byte *iat_data = NULL;
  bfd_size_type iat_datasize = 0;
  bool iat_allocated = false;

  if (time_stamp != 0 && first_thunk != 0 && first_thunk != hint_addr)
    {
      bfd_vma iat_vma = first_thunk + extra->ImageBase;
      asection *iat_section = find_section_by_vma (abfd, iat_vma);

      if (iat_section == NULL)
        {
          fprintf (file, _("\nCould not find section for bound import address table\n"));
        }
      else if (iat_section == section)
        {
          bfd_size_type iat_offset = first_thunk - adj;
          if (iat_offset < datasize)
            {
              iat_data = data + iat_offset;
              iat_datasize = datasize - iat_offset;
            }
        }
      else
        {
          bfd_signed_vma iat_adj = iat_section->vma - extra->ImageBase;
          bfd_size_type iat_offset = first_thunk - iat_adj;

          if (iat_offset < iat_section->size)
            {
              iat_datasize = iat_section->size - iat_offset;
              iat_data = (bfd_byte *) bfd_malloc (iat_datasize);
              if (iat_data != NULL)
                {
                  iat_allocated = true;
                  if (!bfd_get_section_contents (abfd, iat_section, iat_data,
                                                 iat_offset, iat_datasize))
                    {
                      free (iat_data);
                      iat_data = NULL;
                    }
                }
            }
        }
    }

  fprintf (file, _("\tvma:     Ordinal  Hint  Member-Name  Bound-To\n"));

  bool is_64bit = pe->is_pe64;
  unsigned int thunk_size = is_64bit ? 8 : 4;

  for (bfd_size_type j = 0; hint_offset + j + thunk_size <= datasize; j += thunk_size)
    {
      bfd_vma thunk;
      bool is_ordinal;

      if (is_64bit)
        {
          thunk = bfd_get_64 (abfd, data + hint_offset + j);
          is_ordinal = (thunk & 0x8000000000000000ULL) != 0;
        }
      else
        {
          thunk = bfd_get_32 (abfd, data + hint_offset + j);
          is_ordinal = (thunk & 0x80000000) != 0;
        }

      if (thunk == 0)
        break;

      fprintf (file, "\t%08lx  ", (unsigned long) (first_thunk + j));

      if (is_ordinal)
        {
          fprintf (file, "%5u  <none> <none>", (unsigned int) (thunk & 0xFFFF));
        }
      else
        {
          bfd_size_type name_offset = thunk - adj;
          if (name_offset >= datasize || name_offset + 2 >= datasize)
            {
              fprintf (file, _("<corrupt: 0x%08lx>"), (unsigned long) thunk);
            }
          else
            {
              unsigned int hint = bfd_get_16 (abfd, data + name_offset);
              char *member_name = (char *) data + name_offset + 2;
              bfd_size_type max_len = datasize - (name_offset + 2);
              fprintf (file, "<none>  %04x  %.*s", hint, (int) max_len, member_name);
            }
        }

      if (iat_data != NULL && j + thunk_size <= iat_datasize)
        {
          bfd_vma bound_addr = is_64bit
            ? bfd_get_64 (abfd, iat_data + j)
            : bfd_get_32 (abfd, iat_data + j);
          fprintf (file, "\t%08lx", (unsigned long) bound_addr);
        }

      fprintf (file, "\n");
    }

  if (iat_allocated)
    free (iat_data);
}

static bool
pe_print_idata (bfd *abfd, void *vfile)
{
  FILE *file = (FILE *) vfile;
  pe_data_type *pe = pe_data (abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;

  bfd_vma addr = extra->DataDirectory[PE_IMPORT_TABLE].VirtualAddress;
  bfd_size_type size = extra->DataDirectory[PE_IMPORT_TABLE].Size;
  asection *section = NULL;

  if (addr == 0 && size == 0)
    {
      section = bfd_get_section_by_name (abfd, ".idata");
      if (section == NULL || (section->flags & SEC_HAS_CONTENTS) == 0 || section->size == 0)
        return true;
      addr = section->vma;
    }
  else
    {
      addr += extra->ImageBase;
      section = find_section_by_vma (abfd, addr);
      if (section == NULL)
        {
          fprintf (file, _("\nThere is an import table, but the section containing it could not be found\n"));
          return true;
        }
      if (!(section->flags & SEC_HAS_CONTENTS))
        {
          fprintf (file, _("\nThere is an import table in %s, but that section has no contents\n"), section->name);
          return true;
        }
    }

  fprintf (file, _("\nThere is an import table in %s at 0x%lx\n"),
           section->name, (unsigned long) addr);

  fprintf (file, _("\nThe Import Tables (interpreted %s section contents)\n"), section->name);
  fprintf (file, _(" vma:            Hint    Time      Forward  DLL       First\n"
                   "                 Table   Stamp     Chain    Name      Thunk\n"));

  bfd_byte *data = NULL;
  if (!bfd_malloc_and_get_section (abfd, section, &data))
    return false;

  bfd_signed_vma adj = section->vma - extra->ImageBase;
  bfd_size_type dataoff = addr - section->vma;
  bfd_size_type datasize = section->size;

  #define IID_HINT_TABLE_RVA    0
  #define IID_TIME_STAMP        4
  #define IID_FORWARD_CHAIN     8
  #define IID_DLL_NAME_RVA      12
  #define IID_FIRST_THUNK_RVA   16
  #define IID_SIZE              20

  for (bfd_size_type i = dataoff; i + IID_SIZE <= datasize; i += IID_SIZE)
    {
      bfd_vma hint_addr = bfd_get_32 (abfd, data + i + IID_HINT_TABLE_RVA);
      bfd_vma time_stamp = bfd_get_32 (abfd, data + i + IID_TIME_STAMP);
      bfd_vma forward_chain = bfd_get_32 (abfd, data + i + IID_FORWARD_CHAIN);
      bfd_vma dll_name_rva = bfd_get_32 (abfd, data + i + IID_DLL_NAME_RVA);
      bfd_vma first_thunk = bfd_get_32 (abfd, data + i + IID_FIRST_THUNK_RVA);

      if (hint_addr == 0 && first_thunk == 0)
        break;

      fprintf (file, " %08lx\t", (unsigned long) (i + adj));
      fprintf (file, "%08lx %08lx %08lx %08lx %08lx\n",
               (unsigned long) hint_addr,
               (unsigned long) time_stamp,
               (unsigned long) forward_chain,
               (unsigned long) dll_name_rva,
               (unsigned long) first_thunk);

      bfd_size_type name_offset = dll_name_rva - adj;
      if (name_offset >= datasize)
        {
          fprintf (file, _("\n\tDLL Name: <corrupt>\n"));
          break;
        }

      char *dll = (char *) data + name_offset;
      bfd_size_type maxlen = datasize - name_offset;
      fprintf (file, _("\n\tDLL Name: %.*s\n"), (int) maxlen, dll);

      if (hint_addr == 0)
        hint_addr = first_thunk;

      if (hint_addr != 0)
        {
          print_import_thunks (file, abfd, section, data, datasize, adj,
                               hint_addr, first_thunk, time_stamp);
        }

      fprintf (file, "\n");
    }

  free (data);
  return true;
}

#include <stdio.h>
#include "bfd.h"
#include "libbfd.h"

#define IMAGE_EXPORT_DIRECTORY_SIZE 40

struct EDT_type
{
  long export_flags;
  long time_stamp;
  short major_ver;
  short minor_ver;
  bfd_vma name_rva;
  long base;
  unsigned long num_functions;
  unsigned long num_names;
  bfd_vma eat_rva;
  bfd_vma npt_rva;
  bfd_vma ot_rva;
};

static void
parse_edt (bfd *abfd, const bfd_byte *data, struct EDT_type *edt)
{
  edt->export_flags   = bfd_get_32 (abfd, data + 0);
  edt->time_stamp     = bfd_get_32 (abfd, data + 4);
  edt->major_ver      = bfd_get_16 (abfd, data + 8);
  edt->minor_ver      = bfd_get_16 (abfd, data + 10);
  edt->name_rva       = bfd_get_32 (abfd, data + 12);
  edt->base           = bfd_get_32 (abfd, data + 16);
  edt->num_functions  = bfd_get_32 (abfd, data + 20);
  edt->num_names      = bfd_get_32 (abfd, data + 24);
  edt->eat_rva        = bfd_get_32 (abfd, data + 28);
  edt->npt_rva        = bfd_get_32 (abfd, data + 32);
  edt->ot_rva         = bfd_get_32 (abfd, data + 36);
}

static bool
is_rva_in_data (bfd_vma rva, bfd_vma data_rva_base, bfd_size_type data_size)
{
  return (rva >= data_rva_base) && (rva - data_rva_base < data_size);
}

static bool
is_sane_table (bfd_vma table_rva, unsigned long num_entries,
               unsigned int entry_size, bfd_vma data_rva_base,
               bfd_size_type data_size)
{
  if (table_rva < data_rva_base)
    return false;

  bfd_size_type table_offset = table_rva - data_rva_base;
  if (entry_size > 0 && num_entries > (BFD_SIZE_TYPE_MAX / entry_size))
    return false;

  bfd_size_type table_size = num_entries * entry_size;
  return !(table_offset > data_size || table_size > data_size - table_offset);
}

static bool
find_export_section_info (bfd *abfd,
                          struct internal_extra_pe_aouthdr *extra,
                          asection **section_p, bfd_size_type *dataoff_p,
                          bfd_size_type *datasize_p, bfd_vma *vma_p)
{
  bfd_vma rva = extra->DataDirectory[PE_EXPORT_TABLE].VirtualAddress;
  bfd_size_type size = extra->DataDirectory[PE_EXPORT_TABLE].Size;

  if (rva == 0 && size == 0)
    {
      asection *sec = bfd_get_section_by_name (abfd, ".edata");
      if (sec == NULL || sec->size == 0)
        return false;
      *section_p = sec;
      *dataoff_p = 0;
      *datasize_p = sec->size;
      *vma_p = sec->vma;
      return true;
    }

  bfd_vma addr = rva + extra->ImageBase;
  for (asection *sec = abfd->sections; sec != NULL; sec = sec->next)
    {
      if (addr >= sec->vma && addr < sec->vma + sec->size)
        {
          *section_p = sec;
          *dataoff_p = addr - sec->vma;
          *datasize_p = size;
          *vma_p = addr;
          return true;
        }
    }
  return false;
}

static void
print_edt_header (FILE *file, bfd *abfd, const asection *section,
                  const struct EDT_type *edt, const bfd_byte *data,
                  bfd_size_type datasize, bfd_vma data_rva_base)
{
  fprintf (file, _("\nThe Export Tables (interpreted %s section contents)\n\n"), section->name);
  fprintf (file, _("Export Flags \t\t\t%lx\n"), (unsigned long) edt->export_flags);
  fprintf (file, _("Time/Date stamp \t\t%lx\n"), (unsigned long) edt->time_stamp);
  fprintf (file, _("Major/Minor \t\t\t%d/%d\n"), edt->major_ver, edt->minor_ver);
  fprintf (file, _("Name \t\t\t\t"));
  bfd_fprintf_vma (abfd, file, edt->name_rva);

  if (is_rva_in_data (edt->name_rva, data_rva_base, datasize))
    {
      bfd_size_type name_offset = edt->name_rva - data_rva_base;
      fprintf (file, " %.*s\n", (int) (datasize - name_offset), data + name_offset);
    }
  else
    {
      fprintf (file, " (outside .edata section)\n");
    }

  fprintf (file, _("Ordinal Base \t\t\t%ld\n"), edt->base);
  fprintf (file, _("Number in:\n"));
  fprintf (file, _("\tExport Address Table \t\t%08lx\n"), edt->num_functions);
  fprintf (file, _("\t[Name Pointer/Ordinal] Table\t%08lx\n"), edt->num_names);
  fprintf (file, _("Table Addresses\n"));
  fprintf (file, _("\tExport Address Table \t\t"));
  bfd_fprintf_vma (abfd, file, edt->eat_rva);
  fprintf (file, "\n");
  fprintf (file, _("\tName Pointer Table \t\t"));
  bfd_fprintf_vma (abfd, file, edt->npt_rva);
  fprintf (file, "\n");
  fprintf (file, _("\tOrdinal Table \t\t\t"));
  bfd_fprintf_vma (abfd, file, edt->ot_rva);
  fprintf (file, "\n");
}

static void
print_export_address_table (FILE *file, bfd *abfd, const struct EDT_type *edt,
                            const bfd_byte *data, bfd_size_type datasize,
                            bfd_vma data_rva_base)
{
  fprintf (file, _("\nExport Address Table -- Ordinal Base %ld\n"), edt->base);
  fprintf (file, "\t          Ordinal  Address  Type\n");

  if (!is_sane_table (edt->eat_rva, edt->num_functions, 4, data_rva_base, datasize))
    {
      fprintf (file, _("\tInvalid Export Address Table rva (0x%lx) or entry count (0x%lx)\n"),
               (long) edt->eat_rva, (long) edt->num_functions);
      return;
    }

  bfd_size_type eat_offset = edt->eat_rva - data_rva_base;
  for (bfd_size_type i = 0; i < edt->num_functions; ++i)
    {
      bfd_vma eat_member = bfd_get_32 (abfd, data + eat_offset + (i * 4));
      if (eat_member == 0)
        continue;

      if (is_rva_in_data (eat_member, data_rva_base, datasize))
        {
          bfd_size_type member_offset = eat_member - data_rva_base;
          fprintf (file, "\t[%4ld] +base[%4ld] %08lx %s -- %.*s\n",
                   (long) i, (long) (i + edt->base),
                   (unsigned long) eat_member, _("Forwarder RVA"),
                   (int)(datasize - member_offset), data + member_offset);
        }
      else
        {
          fprintf (file, "\t[%4ld] +base[%4ld] %08lx %s\n",
                   (long) i, (long) (i + edt->base),
                   (unsigned long) eat_member, _("Export RVA"));
        }
    }
}

static void
print_name_pointer_tables (FILE *file, bfd *abfd, const struct EDT_type *edt,
                           const bfd_byte *data, bfd_size_type datasize,
                           bfd_vma data_rva_base)
{
  fprintf (file, _("\n[Ordinal/Name Pointer] Table -- Ordinal Base %ld\n"), edt->base);
  fprintf (file, "\t          Ordinal   Hint Name\n");

  if (!is_sane_table (edt->npt_rva, edt->num_names, 4, data_rva_base, datasize))
    {
      fprintf (file, _("\tInvalid Name Pointer Table rva (0x%lx) or entry count (0x%lx)\n"),
               (long) edt->npt_rva, (long) edt->num_names);
      return;
    }

  if (!is_sane_table (edt->ot_rva, edt->num_names, 2, data_rva_base, datasize))
    {
      fprintf (file, _("\tInvalid Ordinal Table rva (0x%lx) or entry count (0x%lx)\n"),
               (long) edt->ot_rva, (long) edt->num_names);
      return;
    }

  bfd_size_type npt_offset = edt->npt_rva - data_rva_base;
  bfd_size_type ot_offset = edt->ot_rva - data_rva_base;

  for (bfd_size_type i = 0; i < edt->num_names; ++i)
    {
      bfd_vma ord = bfd_get_16 (abfd, data + ot_offset + (i * 2));
      bfd_vma name_ptr_rva = bfd_get_32 (abfd, data + npt_offset + (i * 4));

      if (!is_rva_in_data (name_ptr_rva, data_rva_base, datasize))
        {
          fprintf (file, _("\t[%4ld] +base[%4ld]  %04lx <corrupt offset: %lx>\n"),
                   (long) ord, (long) (ord + edt->base), (long) i,
                   (long) name_ptr_rva);
        }
      else
        {
          bfd_size_type name_offset = name_ptr_rva - data_rva_base;
          const char *name = (const char *) data + name_offset;
          fprintf (file, "\t[%4ld] +base[%4ld]  %04lx %.*s\n",
                   (long) ord, (long) (ord + edt->base), (long) i,
                   (int)((const char *)(data + datasize) - name), name);
        }
    }
}

static bool
pe_print_edata (bfd *abfd, void *vfile)
{
  FILE *file = (FILE *) vfile;
  pe_data_type *pe = pe_data (abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;

  asection *section;
  bfd_size_type datasize;
  bfd_size_type dataoff;
  bfd_vma vma;

  if (!find_export_section_info (abfd, extra, &section, &dataoff, &datasize, &vma))
    {
      if (extra->DataDirectory[PE_EXPORT_TABLE].VirtualAddress != 0)
        {
          fprintf (file,
                   _("\nThere is an export table, but the section containing it could not be found\n"));
        }
      return true;
    }

  if (datasize < IMAGE_EXPORT_DIRECTORY_SIZE)
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
           section->name, (unsigned long) vma);

  bfd_byte *data = (bfd_byte *) bfd_malloc (datasize);
  if (data == NULL)
    return false;

  if (!bfd_get_section_contents (abfd, section, data, (file_ptr) dataoff, datasize))
    {
      free (data);
      return false;
    }

  struct EDT_type edt;
  parse_edt (abfd, data, &edt);

  bfd_vma data_rva_base = vma - extra->ImageBase;

  print_edt_header (file, abfd, section, &edt, data, datasize, data_rva_base);
  print_export_address_table (file, abfd, &edt, data, datasize, data_rva_base);
  print_name_pointer_tables (file, abfd, &edt, data, datasize, data_rva_base);

  free (data);
  return true;
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
# define IS_LEGACY_32BIT_PE 1
# define PDATA_ROW_SIZE (3 * 8)
#else
# define IS_LEGACY_32BIT_PE 0
# define PDATA_ROW_SIZE (5 * 4)
#endif
  FILE *file = (FILE *) vfile;
  asection *section = bfd_get_section_by_name (abfd, ".pdata");
  bfd_byte *data = NULL;
  bfd_size_type virt_size;
  const int row_size = PDATA_ROW_SIZE;
  const bfd_size_type entry_read_size = 20;

  if (section == NULL
      || (section->flags & SEC_HAS_CONTENTS) == 0
      || pei_section_data (abfd, section) == NULL)
    return true;

  virt_size = pei_section_data (abfd, section)->virt_size;
  if ((virt_size % row_size) != 0)
    fprintf (file,
	     _("warning, .pdata section size (%ld) is not a multiple of %d\n"),
	     (long) virt_size, row_size);

  fprintf (file,
	   _("\nThe Function Table (interpreted .pdata section contents)\n"));
#if IS_LEGACY_32BIT_PE
  fprintf (file,
	   _(" vma:\t\t\tBegin Address    End Address      Unwind Info\n"));
#else
  fprintf (file, _("\
 vma:\t\tBegin    End      EH       EH       PrologEnd  Exception\n\
     \t\tAddress  Address  Handler  Data     Address    Mask\n"));
#endif

  if (section->size == 0)
    return true;

  if (section->size < virt_size)
    {
      fprintf (file, _("Virtual size of .pdata section (%ld) larger than real size (%ld)\n"),
	       (long) virt_size, (long) section->size);
      return false;
    }

  if (!bfd_malloc_and_get_section (abfd, section, &data))
    return false;

  for (bfd_size_type i = 0; i + entry_read_size <= virt_size; i += row_size)
    {
      bfd_vma begin_addr = GET_PDATA_ENTRY (abfd, data + i + 0);
      bfd_vma end_addr = GET_PDATA_ENTRY (abfd, data + i + 4);
      bfd_vma eh_handler_raw = GET_PDATA_ENTRY (abfd, data + i + 8);
      bfd_vma eh_data = GET_PDATA_ENTRY (abfd, data + i + 12);
      bfd_vma prolog_end_addr_raw = GET_PDATA_ENTRY (abfd, data + i + 16);

      if (begin_addr == 0 && end_addr == 0 && eh_handler_raw == 0
	  && eh_data == 0 && prolog_end_addr_raw == 0)
	{
	  break;
	}

#if !IS_LEGACY_32BIT_PE
      int em_data = ((eh_handler_raw & 0x1) << 2) | (prolog_end_addr_raw & 0x3);
#endif
      bfd_vma eh_handler_clean = eh_handler_raw & ~(bfd_vma) 0x3;
      bfd_vma prolog_end_addr_clean = prolog_end_addr_raw & ~(bfd_vma) 0x3;

      fputc (' ', file);
      bfd_fprintf_vma (abfd, file, i + section->vma);
      fputc ('\t', file);
      bfd_fprintf_vma (abfd, file, begin_addr);
      fputc (' ', file);
      bfd_fprintf_vma (abfd, file, end_addr);
      fputc (' ', file);
      bfd_fprintf_vma (abfd, file, eh_handler_clean);

#if !IS_LEGACY_32BIT_PE
      fputc (' ', file);
      bfd_fprintf_vma (abfd, file, eh_data);
      fputc (' ', file);
      bfd_fprintf_vma (abfd, file, prolog_end_addr_clean);
      fprintf (file, "   %x", em_data);
#endif
      fprintf (file, "\n");
    }

  free (data);

  return true;
#undef IS_LEGACY_32BIT_PE
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
    if (!(bfd_get_file_flags (abfd) & HAS_SYMS)) {
        psc->symcount = 0;
        return NULL;
    }

    long storage = bfd_get_symtab_upper_bound (abfd);
    if (storage < 0) {
        return NULL;
    }

    asymbol **sy = NULL;
    if (storage > 0) {
        sy = bfd_malloc (storage);
        if (sy == NULL) {
            return NULL;
        }
    }

    psc->symcount = bfd_canonicalize_symtab (abfd, sy);
    if (psc->symcount < 0) {
        bfd_free (sy);
        return NULL;
    }

    return sy;
}

static const char *
my_symbol_for_address(bfd *abfd, bfd_vma func, sym_cache *psc)
{
    if (psc->syms == NULL)
    {
        psc->syms = slurp_symtab(abfd, psc);
        if (psc->syms == NULL)
        {
            return NULL;
        }
    }

    for (int i = 0; i < psc->symcount; i++)
    {
        asymbol *symbol = psc->syms[i];
        if (symbol && symbol->section && (symbol->section->vma + symbol->value == func))
        {
            return symbol->name;
        }
    }

    return NULL;
}

static void
cleanup_syms (sym_cache *psc)
{
  if (psc)
    {
      free (psc->syms);
      psc->syms = NULL;
      psc->symcount = 0;
    }
}

/* This is the version for "compressed" pdata.  */

static void
print_compressed_eh_info (bfd *abfd, FILE *file, bfd_vma begin_addr, struct sym_cache *cache)
{
  static const unsigned int EH_INFO_SIZE = 8;
  static const unsigned int EH_INFO_OFFSET_FROM_BEGIN = 8;

  asection *tsection = bfd_get_section_by_name (abfd, ".text");
  if (!tsection
      || !coff_section_data (abfd, tsection)
      || !pei_section_data (abfd, tsection))
    return;

  bfd_vma eh_off = (begin_addr - EH_INFO_OFFSET_FROM_BEGIN) - tsection->vma;
  bfd_byte tdata[EH_INFO_SIZE];

  if (!bfd_get_section_contents (abfd, tsection, tdata, eh_off, EH_INFO_SIZE))
    return;

  bfd_vma eh = bfd_get_32 (abfd, tdata);
  bfd_vma eh_data = bfd_get_32 (abfd, tdata + 4);

  fprintf (file, "%08x  %08x", (unsigned int) eh, (unsigned int) eh_data);

  if (eh != 0)
    {
      const char *s = my_symbol_for_address (abfd, eh, cache);
      if (s)
	fprintf (file, " (%s)", s);
    }
}

static bool
print_pdata_entry (bfd *abfd, FILE *file, const bfd_byte *entry_data, bfd_vma entry_vma, struct sym_cache *cache)
{
  static const bfd_vma PROLOG_LENGTH_MASK    = 0x000000FFUL;
  static const bfd_vma FUNCTION_LENGTH_MASK  = 0x3FFFFF00UL;
  static const int     FUNCTION_LENGTH_SHIFT = 8;
  static const bfd_vma FLAG32BIT_MASK        = 0x40000000UL;
  static const int     FLAG32BIT_SHIFT       = 30;
  static const bfd_vma EXCEPTION_FLAG_MASK   = 0x80000000UL;
  static const int     EXCEPTION_FLAG_SHIFT  = 31;

  bfd_vma begin_addr = GET_PDATA_ENTRY (abfd, entry_data);
  bfd_vma other_data = GET_PDATA_ENTRY (abfd, entry_data + 4);

  if (begin_addr == 0 && other_data == 0)
    return false;

  bfd_vma prolog_length = other_data & PROLOG_LENGTH_MASK;
  bfd_vma function_length = (other_data & FUNCTION_LENGTH_MASK) >> FUNCTION_LENGTH_SHIFT;
  int flag32bit = (int)((other_data & FLAG32BIT_MASK) >> FLAG32BIT_SHIFT);
  int exception_flag = (int)((other_data & EXCEPTION_FLAG_MASK) >> EXCEPTION_FLAG_SHIFT);

  fputc (' ', file);
  bfd_fprintf_vma (abfd, file, entry_vma);
  fputc ('\t', file);
  bfd_fprintf_vma (abfd, file, begin_addr);
  fputc (' ', file);
  bfd_fprintf_vma (abfd, file, prolog_length);
  fputc (' ', file);
  bfd_fprintf_vma (abfd, file, function_length);
  fputc (' ', file);
  fprintf (file, "%2d  %2d   ", flag32bit, exception_flag);

  print_compressed_eh_info (abfd, file, begin_addr, cache);

  fprintf (file, "\n");
  return true;
}

static void
print_pdata_header (FILE *file)
{
  fprintf (file,
	   _("\nThe Function Table (interpreted .pdata section contents)\n"));
  fprintf (file, _(" vma:\t\tBegin    Prolog   Function Flags    Exception EH\n"
		   "     \t\tAddress  Length   Length   32b exc  Handler   Data\n"));
}

bool
_bfd_XX_print_ce_compressed_pdata (bfd *abfd, void *vfile)
{
  static const int PDATA_ROW_SIZE = 8;
  FILE *file = (FILE *) vfile;
  asection *section = bfd_get_section_by_name (abfd, ".pdata");
  bfd_byte *data = NULL;
  struct sym_cache cache = {0, 0};

  if (section == NULL
      || (section->flags & SEC_HAS_CONTENTS) == 0
      || coff_section_data (abfd, section) == NULL
      || pei_section_data (abfd, section) == NULL)
    return true;

  bfd_size_type virt_size = pei_section_data (abfd, section)->virt_size;
  if ((virt_size % PDATA_ROW_SIZE) != 0)
    fprintf (file,
	     /* xgettext:c-format */
	     _("warning, .pdata section size (%ld) is not a multiple of %d\n"),
	     (long) virt_size, PDATA_ROW_SIZE);

  if (section->size == 0)
    return true;

  if (!bfd_malloc_and_get_section (abfd, section, &data))
    {
      free (data);
      return false;
    }

  print_pdata_header (file);

  bfd_size_type stop = (virt_size < section->size) ? virt_size : section->size;

  for (bfd_size_type i = 0; i + PDATA_ROW_SIZE <= stop; i += PDATA_ROW_SIZE)
    {
      if (!print_pdata_entry (abfd, file, data + i, section->vma + i, &cache))
	break;
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

  if (section == NULL || section->size == 0
      || (section->flags & SEC_HAS_CONTENTS) == 0)
    return true;

  fprintf (file,
	   _("\n\nPE File Base Relocations (interpreted .reloc section contents)\n"));

  if (!bfd_malloc_and_get_section (abfd, section, &data))
    return false;

  const bfd_byte *p = data;
  const bfd_byte *end = data + section->size;
  const unsigned int RELOC_BLOCK_HEADER_SIZE = 8;
  const unsigned int RELOC_ENTRY_SIZE = 2;

  while (p + RELOC_BLOCK_HEADER_SIZE <= end)
    {
      const bfd_byte * const block_start = p;
      bfd_vma virtual_address = bfd_get_32 (abfd, p);
      unsigned long size_of_block = bfd_get_32 (abfd, p + 4);

      if (size_of_block < RELOC_BLOCK_HEADER_SIZE)
	break;

      p += RELOC_BLOCK_HEADER_SIZE;

      unsigned long number_of_fixups =
	(size_of_block - RELOC_BLOCK_HEADER_SIZE) / RELOC_ENTRY_SIZE;

      fprintf (file,
	       _("\nVirtual Address: %08lx Chunk size %ld (0x%lx) Number of fixups %ld\n"),
	       (unsigned long) virtual_address, size_of_block, size_of_block,
	       number_of_fixups);

      const bfd_byte * const next_block = block_start + size_of_block;
      const bfd_byte * const block_end = (next_block > end) ? end : next_block;
      int fixup_count = 0;

      while (p + RELOC_ENTRY_SIZE <= block_end)
	{
	  const unsigned short entry = bfd_get_16 (abfd, p);
	  const unsigned int type = (entry & 0xF000) >> 12;
	  const int offset = entry & 0x0FFF;

	  unsigned int display_type = type;
	  if (display_type >= sizeof (tbl) / sizeof (tbl[0]))
	    display_type = (sizeof (tbl) / sizeof (tbl[0])) - 1;

	  fprintf (file,
		   _("\treloc %4d offset %4x [%4lx] %s"),
		   fixup_count, offset,
		   (unsigned long) (offset + virtual_address),
		   tbl[display_type]);

	  p += RELOC_ENTRY_SIZE;
	  fixup_count++;

	  if (type == IMAGE_REL_BASED_HIGHADJ && p + RELOC_ENTRY_SIZE <= block_end)
	    {
	      fprintf (file, " (%4x)",
		       (unsigned int) bfd_get_16 (abfd, p));
	      p += RELOC_ENTRY_SIZE;
	      fixup_count++;
	    }
	  fprintf (file, "\n");
	}
      p = next_block;
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
  if (data + 8 > regions->section_end)
    return regions->section_end + 1;

  /* xgettext:c-format */
  fprintf (file, _("%03x %*.s Entry: "), (int)(data - regions->section_start), indent, " ");

  unsigned long id_or_name_offset = bfd_get_32 (abfd, data);

  if (is_name)
    {
      bfd_byte *name_ptr;
      if (HighBitSet (id_or_name_offset))
	name_ptr = regions->section_start + WithoutHighBit (id_or_name_offset);
      else
	name_ptr = regions->section_start + id_or_name_offset - rva_bias;

      if (name_ptr <= regions->section_start || name_ptr + 2 > regions->section_end)
	{
	  fprintf (file, _("<corrupt string offset: %#lx>\n"), id_or_name_offset);
	  return regions->section_end + 1;
	}

      if (regions->strings_start == NULL)
	regions->strings_start = name_ptr;

      unsigned int len = bfd_get_16 (abfd, name_ptr);
      fprintf (file, _("name: [val: %08lx len %d]: "), id_or_name_offset, len);

      bfd_byte *string_data = name_ptr + 2;
      bfd_size_type string_size_bytes = (bfd_size_type) len * 2;
      if (string_data + string_size_bytes > regions->section_end)
        {
          fprintf (file, _("<corrupt string length: %#x>\n"), len);
          return regions->section_end + 1;
        }

      for (unsigned int i = 0; i < len; ++i)
        {
          char c = string_data[i * 2];
          if (c > 0 && c < ' ')
            fprintf (file, "^%c", c + '@');
          else if (c != '\0')
            fputc (c, file);
        }
    }
  else
    {
      fprintf (file, _("ID: %#08lx"), id_or_name_offset);
    }

  unsigned long value_offset = bfd_get_32 (abfd, data + 4);
  fprintf (file, _(", Value: %#08lx\n"), value_offset);

  if (HighBitSet (value_offset))
    {
      bfd_byte *subdir_data = regions->section_start + WithoutHighBit (value_offset);

      if (subdir_data <= regions->section_start || subdir_data >= regions->section_end)
	return regions->section_end + 1;

      return rsrc_print_resource_directory (file, abfd, indent + 1, subdir_data,
					    regions, rva_bias);
    }

  bfd_byte *leaf = regions->section_start + value_offset;

  if (leaf < regions->section_start || leaf + 16 > regions->section_end)
    return regions->section_end + 1;

  bfd_vma rva = bfd_get_32 (abfd, leaf);
  bfd_size_type size = bfd_get_32 (abfd, leaf + 4);
  unsigned long codepage = bfd_get_32 (abfd, leaf + 8);
  unsigned long reserved = bfd_get_32 (abfd, leaf + 12);

  /* xgettext:c-format */
  fprintf (file, _("%03x %*.s  Leaf: Addr: %#08lx, Size: %#08lx, Codepage: %lu\n"),
	   (int) value_offset, indent, " ", (unsigned long) rva,
	   (unsigned long) size, codepage);

  bfd_byte *resource_data = regions->section_start + (rva - rva_bias);
  if (reserved != 0
      || resource_data < regions->section_start
      || resource_data + size > regions->section_end)
    return regions->section_end + 1;

  if (regions->resource_start == NULL)
    regions->resource_start = resource_data;

  return resource_data + size;
}

#define max(a,b) ((a) > (b) ? (a) : (b))
#define min(a,b) ((a) < (b) ? (a) : (b))

static const char *
get_directory_type_string (unsigned int indent)
{
  switch (indent)
    {
    case 0:
      return "Type";
    case 2:
      return "Name";
    case 4:
      return "Language";
    default:
      return NULL;
    }
}

static bfd_byte *
rsrc_print_resource_directory (FILE * file,
			       bfd * abfd,
			       unsigned int indent,
			       bfd_byte * data,
			       rsrc_regions * regions,
			       bfd_vma rva_bias)
{
  const unsigned int RSRC_DIR_HEADER_SIZE = 16;
  const unsigned int RSRC_DIR_ENTRY_SIZE = 8;

  if (data + RSRC_DIR_HEADER_SIZE > regions->section_end)
    return regions->section_end + 1;

  fprintf (file, "%03x %*.s ", (int) (data - regions->section_start), indent,
	   " ");

  const char *dir_type = get_directory_type_string (indent);
  if (dir_type == NULL)
    {
      fprintf (file, _("<unknown directory type: %d>\n"), indent);
      return regions->section_end + 1;
    }
  fprintf (file, "%s", dir_type);

  unsigned int num_names = bfd_get_16 (abfd, data + 12);
  unsigned int num_ids = bfd_get_16 (abfd, data + 14);

  fprintf (file,
	   _(" Table: Char: %d, Time: %08lx, Ver: %d/%d, Num Names: %d, IDs: %d\n"),
	   (int) bfd_get_32 (abfd, data + 0),
	   (long) bfd_get_32 (abfd, data + 4),
	   (int) bfd_get_16 (abfd, data + 8),
	   (int) bfd_get_16 (abfd, data + 10), num_names, num_ids);

  data += RSRC_DIR_HEADER_SIZE;
  bfd_byte *highest_data = data;

  unsigned int total_entries = num_names + num_ids;
  size_t table_size = (size_t) total_entries * RSRC_DIR_ENTRY_SIZE;

  if (data + table_size > regions->section_end)
    return regions->section_end + 1;

  for (unsigned int i = 0; i < total_entries; ++i)
    {
      bool is_string = (i < num_names);
      bfd_byte *entry_end =
	rsrc_print_resource_entries (file, abfd, indent + 1, is_string, data,
				     regions, rva_bias);
      data += RSRC_DIR_ENTRY_SIZE;
      highest_data = max (highest_data, entry_end);
      if (entry_end >= regions->section_end)
	return entry_end;
    }

  return max (highest_data, data);
}

/* Display the contents of a .rsrc section.  We do not try to
   reproduce the resources, windres does that.  Instead we dump
   the tables in a human readable format.  */

static bool
rsrc_print_section (bfd * abfd, void * vfile)
{
  FILE *file = (FILE *) vfile;
  bfd_byte *section_data = NULL;

  pe_data_type *pe = pe_data (abfd);
  if (pe == NULL)
    return true;

  asection *section = bfd_get_section_by_name (abfd, ".rsrc");
  if (section == NULL || !(section->flags & SEC_HAS_CONTENTS)
      || section->size == 0)
    return true;

  if (!bfd_malloc_and_get_section (abfd, section, &section_data))
    return false;

  rsrc_regions regions;
  regions.section_start = section_data;
  regions.section_end = section_data + section->size;
  regions.strings_start = NULL;
  regions.resource_start = NULL;

  fflush (file);
  fprintf (file, "\nThe .rsrc Resource Directory section:\n");

  bfd_vma rva_bias = section->vma - pe->pe_opthdr.ImageBase;
  bfd_byte *current_pos = section_data;
  const bfd_byte *const corruption_indicator = regions.section_end + 1;

  while (current_pos < regions.section_end)
    {
      bfd_byte *p_before_print = current_pos;

      current_pos =
	rsrc_print_resource_directory (file, abfd, 0, current_pos, &regions,
				       rva_bias);

      if (current_pos == corruption_indicator)
	{
	  fprintf (file, _("Corrupt .rsrc section detected!\n"));
	  break;
	}

      int align_mask = (1 << section->alignment_power) - 1;
      bfd_byte *aligned_pos =
	(bfd_byte *) (((ptrdiff_t) (current_pos + align_mask)) & ~align_mask);

      rva_bias += aligned_pos - p_before_print;
      current_pos = aligned_pos;

      if (current_pos == (regions.section_end - 4))
	{
	  current_pos = regions.section_end;
	}
      else if (current_pos < regions.section_end)
	{
	  bfd_byte *scanner = current_pos;
	  while (scanner < regions.section_end)
	    {
	      if (*scanner != 0)
		{
		  fprintf (file,
			   _("\nWARNING: Extra data in .rsrc section - it will be ignored by Windows:\n"));
		  break;
		}
	      scanner++;
	    }
	  break;
	}
    }

  if (regions.strings_start != NULL)
    fprintf (file, _(" String table starts at offset: %#03x\n"),
	     (int) (regions.strings_start - regions.section_start));

  if (regions.resource_start != NULL)
    fprintf (file, _(" Resources start at offset: %#03x\n"),
	     (int) (regions.resource_start - regions.section_start));

  free (section_data);
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

static asection *
find_section_for_vma (bfd *abfd, bfd_vma vma)
{
  for (asection *sec = abfd->sections; sec != NULL; sec = sec->next)
    {
      if (vma >= sec->vma && vma < (sec->vma + sec->size))
	{
	  return sec;
	}
    }
  return NULL;
}

static void
print_codeview_info (bfd *abfd, FILE *file,
		     const struct internal_IMAGE_DEBUG_DIRECTORY *idd)
{
  char buffer[256 + 1] ATTRIBUTE_ALIGNED_ALIGNOF (CODEVIEW_INFO);
  CODEVIEW_INFO *cvinfo = (CODEVIEW_INFO *) buffer;
  char *pdb = NULL;

  if (!_bfd_XXi_slurp_codeview_record (abfd, (file_ptr) idd->PointerToRawData,
				       idd->SizeOfData, cvinfo, &pdb))
    {
      return;
    }

  char signature[CV_INFO_SIGNATURE_LENGTH * 2 + 1];
  char *sig_ptr = signature;
  size_t sig_rem = sizeof (signature);
  unsigned int sig_len_to_print = cvinfo->SignatureLength;

  if (sig_len_to_print > CV_INFO_SIGNATURE_LENGTH)
    {
      sig_len_to_print = CV_INFO_SIGNATURE_LENGTH;
    }

  for (unsigned int j = 0; j < sig_len_to_print; j++)
    {
      int written = snprintf (sig_ptr, sig_rem, "%02x",
			      cvinfo->Signature[j] & 0xff);
      if (written <= 0 || (size_t) written >= sig_rem)
	{
	  signature[0] = '\0';
	  break;
	}
      sig_ptr += written;
      sig_rem -= written;
    }

  fprintf (file, _("(format %c%c%c%c signature %s age %ld pdb %s)\n"),
	   buffer[0], buffer[1], buffer[2], buffer[3],
	   signature, cvinfo->Age, pdb[0] ? pdb : "(none)");

  free (pdb);
}

static void
print_debug_directory_entry (bfd *abfd, FILE *file,
			     const struct external_IMAGE_DEBUG_DIRECTORY *ext)
{
  struct internal_IMAGE_DEBUG_DIRECTORY idd;
  _bfd_XXi_swap_debugdir_in (abfd, ext, &idd);

  const char *type_name = (idd.Type < IMAGE_NUMBEROF_DEBUG_TYPES)
    ? debug_type_names[idd.Type]
    : debug_type_names[0];

  fprintf (file, " %2ld  %14s %08lx %08lx %08lx\n",
	   idd.Type, type_name, idd.SizeOfData,
	   idd.AddressOfRawData, idd.PointerToRawData);

  if (idd.Type == PE_IMAGE_DEBUG_TYPE_CODEVIEW)
    {
      print_codeview_info (abfd, file, &idd);
    }
}

static bool
pe_print_debugdata (bfd * abfd, void * vfile)
{
  FILE *file = (FILE *) vfile;
  pe_data_type *pe = pe_data (abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;

  bfd_vma addr = extra->DataDirectory[PE_DEBUG_DATA].VirtualAddress;
  bfd_size_type size = extra->DataDirectory[PE_DEBUG_DATA].Size;

  if (size == 0)
    {
      return true;
    }

  addr += extra->ImageBase;
  asection *section = find_section_for_vma (abfd, addr);

  if (section == NULL)
    {
      fprintf (file,
	       _("\nThere is a debug directory, but the section containing it could not be found\n"));
      return true;
    }

  if (!(section->flags & SEC_HAS_CONTENTS))
    {
      fprintf (file,
	       _("\nThere is a debug directory in %s, but that section has no contents\n"),
	       section->name);
      return true;
    }

  bfd_size_type dataoff = addr - section->vma;
  if (dataoff >= section->size || size > (section->size - dataoff))
    {
      fprintf (file,
	       _("\nError: The debug data directory is invalid or extends beyond the end of section '%s'.\n"),
	       section->name);
      return false;
    }

  fprintf (file, _("\nThere is a debug directory in %s at 0x%lx\n\n"),
	   section->name, (unsigned long) addr);
  fprintf (file,
	   _("Type                Size     Rva      Offset\n"));

  bfd_byte *data = NULL;
  if (!bfd_malloc_and_get_section (abfd, section, &data))
    {
      return false;
    }

  const unsigned int entry_size = sizeof (struct external_IMAGE_DEBUG_DIRECTORY);
  unsigned int num_entries = size / entry_size;
  struct external_IMAGE_DEBUG_DIRECTORY *entries =
    (struct external_IMAGE_DEBUG_DIRECTORY *) (data + dataoff);

  for (unsigned int i = 0; i < num_entries; i++)
    {
      print_debug_directory_entry (abfd, file, &entries[i]);
    }

  if (size % entry_size != 0)
    {
      fprintf (file,
	       _("The debug directory size is not a multiple of the debug directory entry size\n"));
    }

  free (data);
  return true;
}

static bool
pe_is_repro (bfd *abfd)
{
  pe_data_type *pe = pe_data (abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
  asection *section = NULL;
  bfd_byte *data = NULL;
  bool is_repro = false;

  bfd_vma addr = extra->DataDirectory[PE_DEBUG_DATA].VirtualAddress;
  bfd_size_type size = extra->DataDirectory[PE_DEBUG_DATA].Size;

  if (size < sizeof (struct external_IMAGE_DEBUG_DIRECTORY))
    return false;

  addr += extra->ImageBase;
  for (asection *sec_iter = abfd->sections; sec_iter != NULL; sec_iter = sec_iter->next)
    {
      if (addr >= sec_iter->vma && addr < (sec_iter->vma + sec_iter->size))
        {
          section = sec_iter;
          break;
        }
    }

  if (section == NULL || (section->flags & SEC_HAS_CONTENTS) == 0)
    return false;

  bfd_size_type dataoff = addr - section->vma;
  if (size > section->size - dataoff)
    return false;

  if (!bfd_malloc_and_get_section (abfd, section, &data))
    return false;

  const struct external_IMAGE_DEBUG_DIRECTORY *dirs =
    (const struct external_IMAGE_DEBUG_DIRECTORY *) (data + dataoff);
  const unsigned int num_dirs = size / sizeof (*dirs);

  for (unsigned int i = 0; i < num_dirs; i++)
    {
      struct internal_IMAGE_DEBUG_DIRECTORY idd;
      _bfd_XXi_swap_debugdir_in (abfd, &dirs[i], &idd);

      if (idd.Type == PE_IMAGE_DEBUG_TYPE_REPRO)
        {
          is_repro = true;
          break;
        }
    }

  free (data);
  return is_repro;
}

/* Print out the program headers.  */

typedef struct {
    unsigned int flag;
    const char *name;
} flag_map_t;

typedef struct {
    int value;
    const char *name;
} value_map_t;

#define CHECKED_FPRINTF(...) \
  do { if (fprintf (__VA_ARGS__) < 0) return false; } while (0)

#define CHECKED_BFD_FPRINTF_VMA(abfd, file, vma) \
  do { bfd_fprintf_vma (abfd, file, vma); if (ferror (file)) return false; } while (0)

static bool
print_mapped_flags (FILE *file, const char *indent, unsigned int flags,
                    const flag_map_t *map, size_t map_size)
{
  size_t i;
  for (i = 0; i < map_size; ++i)
    {
      if ((flags & map[i].flag) != 0)
        {
          if (fprintf (file, "%s%s\n", indent, map[i].name) < 0)
            return false;
        }
    }
  return true;
}

static const char *
get_mapped_name (int value, const value_map_t *map, size_t map_size)
{
  size_t i;
  for (i = 0; i < map_size; ++i)
    {
      if (map[i].value == value)
        return map[i].name;
    }
  return NULL;
}

static bool
print_pe_characteristics (FILE *file, unsigned int flags)
{
  static const flag_map_t characteristics_map[] = {
    {IMAGE_FILE_RELOCS_STRIPPED, "relocations stripped"},
    {IMAGE_FILE_EXECUTABLE_IMAGE, "executable"},
    {IMAGE_FILE_LINE_NUMS_STRIPPED, "line numbers stripped"},
    {IMAGE_FILE_LOCAL_SYMS_STRIPPED, "symbols stripped"},
    {IMAGE_FILE_LARGE_ADDRESS_AWARE, "large address aware"},
    {IMAGE_FILE_BYTES_REVERSED_LO, "little endian"},
    {IMAGE_FILE_32BIT_MACHINE, "32 bit words"},
    {IMAGE_FILE_DEBUG_STRIPPED, "debugging information removed"},
    {IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "copy to swap file if on removable media"},
    {IMAGE_FILE_NET_RUN_FROM_SWAP, "copy to swap file if on network media"},
    {IMAGE_FILE_SYSTEM, "system file"},
    {IMAGE_FILE_DLL, "DLL"},
    {IMAGE_FILE_UP_SYSTEM_ONLY, "run only on uniprocessor machine"},
    {IMAGE_FILE_BYTES_REVERSED_HI, "big endian"},
  };

  CHECKED_FPRINTF (file, _("\nCharacteristics 0x%x\n"), flags);
  return print_mapped_flags (file, "\t", flags, characteristics_map,
                           sizeof (characteristics_map) / sizeof (characteristics_map[0]));
}

static bool
print_pe_timestamp (FILE *file, const bfd *abfd, const pe_data_type *pe)
{
  if (pe_is_repro (abfd))
    {
      CHECKED_FPRINTF (file, "\nTime/Date\t\t%08lx\t(This is a reproducible build file hash, not a timestamp)\n",
                       pe->coff.timestamp);
    }
  else
    {
      time_t t = pe->coff.timestamp;
      struct tm tm_result;
      char time_buf[64];

      if (localtime_r (&t, &tm_result) != NULL
          && strftime (time_buf, sizeof (time_buf), "%a %b %d %H:%M:%S %Y", &tm_result) > 0)
        {
          CHECKED_FPRINTF (file, "\nTime/Date\t\t%s\n", time_buf);
        }
      else
        {
          CHECKED_FPRINTF (file, "\nTime/Date\t\t[invalid timestamp %lx]\n", (unsigned long) t);
        }
    }
  return true;
}

static bool
print_pe_optional_header_info (bfd *abfd, FILE *file, const struct internal_extra_pe_aouthdr *i)
{
#ifndef IMAGE_NT_OPTIONAL_HDR_MAGIC
# define IMAGE_NT_OPTIONAL_HDR_MAGIC 0x10b
#endif
#ifndef IMAGE_NT_OPTIONAL_HDR64_MAGIC
# define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#endif
#ifndef IMAGE_NT_OPTIONAL_HDRROM_MAGIC
# define IMAGE_NT_OPTIONAL_HDRROM_MAGIC 0x107
#endif
  static const value_map_t magic_map[] = {
    {IMAGE_NT_OPTIONAL_HDR_MAGIC, "PE32"},
    {IMAGE_NT_OPTIONAL_HDR64_MAGIC, "PE32+"},
    {IMAGE_NT_OPTIONAL_HDRROM_MAGIC, "ROM"},
  };
  const char *name = get_mapped_name (i->Magic, magic_map, sizeof (magic_map) / sizeof (magic_map[0]));

  CHECKED_FPRINTF (file, "Magic\t\t\t%04x", i->Magic);
  if (name)
    CHECKED_FPRINTF (file, "\t(%s)", name);

  CHECKED_FPRINTF (file, "\nMajorLinkerVersion\t%d\n", i->MajorLinkerVersion);
  CHECKED_FPRINTF (file, "MinorLinkerVersion\t%d\n", i->MinorLinkerVersion);
  CHECKED_FPRINTF (file, "SizeOfCode\t\t");
  CHECKED_BFD_FPRINTF_VMA (abfd, file, i->SizeOfCode);
  CHECKED_FPRINTF (file, "\nSizeOfInitializedData\t");
  CHECKED_BFD_FPRINTF_VMA (abfd, file, i->SizeOfInitializedData);
  CHECKED_FPRINTF (file, "\nSizeOfUninitializedData\t");
  CHECKED_BFD_FPRINTF_VMA (abfd, file, i->SizeOfUninitializedData);
  CHECKED_FPRINTF (file, "\nAddressOfEntryPoint\t");
  CHECKED_BFD_FPRINTF_VMA (abfd, file, i->AddressOfEntryPoint);
  CHECKED_FPRINTF (file, "\nBaseOfCode\t\t");
  CHECKED_BFD_FPRINTF_VMA (abfd, file, i->BaseOfCode);

#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
  CHECKED_FPRINTF (file, "\nBaseOfData\t\t");
  CHECKED_BFD_FPRINTF_VMA (abfd, file, i->BaseOfData);
#endif

  CHECKED_FPRINTF (file, "\nImageBase\t\t");
  CHECKED_BFD_FPRINTF_VMA (abfd, file, i->ImageBase);
  CHECKED_FPRINTF (file, "\nSectionAlignment\t%08x\n", i->SectionAlignment);
  CHECKED_FPRINTF (file, "FileAlignment\t\t%08x\n", i->FileAlignment);
  CHECKED_FPRINTF (file, "MajorOSystemVersion\t%d\n", i->MajorOperatingSystemVersion);
  CHECKED_FPRINTF (file, "MinorOSystemVersion\t%d\n", i->MinorOperatingSystemVersion);
  CHECKED_FPRINTF (file, "MajorImageVersion\t%d\n", i->MajorImageVersion);
  CHECKED_FPRINTF (file, "MinorImageVersion\t%d\n", i->MinorImageVersion);
  CHECKED_FPRINTF (file, "MajorSubsystemVersion\t%d\n", i->MajorSubsystemVersion);
  CHECKED_FPRINTF (file, "MinorSubsystemVersion\t%d\n", i->MinorSubsystemVersion);
  CHECKED_FPRINTF (file, "Win32Version\t\t%08x\n", i->Win32Version);
  CHECKED_FPRINTF (file, "SizeOfImage\t\t%08x\n", i->SizeOfImage);
  CHECKED_FPRINTF (file, "SizeOfHeaders\t\t%08x\n", i->SizeOfHeaders);
  CHECKED_FPRINTF (file, "CheckSum\t\t%08x\n", i->CheckSum);

  return true;
}

static bool
print_pe_subsystem_and_dll_chars (FILE *file, const struct internal_extra_pe_aouthdr *i)
{
  static const value_map_t subsystem_map[] = {
    {IMAGE_SUBSYSTEM_UNKNOWN, "unspecified"},
    {IMAGE_SUBSYSTEM_NATIVE, "NT native"},
    {IMAGE_SUBSYSTEM_WINDOWS_GUI, "Windows GUI"},
    {IMAGE_SUBSYSTEM_WINDOWS_CUI, "Windows CUI"},
    {IMAGE_SUBSYSTEM_POSIX_CUI, "POSIX CUI"},
    {IMAGE_SUBSYSTEM_WINDOWS_CE_GUI, "Wince CUI"},
    {IMAGE_SUBSYSTEM_EFI_APPLICATION, "EFI application"},
    {IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER, "EFI boot service driver"},
    {IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER, "EFI runtime driver"},
    {IMAGE_SUBSYSTEM_SAL_RUNTIME_DRIVER, "SAL runtime driver"},
    {IMAGE_SUBSYSTEM_XBOX, "XBOX"},
  };
  const char *subsystem_name = get_mapped_name (i->Subsystem, subsystem_map, sizeof (subsystem_map) / sizeof (subsystem_map[0]));

  CHECKED_FPRINTF (file, "Subsystem\t\t%08x", i->Subsystem);
  if (subsystem_name)
    CHECKED_FPRINTF (file, "\t(%s)", subsystem_name);

  CHECKED_FPRINTF (file, "\nDllCharacteristics\t%08x\n", i->DllCharacteristics);
  if (i->DllCharacteristics)
    {
      static const flag_map_t dll_characteristics_map[] = {
        {IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA, "HIGH_ENTROPY_VA"},
        {IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE, "DYNAMIC_BASE"},
        {IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY, "FORCE_INTEGRITY"},
        {IMAGE_DLL_CHARACTERISTICS_NX_COMPAT, "NX_COMPAT"},
        {IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, "NO_ISOLATION"},
        {IMAGE_DLLCHARACTERISTICS_NO_SEH, "NO_SEH"},
        {IMAGE_DLLCHARACTERISTICS_NO_BIND, "NO_BIND"},
        {IMAGE_DLLCHARACTERISTICS_APPCONTAINER, "APPCONTAINER"},
        {IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, "WDM_DRIVER"},
        {IMAGE_DLLCHARACTERISTICS_GUARD_CF, "GUARD_CF"},
        {IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, "TERMINAL_SERVICE_AWARE"},
      };
      if (!print_mapped_flags (file, "\t\t\t\t\t", i->DllCharacteristics,
                               dll_characteristics_map,
                               sizeof (dll_characteristics_map) / sizeof (dll_characteristics_map[0])))
        return false;
    }
  return true;
}

static bool
print_pe_sizes_and_loader_flags (bfd *abfd, FILE *file, const struct internal_extra_pe_aouthdr *i)
{
  CHECKED_FPRINTF (file, "SizeOfStackReserve\t");
  CHECKED_BFD_FPRINTF_VMA (abfd, file, i->SizeOfStackReserve);
  CHECKED_FPRINTF (file, "\nSizeOfStackCommit\t");
  CHECKED_BFD_FPRINTF_VMA (abfd, file, i->SizeOfStackCommit);
  CHECKED_FPRINTF (file, "\nSizeOfHeapReserve\t");
  CHECKED_BFD_FPRINTF_VMA (abfd, file, i->SizeOfHeapReserve);
  CHECKED_FPRINTF (file, "\nSizeOfHeapCommit\t");
  CHECKED_BFD_FPRINTF_VMA (abfd, file, i->SizeOfHeapCommit);
  CHECKED_FPRINTF (file, "\nLoaderFlags\t\t%08lx\n", (unsigned long) i->LoaderFlags);
  CHECKED_FPRINTF (file, "NumberOfRvaAndSizes\t%08lx\n", (unsigned long) i->NumberOfRvaAndSizes);
  return true;
}

static bool
print_pe_data_directory (bfd *abfd, FILE *file, const struct internal_extra_pe_aouthdr *i)
{
  int j;

  CHECKED_FPRINTF (file, "\nThe Data Directory\n");
  for (j = 0; j < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; j++)
    {
      CHECKED_FPRINTF (file, "Entry %1x ", j);
      CHECKED_BFD_FPRINTF_VMA (abfd, file, i->DataDirectory[j].VirtualAddress);
      CHECKED_FPRINTF (file, " %08lx ", (unsigned long) i->DataDirectory[j].Size);
      CHECKED_FPRINTF (file, "%s\n", dir_names[j]);
    }
  return true;
}

bool
_bfd_XX_print_private_bfd_data_common (bfd *abfd, void *vfile)
{
  FILE *file;
  pe_data_type *pe;
  struct internal_extra_pe_aouthdr *i;

  if (abfd == NULL || vfile == NULL)
    return false;

  file = (FILE *) vfile;
  pe = pe_data (abfd);
  if (pe == NULL)
    return false;

  i = &pe->pe_opthdr;

  if (!print_pe_characteristics (file, pe->real_flags)
      || !print_pe_timestamp (file, abfd, pe)
      || !print_pe_optional_header_info (abfd, file, i)
      || !print_pe_subsystem_and_dll_chars (file, i)
      || !print_pe_sizes_and_loader_flags (abfd, file, i)
      || !print_pe_data_directory (abfd, file, i))
    return false;

  pe_print_idata (abfd, vfile);
  if (ferror (file)) return false;

  pe_print_edata (abfd, vfile);
  if (ferror (file)) return false;

  if (bfd_coff_have_print_pdata (abfd))
    bfd_coff_print_pdata (abfd, vfile);
  else
    pe_print_pdata (abfd, vfile);
  if (ferror (file)) return false;

  pe_print_reloc (abfd, vfile);
  if (ferror (file)) return false;

  pe_print_debugdata (abfd, file);
  if (ferror (file)) return false;

  rsrc_print_section (abfd, vfile);
  if (ferror (file)) return false;

  return true;
}

static bool
is_vma_in_section (bfd *abfd ATTRIBUTE_UNUSED, asection *sect, void *obj)
{
  if (!sect || !obj)
    {
      return false;
    }

  const bfd_vma addr = *(const bfd_vma *) obj;

  return (addr >= sect->vma) && ((addr - sect->vma) < sect->size);
}

static asection *
find_section_by_vma (bfd *abfd, bfd_vma addr)
{
  if (!abfd)
    {
      return NULL;
    }
  return bfd_sections_find_if (abfd, is_vma_in_section, (void *) &addr);
}

/* Copy any private info we understand from the input bfd
   to the output bfd.  */

static bool
update_debug_directory_pointers (bfd *obfd,
                                 asection *section,
                                 bfd_byte *data,
                                 bfd_vma dataoff,
                                 bfd_size_type debug_dir_size,
                                 bfd_vma image_base)
{
  struct external_IMAGE_DEBUG_DIRECTORY *dd_base =
    (struct external_IMAGE_DEBUG_DIRECTORY *) (data + dataoff);
  const unsigned int num_entries = debug_dir_size / sizeof (*dd_base);

  for (unsigned int i = 0; i < num_entries; i++)
    {
      struct external_IMAGE_DEBUG_DIRECTORY *edd = &dd_base[i];
      struct internal_IMAGE_DEBUG_DIRECTORY idd;

      _bfd_XXi_swap_debugdir_in (obfd, edd, &idd);

      if (idd.AddressOfRawData == 0)
        {
          continue;
        }

      bfd_vma idd_vma = idd.AddressOfRawData + image_base;
      asection *ddsection = find_section_by_vma (obfd, idd_vma);
      if (ddsection == NULL)
        {
          continue;
        }

      idd.PointerToRawData = ddsection->filepos + idd_vma - ddsection->vma;
      _bfd_XXi_swap_debugdir_out (obfd, &idd, edd);
    }

  if (!bfd_set_section_contents (obfd, section, data, 0, section->size))
    {
      _bfd_error_handler (_("failed to update file offsets"
                            " in debug directory"));
      return false;
    }

  return true;
}

static bool
process_debug_directory (bfd *obfd, pe_data_type *ope)
{
  bfd_size_type size = ope->pe_opthdr.DataDirectory[PE_DEBUG_DATA].Size;
  if (size == 0)
    {
      return true;
    }

  bfd_vma addr = ope->pe_opthdr.DataDirectory[PE_DEBUG_DATA].VirtualAddress
                 + ope->pe_opthdr.ImageBase;
  asection *section = find_section_by_vma (obfd, addr + size - 1);

  if (section == NULL || (section->flags & SEC_HAS_CONTENTS) == 0)
    {
      return true;
    }

  bfd_vma dataoff = addr - section->vma;
  if (addr < section->vma
      || section->size < dataoff
      || section->size - dataoff < size)
    {
      _bfd_error_handler
        (_("%pB: Data Directory (%lx bytes at %" PRIx64 ") "
           "extends across section boundary at %" PRIx64),
         obfd, size, (uint64_t) addr, (uint64_t) section->vma);
      return false;
    }

  bfd_byte *data = NULL;
  if (!bfd_malloc_and_get_section (obfd, section, &data))
    {
      _bfd_error_handler (_("%pB: failed to read debug data section"), obfd);
      return false;
    }

  bool success = update_debug_directory_pointers (obfd, section, data,
                                                  dataoff, size,
                                                  ope->pe_opthdr.ImageBase);
  free (data);
  return success;
}

bool
_bfd_XX_bfd_copy_private_bfd_data_common (bfd *ibfd, bfd *obfd)
{
  if (ibfd->xvec->flavour != bfd_target_coff_flavour
      || obfd->xvec->flavour != bfd_target_coff_flavour)
    {
      return true;
    }

  pe_data_type *ipe = pe_data (ibfd);
  pe_data_type *ope = pe_data (obfd);

  ope->dll = ipe->dll;

  if (obfd->xvec != ibfd->xvec)
    {
      ope->pe_opthdr.Subsystem = IMAGE_SUBSYSTEM_UNKNOWN;
    }

  if (!ope->has_reloc_section)
    {
      ope->pe_opthdr.DataDirectory[PE_BASE_RELOCATION_TABLE].VirtualAddress = 0;
      ope->pe_opthdr.DataDirectory[PE_BASE_RELOCATION_TABLE].Size = 0;
    }

  if (!ipe->has_reloc_section
      && !(ipe->real_flags & IMAGE_FILE_RELOCS_STRIPPED))
    {
      ope->dont_strip_reloc = 1;
    }

  memcpy (ope->dos_message, ipe->dos_message, sizeof (ope->dos_message));

  return process_debug_directory (obfd, ope);
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

  struct coff_section_tdata *i_coff = coff_section_data (ibfd, isec);
  if (i_coff == NULL)
    return true;

  struct pei_section_tdata *i_pei = pei_section_data (ibfd, isec);
  if (i_pei == NULL)
    return true;

  struct coff_section_tdata *o_coff = coff_section_data (obfd, osec);
  if (o_coff == NULL)
    {
      o_coff = bfd_zalloc (obfd, sizeof (*o_coff));
      if (o_coff == NULL)
	return false;
      osec->used_by_bfd = o_coff;
    }

  struct pei_section_tdata *o_pei = pei_section_data (obfd, osec);
  if (o_pei == NULL)
    {
      o_pei = bfd_zalloc (obfd, sizeof (*o_pei));
      if (o_pei == NULL)
	return false;
      o_coff->tdata = o_pei;
    }

  o_pei->virt_size = i_pei->virt_size;
  o_pei->pe_flags = i_pei->pe_flags;

  return true;
}

void
_bfd_XX_get_symbol_info (bfd * abfd, asymbol *symbol, symbol_info *ret)
{
  if (abfd == NULL || symbol == NULL || ret == NULL)
    {
      return;
    }

  coff_get_symbol_info (abfd, symbol, ret);
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
  if (data > dataend - 8)
    return dataend + 1;

  if (is_name)
    {
      const bfd_vma name_field = bfd_get_32 (abfd, data);
      bfd_byte *name_ptr;

      if (HighBitSet (name_field))
	name_ptr = datastart + WithoutHighBit (name_field);
      else
	name_ptr = datastart + name_field - rva_bias;

      if (name_ptr < datastart || name_ptr > dataend - 2)
	return dataend + 1;

      const unsigned int name_len = bfd_get_16 (abfd, name_ptr);
      if (name_len == 0 || name_len > 256)
	return dataend + 1;
    }

  const bfd_vma offset_field = bfd_get_32 (abfd, data + 4);

  if (HighBitSet (offset_field))
    {
      bfd_byte *subdir_ptr = datastart + WithoutHighBit (offset_field);
      if (subdir_ptr <= datastart || subdir_ptr >= dataend)
	return dataend + 1;
      return rsrc_count_directory (abfd, datastart, subdir_ptr, dataend, rva_bias);
    }

  bfd_byte *data_entry_ptr = datastart + offset_field;
  if (data_entry_ptr < datastart || data_entry_ptr > dataend - 16)
    return dataend + 1;

  const bfd_vma resource_rva = bfd_get_32 (abfd, data_entry_ptr);
  const bfd_vma resource_size = bfd_get_32 (abfd, data_entry_ptr + 4);

  return datastart + resource_rva - rva_bias + resource_size;
}

static bfd_byte *
rsrc_count_directory (bfd *abfd, bfd_byte *datastart, bfd_byte *data,
		      bfd_byte *dataend, bfd_vma rva_bias)
{
  bfd_byte *highest_data = data;
  unsigned int num_named_entries;
  unsigned int num_id_entries;
  unsigned int total_entries;

  if (data > dataend - 16)
    {
      return dataend + 1;
    }

  num_named_entries = bfd_get_16 (abfd, data + 12);
  num_id_entries = bfd_get_16 (abfd, data + 14);
  total_entries = num_named_entries + num_id_entries;
  data += 16;

  for (unsigned int i = 0; i < total_entries; ++i)
    {
      bfd_byte *entry_end;

      if (data > dataend - 8)
	{
	  return dataend + 1;
	}

      bfd_boolean is_named_entry = (i < num_named_entries);
      entry_end = rsrc_count_entries (abfd, is_named_entry, datastart,
				      data, dataend, rva_bias);
      data += 8;

      if (highest_data < entry_end)
	{
	  highest_data = entry_end;
	}

      if (entry_end >= dataend)
	{
	  break;
	}
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
  const unsigned int ENTRY_SIZE = 8;
  const unsigned int NAME_LEN_SIZE = 2;
  const unsigned int LEAF_INFO_SIZE = 12;
  const unsigned int LEAF_SIZE_OFFSET = 4;
  const unsigned int LEAF_CODEPAGE_OFFSET = 8;

  if (data + ENTRY_SIZE > dataend)
    return dataend;

  unsigned long name_or_id_val = bfd_get_32 (abfd, data);
  unsigned long offset_val = bfd_get_32 (abfd, data + 4);

  entry->parent = parent;
  entry->is_name = is_name;

  if (is_name)
    {
      unsigned long name_offset = WithoutHighBit (name_or_id_val);
      bfd_byte *name_data;

      if (HighBitSet (name_or_id_val))
	{
	  name_data = datastart + name_offset;
	}
      else
	{
	  if (name_offset < rva_bias)
	    return dataend;
	  name_data = datastart + name_offset - rva_bias;
	}

      if (name_data < datastart || name_data + NAME_LEN_SIZE > dataend)
	return dataend;

      entry->name_id.name.len = bfd_get_16 (abfd, name_data);
      entry->name_id.name.string = name_data + NAME_LEN_SIZE;

      if ((size_t) (dataend - entry->name_id.name.string) < entry->name_id.name.len)
	return dataend;
    }
  else
    {
      entry->name_id.id = name_or_id_val;
    }

  if (HighBitSet (offset_val))
    {
      entry->is_dir = true;
      entry->value.directory = bfd_malloc (sizeof (*entry->value.directory));
      if (entry->value.directory == NULL)
	return dataend;

      unsigned long dir_offset = WithoutHighBit (offset_val);
      bfd_byte *dir_data = datastart + dir_offset;

      if (dir_data < datastart || dir_data > dataend)
	return dataend;

      return rsrc_parse_directory (abfd, entry->value.directory,
				   datastart, dir_data,
				   dataend, rva_bias, entry);
    }

  entry->is_dir = false;
  entry->value.leaf = bfd_malloc (sizeof (*entry->value.leaf));
  if (entry->value.leaf == NULL)
    return dataend;

  bfd_byte *leaf_info = datastart + offset_val;
  if (leaf_info < datastart || leaf_info + LEAF_INFO_SIZE > dataend)
    return dataend;

  bfd_vma data_rva = bfd_get_32 (abfd, leaf_info);
  unsigned long size = bfd_get_32 (abfd, leaf_info + LEAF_SIZE_OFFSET);
  entry->value.leaf->size = size;
  entry->value.leaf->codepage = bfd_get_32 (abfd, leaf_info + LEAF_CODEPAGE_OFFSET);

  if (data_rva < rva_bias)
    return dataend;

  bfd_vma data_offset = data_rva - rva_bias;
  bfd_byte *data_ptr = datastart + data_offset;

  if (data_ptr < datastart || size > (size_t) (dataend - data_ptr))
    return dataend;

  entry->value.leaf->data = bfd_malloc (size);
  if (entry->value.leaf->data == NULL)
    return dataend;

  memcpy (entry->value.leaf->data, data_ptr, size);
  return data_ptr + size;
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
  rsrc_entry *head = NULL;
  rsrc_entry **next_ptr = &head;
  rsrc_entry *last_entry = NULL;
  unsigned int i;

  chain->first_entry = NULL;
  chain->last_entry = NULL;

  if (chain->num_entries == 0)
    return highest_data;

  for (i = 0; i < chain->num_entries; ++i)
    {
      rsrc_entry *current_entry = bfd_malloc (sizeof (*current_entry));
      if (current_entry == NULL)
	goto fail;

      *next_ptr = current_entry;
      last_entry = current_entry;

      bfd_byte *entry_end = rsrc_parse_entry (abfd, is_name, current_entry,
					      datastart, data, dataend,
					      rva_bias, parent);
      if (entry_end > dataend)
	goto fail;

      data += 8;
      if (entry_end > highest_data)
	highest_data = entry_end;

      next_ptr = &current_entry->next_entry;
    }

  *next_ptr = NULL;
  chain->first_entry = head;
  chain->last_entry = last_entry;

  return highest_data;

 fail:
  while (head != NULL)
    {
      rsrc_entry *next = head->next_entry;
      bfd_free (head);
      head = next;
    }
  return dataend;
}

static const size_t RSRC_DIR_HEADER_SIZE = 16;
static const size_t RSRC_DIR_CHARACTERISTICS_OFFSET = 0;
static const size_t RSRC_DIR_TIME_OFFSET = 4;
static const size_t RSRC_DIR_MAJOR_OFFSET = 8;
static const size_t RSRC_DIR_MINOR_OFFSET = 10;
static const size_t RSRC_DIR_NUM_NAMES_OFFSET = 12;
static const size_t RSRC_DIR_NUM_IDS_OFFSET = 14;
static const size_t RSRC_ENTRY_SIZE = 8;

static bfd_byte *
rsrc_parse_directory (bfd *	       abfd,
		      rsrc_directory * table,
		      bfd_byte *       datastart,
		      bfd_byte *       data,
		      bfd_byte *       dataend,
		      bfd_vma	       rva_bias,
		      rsrc_entry *     entry)
{
  if (table == NULL)
    return dataend;

  if ((size_t) (dataend - data) < RSRC_DIR_HEADER_SIZE)
    return NULL;

  table->characteristics = bfd_get_32 (abfd, data + RSRC_DIR_CHARACTERISTICS_OFFSET);
  table->time = bfd_get_32 (abfd, data + RSRC_DIR_TIME_OFFSET);
  table->major = bfd_get_16 (abfd, data + RSRC_DIR_MAJOR_OFFSET);
  table->minor = bfd_get_16 (abfd, data + RSRC_DIR_MINOR_OFFSET);

  unsigned int num_names = bfd_get_16 (abfd, data + RSRC_DIR_NUM_NAMES_OFFSET);
  unsigned int num_ids = bfd_get_16 (abfd, data + RSRC_DIR_NUM_IDS_OFFSET);
  table->names.num_entries = num_names;
  table->ids.num_entries = num_ids;
  table->entry = entry;

  if ((num_names > 0 && RSRC_ENTRY_SIZE > (size_t) -1 / num_names)
      || (num_ids > 0 && RSRC_ENTRY_SIZE > (size_t) -1 / num_ids))
    return NULL;

  size_t names_size = (size_t) num_names * RSRC_ENTRY_SIZE;
  size_t ids_size = (size_t) num_ids * RSRC_ENTRY_SIZE;

  if (names_size > (size_t) -1 - ids_size)
    return NULL;

  const bfd_byte *entries_start = data + RSRC_DIR_HEADER_SIZE;
  if ((size_t) (dataend - entries_start) < (names_size + ids_size))
    return NULL;

  bfd_byte *named_entries_data = (bfd_byte *) entries_start;
  bfd_byte *max_ptr = rsrc_parse_entries (abfd, &table->names, true, data,
					  datastart, named_entries_data, dataend, rva_bias, table);
  if (max_ptr == NULL)
    return NULL;

  bfd_byte *id_entries_data = named_entries_data + names_size;
  max_ptr = rsrc_parse_entries (abfd, &table->ids, false, max_ptr,
				datastart, id_entries_data, dataend, rva_bias, table);
  if (max_ptr == NULL)
    return NULL;

  bfd_byte *end_of_entries = id_entries_data + ids_size;
  return max (max_ptr, end_of_entries);
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
  if (!data || !data->next_string || !string)
    {
      return;
    }
  if (string->len > 0 && !string->string)
    {
      return;
    }

  const size_t wide_char_size = sizeof (uint16_t);
  const size_t string_data_size = (size_t) string->len * wide_char_size;
  uint8_t *dest = (uint8_t *) data->next_string;

  bfd_put_16 (data->abfd, string->len, dest);
  memcpy (dest + wide_char_size, string->string, string_data_size);

  data->next_string = dest + wide_char_size + string_data_size;
}

static inline unsigned int
rsrc_compute_rva (const rsrc_write_data *data, const bfd_byte *addr)
{
  assert (data != NULL);
  assert (addr != NULL);
  assert (data->datastart != NULL);
  assert (addr >= data->datastart);

  ptrdiff_t offset = addr - data->datastart;

  assert ((size_t)offset <= UINT_MAX);
  unsigned int base_rva = (unsigned int) offset;

  assert (base_rva <= UINT_MAX - data->rva_bias);

  return base_rva + data->rva_bias;
}

static void
rsrc_write_leaf (rsrc_write_data * data,
		 rsrc_leaf *	   leaf)
{
  if (!data || !leaf)
    {
      return;
    }

  unsigned char *entry_ptr = data->next_leaf;
  const unsigned int field_width = 4;

  bfd_put_32 (data->abfd, rsrc_compute_rva (data, data->next_data), entry_ptr);
  entry_ptr += field_width;
  bfd_put_32 (data->abfd, leaf->size, entry_ptr);
  entry_ptr += field_width;
  bfd_put_32 (data->abfd, leaf->codepage, entry_ptr);
  entry_ptr += field_width;
  bfd_put_32 (data->abfd, 0, entry_ptr);
  entry_ptr += field_width;

  data->next_leaf = entry_ptr;

  if (leaf->data && leaf->size > 0)
    {
      memcpy (data->next_data, leaf->data, leaf->size);
    }

  data->next_data += ((leaf->size + 7) & ~7);
}

static void rsrc_write_directory (rsrc_write_data *, rsrc_directory *);

static void
rsrc_write_entry (rsrc_write_data *  data,
		  bfd_byte *	     where,
		  rsrc_entry *	     entry)
{
  bfd_vma id_val;
  bfd_vma value_val;
  enum { RSRC_ENTRY_VALUE_OFFSET = 4 };
  bfd_byte * const value_ptr = where + RSRC_ENTRY_VALUE_OFFSET;

  if (entry->is_name)
    {
      id_val = SetHighBit (data->next_string - data->datastart);
      rsrc_write_string (data, &entry->name_id.name);
    }
  else
    {
      id_val = entry->name_id.id;
    }
  bfd_put_32 (data->abfd, id_val, where);

  if (entry->is_dir)
    {
      value_val = SetHighBit (data->next_table - data->datastart);
      rsrc_write_directory (data, entry->value.directory);
    }
  else
    {
      value_val = data->next_leaf - data->datastart;
      rsrc_write_leaf (data, entry->value.leaf);
    }
  bfd_put_32 (data->abfd, value_val, value_ptr);
}

static void rsrc_process_entries (struct rsrc_entry *entry, int compute_name_size);

static void
rsrc_compute_region_sizes (rsrc_directory * dir)
{
  if (dir == NULL)
    {
      return;
    }

  sizeof_tables_and_entries += 16;

  rsrc_process_entries (dir->names.first_entry, 1);
  rsrc_process_entries (dir->ids.first_entry, 0);
}

static void
rsrc_process_entries (struct rsrc_entry *entry, int compute_name_size)
{
  for (; entry != NULL; entry = entry->next_entry)
    {
      sizeof_tables_and_entries += 8;

      if (compute_name_size)
        {
          sizeof_strings += (entry->name_id.name.len + 1) * 2;
        }

      if (entry->is_dir)
        {
          rsrc_compute_region_sizes (entry->value.directory);
        }
      else
        {
          sizeof_leaves += 16;
        }
    }
}

static bfd_byte *
rsrc_write_entry_list (rsrc_write_data * data, bfd_byte * write_pos,
		       rsrc_entry * entry, unsigned int count,
		       bfd_boolean is_name_list)
{
  const unsigned int RSRC_ENTRY_SIZE = 8;
  unsigned int i;

  for (i = count; i > 0 && entry != NULL; i--, entry = entry->next_entry)
    {
      BFD_ASSERT (entry->is_name == is_name_list);
      rsrc_write_entry (data, write_pos, entry);
      write_pos += RSRC_ENTRY_SIZE;
    }

  BFD_ASSERT (i == 0);
  BFD_ASSERT (entry == NULL);
  return write_pos;
}

static void
rsrc_write_directory (rsrc_write_data * data,
		      rsrc_directory *  dir)
{
  const unsigned int RSRC_DIR_HEADER_SIZE = 16;
  const unsigned int RSRC_ENTRY_SIZE = 8;
  const unsigned int RSRC_DIR_TIME_OFFSET = 4;
  const unsigned int RSRC_DIR_MAJOR_OFFSET = 8;
  const unsigned int RSRC_DIR_MINOR_OFFSET = 10;
  const unsigned int RSRC_DIR_NUM_NAMES_OFFSET = 12;
  const unsigned int RSRC_DIR_NUM_IDS_OFFSET = 14;

  bfd_byte * const current_table_pos = data->next_table;
  const unsigned int num_names = dir->names.num_entries;
  const unsigned int num_ids = dir->ids.num_entries;

  bfd_put_32 (data->abfd, dir->characteristics, current_table_pos);
  bfd_put_32 (data->abfd, 0 /*dir->time*/, current_table_pos + RSRC_DIR_TIME_OFFSET);
  bfd_put_16 (data->abfd, dir->major, current_table_pos + RSRC_DIR_MAJOR_OFFSET);
  bfd_put_16 (data->abfd, dir->minor, current_table_pos + RSRC_DIR_MINOR_OFFSET);
  bfd_put_16 (data->abfd, num_names, current_table_pos + RSRC_DIR_NUM_NAMES_OFFSET);
  bfd_put_16 (data->abfd, num_ids, current_table_pos + RSRC_DIR_NUM_IDS_OFFSET);

  bfd_byte *write_pos = current_table_pos + RSRC_DIR_HEADER_SIZE;

  write_pos = rsrc_write_entry_list (data, write_pos, dir->names.first_entry,
				     num_names, TRUE);
  write_pos = rsrc_write_entry_list (data, write_pos, dir->ids.first_entry,
				     num_ids, FALSE);

  bfd_byte * const expected_end_pos = current_table_pos + RSRC_DIR_HEADER_SIZE
    + (num_names * RSRC_ENTRY_SIZE)
    + (num_ids * RSRC_ENTRY_SIZE);

  BFD_ASSERT (write_pos == expected_end_pos);
  data->next_table = write_pos;
}

#if ! defined __CYGWIN__ && ! defined __MINGW32__
/* Return the length (number of units) of the first character in S,
   putting its 'ucs4_t' representation in *PUC.  */

static unsigned int
u16_mbtouc (wint_t * puc, const unsigned short * s, unsigned int n)
{
  enum
  {
    HIGH_SURROGATE_START = 0xD800,
    LOW_SURROGATE_START = 0xDC00,
    SURROGATE_END = 0xE000,
    REPLACEMENT_CHAR = 0xFFFD,
    SURROGATE_OFFSET = 0x10000
  };

  if (n == 0)
    {
      return 0;
    }

  unsigned short c1 = *s;

  if (c1 < HIGH_SURROGATE_START || c1 >= SURROGATE_END)
    {
      *puc = c1;
      return 1;
    }

  if (c1 >= LOW_SURROGATE_START)
    {
      *puc = REPLACEMENT_CHAR;
      return 1;
    }

  if (n < 2)
    {
      *puc = REPLACEMENT_CHAR;
      return n;
    }

  unsigned short c2 = s[1];
  if (c2 >= LOW_SURROGATE_START && c2 < SURROGATE_END)
    {
      *puc = SURROGATE_OFFSET +
	(((wint_t) c1 - HIGH_SURROGATE_START) << 10) +
	(c2 - LOW_SURROGATE_START);
      return 2;
    }

  *puc = REPLACEMENT_CHAR;
  return 1;
}
#endif /* not Cygwin/Mingw */

/* Perform a comparison of two entries.  */
static signed int
rsrc_cmp (bool is_name, const rsrc_entry * a, const rsrc_entry * b)
{
  if (!is_name)
    {
      return a->name_id.id - b->name_id.id;
    }

  bfd_byte * astring = a->name_id.name.string;
  const unsigned int alen = a->name_id.name.len;
  bfd_byte * bstring = b->name_id.name.string;
  const unsigned int blen = b->name_id.name.len;
  signed int res;

#if defined(__CYGWIN__)
  res = wcsncasecmp ((const wchar_t *) astring, (const wchar_t *) bstring, min (alen, blen));
#elif defined(__MINGW32__)
  res = wcsnicmp ((const wchar_t *) astring, (const wchar_t *) bstring, min (alen, blen));
#else
  res = 0;
  const unsigned int n = min (alen, blen);
  for (unsigned int i = 0; i < n; ++i, astring += 2, bstring += 2)
    {
      wint_t awc;
      wint_t bwc;

      unsigned int Alen = u16_mbtouc (&awc, (const unsigned short *) astring, 2);
      unsigned int Blen = u16_mbtouc (&bwc, (const unsigned short *) bstring, 2);

      if (Alen != Blen)
	{
	  res = (signed int) Alen - (signed int) Blen;
	  break;
	}

      res = towlower (awc) - towlower (bwc);
      if (res != 0)
	{
	  break;
	}
    }
#endif

  if (res == 0)
    {
      res = (signed int) alen - (signed int) blen;
    }

  return res;
}

static void
rsrc_print_name (char *buffer, rsrc_string string)
{
  if (!buffer || !string.string || string.len == 0)
  {
    return;
  }

  char *dest = buffer + strlen (buffer);
  bfd_byte *src = string.string;
  unsigned int i;

  for (i = 0; i < string.len; ++i)
  {
    dest[i] = (char) src[i * 2];
  }
  dest[string.len] = '\0';
}

typedef struct
{
  unsigned int id;
  const char *name;
} rsrc_type_map_entry;

static const rsrc_type_map_entry rsrc_type_map[] = {
  {1, "CURSOR"}, {2, "BITMAP"}, {3, "ICON"}, {4, "MENU"},
  {5, "DIALOG"}, {6, "STRING"}, {7, "FONTDIR"}, {8, "FONT"},
  {9, "ACCELERATOR"}, {10, "RCDATA"}, {11, "MESSAGETABLE"},
  {12, "GROUP_CURSOR"}, {14, "GROUP_ICON"}, {16, "VERSION"},
  {17, "DLGINCLUDE"}, {19, "PLUGPLAY"}, {20, "VXD"},
  {21, "ANICURSOR"}, {22, "ANIICON"}, {23, "HTML"}, {24, "MANIFEST"},
  {240, "DLGINIT"}, {241, "TOOLBAR"}
};

static const char *
get_rsrc_type_name (unsigned int id)
{
  for (size_t i = 0; i < sizeof (rsrc_type_map) / sizeof (rsrc_type_map[0]); ++i)
    {
      if (rsrc_type_map[i].id == id)
	{
	  return rsrc_type_map[i].name;
	}
    }
  return NULL;
}

static const char *
rsrc_resource_name (rsrc_entry *entry, rsrc_directory *dir, char *buffer)
{
  const size_t buffer_size = 512;
  char *p = buffer;
  size_t remaining = buffer_size;
  int written;

  buffer[0] = '\0';

  bool is_string_type = false;
  rsrc_entry *type_entry = NULL;
  if (dir && dir->entry && dir->entry->parent)
    {
      type_entry = dir->entry->parent->entry;
    }

  if (type_entry)
    {
      written = snprintf (p, remaining, "type: ");
      if (written <= 0 || (size_t) written >= remaining) return buffer;
      p += written;
      remaining -= written;

      if (type_entry->is_name)
	{
	  char *p_old = p;
	  rsrc_print_name (p, type_entry->name_id.name);
	  size_t name_len = strlen (p_old);
	  if (name_len < remaining)
	    {
	      p += name_len;
	      remaining -= name_len;
	    }
	  else
	    {
	      return buffer;
	    }
	}
      else
	{
	  unsigned int type_id = type_entry->name_id.id;
	  written = snprintf (p, remaining, "%x", type_id);
	  if (written <= 0 || (size_t) written >= remaining) return buffer;
	  p += written;
	  remaining -= written;

	  const char *type_name = get_rsrc_type_name (type_id);
	  if (type_name)
	    {
	      written = snprintf (p, remaining, " (%s)", type_name);
	      if (written <= 0 || (size_t) written >= remaining) return buffer;
	      p += written;
	      remaining -= written;
	    }
	  if (type_id == 6)
	    {
	      is_string_type = true;
	    }
	}
    }

  if (dir && dir->entry)
    {
      written = snprintf (p, remaining, " name: ");
      if (written <= 0 || (size_t) written >= remaining) return buffer;
      p += written;
      remaining -= written;

      if (dir->entry->is_name)
	{
	  char *p_old = p;
	  rsrc_print_name (p, dir->entry->name_id.name);
	  size_t name_len = strlen (p_old);
	  if (name_len < remaining)
	    {
	      p += name_len;
	      remaining -= name_len;
	    }
	  else
	    {
	      return buffer;
	    }
	}
      else
	{
	  unsigned int name_id = dir->entry->name_id.id;
	  written = snprintf (p, remaining, "%x", name_id);
	  if (written <= 0 || (size_t) written >= remaining) return buffer;
	  p += written;
	  remaining -= written;

	  if (is_string_type)
	    {
	      written = snprintf (p, remaining, " (resource id range: %d - %d)",
				  (name_id - 1) << 4, (name_id << 4) - 1);
	      if (written <= 0 || (size_t) written >= remaining) return buffer;
	      p += written;
	      remaining -= written;
	    }
	}
    }

  if (entry)
    {
      written = snprintf (p, remaining, " lang: ");
      if (written <= 0 || (size_t) written >= remaining) return buffer;
      p += written;
      remaining -= written;

      if (entry->is_name)
	{
	  rsrc_print_name (p, entry->name_id.name);
	}
      else
	{
	  snprintf (p, remaining, "%x", entry->name_id.id);
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

#define NUM_STRING_ENTRIES 16

static inline unsigned int
read_le16 (const bfd_byte *p)
{
  return p[0] | ((unsigned int) p[1] << 8);
}

static inline size_t
get_string_entry_size (unsigned int len)
{
  return (size_t) (len + 1) * 2;
}

static bool
rsrc_merge_string_entries (rsrc_entry * a, rsrc_entry * b)
{
  unsigned int a_lengths[NUM_STRING_ENTRIES];
  unsigned int b_lengths[NUM_STRING_ENTRIES];
  size_t copy_needed = 0;
  unsigned int i;

  BFD_ASSERT (!a->is_dir && a->value.leaf != NULL);
  BFD_ASSERT (!b->is_dir && b->value.leaf != NULL);

  const bfd_byte *a_scan_ptr = a->value.leaf->data;
  const bfd_byte *b_scan_ptr = b->value.leaf->data;

  for (i = 0; i < NUM_STRING_ENTRIES; ++i)
    {
      unsigned int alen = read_le16 (a_scan_ptr);
      unsigned int blen = read_le16 (b_scan_ptr);
      a_lengths[i] = alen;
      b_lengths[i] = blen;

      size_t a_entry_size = get_string_entry_size (alen);
      size_t b_entry_size = get_string_entry_size (blen);

      if (alen == 0)
	{
	  if (blen != 0)
	    copy_needed += b_entry_size - a_entry_size;
	}
      else if (blen != 0)
	{
	  if (alen != blen || memcmp (a_scan_ptr + 2, b_scan_ptr + 2, alen * 2) != 0)
	    {
	      if (a->parent && a->parent->entry && !a->parent->entry->is_name)
		_bfd_error_handler (_(".rsrc merge failure: duplicate string resource: %d"),
				    ((a->parent->entry->name_id.id - 1) << 4) + i);
	      return false;
	    }
	}

      a_scan_ptr += a_entry_size;
      b_scan_ptr += b_entry_size;
    }

  if (copy_needed == 0)
    return true;

  size_t new_size = a->value.leaf->size + copy_needed;
  bfd_byte *new_data = bfd_malloc (new_size);
  if (new_data == NULL)
    return false;

  bfd_byte *n_ptr = new_data;
  const bfd_byte *a_copy_ptr = a->value.leaf->data;
  const bfd_byte *b_copy_ptr = b->value.leaf->data;

  for (i = 0; i < NUM_STRING_ENTRIES; ++i)
    {
      unsigned int alen = a_lengths[i];
      unsigned int blen = b_lengths[i];
      size_t a_entry_size = get_string_entry_size (alen);
      size_t b_entry_size = get_string_entry_size (blen);

      if (alen != 0)
	{
	  memcpy (n_ptr, a_copy_ptr, a_entry_size);
	  n_ptr += a_entry_size;
	}
      else
	{
	  memcpy (n_ptr, b_copy_ptr, b_entry_size);
	  n_ptr += b_entry_size;
	}

      a_copy_ptr += a_entry_size;
      b_copy_ptr += b_entry_size;
    }

  BFD_ASSERT ((size_t) (n_ptr - new_data) == new_size);

  free (a->value.leaf->data);
  a->value.leaf->data = new_data;
  a->value.leaf->size = new_size;

  return true;
}

static void rsrc_merge (rsrc_entry *, rsrc_entry *);

/* Sort the entries in given part of the directory.
   We use an old fashioned bubble sort because we are dealing
   with lists and we want to handle matches specially.  */

static const int RT_MANIFEST = 0x18;
static const int RT_STRING = 0x6;

static bool
is_manifest_context (const rsrc_entry *entry, const rsrc_directory *dir)
{
  return (dir != NULL
	  && dir->entry != NULL
	  && !dir->entry->is_name
	  && dir->entry->name_id.id == RT_MANIFEST
	  && !entry->is_name
	  && entry->name_id.id == 1);
}

static bool
is_default_manifest_dir (const rsrc_entry *entry)
{
  rsrc_dir_chain *ids = &entry->value.directory->ids;
  return (entry->value.directory->names.num_entries == 0
	  && ids->num_entries == 1
	  && ids->first_entry != NULL
	  && !ids->first_entry->is_name
	  && ids->first_entry->name_id.id == 0);
}

static bool
is_string_table_context (const rsrc_directory *dir)
{
  return (dir != NULL
	  && dir->entry != NULL
	  && dir->entry->parent != NULL
	  && dir->entry->parent->entry != NULL
	  && !dir->entry->parent->entry->is_name
	  && dir->entry->parent->entry->name_id.id == RT_STRING);
}

static bool
is_droppable_manifest_lang_entry (const rsrc_entry *entry,
				  const rsrc_directory *dir)
{
  return (!entry->is_name
	  && entry->name_id.id == 0
	  && dir != NULL
	  && dir->entry != NULL
	  && !dir->entry->is_name
	  && dir->entry->name_id.id == 1
	  && dir->entry->parent != NULL
	  && dir->entry->parent->entry != NULL
	  && !dir->entry->parent->entry->is_name
	  && dir->entry->parent->entry->name_id.id == RT_MANIFEST);
}

static void
report_duplicate_leaf_error (rsrc_entry *entry, rsrc_directory *dir)
{
  if (dir != NULL
      && dir->entry != NULL
      && dir->entry->parent != NULL
      && dir->entry->parent->entry != NULL)
    {
      char buff[256];
      _bfd_error_handler (_(".rsrc merge failure: duplicate leaf: %s"),
			  rsrc_resource_name (entry, dir, buff));
    }
  else
    {
      _bfd_error_handler (_(".rsrc merge failure: duplicate leaf"));
    }
  bfd_set_error (bfd_error_file_truncated);
}

static void
rsrc_sort_entries (rsrc_dir_chain *chain,
		   bool is_name,
		   rsrc_directory *dir)
{
  rsrc_entry *entry;
  rsrc_entry *next;
  rsrc_entry **points_to_entry;
  bool swapped;

  if (chain->num_entries < 2)
    return;

  do
    {
      swapped = false;
      points_to_entry = &chain->first_entry;
      entry = *points_to_entry;
      next  = entry->next_entry;

      while (next)
	{
	  signed int cmp = rsrc_cmp (is_name, entry, next);

	  if (cmp > 0)
	    {
	      entry->next_entry = next->next_entry;
	      next->next_entry = entry;
	      *points_to_entry = next;
	      swapped = true;

	      points_to_entry = &next->next_entry;
	      next = entry->next_entry;
	    }
	  else if (cmp == 0)
	    {
	      if (entry->is_dir != next->is_dir)
		{
		  _bfd_error_handler (_(".rsrc merge failure: a directory matches a leaf"));
		  bfd_set_error (bfd_error_file_truncated);
		  return;
		}

	      if (entry->is_dir)
		{
		  if (is_manifest_context (entry, dir))
		    {
		      if (is_default_manifest_dir (next))
			/* Drop NEXT by falling through. */
			;
		      else if (is_default_manifest_dir (entry))
			{
			  /* Swap ENTRY and NEXT. The old ENTRY will be dropped. */
			  entry->next_entry = next->next_entry;
			  next->next_entry = entry;
			  *points_to_entry = next;
			  points_to_entry = &next->next_entry;
			  next = entry->next_entry;
			  swapped = true;
			}
		      else
			{
			  _bfd_error_handler (_(".rsrc merge failure: multiple non-default manifests"));
			  bfd_set_error (bfd_error_file_truncated);
			  return;
			}
		      entry->next_entry = next->next_entry;
		      chain->num_entries--;
		      if (chain->num_entries < 2)
			{
			  chain->last_entry = entry;
			  return;
			}
		      next = entry->next_entry;
		      continue;
		    }
		  else
		    {
		      rsrc_merge (entry, next);
		    }
		}
	      else /* is leaf */
		{
		  if (is_string_table_context (dir))
		    {
		      if (!rsrc_merge_string_entries (entry, next))
			{
			  bfd_set_error (bfd_error_file_truncated);
			  return;
			}
		    }
		  else if (is_droppable_manifest_lang_entry (entry, dir))
		    /* This is a default manifest, which can be dropped. */
		    ;
		  else
		    {
		      report_duplicate_leaf_error (entry, dir);
		      return;
		    }
		}

	      entry->next_entry = next->next_entry;
	      chain->num_entries--;
	      if (chain->num_entries < 2)
		{
		  chain->last_entry = entry;
		  return;
		}
	      next = entry->next_entry;
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

/* Attach B's chain onto A.  */
static void
rsrc_attach_chain (rsrc_dir_chain * achain, rsrc_dir_chain * bchain)
{
  if (!achain || !bchain || bchain->num_entries == 0)
    {
      return;
    }

  if (achain->first_entry == NULL)
    {
      achain->first_entry = bchain->first_entry;
    }
  else
    {
      achain->last_entry->next_entry = bchain->first_entry;
    }

  achain->last_entry = bchain->last_entry;
  achain->num_entries += bchain->num_entries;

  bchain->num_entries = 0;
  bchain->first_entry = NULL;
  bchain->last_entry = NULL;
}

static void
rsrc_merge (struct rsrc_entry *a, struct rsrc_entry *b)
{
  BFD_ASSERT (a && a->is_dir);
  BFD_ASSERT (b && b->is_dir);

  rsrc_directory *adir = a->value.directory;
  rsrc_directory *bdir = b->value.directory;

  if (!adir || !bdir)
    {
      _bfd_error_handler (_(".rsrc merge failure: invalid directory entry"));
      bfd_set_error (bfd_error_invalid_operation);
      return;
    }

  const char *error_msg = NULL;
  if (adir->characteristics != bdir->characteristics)
    {
      error_msg = _(".rsrc merge failure: dirs with differing characteristics");
    }
  else if (adir->major != bdir->major || adir->minor != bdir->minor)
    {
      error_msg = _(".rsrc merge failure: differing directory versions");
    }

  if (error_msg)
    {
      _bfd_error_handler (error_msg);
      bfd_set_error (bfd_error_file_truncated);
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

static void rsrc_free_directory (rsrc_directory *dir);

static void
rsrc_free_entry_list (struct rsrc_entry_list *list)
{
  struct rsrc_entry *entry = list->first_entry;
  while (entry)
    {
      struct rsrc_entry *next = entry->next;
      if (entry->dir)
	{
	  rsrc_free_directory (entry->dir);
	  free (entry->dir);
	}
      free (entry);
      entry = next;
    }
}

static void
rsrc_free_directory (rsrc_directory *dir)
{
  if (dir)
    {
      rsrc_free_entry_list (&dir->names);
      rsrc_free_entry_list (&dir->ids);
    }
}

static void
rsrc_process_section (bfd *abfd, struct coff_final_link_info *pfinfo)
{
  asection *sec = bfd_get_section_by_name (abfd, ".rsrc");
  if (sec == NULL || sec->rawsize == 0)
    return;

  pe_data_type *pe = pe_data (abfd);
  if (pe == NULL)
    return;

  bfd_byte *datastart = NULL;
  if (!bfd_malloc_and_get_section (abfd, sec, &datastart))
    return;

  ptrdiff_t *rsrc_sizes = NULL;
  rsrc_directory *type_tables = NULL;
  rsrc_directory new_table = { {0}, {0} };
  bfd_byte *new_data = NULL;
  bfd_size_type size = sec->rawsize;

  unsigned int num_input_rsrc = 0;
  unsigned int max_num_input_rsrc = 4;
  rsrc_sizes = bfd_malloc (max_num_input_rsrc * sizeof (*rsrc_sizes));
  if (rsrc_sizes == NULL)
    goto end;

  for (bfd *input = pfinfo->info->input_bfds; input != NULL; input = input->link.next)
    {
      asection *rsrc_sec = bfd_get_section_by_name (input, ".rsrc");

      if (rsrc_sec != NULL && !discarded_section (rsrc_sec))
	{
	  if (num_input_rsrc >= max_num_input_rsrc)
	    {
	      unsigned int new_max = max_num_input_rsrc * 2;
	      ptrdiff_t *new_sizes = bfd_realloc (rsrc_sizes, new_max * sizeof (*rsrc_sizes));
	      if (new_sizes == NULL)
		goto end;
	      rsrc_sizes = new_sizes;
	      max_num_input_rsrc = new_max;
	    }

	  BFD_ASSERT (rsrc_sec->size > 0);
	  rsrc_sizes[num_input_rsrc++] = rsrc_sec->size;
	}
    }

  if (num_input_rsrc < 2)
    goto end;

  bfd_byte *dataend = datastart + size;
  bfd_byte *current_data = datastart;
  bfd_vma rva_bias = sec->vma - pe->pe_opthdr.ImageBase;

  for (unsigned int i = 0; i < num_input_rsrc; ++i)
    {
      bfd_byte *p = current_data;
      bfd_byte *next_data = rsrc_count_directory (abfd, p, p, dataend, rva_bias);

      if (next_data > dataend || (next_data - p) > rsrc_sizes[i])
	{
	  _bfd_error_handler (_("%pB: .rsrc merge failure: corrupt or unexpected .rsrc size"), abfd);
	  bfd_set_error (bfd_error_file_truncated);
	  goto end;
	}
      current_data += rsrc_sizes[i];
      rva_bias += rsrc_sizes[i];
    }
  BFD_ASSERT ((unsigned int)(dataend - datastart) == (unsigned int)(current_data - datastart));

  type_tables = bfd_malloc (num_input_rsrc * sizeof (*type_tables));
  if (type_tables == NULL)
    goto end;

  current_data = datastart;
  rva_bias = sec->vma - pe->pe_opthdr.ImageBase;
  for (unsigned int i = 0; i < num_input_rsrc; ++i)
    {
      (void) rsrc_parse_directory (abfd, type_tables + i, current_data, current_data, dataend, rva_bias, NULL);
      current_data += rsrc_sizes[i];
      rva_bias += rsrc_sizes[i];
    }

  new_table.characteristics = type_tables[0].characteristics;
  new_table.time = type_tables[0].time;
  new_table.major = type_tables[0].major;
  new_table.minor = type_tables[0].minor;

  for (unsigned int i = 0; i < num_input_rsrc; i++)
    rsrc_attach_chain (&new_table.names, &type_tables[i].names);
  rsrc_sort_entries (&new_table.names, true, &new_table);

  for (unsigned int i = 0; i < num_input_rsrc; i++)
    rsrc_attach_chain (&new_table.ids, &type_tables[i].ids);
  rsrc_sort_entries (&new_table.ids, false, &new_table);

  bfd_size_type sizeof_leaves = 0;
  bfd_size_type sizeof_strings = 0;
  bfd_size_type sizeof_tables_and_entries = 0;
  rsrc_compute_region_sizes (&new_table, &sizeof_tables_and_entries, &sizeof_strings, &sizeof_leaves);

  sizeof_strings = (sizeof_strings + 7) & ~7;

  new_data = bfd_zalloc (abfd, size);
  if (new_data == NULL)
    goto end;

  rsrc_write_data write_data;
  write_data.abfd = abfd;
  write_data.datastart = new_data;
  write_data.next_table = new_data;
  write_data.next_leaf = new_data + sizeof_tables_and_entries;
  write_data.next_string = write_data.next_leaf + sizeof_leaves;
  write_data.next_data = write_data.next_string + sizeof_strings;
  write_data.rva_bias = sec->vma - pe->pe_opthdr.ImageBase;

  rsrc_write_directory (&write_data, &new_table);

  bfd_set_section_contents (pfinfo->output_bfd, sec, new_data, 0, size);
  sec->size = sec->rawsize = size;
  new_data = NULL;

end:
  rsrc_free_directory (&new_table);
  free (type_tables);
  free (rsrc_sizes);
  free (datastart);
  free (new_data);
}

/* Handle the .idata section and other things that need symbol table
   access.  */

static bool
is_defined_symbol (const struct coff_link_hash_entry *h)
{
  return (h != NULL
	  && (h->root.type == bfd_link_hash_defined
	      || h->root.type == bfd_link_hash_defweak)
	  && h->root.u.def.section != NULL
	  && h->root.u.def.section->output_section != NULL);
}

static bfd_vma
get_symbol_vma (const struct coff_link_hash_entry *h)
{
  return (h->root.u.def.value
	  + h->root.u.def.section->output_section->vma
	  + h->root.u.def.section->output_offset);
}

static bool
is_legacy_windows_x86 (bfd *abfd)
{
  PE_COFF_DATA_TYPE *pe = pe_data (abfd);
  return (bfd_get_arch (abfd) == bfd_arch_i386
	  && ((bfd_get_mach (abfd) & ~bfd_mach_i386_intel_syntax)
	      == bfd_mach_i386_i386)
	  && (pe->pe_opthdr.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI
	      || pe->pe_opthdr.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI)
	  && (pe->pe_opthdr.MajorSubsystemVersion * 256
	      + pe->pe_opthdr.MinorSubsystemVersion
	      <= 0x0501));
}

bool
_bfd_XXi_final_link_postscript (bfd *abfd, struct coff_final_link_info *pfinfo)
{
  struct bfd_link_info *info = pfinfo->info;
  struct coff_link_hash_entry *h_start, *h_end;
  bool result = true;

  h_start = coff_link_hash_lookup (coff_hash_table (info), ".idata$2", false, false, true);
  if (h_start != NULL)
    {
      if (is_defined_symbol (h_start))
	{
	  bfd_vma vma2 = get_symbol_vma (h_start);
	  pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_TABLE].VirtualAddress = vma2;

	  h_end = coff_link_hash_lookup (coff_hash_table (info), ".idata$4", false, false, true);
	  if (is_defined_symbol (h_end))
	    pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_TABLE].Size = get_symbol_vma (h_end) - vma2;
	  else
	    {
	      _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: %s is missing"), abfd, PE_IMPORT_TABLE, ".idata$4");
	      result = false;
	    }
	}
      else
	{
	  _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: %s is missing"), abfd, PE_IMPORT_TABLE, ".idata$2");
	  result = false;
	}

      h_start = coff_link_hash_lookup (coff_hash_table (info), ".idata$5", false, false, true);
      if (is_defined_symbol (h_start))
	{
	  bfd_vma vma5 = get_symbol_vma (h_start);
	  pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].VirtualAddress = vma5;

	  h_end = coff_link_hash_lookup (coff_hash_table (info), ".idata$6", false, false, true);
	  if (is_defined_symbol (h_end))
	    pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].Size = get_symbol_vma (h_end) - vma5;
	  else
	    {
	      _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: %s is missing"), abfd, PE_IMPORT_ADDRESS_TABLE, ".idata$6");
	      result = false;
	    }
	}
      else
	{
	  _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: %s is missing"), abfd, PE_IMPORT_ADDRESS_TABLE, ".idata$5");
	  result = false;
	}
    }
  else
    {
      h_start = coff_link_hash_lookup (coff_hash_table (info), "__IAT_start__", false, false, true);
      if (is_defined_symbol (h_start))
	{
	  bfd_vma iat_va = get_symbol_vma (h_start);
	  h_end = coff_link_hash_lookup (coff_hash_table (info), "__IAT_end__", false, false, true);
	  if (is_defined_symbol (h_end))
	    {
	      bfd_vma size = get_symbol_vma (h_end) - iat_va;
	      pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].Size = size;
	      if (size != 0)
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

  h_start = coff_link_hash_lookup (coff_hash_table (info), "__DELAY_IMPORT_DIRECTORY_start__", false, false, true);
  if (is_defined_symbol (h_start))
    {
      bfd_vma delay_va = get_symbol_vma (h_start);
      h_end = coff_link_hash_lookup (coff_hash_table (info), "__DELAY_IMPORT_DIRECTORY_end__", false, false, true);
      if (is_defined_symbol (h_end))
	{
	  bfd_vma size = get_symbol_vma (h_end) - delay_va;
	  pe_data (abfd)->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR].Size = size;
	  if (size != 0)
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

  char name[32];
  const char leading_char = bfd_get_symbol_leading_char (abfd);
  if (leading_char != '\0')
    snprintf (name, sizeof (name), "%c_tls_used", leading_char);
  else
    snprintf (name, sizeof (name), "_tls_used");

  struct coff_link_hash_entry *h = coff_link_hash_lookup (coff_hash_table (info), name, false, false, true);
  if (h != NULL)
    {
      if (is_defined_symbol (h))
	{
	  pe_data (abfd)->pe_opthdr.DataDirectory[PE_TLS_TABLE].VirtualAddress =
	    get_symbol_vma (h) - pe_data (abfd)->pe_opthdr.ImageBase;
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
	  pe_data (abfd)->pe_opthdr.DataDirectory[PE_TLS_TABLE].Size = 0x18;
#else
	  pe_data (abfd)->pe_opthdr.DataDirectory[PE_TLS_TABLE].Size = 0x28;
#endif
	}
      else
	{
	  _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
			      abfd, PE_TLS_TABLE, name);
	  result = false;
	}
    }

  if (leading_char != '\0')
    snprintf (name, sizeof (name), "%c_load_config_used", leading_char);
  else
    snprintf (name, sizeof (name), "_load_config_used");

  h = coff_link_hash_lookup (coff_hash_table (info), name, false, false, true);
  if (h != NULL)
    {
      if (is_defined_symbol (h))
	{
	  bfd_vma vma = get_symbol_vma (h);
	  pe_data (abfd)->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].VirtualAddress =
	    vma - pe_data (abfd)->pe_opthdr.ImageBase;

	  unsigned int align_mask = (bfd_arch_bits_per_address (abfd) / bfd_arch_bits_per_byte (abfd)) - 1;
	  if ((vma & align_mask) != 0)
	    {
	      _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: %s not properly aligned"),
				  abfd, PE_LOAD_CONFIG_TABLE, name);
	      result = false;
	    }

	  char data[4];
	  asection *sec = h->root.u.def.section;
	  bfd_vma offset = sec->output_offset + h->root.u.def.value;
	  if (bfd_get_section_contents (abfd, sec->output_section, data, offset, 4))
	    {
	      uint32_t size = bfd_get_32 (abfd, data);
	      pe_data (abfd)->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].Size =
		is_legacy_windows_x86 (abfd) ? 64 : size;

	      if (size > sec->size - h->root.u.def.value)
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
  asection *pdata_sec = bfd_get_section_by_name (abfd, ".pdata");
  if (pdata_sec != NULL && pdata_sec->rawsize > 0)
    {
      bfd_byte *pdata_contents = NULL;
      if (bfd_malloc_and_get_section (abfd, pdata_sec, &pdata_contents))
	{
	  const size_t entry_size = 12;
	  qsort (pdata_contents, (size_t) (pdata_sec->rawsize / entry_size),
		 entry_size, sort_x64_pdata);
	  bfd_set_section_contents (pfinfo->output_bfd, pdata_sec,
				    pdata_contents, 0, pdata_sec->rawsize);
	  free (pdata_contents);
	}
      else
	result = false;
    }
#endif

  rsrc_process_section (abfd, pfinfo);

  return result;
}
