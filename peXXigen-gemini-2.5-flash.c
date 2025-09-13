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
  if (in->n_sclass == C_SECTION)
    {
      char namebuf[SYMNMLEN + 1];
      const char *name = NULL;
      asection *sec = NULL;

      in->n_value = 0x0;

      if (in->n_scnum == 0)
        {
          name = _bfd_coff_internal_syment_name (abfd, in, namebuf);
          if (name == NULL)
            {
              _bfd_error_handler (_("%pB: unable to find name for empty section"), abfd);
              bfd_set_error (bfd_error_invalid_target);
              return;
            }

          sec = bfd_get_section_by_name (abfd, name);
          if (sec != NULL)
            {
              in->n_scnum = sec->target_index;
            }
          else
            {
              int unused_section_number = 0;
              flagword flags;
              size_t name_len;
              char *sec_name;
              asection *temp_sec;

              for (temp_sec = abfd->sections; temp_sec; temp_sec = temp_sec->next)
                if (unused_section_number <= temp_sec->target_index)
                  unused_section_number = temp_sec->target_index + 1;

              name_len = strlen (name) + 1;
              sec_name = bfd_alloc (abfd, name_len);
              if (sec_name == NULL)
                {
                  _bfd_error_handler (_("%pB: out of memory creating name for empty section"), abfd);
                  return;
                }
              memcpy (sec_name, name, name_len);

              flags = (SEC_HAS_CONTENTS | SEC_ALLOC | SEC_DATA | SEC_LOAD
                       | SEC_LINKER_CREATED);
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
        }
      in->n_sclass = C_STAT;
    }
#endif
}

static bool
abs_finder (bfd * abfd ATTRIBUTE_UNUSED, asection * sec, void * data)
{
  static const bfd_vma BFD_32BIT_ADDRESS_SPACE_WINDOW_SIZE = (1ULL << 32);

  const bfd_vma abs_val = * (const bfd_vma *) data;

  const bfd_vma region_upper_bound = sec->vma + BFD_32BIT_ADDRESS_SPACE_WINDOW_SIZE;

  return (sec->vma <= abs_val) && (region_upper_bound > abs_val);
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
    memcpy (ext->e.e.name, in->_n._n_name, SYMNMLEN);

  if (sizeof (in->n_value) > 4 && in->n_scnum == N_ABS && in->n_value > 0xFFFFFFFFUL)
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
    H_PUT_16 (abfd, in->n_type, ext->e_type);
  else
    H_PUT_32 (abfd, in->n_type, ext->e_type);

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

  if ((in_class == C_STAT || in_class == C_LEAFSTAT || in_class == C_HIDDEN) && type == T_NULL)
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
  int i;

  memset (ext, 0, AUXESZ);

  if (in_class == C_FILE)
    {
      if (in->x_file.x_n.x_fname[0] == 0)
	{
	  H_PUT_32 (abfd, 0, ext->x_file.x_n.x_zeroes);
	  H_PUT_32 (abfd, in->x_file.x_n.x_n.x_offset, ext->x_file.x_n.x_offset);
	}
      else
#if FILNMLEN != E_FILNMLEN
#error we need to cope with truncating or extending x_fname
#endif
	memcpy (ext->x_file.x_fname, in->x_file.x_n.x_fname, E_FILNMLEN);

      return AUXESZ;
    }

  if ((in_class == C_STAT || in_class == C_LEAFSTAT || in_class == C_HIDDEN)
      && type == T_NULL)
    {
      PUT_SCN_SCNLEN (abfd, in->x_scn.x_scnlen, ext);
      PUT_SCN_NRELOC (abfd, in->x_scn.x_nreloc, ext);
      PUT_SCN_NLINNO (abfd, in->x_scn.x_nlinno, ext);
      H_PUT_32 (abfd, in->x_scn.x_checksum, ext->x_scn.x_checksum);
      H_PUT_16 (abfd, in->x_scn.x_associated, ext->x_scn.x_associated);
      H_PUT_8 (abfd, in->x_scn.x_comdat, ext->x_scn.x_comdat);
      return AUXESZ;
    }

  /* Fall through cases for C_STAT, C_LEAFSTAT, C_HIDDEN when type != T_NULL
     and all other in_class values.  */

  H_PUT_32 (abfd, in->x_sym.x_tagndx.u32, ext->x_sym.x_tagndx);
  H_PUT_16 (abfd, in->x_sym.x_tvndx, ext->x_sym.x_tvndx);

  if (in_class == C_BLOCK || in_class == C_FCN || ISFCN (type)
      || ISTAG (in_class))
    {
      PUT_FCN_LNNOPTR (abfd, in->x_sym.x_fcnary.x_fcn.x_lnnoptr,  ext);
      PUT_FCN_ENDNDX  (abfd, in->x_sym.x_fcnary.x_fcn.x_endndx.u32, ext);
    }
  else
    {
      for (i = 0; i < 4; ++i)
	{
	  H_PUT_16 (abfd, in->x_sym.x_fcnary.x_ary.x_dimen[i],
		    ext->x_sym.x_fcnary.x_ary.x_dimen[i]);
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
_bfd_XXi_swap_lineno_in (bfd * abfd, void * ext1, void * in1)
{
  if (abfd == NULL || ext1 == NULL || in1 == NULL)
    {
      return;
    }

  LINENO *ext = (LINENO *) ext1;
  struct internal_lineno *in = (struct internal_lineno *) in1;

  in->l_addr.l_symndx = H_GET_32 (abfd, ext->l_addr.l_symndx);
  in->l_lnno = GET_LINENO_LNNO (abfd, ext);
}

unsigned int
_bfd_XXi_swap_lineno_out (bfd * abfd,
                         const struct internal_lineno *in_lineno,
                         struct external_lineno *ext_lineno)
{
  H_PUT_32 (abfd, in_lineno->l_addr.l_symndx, ext_lineno->l_addr.l_symndx);

  PUT_LINENO_LNNO (abfd, in_lineno->l_lnno, ext_lineno);
  return LINESZ;
}

void
_bfd_XXi_swap_aouthdr_in (bfd * abfd,
                          const void * aouthdr_ext1,
                          void * aouthdr_int1)
{
  const PEAOUTHDR * src = (const PEAOUTHDR *) aouthdr_ext1;
  const AOUTHDR * aouthdr_ext = (const AOUTHDR *) aouthdr_ext1;
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
  a->SizeOfCode = aouthdr_int->tsize ;
  a->SizeOfInitializedData = aouthdr_int->dsize ;
  a->SizeOfUninitializedData = aouthdr_int->bsize ;
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
  unsigned idx;
  for (idx = 0;
       idx < a->NumberOfRvaAndSizes && idx < IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
       idx++)
    {
      /* If data directory is empty, rva also should be 0.  */
      int size = H_GET_32 (abfd, src->DataDirectory[idx][1]);
      int vma = size ? H_GET_32 (abfd, src->DataDirectory[idx][0]) : 0;

      a->DataDirectory[idx].Size = size;
      a->DataDirectory[idx].VirtualAddress = vma;
    }

  while (idx < IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
    {
      a->DataDirectory[idx].Size = 0;
      a->DataDirectory[idx].VirtualAddress = 0;
      idx++;
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
		const char *name,
		bfd_vma base)
{
  if (abfd == NULL || aout == NULL || name == NULL)
    {
      return;
    }

  asection *sec = bfd_get_section_by_name (abfd, name);
  if (sec == NULL)
    {
      return;
    }

  struct coff_section_info *coff_data = coff_section_data (abfd, sec);
  struct internal_extra_pe_section_data *pei_data = pei_section_data (abfd, sec);

  if (coff_data == NULL || pei_data == NULL)
    {
      return;
    }

  int size = pei_data->virt_size;
  aout->DataDirectory[idx].Size = (unsigned int)size;

  if (size != 0)
    {
      aout->DataDirectory[idx].VirtualAddress = (unsigned int)((sec->vma - base) & 0xffffffffU);
      sec->flags |= SEC_DATA;
    }
}

static inline void
bfd_pe_adjust_vma_and_truncate(bfd_vma *addr, bfd_vma image_base)
{
  if (*addr)
    {
      *addr -= image_base;
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
      *addr &= 0xffffffff;
#endif
    }
}

static inline void
bfd_pe_put_linker_version(bfd *abfd, const struct internal_extra_pe_aouthdr *extra, PEAOUTHDR *aouthdr_out)
{
  if (extra->MajorLinkerVersion || extra->MinorLinkerVersion)
    {
      H_PUT_8 (abfd, extra->MajorLinkerVersion, aouthdr_out->standard.vstamp);
      H_PUT_8 (abfd, extra->MinorLinkerVersion, aouthdr_out->standard.vstamp + 1);
    }
  else
    {
#define BFD_LINKER_MAJOR_VERSION ((unsigned short) (BFD_VERSION / 100000000))
#define BFD_LINKER_MINOR_VERSION ((unsigned short) ((BFD_VERSION / 1000000) % 100))

      unsigned short linker_maj = BFD_LINKER_MAJOR_VERSION;
      unsigned short linker_min = BFD_LINKER_MINOR_VERSION;

      H_PUT_16 (abfd, (linker_maj + linker_min * 256), aouthdr_out->standard.vstamp);

#undef BFD_LINKER_MAJOR_VERSION
#undef BFD_LINKER_MINOR_VERSION
    }
}

unsigned int
_bfd_XXi_swap_aouthdr_out (bfd * abfd, void * in, void * out)
{
  struct internal_aouthdr *aouthdr_in = (struct internal_aouthdr *) in;
  pe_data_type *pe = pe_data (abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
  PEAOUTHDR *aouthdr_out = (PEAOUTHDR *) out;

  bfd_vma section_align = extra->SectionAlignment;
  bfd_vma file_align = extra->FileAlignment;
  bfd_vma image_base = extra->ImageBase;

#define ALIGN_TO_FILE(x) (((x) + file_align - 1) & -(file_align))
#define ALIGN_TO_SECTION(x) (((x) + section_align - 1) & -(section_align))

  bfd_pe_adjust_vma_and_truncate(&aouthdr_in->text_start, image_base);
  bfd_pe_adjust_vma_and_truncate(&aouthdr_in->data_start, image_base);
  bfd_pe_adjust_vma_and_truncate(&aouthdr_in->entry, image_base);

  aouthdr_in->bsize = ALIGN_TO_FILE(aouthdr_in->bsize);

  extra->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

  add_data_entry (abfd, extra, PE_EXPORT_TABLE, ".edata", image_base);
  add_data_entry (abfd, extra, PE_RESOURCE_TABLE, ".rsrc", image_base);
  add_data_entry (abfd, extra, PE_EXCEPTION_TABLE, ".pdata", image_base);

  if (extra->DataDirectory[PE_IMPORT_TABLE].VirtualAddress == 0)
    add_data_entry (abfd, extra, PE_IMPORT_TABLE, ".idata", image_base);

  if (pe->has_reloc_section)
    add_data_entry (abfd, extra, PE_BASE_RELOCATION_TABLE, ".reloc", image_base);

  {
    asection *sec;
    bfd_vma header_size = 0;
    bfd_vma data_total_size = 0;
    bfd_vma text_total_size = 0;
    bfd_vma image_total_size = 0;
    bfd_vma last_section_vma = 0;
    bfd_vma last_section_virt_size = 0;

    for (sec = abfd->sections; sec; sec = sec->next)
      {
	bfd_vma rounded_size = ALIGN_TO_FILE(sec->size);

	if (rounded_size == 0)
	  continue;

	if (header_size == 0)
	  header_size = sec->filepos;
	if (sec->flags & SEC_DATA)
	  data_total_size += rounded_size;
	if (sec->flags & SEC_CODE)
	  text_total_size += rounded_size;

	if (coff_section_data (abfd, sec) != NULL
	    && pei_section_data (abfd, sec) != NULL)
	  {
	    last_section_vma = sec->vma;
	    last_section_virt_size = pei_section_data (abfd, sec)->virt_size;
	  }
      }

    aouthdr_in->dsize = data_total_size;
    aouthdr_in->tsize = text_total_size;
    extra->SizeOfHeaders = header_size;

    if (last_section_vma > 0 || last_section_virt_size > 0)
      {
	image_total_size = ALIGN_TO_SECTION(last_section_vma - image_base + ALIGN_TO_FILE(last_section_virt_size));
      }
    else
      {
	image_total_size = ALIGN_TO_SECTION(header_size);
      }
    extra->SizeOfImage = image_total_size;
  }

  H_PUT_16 (abfd, aouthdr_in->magic, aouthdr_out->standard.magic);

  bfd_pe_put_linker_version(abfd, extra, aouthdr_out);

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

#undef ALIGN_TO_FILE
#undef ALIGN_TO_SECTION

  return AOUTSZ;
}

unsigned int
_bfd_XXi_only_swap_filehdr_out (bfd * abfd, void * in, void * out)
{
  struct internal_filehdr *filehdr_in = (struct internal_filehdr *) in;
  struct external_PEI_filehdr *filehdr_out = (struct external_PEI_filehdr *) out;
  struct bfd_pe_data *ped = pe_data (abfd);

  if (ped->has_reloc_section || ped->dont_strip_reloc)
    filehdr_in->f_flags &= ~F_RELFLG;

  if (ped->dll)
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

  memcpy (filehdr_in->pe.dos_message, ped->dos_message,
	  sizeof (filehdr_in->pe.dos_message));

  filehdr_in->pe.nt_signature = IMAGE_NT_SIGNATURE;

  H_PUT_16 (abfd, filehdr_in->f_magic, filehdr_out->f_magic);
  H_PUT_16 (abfd, filehdr_in->f_nscns, filehdr_out->f_nscns);

  time_t timestamp_value;
  if (ped->timestamp == (time_t)-1)
    {
      timestamp_value = bfd_get_current_time (0);
    }
  else
    {
      timestamp_value = ped->timestamp;
    }
  H_PUT_32 (abfd, timestamp_value, filehdr_out->f_timdat);

  PUT_FILEHDR_SYMPTR (abfd, filehdr_in->f_symptr,
		      filehdr_out->f_symptr);
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

static const struct {
    const char *section_name_str;
    unsigned long must_have;
} known_pe_section_flags[] =
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
_bfd_XXi_swap_scnhdr_out (bfd * abfd, void * in, void * out)
{
  struct internal_scnhdr *scnhdr_int = (struct internal_scnhdr *) in;
  SCNHDR *scnhdr_ext = (SCNHDR *) out;
  unsigned int ret = SCNHSZ;
  bfd_vma virtual_size_val;
  bfd_vma raw_data_size_val;
  unsigned long section_flags = scnhdr_int->s_flags;

  memcpy (scnhdr_ext->s_name, scnhdr_int->s_name, sizeof (scnhdr_int->s_name));

  bfd_vma rva_val = scnhdr_int->s_vaddr - pe_data (abfd)->pe_opthdr.ImageBase;
  if (scnhdr_int->s_vaddr < pe_data (abfd)->pe_opthdr.ImageBase) {
    _bfd_error_handler (_("%pB:%.8s: section below image base"),
                        abfd, scnhdr_int->s_name);
  }
#if !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
  else if (rva_val != (rva_val & 0xffffffffU)) {
    _bfd_error_handler (_("%pB:%.8s: RVA truncated"), abfd, scnhdr_int->s_name);
  }
  PUT_SCNHDR_VADDR (abfd, rva_val & 0xffffffffU, scnhdr_ext->s_vaddr);
#else
  PUT_SCNHDR_VADDR (abfd, rva_val, scnhdr_ext->s_vaddr);
#endif

  if ((section_flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0) {
      if (bfd_pei_p (abfd)) {
          virtual_size_val = scnhdr_int->s_size;
          raw_data_size_val = 0;
      } else {
          virtual_size_val = 0;
          raw_data_size_val = scnhdr_int->s_size;
      }
  } else {
      if (bfd_pei_p (abfd)) {
          virtual_size_val = scnhdr_int->s_paddr;
      } else {
          virtual_size_val = 0;
      }
      raw_data_size_val = scnhdr_int->s_size;
  }

  PUT_SCNHDR_SIZE (abfd, raw_data_size_val, scnhdr_ext->s_size);
  PUT_SCNHDR_PADDR (abfd, virtual_size_val, scnhdr_ext->s_paddr);

  PUT_SCNHDR_SCNPTR (abfd, scnhdr_int->s_scnptr, scnhdr_ext->s_scnptr);
  PUT_SCNHDR_RELPTR (abfd, scnhdr_int->s_relptr, scnhdr_ext->s_relptr);
  PUT_SCNHDR_LNNOPTR (abfd, scnhdr_int->s_lnnoptr, scnhdr_ext->s_lnnoptr);

  {
    size_t i;
    for (i = 0; i < ARRAY_SIZE (known_pe_section_flags); i++) {
      const char *known_name = known_pe_section_flags[i].section_name_str;
      if (memcmp (scnhdr_int->s_name, known_name, SCNNMLEN) == 0) {
        section_flags |= known_pe_section_flags[i].must_have;

        if (memcmp (scnhdr_int->s_name, ".text", SCNNMLEN) == 0) {
            if (bfd_get_file_flags (abfd) & WP_TEXT) {
                section_flags &= ~IMAGE_SCN_MEM_WRITE;
            }
        }
        break;
      }
    }
  }

  if (coff_data (abfd) != NULL
      && coff_data (abfd)->link_info != NULL
      && !bfd_link_relocatable (coff_data (abfd)->link_info)
      && !bfd_link_pic (coff_data (abfd)->link_info)
      && memcmp (scnhdr_int->s_name, ".text", SCNNMLEN) == 0) {
      H_PUT_16 (abfd, (scnhdr_int->s_nlnno & 0xffff), scnhdr_ext->s_nlnno);
      H_PUT_16 (abfd, (scnhdr_int->s_nlnno >> 16), scnhdr_ext->s_nreloc);
  } else {
      if (scnhdr_int->s_nlnno <= 0xffff) {
          H_PUT_16 (abfd, scnhdr_int->s_nlnno, scnhdr_ext->s_nlnno);
      } else {
          _bfd_error_handler (_("%pB: line number overflow: 0x%lx > 0xffff"),
                              abfd, (unsigned long)scnhdr_int->s_nlnno);
          bfd_set_error (bfd_error_file_truncated);
          H_PUT_16 (abfd, 0xffff, scnhdr_ext->s_nlnno);
          ret = 0;
      }

      if (scnhdr_int->s_nreloc < 0xffff) {
          H_PUT_16 (abfd, scnhdr_int->s_nreloc, scnhdr_ext->s_nreloc);
      } else {
          H_PUT_16 (abfd, 0xffff, scnhdr_ext->s_nreloc);
          section_flags |= IMAGE_SCN_LNK_NRELOC_OVFL;
      }
  }

  H_PUT_32 (abfd, section_flags, scnhdr_ext->s_flags);

  return ret;
}

void
_bfd_XXi_swap_debugdir_in (bfd * abfd,
                            const struct external_IMAGE_DEBUG_DIRECTORY *ext,
                            struct internal_IMAGE_DEBUG_DIRECTORY *in)
{
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
_bfd_XXi_swap_debugdir_out (bfd * abfd, const void * inp, void * extp)
{
  if (abfd == NULL || inp == NULL || extp == NULL)
    {
      return 0;
    }

  const struct internal_IMAGE_DEBUG_DIRECTORY *in = (const struct internal_IMAGE_DEBUG_DIRECTORY *) inp;
  struct external_IMAGE_DEBUG_DIRECTORY *ext = (struct external_IMAGE_DEBUG_DIRECTORY *) extp;

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
_bfd_XXi_slurp_codeview_record (bfd * abfd, file_ptr where, unsigned long length,
                                CODEVIEW_INFO *cvinfo, char **pdb)
{
  /* Define constants for buffer size and maximum data length to read.
     The original code's `buffer[256+1]` and `length = 256` implies
     a fixed maximum read length of 256 bytes for the record data,
     with an additional byte for a null terminator. */
#define CODEVIEW_MAX_RECORD_DATA_READ_LENGTH 256
#define CODEVIEW_RECORD_BUFFER_SIZE (CODEVIEW_MAX_RECORD_DATA_READ_LENGTH + 1)

  char buffer[CODEVIEW_RECORD_BUFFER_SIZE];
  bfd_size_type nread_bytes;
  unsigned long bytes_to_read = length;

  /* Basic validation of required input pointers. */
  if (abfd == NULL || cvinfo == NULL)
    return NULL;

  /* Seek to the record's starting position in the BFD stream. */
  if (bfd_seek (abfd, where, SEEK_SET) != 0)
    return NULL;

  /* Truncate the amount to read if the provided length exceeds our fixed-size buffer's
     data capacity. This behavior mirrors the original code, preventing buffer
     overflows during `bfd_read` but also implicitly truncating larger records. */
  if (bytes_to_read > CODEVIEW_MAX_RECORD_DATA_READ_LENGTH)
    bytes_to_read = CODEVIEW_MAX_RECORD_DATA_READ_LENGTH;

  /* Validate that the amount of data we intend to read is at least sufficient
     for the smallest possible CodeView record header plus a null terminator
     for the PdbFileName string.
     The original condition `length <= sizeof (CV_INFO_PDB70) && length <= sizeof (CV_INFO_PDB20)`
     effectively meant that `length` must be strictly greater than
     `MIN(sizeof(CV_INFO_PDB70), sizeof(CV_INFO_PDB20))` to proceed.
     Assuming `CV_INFO_PDB20` is the smaller fixed-size header.
     A record needs its fixed header size plus at least 1 byte for the filename's null terminator. */
#define CODEVIEW_MIN_VALID_RECORD_LENGTH (sizeof(CV_INFO_PDB20) + 1)
  if (bytes_to_read < CODEVIEW_MIN_VALID_RECORD_LENGTH)
    return NULL;

  /* Read the record data into the buffer. */
  nread_bytes = bfd_read (buffer, bytes_to_read, abfd);
  if (bytes_to_read != nread_bytes)
    return NULL; /* Failed to read the expected number of bytes. */

  /* Ensure null termination of the string part within the buffer.
     This is safe because `nread_bytes` is at most `CODEVIEW_MAX_RECORD_DATA_READ_LENGTH`,
     so `buffer + nread_bytes` will always point within the allocated `buffer`. */
  memset (buffer + nread_bytes, 0, sizeof (buffer) - nread_bytes);

  /* Read the common CodeView signature field. */
  cvinfo->CVSignature = H_GET_32 (abfd, buffer);
  cvinfo->Age = 0; /* Initialize Age, it will be overwritten if a valid format is found. */

  /* Process PDB70 format if the signature matches and enough data was read
     for its fixed part (header plus at least one byte for filename). */
  if ((cvinfo->CVSignature == CVINFO_PDB70_CVSIGNATURE)
      && (nread_bytes > sizeof (CV_INFO_PDB70)))
    {
      /* The buffer holds raw bytes from the file. Casting to a struct pointer
         is a common pattern in BFD for parsing byte streams, relying on
         `H_GET_32`, `bfd_getlXX`, `bfd_putbXX`, and `memcpy` to handle endianness
         and potentially unaligned access safely. */
      const CV_INFO_PDB70 *cvinfo70_ptr = (const CV_INFO_PDB70 *)(const void *)buffer;

      cvinfo->Age = H_GET_32(abfd, cvinfo70_ptr->Age);

      /* Perform GUID byte swapping for the PDB70 signature.
         This sequence correctly reorders the GUID fields from little-endian
         (as stored in the file) to the target platform's representation. */
      bfd_putb32 (bfd_getl32 (cvinfo70_ptr->Signature), cvinfo->Signature);
      bfd_putb16 (bfd_getl16 (&(cvinfo70_ptr->Signature[4])), &(cvinfo->Signature[4]));
      bfd_putb16 (bfd_getl16 (&(cvinfo70_ptr->Signature[6])), &(cvinfo->Signature[6]));
      memcpy (&(cvinfo->Signature[8]), &(cvinfo70_ptr->Signature[8]), 8);

      cvinfo->SignatureLength = CV_INFO_SIGNATURE_LENGTH;

      /* Duplicate the PdbFileName string if `pdb` pointer is provided.
         The filename string starts immediately after the fixed part of `CV_INFO_PDB70`. */
      if (pdb != NULL)
        *pdb = xstrdup ((const char *)(cvinfo70_ptr->PdbFileName));

      return cvinfo;
    }
  /* Process PDB20 format if the signature matches and enough data was read
     for its fixed part. */
  else if ((cvinfo->CVSignature == CVINFO_PDB20_CVSIGNATURE)
	   && (nread_bytes > sizeof (CV_INFO_PDB20)))
    {
      const CV_INFO_PDB20 *cvinfo20_ptr = (const CV_INFO_PDB20 *)(const void *)buffer;

      cvinfo->Age = H_GET_32(abfd, cvinfo20_ptr->Age);
      /* PDB20 signature is simpler; directly copy its 4 bytes. */
      memcpy (cvinfo->Signature, cvinfo20_ptr->Signature, 4);
      cvinfo->SignatureLength = 4;

      /* Duplicate the PdbFileName string if `pdb` pointer is provided. */
      if (pdb != NULL)
	*pdb = xstrdup ((const char *)(cvinfo20_ptr->PdbFileName));

      return cvinfo;
    }

  /* Return NULL if no valid CodeView record format was recognized or processed. */
  return NULL;
}

#undef CODEVIEW_MAX_RECORD_DATA_READ_LENGTH
#undef CODEVIEW_RECORD_BUFFER_SIZE
#undef CODEVIEW_MIN_VALID_RECORD_LENGTH

unsigned int
_bfd_XXi_write_codeview_record (bfd * abfd, file_ptr where, CODEVIEW_INFO *cvinfo,
				const char *pdb)
{
  size_t pdb_len;
  size_t total_size;
  size_t written_bytes;
  CV_INFO_PDB70 *cvinfo70_buf = NULL;

  pdb_len = (pdb != NULL) ? strlen(pdb) : 0;
  total_size = sizeof(CV_INFO_PDB70) + pdb_len + 1;

  if (bfd_seek(abfd, where, SEEK_SET) != 0)
    {
      return 0;
    }

  cvinfo70_buf = (CV_INFO_PDB70 *) bfd_malloc(total_size);
  if (cvinfo70_buf == NULL)
    {
      return 0;
    }

  H_PUT_32(abfd, CVINFO_PDB70_CVSIGNATURE, cvinfo70_buf->CvSignature);

  bfd_putl32(bfd_getb32(cvinfo->Signature), cvinfo70_buf->Signature);
  bfd_putl16(bfd_getb16(&(cvinfo->Signature[4])), &(cvinfo70_buf->Signature[4]));
  bfd_putl16(bfd_getb16(&(cvinfo->Signature[6])), &(cvinfo70_buf->Signature[6]));
  memcpy(&(cvinfo70_buf->Signature[8]), &(cvinfo->Signature[8]), 8);

  H_PUT_32(abfd, cvinfo->Age, cvinfo70_buf->Age);

  if (pdb == NULL)
    {
      cvinfo70_buf->PdbFileName[0] = '\0';
    }
  else
    {
      memcpy(cvinfo70_buf->PdbFileName, pdb, pdb_len + 1);
    }

  written_bytes = bfd_write(cvinfo70_buf, total_size, abfd);

  free(cvinfo70_buf);

  if (written_bytes != total_size)
    {
      return 0;
    }

  return (unsigned int) total_size;
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
  if ((section->flags & SEC_HAS_CONTENTS) == 0) {
    return false;
  }

  if (dataoff > section->size || datasize > section->size - dataoff) {
    return false;
  }

  ufile_ptr filesize = bfd_get_file_size (abfd);

  if (filesize != 0) {
    ufile_ptr section_start_in_file = (ufile_ptr) section->filepos;

    if (section_start_in_file > filesize) {
      return false;
    }

    // Check if the data offset from the section's start position in the file
    // extends beyond the file's boundary.
    // This avoids explicit addition (section_start_in_file + dataoff) which could overflow,
    // by comparing `dataoff` to the remaining file space.
    if (dataoff > filesize - section_start_in_file) {
      return false;
    }

    // Check if the data size, when added to the data's start position in the file,
    // extends beyond the file's boundary.
    // This also avoids explicit addition (section_start_in_file + dataoff + datasize)
    // by comparing `datasize` to the remaining file space after the data's start.
    if (datasize > filesize - section_start_in_file - dataoff) {
      return false;
    }
  }

  return true;
}

static asection *
find_pe_section_by_rva_and_size (bfd *abfd, bfd_vma rva, bfd_vma image_base, bfd_size_type *out_section_size)
{
  bfd_vma va = rva + image_base;
  asection *section;

  for (section = abfd->sections; section != NULL; section = section->next)
    {
      if (va >= section->vma && va < section->vma + section->size)
        {
          if (out_section_size != NULL)
            *out_section_size = section->size;
          return section;
        }
    }
  return NULL;
}

static bool
pe_print_idata (bfd * abfd, void * vfile)
{
  FILE *file = (FILE *) vfile;
  bfd_byte *data = NULL;
  asection *section = NULL;
  bfd_signed_vma section_rva_base; // RVA of the section's VMA (section->vma - ImageBase)
  bfd_size_type section_content_size = 0; // Size of the section containing the import table
  bfd_vma import_table_va = 0; // Virtual Address of the import table
  bfd_size_type import_table_offset_in_section = 0; // Offset of the import table data within the section content

  pe_data_type *pe = pe_data (abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;

  bfd_vma data_directory_rva = extra->DataDirectory[PE_IMPORT_TABLE].VirtualAddress;
  bfd_size_type data_directory_size = extra->DataDirectory[PE_IMPORT_TABLE].Size;

  // Determine the section containing the import table
  if (data_directory_rva == 0 && data_directory_size == 0)
    {
      // Case 1: DataDirectory entry is zero, try to find ".idata" section by name
      section = bfd_get_section_by_name (abfd, ".idata");
      if (section == NULL)
        {
          return true; // No .idata section found, nothing to print.
        }

      if (!(section->flags & SEC_HAS_CONTENTS))
        {
          return true; // .idata section found but has no contents.
        }

      import_table_va = section->vma;
      section_content_size = section->size;
      if (section_content_size == 0)
        {
          return true;
        }
    }
  else
    {
      // Case 2: DataDirectory entry exists, find section by RVA
      section = find_pe_section_by_rva_and_size (abfd, data_directory_rva, extra->ImageBase, &section_content_size);
      if (section == NULL)
        {
          fprintf (file,
                   _("\nThere is an import table, but the section containing it could not be found\n"));
          return true;
        }

      if (!(section->flags & SEC_HAS_CONTENTS))
        {
          fprintf (file,
                   _("\nThere is an import table in %s, but that section has no contents\n"),
                   section->name);
          return true;
        }
      import_table_va = section->vma;
    }

  // xgettext:c-format
  fprintf (file, _("\nThere is an import table in %s at 0x%lx\n"),
           section->name, (unsigned long) import_table_va);

  // Calculate the offset of the import table within the section's contents (data buffer).
  if (data_directory_rva == 0 && data_directory_size == 0)
    {
      // If found by .idata name, the import table starts at the beginning of the section's data.
      import_table_offset_in_section = 0;
    }
  else
    {
      // If found by DataDirectory RVA, calculate its offset relative to the section's VMA.
      // (data_directory_rva + ImageBase) is the VA of the import table.
      // (VA of import table) - (VA of section start) is the offset.
      import_table_offset_in_section = (data_directory_rva + extra->ImageBase) - section->vma;
    }

  // Sanity check on calculated offset. This offset is into the `data` buffer.
  if (import_table_offset_in_section < 0 || import_table_offset_in_section >= section_content_size) {
      fprintf (file,
               _("\nInternal error: Import table offset (0x%lx) out of bounds for section %s (Size 0x%lx)\n"),
               (unsigned long) import_table_offset_in_section, section->name,
               (unsigned long) section_content_size);
      return true; // Cannot parse if the table is misplaced.
  }

  fprintf (file,
           _("\nThe Import Tables (interpreted %s section contents)\n"),
           section->name);
  fprintf (file,
           _("\
 vma:            Hint    Time      Forward  DLL       First\n\
                 Table   Stamp     Chain    Name      Thunk\n"));

  // Read the entire section's contents.
  if (!bfd_malloc_and_get_section (abfd, section, &data))
    {
      return false; // Critical error: cannot read section.
    }

  // section_rva_base is the RVA of the section's starting VMA.
  // It's used to convert RVAs (like dll_name_rva) into offsets within the `data` buffer.
  // data_buffer_offset = RVA - section_rva_base
  section_rva_base = section->vma - extra->ImageBase;

  // Print all image import descriptors.
  bfd_size_type i;
  for (i = import_table_offset_in_section;
       i + 20 <= section_content_size; // 20 is IMAGE_IMPORT_DESCRIPTOR_SIZE
       i += 20)
    {
      bfd_vma descriptor_rva_base = (section->vma - extra->ImageBase) + i; // RVA of current descriptor
      bfd_vma hint_table_rva = bfd_get_32 (abfd, data + i + 0); // IMAGE_IMPORT_DESCRIPTOR_HINT_RVA_OFFSET
      bfd_vma time_stamp = bfd_get_32 (abfd, data + i + 4); // IMAGE_IMPORT_DESCRIPTOR_TIME_STAMP_OFFSET
      bfd_vma forward_chain_rva = bfd_get_32 (abfd, data + i + 8); // IMAGE_IMPORT_DESCRIPTOR_FORWARD_CHAIN_OFFSET
      bfd_vma dll_name_rva = bfd_get_32 (abfd, data + i + 12); // IMAGE_IMPORT_DESCRIPTOR_DLL_NAME_RVA_OFFSET
      bfd_vma first_thunk_rva = bfd_get_32 (abfd, data + i + 16); // IMAGE_IMPORT_DESCRIPTOR_FIRST_THUNK_RVA_OFFSET

      fprintf (file, " %08lx\t", (unsigned long) (descriptor_rva_base));
      fprintf (file, "%08lx %08lx %08lx %08lx %08lx\n",
               (unsigned long) hint_table_rva,
               (unsigned long) time_stamp,
               (unsigned long) forward_chain_rva,
               (unsigned long) dll_name_rva,
               (unsigned long) first_thunk_rva);

      if (hint_table_rva == 0 && first_thunk_rva == 0)
        break; // End of import descriptor list

      // Print DLL Name
      // Convert dll_name_rva to an offset within the current section's data.
      bfd_size_type dll_name_offset = dll_name_rva - section_rva_base;
      if (dll_name_offset < 0 || dll_name_offset >= section_content_size)
        {
          fprintf (file, _("\n\tDLL Name: <corrupt RVA: 0x%lx>\n"), (unsigned long) dll_name_rva);
        }
      else
        {
          char *dll_str = (char *) (data + dll_name_offset);
          // Calculate max length to print to avoid reading past section boundaries
          bfd_size_type max_dll_len = section_content_size - dll_name_offset;
          bfd_size_type actual_dll_len = 0;
          if (max_dll_len > 0) {
            for (actual_dll_len = 0; actual_dll_len < max_dll_len && dll_str[actual_dll_len] != '\0'; ++actual_dll_len);
          }
          if (actual_dll_len > 0) {
            fprintf (file, _("\n\tDLL Name: %.*s\n"), (int) actual_dll_len, dll_str);
          } else {
            fprintf (file, _("\n\tDLL Name: <empty or invalid string at offset 0x%lx>\n"), (unsigned long)dll_name_offset);
          }
        }

      // Determine the RVA of the Hint/Name table.
      bfd_vma current_hint_rva = (hint_table_rva != 0) ? hint_table_rva : first_thunk_rva;
      if (current_hint_rva != 0)
        {
          bfd_size_type hint_offset_in_section = current_hint_rva - section_rva_base;

          if (hint_offset_in_section < 0 || hint_offset_in_section >= section_content_size)
            {
              fprintf (file, _("\n\tHint table RVA (0x%lx) points outside its section\n"), (unsigned long) current_hint_rva);
              fprintf (file, "\n");
              continue;
            }

          bfd_byte *ft_data = data; // Pointer to the thunk data
          bfd_size_type ft_data_size_available = section_content_size;
          bfd_size_type ft_offset_in_buffer = first_thunk_rva - section_rva_base;
          bool ft_allocated = false;

          fprintf (file, _("\tvma:     Ordinal  Hint  Member-Name  Bound-To\n"));

          // If the first thunk table is in a different section than the import descriptor table
          if (first_thunk_rva != current_hint_rva)
            {
              bfd_size_type temp_ft_section_size;
              asection *temp_ft_section = find_pe_section_by_rva_and_size (abfd, first_thunk_rva, extra->ImageBase, &temp_ft_section_size);

              if (temp_ft_section == NULL)
                {
                  fprintf (file,
                           _("\nThere is a first thunk, but the section containing it could not be found\n"));
                  fprintf (file, "\n");
                  continue;
                }

              if (temp_ft_section != section)
                {
                  // Need to load data for this separate section
                  bfd_size_type temp_ft_offset_in_section = first_thunk_rva - (temp_ft_section->vma - extra->ImageBase);
                  ft_data_size_available = temp_ft_section->size - temp_ft_offset_in_section;

                  // Basic sanity check for the requested region within the section
                  if (temp_ft_offset_in_section < 0 || temp_ft_offset_in_section + ft_data_size_available > temp_ft_section->size) {
                    fprintf (file, _("\nThunk data region is invalid within section %s\n"), temp_ft_section->name);
                    fprintf (file, "\n");
                    continue;
                  }

                  ft_data = (bfd_byte *) bfd_malloc (ft_data_size_available);
                  if (ft_data == NULL)
                    {
                      fprintf (file, _("\nMemory allocation failed for thunk data\n"));
                      fprintf (file, "\n");
                      continue;
                    }
                  ft_allocated = true;

                  if (!bfd_get_section_contents (abfd, temp_ft_section, ft_data,
                                                 (bfd_vma) temp_ft_offset_in_section, ft_data_size_available))
                    {
                      free (ft_data);
                      ft_allocated = false;
                      fprintf (file, _("\nCould not read thunk data from section %s\n"), temp_ft_section->name);
                      fprintf (file, "\n");
                      continue;
                    }
                  ft_offset_in_buffer = 0; // The `ft_data` buffer now starts at the thunk data.
                }
            }
          
          // Print HintName vector entries.
          bfd_size_type j;
          for (j = 0; hint_offset_in_section + j + IMAGE_THUNK_DATA_ENTRY_SIZE <= section_content_size; j += IMAGE_THUNK_DATA_ENTRY_SIZE)
            {
              bfd_vma member_or_ordinal_rva;
#ifdef COFF_WITH_pex64
              bfd_vma member_high_val;
              member_or_ordinal_rva = bfd_get_32 (abfd, data + hint_offset_in_section + j);
              member_high_val = bfd_get_32 (abfd, data + hint_offset_in_section + j + 4);
              if (!member_or_ordinal_rva && !member_high_val)
                break; // End of list for 64-bit thunk
#else
              member_or_ordinal_rva = bfd_get_32 (abfd, data + hint_offset_in_section + j);
              if (member_or_ordinal_rva == 0)
                break; // End of list for 32-bit thunk
#endif

              // Check if it's an ordinal import (MSB of the thunk data is set)
#ifdef COFF_WITH_pex64
              if (HighBitSet (member_high_val)) // For PE32+, check MSB of upper 32-bits (bit 63)
#else
              if (HighBitSet (member_or_ordinal_rva)) // For PE32, check MSB of the 32-bit value (bit 31)
#endif
                {
                  unsigned int ordinal = member_or_ordinal_rva & 0xffff;
                  fprintf (file, "\t%08lx  %5u  <none> <none>",
                           (unsigned long)(first_thunk_rva + j), ordinal);
                }
              else
                {
                  // It's a Hint/Name RVA
                  bfd_size_type member_name_offset = member_or_ordinal_rva - section_rva_base;

                  // PR binutils/17512: Handle corrupt PE data.
                  // Ensure member_name_offset + 2 (for Hint field) is within bounds and allows for at least a null terminator.
                  if (member_name_offset < 0 || member_name_offset + 2 >= section_content_size)
                    {
                      fprintf (file, _("\t<corrupt: 0x%08lx>"), (unsigned long) member_or_ordinal_rva);
                    }
                  else
                    {
                      unsigned int hint = bfd_get_16 (abfd, data + member_name_offset);
                      char *member_name_str = (char *) data + member_name_offset + 2;

                      // Calculate max length to print, avoiding reads beyond section data.
                      bfd_size_type max_name_print_len = section_content_size - (member_name_offset + 2);
                      if (max_name_print_len < 0) max_name_print_len = 0; // Defensive

                      fprintf (file, "\t%08lx  <none>  %04x  %.*s",
                               (unsigned long)(first_thunk_rva + j), hint,
                               (int) max_name_print_len, member_name_str);
                    }
                }

              // If the time stamp is not zero, the import address table holds actual addresses.
              if (time_stamp != 0
                  && first_thunk_rva != 0
                  && first_thunk_rva != current_hint_rva
                  && ft_offset_in_buffer + j + 4 <= ft_data_size_available) // Expecting 4-byte addresses for bound-to.
                {
                  fprintf (file, "\t%08lx",
                           (unsigned long) bfd_get_32 (abfd, ft_data + ft_offset_in_buffer + j));
                }

              fprintf (file, "\n");
            }

          if (ft_allocated)
            free (ft_data);
        }

      fprintf (file, "\n");
    }

  free (data); // Free the main section data

  return true;
}

static bool
pe_print_edata (bfd * abfd, void * vfile)
{
  FILE *file = (FILE *) vfile;
  bfd_byte *data = NULL; // Initialize to NULL for consistent cleanup
  asection *section = NULL;
  bfd_size_type datasize = 0;
  bfd_size_type dataoff = 0;
  bfd_vma adj = 0; // Adjustment for RVA to data buffer offset conversion
  
  // Define EDT_type locally as in original code.
  struct EDT_type
  {
    long export_flags;
    long time_stamp;
    short major_ver;
    short minor_ver;
    bfd_vma name; // RVA - relative to image base.
    long base;    // Ordinal base.
    unsigned long num_functions; // Number in the export address table.
    unsigned long num_names;     // Number in the name pointer table.
    bfd_vma eat_addr; // RVA to the export address table.
    bfd_vma npt_addr; // RVA to the Export Name Pointer Table.
    bfd_vma ot_addr;  // RVA to the Ordinal Table.
  } edt;

  pe_data_type *pe = pe_data (abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;

  bfd_vma export_table_va; // Virtual Address of the Export Table

  // --- Start: Locate Export Table and its Section ---
  export_table_va = extra->DataDirectory[PE_EXPORT_TABLE].VirtualAddress;

  if (export_table_va == 0 && extra->DataDirectory[PE_EXPORT_TABLE].Size == 0)
    {
      // Export table not specified in DataDirectory, try finding .edata section by name
      section = bfd_get_section_by_name (abfd, ".edata");
      if (section == NULL)
        {
          // No export table found by either method. This is not a critical error
          // for the function's overall goal (to print if found).
          return true;
        }

      export_table_va = section->vma;
      dataoff = 0; // The table starts at the beginning of the .edata section
      datasize = section->size;
      if (datasize == 0)
        {
          // Empty .edata section. Nothing to print.
          return true;
        }
    }
  else
    {
      export_table_va += extra->ImageBase; // Convert RVA from DataDirectory to VA

      // Find the section that contains the export table VA
      for (section = abfd->sections; section != NULL; section = section->next)
        if (export_table_va >= section->vma && export_table_va < section->vma + section->size)
          break;

      if (section == NULL)
        {
          fprintf (file,
                   _("\nThere is an export table, but the section containing it could not be found\n"));
          return true;
        }

      dataoff = export_table_va - section->vma; // Offset within the section data
      datasize = extra->DataDirectory[PE_EXPORT_TABLE].Size;
    }

  // --- End: Locate Export Table and its Section ---

  // --- Start: Initial Sanity Checks and Content Read ---
  // Ensure the reported size is at least enough for the EDT itself
  if (datasize < sizeof(struct EDT_type))
    {
      fprintf (file,
               _("\nThere is an export table in %s, but it is too small (%d bytes, expected at least %zu)\n"),
               section->name, (int) datasize, sizeof(struct EDT_type));
      return true;
    }

  // Verify that the section contents can actually be read for the determined range
  if (!get_contents_sanity_check (abfd, section, dataoff, datasize))
    {
      fprintf (file,
               _("\nThere is an export table in %s, but contents cannot be read\n"),
               section->name);
      return true;
    }
  
  fprintf (file, _("\nThere is an export table in %s at 0x%lx\n"),
           section->name, (unsigned long) export_table_va);

  data = (bfd_byte *) bfd_malloc (datasize);
  if (data == NULL)
    {
      // Critical error: memory allocation failed
      return false; // Return false to indicate a critical resource failure
    }

  if (! bfd_get_section_contents (abfd, section, data,
                                  (file_ptr) dataoff, datasize))
    {
      fprintf (file,
               _("Failed to read export table contents from %s\n"),
               section->name);
      goto cleanup; // Use goto for consistent memory cleanup
    }
  // --- End: Initial Sanity Checks and Content Read ---

  // --- Start: Populate EDT struct from raw data ---
  // Reading fields from the 'data' buffer using bfd_get_xx for endianness.
  // The offsets correspond to the PE file format, not necessarily C struct packing.
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
  // --- End: Populate EDT struct ---

  // Calculate the adjustment value to convert RVAs (relative to ImageBase)
  // into offsets within our 'data' buffer.
  // 'adj' is the RVA that corresponds to 'data[0]' (the start of the export table data).
  adj = section->vma + dataoff - extra->ImageBase;

  // --- Start: Dump the Export Directory Table (EDT) details ---
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
  bfd_fprintf_vma (abfd, file, edt.name); // Print the RVA of the DLL name

  // If the RVA of the name points within the loaded export table data, print the string.
  if (edt.name >= adj && edt.name < adj + datasize)
    {
      bfd_vma name_offset_in_data = edt.name - adj;
      // Use %.*s to print a bounded string, preventing read past buffer end.
      fprintf (file, " %.*s\n",
               (int) (datasize - name_offset_in_data),
               (const char *)data + name_offset_in_data);
    }
  else
    {
      fprintf (file, "(outside .edata section)\n");
    }

  fprintf (file,
           _("Ordinal Base \t\t\t%ld\n"), edt.base);
  fprintf (file,
           _("Number in:\n"));
  fprintf (file,
           _("\tExport Address Table \t\t%08lx\n"), (unsigned long) edt.num_functions);
  fprintf (file,
           _("\t[Name Pointer/Ordinal] Table\t%08lx\n"), (unsigned long) edt.num_names);

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
  // --- End: Dump the EDT details ---


  // --- Start: Dump Export Address Table (EAT) ---
  fprintf (file,
          _("\nExport Address Table -- Ordinal Base %ld\n"),
          edt.base);
  fprintf (file, "\t          Ordinal  Address  Type\n");

  // Perform robust validation of EAT parameters before processing entries.
  // Check for RVA validity and potential integer overflow during size calculations.
  if (edt.num_functions > 0 &&
      (edt.eat_addr < adj || // EAT RVA starts before the beginning of the loaded data
       edt.eat_addr - adj >= datasize || // EAT RVA starts at or after the end of the loaded data
       (bfd_vma)edt.num_functions > (BFD_VMA_MAX / sizeof(bfd_vma)) || // Overflow check for total size
       edt.eat_addr - adj + (bfd_vma)edt.num_functions * sizeof(bfd_vma) > datasize)) // EAT extends beyond loaded data
    {
      fprintf (file, _("\tInvalid Export Address Table rva (0x%lx) or entry count (0x%lx)\n"),
               (unsigned long) edt.eat_addr, (unsigned long) edt.num_functions);
    }
  else
    {
      for (bfd_size_type i = 0; i < edt.num_functions; ++i)
        {
          // Calculate offset to the current EAT entry within the 'data' buffer.
          bfd_vma eat_member_offset = (edt.eat_addr - adj) + (i * sizeof(bfd_vma));
          
          // Check if reading the 4-byte entry would go out of bounds of 'data'.
          if (eat_member_offset + sizeof(bfd_vma) > datasize)
            {
              fprintf (file, _("\t[%4ld] +base[%4ld] <corrupt EAT entry at index %ld - out of bounds>\n"),
                       (long) i, (long) (i + edt.base), (long)i);
              break; // Abort processing this table as it's corrupt
            }

          bfd_vma eat_member_value = bfd_get_32 (abfd, data + eat_member_offset);

          if (eat_member_value == 0)
            {
              continue; // Skip null (unused) entries
            }

          // Determine if the entry is an RVA to a forwarding string or an actual export.
          if (eat_member_value >= adj && eat_member_value < adj + datasize)
            {
              // It's a forwarder RVA, pointing to a string within the .edata section
              bfd_vma forwarder_str_offset = eat_member_value - adj;
              if (forwarder_str_offset < datasize) // Ensure start of string is within bounds
                {
                  fprintf (file,
                           "\t[%4ld] +base[%4ld] %08lx %s -- %.*s\n",
                           (long) i,
                           (long) (i + edt.base),
                           (unsigned long) eat_member_value,
                           _("Forwarder RVA"),
                           (int)(datasize - forwarder_str_offset), // Max length to read safely
                           (const char *)data + forwarder_str_offset);
                }
              else
                {
                  // Corrupt forwarder RVA points outside valid data range
                  fprintf (file,
                           _("\t[%4ld] +base[%4ld] %08lx %s -- <corrupt forwarder string offset 0x%lx, points outside buffer>\n"),
                           (long) i, (long) (i + edt.base), (unsigned long) eat_member_value,
                           _("Forwarder RVA"), (unsigned long)forwarder_str_offset);
                }
            }
          else
            {
              // Export RVA, pointing to an address usually outside the .edata section
              fprintf (file,
                       "\t[%4ld] +base[%4ld] %08lx %s\n",
                       (long) i,
                       (long) (i + edt.base),
                       (unsigned long) eat_member_value,
                       _("Export RVA"));
            }
        }
    }
  // --- End: Dump Export Address Table (EAT) ---


  // --- Start: Dump Export Name Pointer Table (NPT) and Ordinal Table (OT) ---
  fprintf (file,
           _("\n[Ordinal/Name Pointer] Table -- Ordinal Base %ld\n"),
          edt.base);
  fprintf (file, "\t          Ordinal   Hint Name\n");

  // Validate NPT and OT parameters separately for clearer error messages.
  bool npt_corrupt = false;
  bool ot_corrupt = false;

  // Validate Name Pointer Table (NPT)
  if (edt.num_names > 0 &&
      (edt.npt_addr < adj || edt.npt_addr - adj >= datasize ||
       (bfd_vma)edt.num_names > (BFD_VMA_MAX / sizeof(bfd_vma)) || // Overflow check
       edt.npt_addr - adj + (bfd_vma)edt.num_names * sizeof(bfd_vma) > datasize))
    {
      npt_corrupt = true;
      fprintf (file, _("\tInvalid Name Pointer Table rva (0x%lx) or entry count (0x%lx)\n"),
               (unsigned long) edt.npt_addr, (unsigned long) edt.num_names);
    }

  // Validate Ordinal Table (OT)
  if (edt.num_names > 0 &&
      (edt.ot_addr < adj || edt.ot_addr - adj >= datasize ||
       (bfd_vma)edt.num_names > (BFD_VMA_MAX / sizeof(short)) || // Overflow check for short (2 bytes)
       edt.ot_addr - adj + (bfd_vma)edt.num_names * sizeof(short) > datasize))
    {
      ot_corrupt = true;
      fprintf (file, _("\tInvalid Ordinal Table rva (0x%lx) or entry count (0x%lx)\n"),
               (unsigned long) edt.ot_addr, (unsigned long) edt.num_names);
    }

  if (!npt_corrupt && !ot_corrupt)
    {
      for (bfd_size_type i = 0; i < edt.num_names; ++i)
        {
          bfd_vma name_ptr_rva; // RVA of the export name string
          bfd_vma ordinal_hint; // Ordinal hint (index into EAT)

          // Calculate offsets to the current NPT and OT entries within 'data'.
          bfd_vma npt_entry_offset = (edt.npt_addr - adj) + (i * sizeof(bfd_vma));
          bfd_vma ot_entry_offset = (edt.ot_addr - adj) + (i * sizeof(short));

          // Check if reading these entries would go out of bounds.
          if (npt_entry_offset + sizeof(bfd_vma) > datasize || ot_entry_offset + sizeof(short) > datasize)
            {
              fprintf (file, _("\t[%4ld] +base[??]  <corrupt NPT/OT entry at index %ld - out of bounds>\n"),
                       (long) i, (long) i);
              break; // Abort processing this table
            }

          ordinal_hint = bfd_get_16 (abfd, data + ot_entry_offset);
          name_ptr_rva = bfd_get_32 (abfd, data + npt_entry_offset);

          // Check if the name_ptr_rva points within the loaded export table data.
          if (name_ptr_rva >= adj && name_ptr_rva < adj + datasize)
            {
              bfd_vma name_offset_in_data = name_ptr_rva - adj;
              const char *name_str = (const char *)data + name_offset_in_data;

              // Ensure the starting position of the string is valid.
              if (name_offset_in_data < datasize)
                {
                  fprintf (file,
                           "\t[%4ld] +base[%4ld]  %04lx %.*s\n",
                           (long) ordinal_hint, (long) (ordinal_hint + edt.base), (long) i,
                           (int)(datasize - name_offset_in_data), // Max length to read safely
                           name_str);
                }
              else
                {
                   fprintf (file, _("\t[%4ld] +base[%4ld]  %04lx <corrupt name string offset 0x%lx, points outside buffer>\n"),
                           (long) ordinal_hint, (long) (ordinal_hint + edt.base), (long) i, (unsigned long) name_ptr_rva);
                }
            }
          else
            {
              fprintf (file, _("\t[%4ld] +base[%4ld]  %04lx <corrupt offset to name: %lx, outside buffer>\n"),
                       (long) ordinal_hint, (long) (ordinal_hint + edt.base), (long) i, (unsigned long) name_ptr_rva);
            }
        }
    }
  // --- End: Dump NPT/OT ---

cleanup:
  free (data); // Free the allocated memory for section contents

  return true; // Return true on success or if no export table was found/could be parsed (non-critical)
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
#else
# define PDATA_ROW_SIZE	(5 * 4)
#endif
  FILE *file = (FILE *) vfile;
  bfd_byte *data = NULL; /* Initialize to NULL for safe free. */
  asection *section = bfd_get_section_by_name (abfd, ".pdata");
  struct coff_section_data *sdata; /* Specific PE-internal data. */
  bfd_size_type datasize;
  bfd_size_type i;
  bfd_size_type stop;
  const int pdata_entry_byte_size = 4; /* Each individual entry (BeginAddress, EndAddress, etc.) is assumed 4 bytes from explicit offsets. */
  const int num_pdata_sub_entries = 5; /* Number of sub-entries interpreted for each row. */
  const int interpreted_row_byte_size = num_pdata_sub_entries * pdata_entry_byte_size;
  const int loop_step_size = PDATA_ROW_SIZE; /* The byte size of a full row, used for loop iteration. */

  bool result = true; /* Default to success if nothing to print or printing completes. */

  /* Check for section existence and contents early. */
  if (section == NULL || (section->flags & SEC_HAS_CONTENTS) == 0)
    goto cleanup;

  /* Retrieve PE-specific section data. */
  sdata = pei_section_data (abfd, section);
  if (sdata == NULL)
    goto cleanup;

  stop = sdata->virt_size;
  datasize = section->size;

  /* If virtual size is zero, there's nothing to print. */
  if (stop == 0)
    goto cleanup;

  /* Warn if the section size is not a multiple of the expected row size. */
  if ((stop % loop_step_size) != 0)
    fprintf (file,
	     _("warning, .pdata section size (%ld) is not a multiple of %d\n"),
	     (long) stop, loop_step_size);

  /* PR 17512: file: 002-193900-0.004.
     Check for virtual size exceeding real size, indicating an issue. */
  if (datasize < stop)
    {
      fprintf (file, _("Virtual size of .pdata section (%ld) larger than real size (%ld)\n"),
	       (long) stop, (long) datasize);
      result = false;
      goto cleanup;
    }

  /* Allocate memory and read section data. Handle allocation failure. */
  if (! bfd_malloc_and_get_section (abfd, section, &data))
    {
      result = false; /* Indicate failure to acquire data. */
      goto cleanup;   /* data is NULL, so free(NULL) is safe but not needed. */
    }

  /* Print table headers based on architecture/format. */
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

  /* Iterate through the .pdata section, processing entries. */
  for (i = 0; i < stop; i += loop_step_size)
    {
      bfd_vma begin_addr;
      bfd_vma end_addr;
      bfd_vma eh_handler;
      bfd_vma eh_data_field; /* Renamed to avoid shadowing the 'data' pointer variable. */
      bfd_vma prolog_end_addr;
#if !defined(COFF_WITH_pep) || defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined (COFF_WITH_peRiscV64)
      int em_data;
#endif

      /* Ensure there are enough bytes remaining in the section for the full interpreted row. */
      if (i + interpreted_row_byte_size > stop)
	break;

      /* Extract function table entries using specific byte offsets. */
      begin_addr      = GET_PDATA_ENTRY (abfd, data + i                                   );
      end_addr	      = GET_PDATA_ENTRY (abfd, data + i +  pdata_entry_byte_size          );
      eh_handler      = GET_PDATA_ENTRY (abfd, data + i + (2 * pdata_entry_byte_size));
      eh_data_field   = GET_PDATA_ENTRY (abfd, data + i + (3 * pdata_entry_byte_size));
      prolog_end_addr = GET_PDATA_ENTRY (abfd, data + i + (4 * pdata_entry_byte_size));

      /* If all interpreted fields are zero, assume end of meaningful data/start of padding. */
      if (begin_addr == 0 && end_addr == 0 && eh_handler == 0
	  && eh_data_field == 0 && prolog_end_addr == 0)
	break;

      /* Perform conditional calculations and bitmasking. */
#if !defined(COFF_WITH_pep) || defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined (COFF_WITH_peRiscV64)
      em_data = ((eh_handler & 0x1) << 2) | (prolog_end_addr & 0x3);
#endif
      eh_handler &= ~(bfd_vma) 0x3;
      prolog_end_addr &= ~(bfd_vma) 0x3;

      /* Print the interpreted data to the file. */
      fputc (' ', file);
      bfd_fprintf_vma (abfd, file, i + section->vma); fputc ('\t', file);
      bfd_fprintf_vma (abfd, file, begin_addr); fputc (' ', file);
      bfd_fprintf_vma (abfd, file, end_addr); fputc (' ', file);
      bfd_fprintf_vma (abfd, file, eh_handler);
#if !defined(COFF_WITH_pep) || defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined (COFF_WITH_peRiscV64)
      fputc (' ', file);
      bfd_fprintf_vma (abfd, file, eh_data_field); fputc (' ', file);
      bfd_fprintf_vma (abfd, file, prolog_end_addr);
      fprintf (file, "   %x", em_data);
#endif
      fprintf (file, "\n");
    }

cleanup:
  /* Free allocated memory if it was successfully assigned. */
  if (data != NULL)
    free (data);

  return result;
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
  asymbol ** sy = NULL;
  long storage;
  long canonical_symcount;

  psc->symcount = 0;

  if (!(bfd_get_file_flags (abfd) & HAS_SYMS))
    {
      return NULL;
    }

  storage = bfd_get_symtab_upper_bound (abfd);
  if (storage < 0)
    {
      return NULL;
    }

  if (storage > 0)
    {
      sy = (asymbol **) bfd_malloc (storage);
      if (sy == NULL)
        {
          return NULL;
        }
    }

  canonical_symcount = bfd_canonicalize_symtab (abfd, sy);

  if (canonical_symcount < 0)
    {
      if (sy != NULL)
        {
          bfd_free (sy);
        }
      psc->symcount = canonical_symcount; /* Preserve original error indication */
      return NULL;
    }

  psc->symcount = canonical_symcount;
  return sy;
}

static const char *
my_symbol_for_address (bfd *abfd, bfd_vma func, sym_cache *psc)
{
  if (psc->syms == NULL)
    {
      psc->syms = slurp_symtab (abfd, psc);
      if (psc->syms == NULL || psc->symcount == 0)
        {
          return NULL;
        }
    }

  for (size_t i = 0; i < psc->symcount; i++)
    {
      bfd_symbol *symbol_entry = psc->syms[i];

      if (symbol_entry == NULL || symbol_entry->section == NULL)
        {
          continue;
        }

      bfd_vma symbol_address = symbol_entry->section->vma + symbol_entry->value;

      if (symbol_address == func)
        {
          if (symbol_entry->name != NULL)
            {
              return symbol_entry->name;
            }
          else
            {
              return NULL;
            }
        }
    }

  return NULL;
}

static void
cleanup_syms (sym_cache *psc)
{
  if (psc == NULL)
    {
      return;
    }
  psc->symcount = 0;
  free (psc->syms);
  psc->syms = NULL;
}

/* This is the version for "compressed" pdata.  */

bool
_bfd_XX_print_ce_compressed_pdata (bfd *abfd, void *vfile)
{
  FILE *file = (FILE *) vfile;
  bfd_byte *pdata_contents = NULL;
  asection *pdata_section = bfd_get_section_by_name (abfd, ".pdata");
  struct sym_cache sym_cache = {0, 0};

  static const int PDATA_ROW_SIZE_IN_BYTES = 2 * 4; // Two 4-byte BFD_VMAs
  static const unsigned int PROLOG_LENGTH_MASK = 0x000000FF;
  static const unsigned int FUNCTION_LENGTH_MASK = 0x3FFFFF00;
  static const int FUNCTION_LENGTH_SHIFT = 8;
  static const unsigned int FLAG_32BIT_MASK = 0x40000000;
  static const int FLAG_32BIT_SHIFT = 30;
  static const unsigned int EXCEPTION_FLAG_MASK = 0x80000000;
  static const int EXCEPTION_FLAG_SHIFT = 31;
  static const size_t EH_DATA_BUFFER_SIZE = 8; // For two 4-byte BFD_VMAs (EH address + EH data)

  if (pdata_section == NULL || (pdata_section->flags & SEC_HAS_CONTENTS) == 0 || pdata_section->size == 0)
    return true;

  struct pei_section_data *pei_sdata = pei_section_data (abfd, pdata_section);
  if (pei_sdata == NULL)
    return true;

  bfd_size_type pdata_virt_size = pei_sdata->virt_size;
  if ((pdata_virt_size % PDATA_ROW_SIZE_IN_BYTES) != 0)
    fprintf (file,
             _("warning, .pdata section virtual size (%ld) is not a multiple of %d\n"),
             (long) pdata_virt_size, PDATA_ROW_SIZE_IN_BYTES);

  fprintf (file, _("\nThe Function Table (interpreted .pdata section contents)\n"));
  fprintf (file, _("\
 vma:\t\tBegin    Prolog   Function Flags    Exception EH\n\
     \t\tAddress  Length   Length   32b exc  Handler   Data\n"));

  if (!bfd_malloc_and_get_section (abfd, pdata_section, &pdata_contents))
  {
    return false;
  }

  bfd_size_type effective_pdata_size = pdata_section->size;
  if (pdata_virt_size < effective_pdata_size)
    effective_pdata_size = pdata_virt_size;

  asection *text_section = bfd_get_section_by_name (abfd, ".text");
  bfd_byte *eh_data_buffer = NULL;
  if (text_section)
  {
    eh_data_buffer = (bfd_byte *) bfd_malloc (EH_DATA_BUFFER_SIZE);
  }

  for (bfd_size_type i = 0; i < effective_pdata_size; i += PDATA_ROW_SIZE_IN_BYTES)
  {
    if (i + PDATA_ROW_SIZE_IN_BYTES > effective_pdata_size)
      break;

    bfd_vma begin_addr = GET_PDATA_ENTRY (abfd, pdata_contents + i);
    bfd_vma other_data = GET_PDATA_ENTRY (abfd, pdata_contents + i + 4);

    if (begin_addr == 0 && other_data == 0)
      break;

    bfd_vma prolog_length = (other_data & PROLOG_LENGTH_MASK);
    bfd_vma function_length = (other_data & FUNCTION_LENGTH_MASK) >> FUNCTION_LENGTH_SHIFT;
    int flag32bit = (int)((other_data & FLAG_32BIT_MASK) >> FLAG_32BIT_SHIFT);
    int exception_flag = (int)((other_data & EXCEPTION_FLAG_MASK) >> EXCEPTION_FLAG_SHIFT);

    fputc (' ', file);
    bfd_fprintf_vma (abfd, file, i + pdata_section->vma); fputc ('\t', file);
    bfd_fprintf_vma (abfd, file, begin_addr); fputc (' ', file);
    bfd_fprintf_vma (abfd, file, prolog_length); fputc (' ', file);
    bfd_fprintf_vma (abfd, file, function_length); fputc (' ', file);
    fprintf (file, "%2d  %2d   ", flag32bit, exception_flag);

    if (text_section && eh_data_buffer)
    {
      bfd_vma eh_offset_in_text = (begin_addr - 8) - text_section->vma;

      if (eh_offset_in_text < text_section->size &&
          eh_offset_in_text + EH_DATA_BUFFER_SIZE <= text_section->size)
      {
        if (bfd_get_section_contents (abfd, text_section, eh_data_buffer, eh_offset_in_text, EH_DATA_BUFFER_SIZE))
        {
          bfd_vma eh_address = bfd_get_32 (abfd, eh_data_buffer);
          bfd_vma eh_extra_data = bfd_get_32 (abfd, eh_data_buffer + 4);
          fprintf (file, "%08x  ", (unsigned int) eh_address);
          fprintf (file, "%08x", (unsigned int) eh_extra_data);

          if (eh_address != 0)
          {
            const char *symbol_name = my_symbol_for_address (abfd, eh_address, &sym_cache);
            if (symbol_name)
              fprintf (file, " (%s) ", symbol_name);
          }
        }
      }
    }
    fprintf (file, "\n");
  }

  free (pdata_contents);
  free (eh_data_buffer);
  cleanup_syms (&sym_cache);

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
  bfd_byte *data = NULL; // Initialize to NULL for safe cleanup.
  bool result = true; // Assume success initially.

  asection *section = bfd_get_section_by_name (abfd, ".reloc");

  // If the .reloc section does not exist, is empty, or has no contents,
  // there's nothing to process or print. Return true to indicate a successful
  // no-operation, consistent with original functionality.
  if (section == NULL
      || section->size == 0
      || (section->flags & SEC_HAS_CONTENTS) == 0)
    {
      return true;
    }

  // Attempt to allocate memory and read the section's contents.
  // If this operation fails, bfd_malloc_and_get_section typically sets an error
  // and returns false. The `data` pointer may or may not be NULL, but it shouldn't
  // be freed by the caller in this specific failure path without explicit knowledge
  // of the bfd API contract for failure. Using `goto cleanup` ensures `data` is
  // freed only if it's non-NULL, handling all scenarios robustly.
  if (!bfd_malloc_and_get_section (abfd, section, &data))
    {
      result = false; // An error occurred during memory allocation or data retrieval.
      goto cleanup;   // Jump to the cleanup section to handle `data` if necessary.
    }

  // Print the header for the relocation information.
  fprintf (file,
	   _("\n\nPE File Base Relocations (interpreted .reloc section contents)\n"));

  bfd_byte *current_data_ptr = data;
  bfd_byte *section_end_ptr = data + section->size;

  // Iterate through the relocation blocks. Each block starts with an 8-byte header.
  // Ensure there are enough bytes for a block header before attempting to read.
  while (current_data_ptr + 8 <= section_end_ptr)
    {
      bfd_vma virtual_address;
      unsigned long block_size; // Total size of the block, including its 8-byte header.
      unsigned long reported_num_fixups;
      bfd_byte *block_content_boundary_ptr; // The byte position *after* the last valid byte of this block.

      // Read the VirtualAddress (4 bytes) and BlockSize (4 bytes) from the header.
      virtual_address = bfd_get_32 (abfd, current_data_ptr);
      block_size = bfd_get_32 (abfd, current_data_ptr + 4);

      current_data_ptr += 8; // Advance pointer past the block header.

      // If block_size is 0, it typically indicates the end of valid relocation blocks
      // or a malformed block. Stop processing further blocks, consistent with original logic.
      if (block_size == 0)
	    {
	      break;
	    }

      // Calculate the number of fixups to be reported. Each fixup is 2 bytes.
      // The `block_size` includes the 8-byte header.
      // If `block_size` is less than 8, it's a malformed block; report 0 fixups.
      if (block_size < 8)
        {
          reported_num_fixups = 0;
        }
      else
        {
          reported_num_fixups = (block_size - 8) / 2;
        }

      fprintf (file,
	       _("\nVirtual Address: %08lx Chunk size %ld (0x%lx) Number of fixups %ld\n"),
	       (unsigned long) virtual_address,
           block_size,
           block_size,
           reported_num_fixups);

      // Calculate the absolute end position of this relocation block's data
      // (header + entries + potential padding) within the section.
      // `current_data_ptr - 8` points to the start of the current block header.
      block_content_boundary_ptr = (current_data_ptr - 8) + block_size;

      // Ensure we don't try to read past the end of the entire section.
      // This clips `block_content_boundary_ptr` if `block_size` declared in the header is too large.
      if (block_content_boundary_ptr > section_end_ptr)
	    {
	      block_content_boundary_ptr = section_end_ptr;
	    }

      int fixup_entry_index = 0;
      // Iterate through fixup entries within the current block. Each entry is at least 2 bytes.
      // Ensure there are enough bytes for an entry before attempting to read.
      while (current_data_ptr + 2 <= block_content_boundary_ptr)
	    {
	      unsigned short entry_value = bfd_get_16 (abfd, current_data_ptr);
	      unsigned int type = (entry_value & 0xF000) >> 12; // High 4 bits for type.
	      int offset = entry_value & 0x0FFF;             // Low 12 bits for offset.

	      // Ensure the 'type' index is within the bounds of the 'tbl' array.
	      // 'tbl' is assumed to be an external global constant array (e.g., const char *tbl[]).
	      // The last element is typically a generic "Unknown" type for clamping.
	      const unsigned int tbl_array_size = sizeof (tbl) / sizeof (tbl[0]);
	      if (type >= tbl_array_size)
	        {
	          type = tbl_array_size - 1; // Clamp to the last, "unknown" entry.
	        }

	      fprintf (file,
		       _("\treloc %4d offset %4x [%4lx] %s"),
		       fixup_entry_index,
               offset,
               (unsigned long) (offset + virtual_address),
               tbl[type]);

	      current_data_ptr += 2; // Advance past the current 2-byte fixup entry.
	      fixup_entry_index++;

	      // Handle IMAGE_REL_BASED_HIGHADJ. This type requires an additional
	      // 2-byte argument immediately following the fixup entry.
	      // Ensure there are enough bytes for this argument before reading.
	      if (type == IMAGE_REL_BASED_HIGHADJ && current_data_ptr + 2 <= block_content_boundary_ptr)
	        {
	          fprintf (file, " (%4x)", (unsigned int) bfd_get_16 (abfd, current_data_ptr));
	          current_data_ptr += 2; // Advance past the HIGHADJ argument.
	          fixup_entry_index++;   // Increment index as the argument effectively consumes another slot.
	        }

	      fprintf (file, "\n");
	    }

      // After processing all entries in the current block, explicitly advance `current_data_ptr`
      // to the start of the next expected block header. This accounts for any padding bytes
      // implied by `block_size` but not explicitly consumed by entries.
      // This ensures correct alignment for the next iteration of the outer loop, reflecting
      // that the next block header starts at `(original_block_header_start) + block_size`.
      current_data_ptr = (current_data_ptr - 8) + block_size;

      // Ensure that `current_data_ptr` does not advance past the end of the section.
      // This provides robustness against excessively large `block_size` values declared in the file.
      if (current_data_ptr > section_end_ptr)
        {
          current_data_ptr = section_end_ptr;
        }
    }

cleanup:
  // Free the dynamically allocated section data if it was successfully allocated.
  // `free(NULL)` is safe, but this explicit check improves clarity.
  if (data != NULL)
    {
      free (data);
    }

  return result;
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
  unsigned long entry_id_or_name_offset;
  unsigned long entry_value_or_dir_offset;
  bfd_byte *current_data_ptr = data;

  if (current_data_ptr < regions->section_start || current_data_ptr + 8 > regions->section_end)
    return regions->section_end + 1;

  fprintf (file, _("%03x %*.s Entry: "), (int)(current_data_ptr - regions->section_start), indent, " ");

  entry_id_or_name_offset = (unsigned long) bfd_get_32 (abfd, current_data_ptr);
  current_data_ptr += 4;

  if (is_name)
    {
      bfd_byte *name_string_ptr;
      unsigned int string_len;

      if (HighBitSet (entry_id_or_name_offset))
        name_string_ptr = regions->section_start + WithoutHighBit (entry_id_or_name_offset);
      else
        name_string_ptr = regions->section_start + entry_id_or_name_offset - rva_bias;

      if (name_string_ptr < regions->section_start || name_string_ptr + 2 > regions->section_end)
        {
          fprintf (file, _("<corrupt string offset: %#lx>\n"), entry_id_or_name_offset);
          return regions->section_end + 1;
        }

      if (regions->strings_start == NULL)
        regions->strings_start = name_string_ptr;

      string_len = bfd_get_16 (abfd, name_string_ptr);
      fprintf (file, _("name: [val: %08lx len %d]: "), entry_id_or_name_offset, string_len);

      if (name_string_ptr + 2 + (unsigned long)string_len * 2 > regions->section_end)
        {
          fprintf (file, _("<corrupt string length: %#x>\n"), string_len);
          return regions->section_end + 1;
        }

      name_string_ptr += 2;

      unsigned int i;
      for (i = 0; i < string_len; ++i)
        {
          char c = *name_string_ptr;

          if (c > 0 && c < 32)
            fprintf (file, "^%c", c + 64);
          else
            fprintf (file, "%.1s", name_string_ptr);

          name_string_ptr += 2;
        }
    }
  else
    {
      fprintf (file, _("ID: %#08lx"), entry_id_or_name_offset);
    }

  entry_value_or_dir_offset = (unsigned long) bfd_get_32 (abfd, current_data_ptr);
  current_data_ptr += 4;

  fprintf (file, _(", Value: %#08lx\n"), entry_value_or_dir_offset);

  if (HighBitSet (entry_value_or_dir_offset))
    {
      bfd_byte *subdir_data_ptr;
      subdir_data_ptr = regions->section_start + WithoutHighBit (entry_value_or_dir_offset);

      if (subdir_data_ptr < regions->section_start || subdir_data_ptr > regions->section_end)
        return regions->section_end + 1;

      return rsrc_print_resource_directory (file, abfd, indent + 1, subdir_data_ptr,
                                            regions, rva_bias);
    }
  else
    {
      bfd_byte *leaf_data_ptr;
      unsigned long resource_address;
      unsigned long resource_size;
      unsigned long code_page;
      unsigned long reserved_value;

      leaf_data_ptr = regions->section_start + entry_value_or_dir_offset;

      if (leaf_data_ptr < regions->section_start || leaf_data_ptr + 16 > regions->section_end)
        return regions->section_end + 1;

      resource_address = (unsigned long) bfd_get_32 (abfd, leaf_data_ptr);
      resource_size = (unsigned long) bfd_get_32 (abfd, leaf_data_ptr + 4);
      code_page = (unsigned long) bfd_get_32 (abfd, leaf_data_ptr + 8);
      reserved_value = (unsigned long) bfd_get_32 (abfd, leaf_data_ptr + 12);

      fprintf (file, _("%03x %*.s  Leaf: Addr: %#08lx, Size: %#08lx, Codepage: %lu\n"),
               (int) (entry_value_or_dir_offset), indent, " ",
               resource_address, resource_size, code_page);

      if (reserved_value != 0 ||
          (regions->section_start + (resource_address - rva_bias) < regions->section_start) ||
          (regions->section_start + (resource_address - rva_bias) + resource_size > regions->section_end))
        return regions->section_end + 1;

      if (regions->resource_start == NULL)
        regions->resource_start = regions->section_start + (resource_address - rva_bias);

      return regions->section_start + (resource_address - rva_bias) + resource_size;
    }
}

#define max(a,b) ((a) > (b) ? (a) : (b))
#define min(a,b) ((a) < (b) ? (a) : (b))

enum ResourceDirectoryOffsets {
    RSRC_DIR_CHARACTERISTICS_OFFSET = 0,
    RSRC_DIR_TIMEDATE_STAMP_OFFSET = 4,
    RSRC_DIR_MAJOR_VERSION_OFFSET = 8,
    RSRC_DIR_MINOR_VERSION_OFFSET = 10,
    RSRC_DIR_NUM_NAMED_OFFSET = 12,
    RSRC_DIR_NUM_ID_OFFSET = 14,
    RSRC_DIR_HEADER_SIZE = 16
};

static bfd_byte *
process_resource_entries_loop(FILE *file, bfd *abfd, unsigned int indent,
                              bool is_named, unsigned int count,
                              bfd_byte **data_ptr, rsrc_regions *regions,
                              bfd_vma rva_bias, bfd_byte *highest_data_seen)
{
  bfd_byte *current_data = *data_ptr;
  bfd_byte *highest = highest_data_seen;

  for (unsigned int i = 0; i < count; ++i)
    {
      bfd_byte *entry_end;

      if (current_data + 8 > regions->section_end)
        return regions->section_end + 1;

      entry_end = rsrc_print_resource_entries(file, abfd, indent + 1, is_named,
                                             current_data, regions, rva_bias);
      current_data += 8;
      highest = max(highest, entry_end);
      if (entry_end >= regions->section_end)
        return entry_end;
    }
  *data_ptr = current_data;
  return highest;
}

static bfd_byte *
rsrc_print_resource_directory (FILE *	      file,
			       bfd *	      abfd,
			       unsigned int   indent,
			       bfd_byte *     data,
			       rsrc_regions * regions,
			       bfd_vma	      rva_bias)
{
  unsigned int num_names;
  unsigned int num_ids;
  bfd_byte * highest_data = data;

  if (data + RSRC_DIR_HEADER_SIZE > regions->section_end)
    return regions->section_end + 1;

  fprintf (file, "%03x %*.s ", (int)(data - regions->section_start), indent, " ");
  switch (indent)
    {
    case 0: fprintf (file, _("Type")); break;
    case 2: fprintf (file, _("Name")); break;
    case 4: fprintf (file, _("Language")); break;
    default:
      fprintf (file, _("<unknown directory type: %d>\n"), indent);
      return regions->section_end + 1;
    }

  num_names = bfd_get_16 (abfd, data + RSRC_DIR_NUM_NAMED_OFFSET);
  num_ids = bfd_get_16 (abfd, data + RSRC_DIR_NUM_ID_OFFSET);

  fprintf (file, _(" Table: Char: %u, Time: %08lx, Ver: %u/%u, Num Names: %u, IDs: %u\n"),
	   (unsigned int) bfd_get_32 (abfd, data + RSRC_DIR_CHARACTERISTICS_OFFSET),
	   (unsigned long) bfd_get_32 (abfd, data + RSRC_DIR_TIMEDATE_STAMP_OFFSET),
	   (unsigned int) bfd_get_16 (abfd, data + RSRC_DIR_MAJOR_VERSION_OFFSET),
	   (unsigned int) bfd_get_16 (abfd, data + RSRC_DIR_MINOR_VERSION_OFFSET),
	   num_names,
	   num_ids);

  data += RSRC_DIR_HEADER_SIZE;

  highest_data = process_resource_entries_loop(file, abfd, indent, true, num_names,
                                                &data, regions, rva_bias, highest_data);
  if (highest_data >= regions->section_end)
    return highest_data;

  highest_data = process_resource_entries_loop(file, abfd, indent, false, num_ids,
                                                &data, regions, rva_bias, highest_data);
  if (highest_data >= regions->section_end)
    return highest_data;

  return max(highest_data, data);
}

/* Display the contents of a .rsrc section.  We do not try to
   reproduce the resources, windres does that.  Instead we dump
   the tables in a human readable format.  */

static bool
rsrc_print_section (bfd * abfd, void * vfile)
{
  FILE * file = (FILE *) vfile;
  pe_data_type * pe = NULL;
  asection * section = NULL;
  bfd_byte * section_data = NULL; // Base pointer for allocated section memory
  bfd_byte * current_ptr = NULL;  // Pointer for iterating through section data
  bfd_size_type datasize = 0;
  bfd_vma rva_bias = 0;
  rsrc_regions regions;
  bool result = true; // Default to success, consistent with no-section cases

  pe = pe_data (abfd);
  if (pe == NULL)
    {
      // No PE data found, nothing to print in this section.
      return true; // Considered a non-error exit.
    }

  section = bfd_get_section_by_name (abfd, ".rsrc");
  if (section == NULL)
    {
      // The .rsrc section does not exist, nothing to print.
      return true; // Considered a non-error exit.
    }

  if (!(section->flags & SEC_HAS_CONTENTS))
    {
      // The .rsrc section exists but indicates it has no contents.
      return true; // Considered a non-error exit.
    }

  datasize = section->size;
  if (datasize == 0)
    {
      // The .rsrc section has contents flag but zero size.
      return true; // Considered a non-error exit.
    }

  // Allocate memory and read the entire .rsrc section data.
  // If bfd_malloc_and_get_section fails, `section_data` will not be allocated.
  if (!bfd_malloc_and_get_section (abfd, section, &section_data))
    {
      // A critical error occurred while trying to read the section data.
      result = false; // Indicate an actual failure.
      goto cleanup;
    }

  // Initialize pointers for iteration and the regions structure.
  current_ptr = section_data;
  // Calculate the RVA bias: the difference between the section's VMA and the image base.
  rva_bias = section->vma - pe->pe_opthdr.ImageBase;

  regions.section_start = section_data;
  regions.section_end = section_data + datasize;
  regions.strings_start = NULL;
  regions.resource_start = NULL;

  fprintf (file, "\nThe .rsrc Resource Directory section:\n");

  // Loop through the .rsrc section data until the end is reached.
  while (current_ptr < regions.section_end)
    {
      bfd_byte * start_of_current_entry = current_ptr;

      // Process the current resource directory entry.
      // `rsrc_print_resource_directory` returns the pointer to the next byte to process,
      // or a special sentinel value (regions.section_end + 1) if corruption is detected.
      current_ptr = rsrc_print_resource_directory (file, abfd, 0, current_ptr, &regions, rva_bias);

      if (current_ptr == regions.section_end + 1)
        {
          fprintf (file, _("Corrupt .rsrc section detected!\n"));
          // Corruption detected. The loop condition (current_ptr < regions.section_end)
          // will now be false, causing the loop to terminate, preserving the original behavior.
          break;
        }
      else
        {
          bfd_byte * next_unaligned_ptr = current_ptr; // Store the pointer returned by the processing function.

          // Calculate the alignment mask based on the section's alignment power.
          int align_mask = (1 << section->alignment_power) - 1;

          // Align `current_ptr` to the next boundary. This finds the smallest address
          // greater than or equal to `next_unaligned_ptr` that satisfies the alignment.
          current_ptr = (bfd_byte *) (((ptrdiff_t) (next_unaligned_ptr + align_mask)) & ~ align_mask);

          // Update the RVA bias. This bias tracks the RVA of `current_ptr` relative to `ImageBase`.
          // It's increased by the total number of bytes consumed by the current entry
          // plus any alignment padding.
          rva_bias += (current_ptr - start_of_current_entry);

          // Handle a specific legacy alignment quirk for the .rsrc section end.
          if (current_ptr == (regions.section_end - 4))
            {
              current_ptr = regions.section_end; // Force `current_ptr` to the end if exactly 4 bytes short.
            }
          // Check for extra non-zero padding bytes if `current_ptr` is still within section bounds.
          else if (current_ptr < regions.section_end)
            {
              bfd_byte * check_and_advance_ptr = current_ptr;
              bool non_zero_padding_found = false;

              // The original logic checks bytes *after* the currently aligned position.
              // So, if `check_and_advance_ptr` is valid, advance one byte for the first check.
              if (check_and_advance_ptr < regions.section_end) {
                check_and_advance_ptr++;
              }

              while (check_and_advance_ptr < regions.section_end)
                {
                  if (*check_and_advance_ptr != 0)
                    {
                      non_zero_padding_found = true;
                      break; // Stop at the first non-zero byte found.
                    }
                  check_and_advance_ptr++;
                }

              if (non_zero_padding_found)
                {
                  fprintf (file, _("\nWARNING: Extra data in .rsrc section - it will be ignored by Windows:\n"));
                }
              // Update the main loop iterator `current_ptr` to skip over any zero padding found.
              current_ptr = check_and_advance_ptr;
            }
        }
    } // End of while loop

  // Print summary information about string and resource tables if their start offsets were located.
  if (regions.strings_start != NULL)
    fprintf (file, _(" String table starts at offset: %#03x\n"),
             (int) (regions.strings_start - regions.section_start));
  if (regions.resource_start != NULL)
    fprintf (file, _(" Resources start at offset: %#03x\n"),
             (int) (regions.resource_start - regions.section_start));

cleanup:
  // Ensure the allocated section data is freed.
  if (section_data != NULL)
    {
      free (section_data);
    }

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
pe_print_debugdata (bfd *abfd, void *vfile)
{
  FILE *file = (FILE *) vfile;
  pe_data_type *pe = pe_data (abfd);
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

  for (section = abfd->sections; section != NULL; section = section->next)
    {
      if (addr >= section->vma && addr < (section->vma + section->size))
	    break;
    }

  if (section == NULL)
    {
      fprintf (file,
	       _("\nThere is a debug directory, but the section containing it could not be found\n"));
      return true;
    }
  else if (!(section->flags & SEC_HAS_CONTENTS))
    {
      fprintf (file,
	       _("\nThere is a debug directory in %s, but that section has no contents\n"),
	       section->name);
      return true;
    }
  else if (section->size < size)
    {
      fprintf (file,
	       _("\nError: section %s contains the debug data starting address but it is too small\n"),
	       section->name);
      return false;
    }

  dataoff = addr - section->vma;

  if (size > (section->size - dataoff))
    {
      fprintf (file, _("The debug data size field in the data directory is too big for the section"));
      return false;
    }

  fprintf (file, _("\nThere is a debug directory in %s at 0x%lx\n\n"),
	   section->name, (unsigned long) addr);

  fprintf (file,
	   _("Type                Size     Rva      Offset\n"));

  if (!bfd_malloc_and_get_section (abfd, section, &data))
    {
      fprintf (file, _("Error: Failed to read section %s contents.\n"), section->name);
      return false;
    }

  bfd_size_type num_entries = size / sizeof (struct external_IMAGE_DEBUG_DIRECTORY);

  for (i = 0; i < num_entries; i++)
    {
      const char *type_name;
      struct external_IMAGE_DEBUG_DIRECTORY *ext
	= (struct external_IMAGE_DEBUG_DIRECTORY *)(data + dataoff + (i * sizeof(struct external_IMAGE_DEBUG_DIRECTORY)));
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
	  CODEVIEW_INFO *cvinfo = NULL;
	  char *pdb = NULL;

	  if (idd.SizeOfData < 20)
	    {
	      fprintf (file, _(" (Invalid CodeView data size %lu - too small)\n"), (unsigned long) idd.SizeOfData);
	      continue;
	    }

	  cvinfo = (CODEVIEW_INFO *) bfd_malloc (idd.SizeOfData);
	  if (cvinfo == NULL)
	    {
	      fprintf (file, _(" (Out of memory for CodeView data, size %lu)\n"), (unsigned long) idd.SizeOfData);
	      continue;
	    }

	  if (!_bfd_XXi_slurp_codeview_record (abfd, (file_ptr) idd.PointerToRawData,
					       idd.SizeOfData, cvinfo, &pdb))
	    {
	      fprintf (file, _(" (Failed to slurp CodeView record at offset 0x%lx)\n"), (unsigned long) idd.PointerToRawData);
	      free (cvinfo);
	      continue;
	    }

	  unsigned int sig_len_to_print = cvinfo->SignatureLength;
	  if (sig_len_to_print > CV_INFO_SIGNATURE_LENGTH)
	    sig_len_to_print = CV_INFO_SIGNATURE_LENGTH;

	  for (j = 0; j < sig_len_to_print; j++)
	    sprintf (&signature[j*2], "%02x", cvinfo->Signature[j] & 0xff);
	  signature[sig_len_to_print * 2] = '\0';

	  fprintf (file, _("(format %c%c%c%c signature %s age %ld pdb %s)\n"),
		   ((char *)cvinfo)[0], ((char *)cvinfo)[1], ((char *)cvinfo)[2], ((char *)cvinfo)[3],
		   signature, cvinfo->Age, (pdb && pdb[0]) ? pdb : "(none)");

	  free (pdb);
	  free (cvinfo);
	}
    }

  free(data);

  if (size % sizeof (struct external_IMAGE_DEBUG_DIRECTORY) != 0)
    fprintf (file,
	    _("The debug directory size is not a multiple of the debug directory entry size (remainder %lu bytes)\n"),
	    (unsigned long) (size % sizeof (struct external_IMAGE_DEBUG_DIRECTORY)));

  return true;
}

static bool
pe_is_repro (bfd * abfd)
{
  pe_data_type *pe = pe_data (abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
  asection *section = NULL;
  bfd_byte *data = NULL;
  bool res = false;

  bfd_vma debug_dir_rva = extra->DataDirectory[PE_DEBUG_DATA].VirtualAddress;
  bfd_size_type debug_dir_size = extra->DataDirectory[PE_DEBUG_DATA].Size;

  if (debug_dir_size == 0)
    goto cleanup;

  bfd_vma target_vma = debug_dir_rva + extra->ImageBase;

  for (section = abfd->sections; section != NULL; section = section->next)
    {
      if (target_vma >= section->vma && target_vma < (section->vma + section->size))
	    break;
    }

  if (section == NULL
      || !(section->flags & SEC_HAS_CONTENTS))
    {
      goto cleanup;
    }

  bfd_size_type data_offset_in_section = target_vma - section->vma;

  if (data_offset_in_section >= section->size
      || debug_dir_size > (section->size - data_offset_in_section))
    {
      goto cleanup;
    }

  if (!bfd_malloc_and_get_section (abfd, section, &data))
    {
      goto cleanup;
    }

  bfd_size_type entry_size = sizeof (struct external_IMAGE_DEBUG_DIRECTORY);
  if (entry_size == 0)
    {
      goto cleanup;
    }

  bfd_size_type num_debug_entries = debug_dir_size / entry_size;

  if (num_debug_entries == 0)
    {
      goto cleanup;
    }

  struct external_IMAGE_DEBUG_DIRECTORY *ext_debug_dirs =
    (struct external_IMAGE_DEBUG_DIRECTORY *)(data + data_offset_in_section);

  for (bfd_size_type i = 0; i < num_debug_entries; i++)
    {
      struct external_IMAGE_DEBUG_DIRECTORY *ext_entry = &ext_debug_dirs[i];
      struct internal_IMAGE_DEBUG_DIRECTORY idd_entry;

      _bfd_XXi_swap_debugdir_in (abfd, ext_entry, &idd_entry);

      if (idd_entry.Type == PE_IMAGE_DEBUG_TYPE_REPRO)
        {
          res = true;
          break;
        }
    }

cleanup:
  free(data);
  return res;
}

/* Print out the program headers.  */

bool
_bfd_XX_print_private_bfd_data_common (bfd * abfd, void * vfile)
{
  FILE *file = (FILE *) vfile;
  pe_data_type *pe = pe_data (abfd);
  const struct internal_extra_pe_aouthdr *opthdr = &pe->pe_opthdr;
  const char *name;
  const char *subsystem_name;
  int j;

  /* Input validation: Ensure critical pointers are not NULL. */
  if (!file || !abfd || !pe || !opthdr)
    {
      /* Original function always returns true, maintaining external behavior.
         In a more robust system, this might set a BFD error and return false. */
      return true;
    }

  /* Structure for flag descriptions. */
  typedef struct {
      unsigned int flag_mask;
      const char *description;
  } FlagDescription;

  /* Helper to print file characteristics. */
  static void
  print_file_characteristics (FILE *out_file, unsigned int real_flags_val)
  {
    static const FlagDescription characteristics_flags[] = {
      { IMAGE_FILE_RELOCS_STRIPPED,       "relocations stripped" },
      { IMAGE_FILE_EXECUTABLE_IMAGE,      "executable" },
      { IMAGE_FILE_LINE_NUMS_STRIPPED,    "line numbers stripped" },
      { IMAGE_FILE_LOCAL_SYMS_STRIPPED,   "symbols stripped" },
      { IMAGE_FILE_LARGE_ADDRESS_AWARE,   "large address aware" },
      { IMAGE_FILE_BYTES_REVERSED_LO,     "little endian" },
      { IMAGE_FILE_32BIT_MACHINE,         "32 bit words" },
      { IMAGE_FILE_DEBUG_STRIPPED,        "debugging information removed" },
      { IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "copy to swap file if on removable media" },
      { IMAGE_FILE_NET_RUN_FROM_SWAP,     "copy to swap file if on network media" },
      { IMAGE_FILE_SYSTEM,                "system file" },
      { IMAGE_FILE_DLL,                   "DLL" },
      { IMAGE_FILE_UP_SYSTEM_ONLY,        "run only on uniprocessor machine" },
      { IMAGE_FILE_BYTES_REVERSED_HI,     "big endian" }
    };
    const size_t num_flags = sizeof(characteristics_flags) / sizeof(characteristics_flags[0]);
    size_t i;

    fprintf (out_file, _("\nCharacteristics 0x%x\n"), real_flags_val);
    for (i = 0; i < num_flags; ++i)
      {
        if (real_flags_val & characteristics_flags[i].flag_mask)
          {
            fprintf (out_file, "\t%s\n", characteristics_flags[i].description);
          }
      }
  }

  /* Helper to print timestamp information. */
  static void
  print_timestamp_info (bfd *bfd_obj, FILE *out_file, time_t timestamp_val)
  {
    if (pe_is_repro (bfd_obj))
      {
        fprintf (out_file, "\nTime/Date\t\t%08lx", (unsigned long) timestamp_val);
        fprintf (out_file, "\t(This is a reproducible build file hash, not a timestamp)\n");
      }
    else
      {
        fprintf (out_file, "\nTime/Date\t\t%s", ctime (&timestamp_val));
      }
  }

  /* Helper to get the name for the optional header magic value. */
  static const char *
  get_magic_name (unsigned short magic_value)
  {
    switch (magic_value)
      {
      case IMAGE_NT_OPTIONAL_HDR_MAGIC: return "PE32";
      case IMAGE_NT_OPTIONAL_HDR64_MAGIC: return "PE32+";
      case IMAGE_NT_OPTIONAL_HDRROM_MAGIC: return "ROM";
      default: return NULL;
      }
  }

  /* Helper to get the name for the subsystem value. */
  static const char *
  get_subsystem_name (unsigned short subsystem_value)
  {
    switch (subsystem_value)
      {
      case IMAGE_SUBSYSTEM_UNKNOWN:              return "unspecified";
      case IMAGE_SUBSYSTEM_NATIVE:               return "NT native";
      case IMAGE_SUBSYSTEM_WINDOWS_GUI:          return "Windows GUI";
      case IMAGE_SUBSYSTEM_WINDOWS_CUI:          return "Windows CUI";
      case IMAGE_SUBSYSTEM_POSIX_CUI:            return "POSIX CUI";
      case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:       return "Wince CUI";
      case IMAGE_SUBSYSTEM_EFI_APPLICATION:      return "EFI application";
      case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return "EFI boot service driver";
      case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:   return "EFI runtime driver";
      case IMAGE_SUBSYSTEM_SAL_RUNTIME_DRIVER:   return "SAL runtime driver";
      case IMAGE_SUBSYSTEM_XBOX:                 return "XBOX";
      default: return NULL;
      }
  }

  /* Helper to print DLL characteristics. */
  static void
  print_dll_characteristics (FILE *out_file, unsigned short dll_chars_val)
  {
    static const FlagDescription dll_characteristics_flags[] = {
      { IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA,      "HIGH_ENTROPY_VA" },
      { IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE,         "DYNAMIC_BASE" },
      { IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY,      "FORCE_INTEGRITY" },
      { IMAGE_DLL_CHARACTERISTICS_NX_COMPAT,            "NX_COMPAT" },
      { IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,          "NO_ISOLATION" },
      { IMAGE_DLLCHARACTERISTICS_NO_SEH,                "NO_SEH" },
      { IMAGE_DLLCHARACTERISTICS_NO_BIND,               "NO_BIND" },
      { IMAGE_DLLCHARACTERISTICS_APPCONTAINER,          "APPCONTAINER" },
      { IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,            "WDM_DRIVER" },
      { IMAGE_DLLCHARACTERISTICS_GUARD_CF,              "GUARD_CF" },
      { IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, "TERMINAL_SERVICE_AWARE" }
    };
    const size_t num_flags = sizeof(dll_characteristics_flags) / sizeof(dll_characteristics_flags[0]);
    size_t i;
    const char *indent = "\t\t\t\t\t";

    if (dll_chars_val == 0)
      {
        return; /* No characteristics set, print nothing. */
      }

    for (i = 0; i < num_flags; ++i)
      {
        if (dll_chars_val & dll_characteristics_flags[i].flag_mask)
          {
            fprintf (out_file, "%s%s\n", indent, dll_characteristics_flags[i].description);
          }
      }
  }

  /* Helper to print the data directory entries. */
  static void
  print_data_directory (bfd *bfd_obj, FILE *out_file, const IMAGE_DATA_DIRECTORY *data_directory_arr)
  {
    int k;
    fprintf (out_file, "\nThe Data Directory\n");
    for (k = 0; k < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; k++)
      {
        fprintf (out_file, "Entry %1x ", k);
        bfd_fprintf_vma (bfd_obj, out_file, data_directory_arr[k].VirtualAddress);
        fprintf (out_file, " %08lx ", (unsigned long) data_directory_arr[k].Size);
        fprintf (out_file, "%s\n", dir_names[k]);
      }
  }


  /* ------------------- Main Function Body ------------------- */

  /* Characteristics */
  print_file_characteristics (file, pe->real_flags);

  /* Time/Date */
  print_timestamp_info (abfd, file, pe->coff.timestamp);

  /* Optional Header Magic */
  name = get_magic_name (opthdr->Magic);
  fprintf (file, "\nMagic\t\t\t%04x", opthdr->Magic);
  if (name)
    fprintf (file, "\t(%s)", name);
  fprintf (file, "\n");

  /* Optional Header Details (common fields) */
  fprintf (file, "MajorLinkerVersion\t%d\n", opthdr->MajorLinkerVersion);
  fprintf (file, "MinorLinkerVersion\t%d\n", opthdr->MinorLinkerVersion);
  fprintf (file, "SizeOfCode\t\t");
  bfd_fprintf_vma (abfd, file, opthdr->SizeOfCode);
  fprintf (file, "\nSizeOfInitializedData\t");
  bfd_fprintf_vma (abfd, file, opthdr->SizeOfInitializedData);
  fprintf (file, "\nSizeOfUninitializedData\t");
  bfd_fprintf_vma (abfd, file, opthdr->SizeOfUninitializedData);
  fprintf (file, "\nAddressOfEntryPoint\t");
  bfd_fprintf_vma (abfd, file, opthdr->AddressOfEntryPoint);
  fprintf (file, "\nBaseOfCode\t\t");
  bfd_fprintf_vma (abfd, file, opthdr->BaseOfCode);
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
  /* PE32+ does not have BaseOfData member!  */
  fprintf (file, "\nBaseOfData\t\t");
  bfd_fprintf_vma (abfd, file, opthdr->BaseOfData);
#endif

  fprintf (file, "\nImageBase\t\t");
  bfd_fprintf_vma (abfd, file, opthdr->ImageBase);
  fprintf (file, "\nSectionAlignment\t%08x\n", opthdr->SectionAlignment);
  fprintf (file, "FileAlignment\t\t%08x\n", opthdr->FileAlignment);
  fprintf (file, "MajorOSystemVersion\t%d\n", opthdr->MajorOperatingSystemVersion);
  fprintf (file, "MinorOSystemVersion\t%d\n", opthdr->MinorOperatingSystemVersion);
  fprintf (file, "MajorImageVersion\t%d\n", opthdr->MajorImageVersion);
  fprintf (file, "MinorImageVersion\t%d\n", opthdr->MinorImageVersion);
  fprintf (file, "MajorSubsystemVersion\t%d\n", opthdr->MajorSubsystemVersion);
  fprintf (file, "MinorSubsystemVersion\t%d\n", opthdr->MinorSubsystemVersion);
  fprintf (file, "Win32Version\t\t%08x\n", opthdr->Win32Version);
  fprintf (file, "SizeOfImage\t\t%08x\n", opthdr->SizeOfImage);
  fprintf (file, "SizeOfHeaders\t\t%08x\n", opthdr->SizeOfHeaders);
  fprintf (file, "CheckSum\t\t%08x\n", opthdr->CheckSum);

  /* Subsystem */
  subsystem_name = get_subsystem_name (opthdr->Subsystem);
  fprintf (file, "Subsystem\t\t%08x", opthdr->Subsystem);
  if (subsystem_name)
    fprintf (file, "\t(%s)", subsystem_name);
  fprintf (file, "\n");

  /* DLL Characteristics */
  fprintf (file, "DllCharacteristics\t%08x\n", opthdr->DllCharacteristics);
  print_dll_characteristics (file, opthdr->DllCharacteristics);

  /* Stack, Heap, Loader, RVA sizes */
  fprintf (file, "SizeOfStackReserve\t");
  bfd_fprintf_vma (abfd, file, opthdr->SizeOfStackReserve);
  fprintf (file, "\nSizeOfStackCommit\t");
  bfd_fprintf_vma (abfd, file, opthdr->SizeOfStackCommit);
  fprintf (file, "\nSizeOfHeapReserve\t");
  bfd_fprintf_vma (abfd, file, opthdr->SizeOfHeapReserve);
  fprintf (file, "\nSizeOfHeapCommit\t");
  bfd_fprintf_vma (abfd, file, opthdr->SizeOfHeapCommit);
  fprintf (file, "\nLoaderFlags\t\t%08lx\n", (unsigned long) opthdr->LoaderFlags);
  fprintf (file, "NumberOfRvaAndSizes\t%08lx\n",
           (unsigned long) opthdr->NumberOfRvaAndSizes);

  /* Data Directory */
  print_data_directory (abfd, file, opthdr->DataDirectory);

  /* Other PE data printing functions */
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
  if (obj == NULL)
    {
      return false;
    }

  bfd_vma addr = * (bfd_vma *) obj;
  return (addr >= sect->vma) && (addr < (sect->vma + sect->size));
}

static asection *
find_section_by_vma (bfd *abfd, const bfd_vma addr)
{
  return bfd_sections_find_if (abfd, is_vma_in_section, (void *) & addr);
}

/* Copy any private info we understand from the input bfd
   to the output bfd.  */

bool
_bfd_XX_bfd_copy_private_bfd_data_common (bfd * ibfd, bfd * obfd)
{
  pe_data_type *ipe, *ope;
  bfd_size_type debug_dir_size;
  bfd_byte *data = NULL;
  bool success = true;

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
      && !(ipe->real_flags & IMAGE_FILE_RELOCS_STRIPPED))
    ope->dont_strip_reloc = 1;

  memcpy (ope->dos_message, ipe->dos_message, sizeof (ope->dos_message));

  debug_dir_size = ope->pe_opthdr.DataDirectory[PE_DEBUG_DATA].Size;
  if (debug_dir_size == 0)
    return true;

  bfd_vma addr = ope->pe_opthdr.DataDirectory[PE_DEBUG_DATA].VirtualAddress
                 + ope->pe_opthdr.ImageBase;
  bfd_vma last = addr + debug_dir_size - 1;
  asection *section = find_section_by_vma (obfd, last);

  if (section == NULL)
    return true;

  bfd_vma dataoff = addr - section->vma;

  if (addr < section->vma
      || section->size < dataoff
      || section->size - dataoff < debug_dir_size)
    {
      _bfd_error_handler
        (_("%pB: Data Directory (%lx bytes at %" PRIx64 ") "
           "extends across section boundary at %" PRIx64),
         obfd, debug_dir_size, (uint64_t) addr, (uint64_t) section->vma);
      return false;
    }

  if (!(section->flags & SEC_HAS_CONTENTS))
    {
      _bfd_error_handler (_("%pB: debug data section has no contents"), obfd);
      return false;
    }

  if (!bfd_malloc_and_get_section (obfd, section, &data))
    {
      _bfd_error_handler (_("%pB: failed to read debug data section"), obfd);
      return false;
    }

  unsigned int i;
  struct external_IMAGE_DEBUG_DIRECTORY *dd_ext =
    (struct external_IMAGE_DEBUG_DIRECTORY *)(data + dataoff);
  unsigned int num_debug_dirs = debug_dir_size
                                / sizeof (struct external_IMAGE_DEBUG_DIRECTORY);

  for (i = 0; i < num_debug_dirs; i++)
    {
      asection *ddsection;
      struct external_IMAGE_DEBUG_DIRECTORY *edd = &(dd_ext[i]);
      struct internal_IMAGE_DEBUG_DIRECTORY idd;
      bfd_vma idd_vma;

      _bfd_XXi_swap_debugdir_in (obfd, edd, &idd);

      if (idd.AddressOfRawData == 0)
        continue;

      idd_vma = idd.AddressOfRawData + ope->pe_opthdr.ImageBase;
      ddsection = find_section_by_vma (obfd, idd_vma);
      if (!ddsection)
        continue;

      idd.PointerToRawData
        = ddsection->filepos + idd_vma - ddsection->vma;
      _bfd_XXi_swap_debugdir_out (obfd, &idd, edd);
    }

  if (!bfd_set_section_contents (obfd, section, data, 0, section->size))
    {
      _bfd_error_handler (_("failed to update file offsets in debug directory"));
      success = false;
    }

  free (data);
  return success;
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

  struct coff_section_tdata *input_coff_data = coff_section_data (ibfd, isec);
  struct pei_section_tdata *input_pei_data = pei_section_data (ibfd, isec);

  if (input_coff_data == NULL || input_pei_data == NULL)
    return true;

  struct coff_section_tdata *output_coff_data = coff_section_data (obfd, osec);
  struct pei_section_tdata *output_pei_data;

  if (output_coff_data == NULL)
    {
      size_t amt = sizeof (struct coff_section_tdata);
      osec->used_by_bfd = bfd_zalloc (obfd, amt);
      if (osec->used_by_bfd == NULL)
	return false;
      output_coff_data = (struct coff_section_tdata *) osec->used_by_bfd;
    }

  output_pei_data = (struct pei_section_tdata *) output_coff_data->tdata;

  if (output_pei_data == NULL)
    {
      size_t amt = sizeof (struct pei_section_tdata);
      output_coff_data->tdata = bfd_zalloc (obfd, amt);
      if (output_coff_data->tdata == NULL)
	return false;
      output_pei_data = (struct pei_section_tdata *) output_coff_data->tdata;
    }

  output_pei_data->virt_size = input_pei_data->virt_size;
  output_pei_data->pe_flags = input_pei_data->pe_flags;

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
  unsigned long entry_value;
  unsigned long address_value;
  unsigned long size_value;

  if (data == NULL || datastart == NULL || dataend == NULL || data < datastart || data + 8 > dataend)
    return dataend + 1;

  if (is_name)
    {
      bfd_byte *name_ptr;
      unsigned int name_len;

      entry_value = bfd_get_32 (abfd, data);

      if (HighBitSet (entry_value))
	name_ptr = datastart + WithoutHighBit (entry_value);
      else
	name_ptr = datastart + entry_value - rva_bias;

      if (name_ptr == NULL || name_ptr < datastart || name_ptr + 2 > dataend)
	return dataend + 1;

      name_len = bfd_get_16 (abfd, name_ptr);

      if (name_len == 0 || name_len > 256 || name_ptr + 2 + name_len > dataend)
	return dataend + 1;
    }

  entry_value = bfd_get_32 (abfd, data + 4);

  if (HighBitSet (entry_value))
    {
      bfd_byte *subdir_ptr = datastart + WithoutHighBit (entry_value);

      if (subdir_ptr == NULL || subdir_ptr < datastart || subdir_ptr >= dataend)
	return dataend + 1;

      return rsrc_count_directory (abfd, datastart, subdir_ptr, dataend, rva_bias);
    }
  else
    {
      bfd_byte *data_entry_struct_ptr = datastart + entry_value - rva_bias;

      if (data_entry_struct_ptr == NULL || data_entry_struct_ptr < datastart || data_entry_struct_ptr + 16 > dataend)
	return dataend + 1;

      address_value = bfd_get_32 (abfd, data_entry_struct_ptr);
      size_value = bfd_get_32 (abfd, data_entry_struct_ptr + 4);

      bfd_byte *resource_data_start_ptr = datastart + address_value - rva_bias;
      bfd_byte *resource_data_end_ptr = resource_data_start_ptr + size_value;

      if (resource_data_start_ptr == NULL || resource_data_start_ptr < datastart || resource_data_end_ptr > dataend || resource_data_end_ptr < resource_data_start_ptr)
        return dataend + 1;

      return resource_data_end_ptr;
    }
}

#define RSRC_DIRECTORY_HEADER_SIZE    16
#define RSRC_OFFSET_NUM_NAMED_ENTRIES 12
#define RSRC_OFFSET_NUM_ID_ENTRIES    14
#define RSRC_ENTRY_HEADER_SIZE        8

static bfd_byte *
rsrc_count_directory (bfd *	     abfd,
		      bfd_byte *     datastart,
		      bfd_byte *     data,
		      bfd_byte *     dataend,
		      bfd_vma	     rva_bias)
{
  unsigned int num_total_entries;
  unsigned int num_named_entries;
  unsigned int num_id_entries_initial;
  bfd_byte *   highest_data = data;
  bfd_byte *   current_entry_ptr = data;

  if (current_entry_ptr + RSRC_DIRECTORY_HEADER_SIZE > dataend)
    return dataend + 1;

  num_named_entries      = bfd_get_16 (abfd, current_entry_ptr + RSRC_OFFSET_NUM_NAMED_ENTRIES);
  num_id_entries_initial = bfd_get_16 (abfd, current_entry_ptr + RSRC_OFFSET_NUM_ID_ENTRIES);

  num_total_entries = num_named_entries + num_id_entries_initial;

  current_entry_ptr += RSRC_DIRECTORY_HEADER_SIZE;

  for (unsigned int i = 0; i < num_total_entries; ++i)
    {
      if (current_entry_ptr + RSRC_ENTRY_HEADER_SIZE > dataend)
        return dataend + 1;

      bfd_byte * entry_end;
      int is_named_entry = (i < num_named_entries);

      entry_end = rsrc_count_entries (abfd, is_named_entry,
				      datastart, current_entry_ptr, dataend, rva_bias);

      current_entry_ptr += RSRC_ENTRY_HEADER_SIZE;

      highest_data = MAX (highest_data, entry_end);

      if (entry_end > dataend)
	return entry_end;
    }

  return MAX (highest_data, current_entry_ptr);
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
  unsigned long val;

#define RSRC_ENTRY_NAME_ID_VAL_OFFSET     0
#define RSRC_ENTRY_VALUE_DATA_OFFSET      4
#define RSRC_ENTRY_TOTAL_SIZE             8

#define RSRC_NAME_LENGTH_SIZE             2

#define RSRC_LEAF_INFO_ADDR_OFFSET        0
#define RSRC_LEAF_INFO_SIZE_OFFSET        4
#define RSRC_LEAF_INFO_CODEPAGE_OFFSET    8
#define RSRC_LEAF_INFO_RESERVED_OFFSET   12 /* Original code commented on this field */
#define RSRC_LEAF_INFO_TOTAL_SIZE        16 /* Total size of the leaf info block */

  if (entry == NULL || data == NULL || datastart == NULL || dataend == NULL || parent == NULL)
    return dataend; /* Or specific error handling for NULL pointers if different */

  if (data < datastart || data + RSRC_ENTRY_TOTAL_SIZE > dataend || data + RSRC_ENTRY_TOTAL_SIZE < data)
    return dataend;

  entry->parent = parent;
  entry->is_name = is_name;

  val = bfd_get_32 (abfd, data + RSRC_ENTRY_NAME_ID_VAL_OFFSET);

  if (is_name)
    {
      bfd_byte *name_ptr_base;
      unsigned long name_offset_val = val;

      if (HighBitSet (name_offset_val))
	{
	  name_ptr_base = datastart + WithoutHighBit (name_offset_val);
	}
      else
	{
	  /* The subtraction name_offset_val - rva_bias can underflow if name_offset_val < rva_bias.
	     Assuming the resource format ensures name_offset_val is an RVA and >= rva_bias for this path. */
	  name_ptr_base = datastart + name_offset_val - rva_bias;
	}

      if (name_ptr_base < datastart || name_ptr_base + RSRC_NAME_LENGTH_SIZE > dataend || name_ptr_base + RSRC_NAME_LENGTH_SIZE < name_ptr_base)
	return dataend;

      entry->name_id.name.len = bfd_get_16 (abfd, name_ptr_base);
      entry->name_id.name.string = name_ptr_base + RSRC_NAME_LENGTH_SIZE;

      /* Ensure the entire string data (length + string bytes) is within bounds.
         Adding a wrap-around check for 'entry->name_id.name.len' in case it's maliciously large. */
      if (entry->name_id.name.string < datastart ||
          entry->name_id.name.string + entry->name_id.name.len > dataend ||
          entry->name_id.name.string + entry->name_id.name.len < entry->name_id.name.string)
	return dataend;
    }
  else
    {
      entry->name_id.id = val;
    }

  val = bfd_get_32 (abfd, data + RSRC_ENTRY_VALUE_DATA_OFFSET);

  if (HighBitSet (val))
    {
      entry->is_dir = true;
      entry->value.directory = bfd_malloc (sizeof (*entry->value.directory));
      if (entry->value.directory == NULL)
	return dataend;

      bfd_byte *dir_data_ptr = datastart + WithoutHighBit (val);

      /* For a directory, we only know its starting pointer.
         The actual size is determined during rsrc_parse_directory.
         Ensure the starting pointer is valid. */
      if (dir_data_ptr < datastart || dir_data_ptr > dataend)
	return dataend;

      return rsrc_parse_directory (abfd, entry->value.directory,
				   datastart,
				   dir_data_ptr,
				   dataend, rva_bias, entry);
    }

  entry->is_dir = false;
  entry->value.leaf = bfd_malloc (sizeof (*entry->value.leaf));
  if (entry->value.leaf == NULL)
    return dataend;

  bfd_byte *leaf_info_ptr = datastart + val;

  /* Ensure the leaf information block is entirely within readable bounds. */
  if (leaf_info_ptr < datastart ||
      leaf_info_ptr + RSRC_LEAF_INFO_TOTAL_SIZE > dataend ||
      leaf_info_ptr + RSRC_LEAF_INFO_TOTAL_SIZE < leaf_info_ptr)
    return dataend;

  unsigned long resource_addr_rva = bfd_get_32 (abfd, leaf_info_ptr + RSRC_LEAF_INFO_ADDR_OFFSET);
  unsigned long resource_size = bfd_get_32 (abfd, leaf_info_ptr + RSRC_LEAF_INFO_SIZE_OFFSET);
  entry->value.leaf->size = resource_size;
  entry->value.leaf->codepage = bfd_get_32 (abfd, leaf_info_ptr + RSRC_LEAF_INFO_CODEPAGE_OFFSET);
  /* The reserved field (leaf_info_ptr + RSRC_LEAF_INFO_RESERVED_OFFSET) is read but not used,
     consistent with original logic's FIXME comment. */

  /* Calculate the actual start of the resource data in the file.
     Similar potential underflow if resource_addr_rva < rva_bias;
     assuming correctness for the resource format. */
  bfd_byte *resource_data_start = datastart + resource_addr_rva - rva_bias;

  /* Ensure the resource data itself, of 'resource_size' bytes,
     is entirely within the dataend boundary.
     Adding a wrap-around check for 'resource_size' in case it's maliciously large. */
  if (resource_data_start < datastart ||
      resource_data_start + resource_size > dataend ||
      resource_data_start + resource_size < resource_data_start)
    return dataend;

  entry->value.leaf->data = bfd_malloc (resource_size);
  if (entry->value.leaf->data == NULL)
    return dataend;

  memcpy (entry->value.leaf->data, resource_data_start, resource_size);

  return resource_data_start + resource_size;

#undef RSRC_ENTRY_NAME_ID_VAL_OFFSET
#undef RSRC_ENTRY_VALUE_DATA_OFFSET
#undef RSRC_ENTRY_TOTAL_SIZE
#undef RSRC_NAME_LENGTH_SIZE
#undef RSRC_LEAF_INFO_ADDR_OFFSET
#undef RSRC_LEAF_INFO_SIZE_OFFSET
#undef RSRC_LEAF_INFO_CODEPAGE_OFFSET
#undef RSRC_LEAF_INFO_RESERVED_OFFSET
#undef RSRC_LEAF_INFO_TOTAL_SIZE
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
  rsrc_entry *head_entry = NULL;
  rsrc_entry *current_entry = NULL;
  bfd_byte *highest_data_result = highest_data;

  if (chain->num_entries == 0)
    {
      chain->first_entry = NULL;
      chain->last_entry = NULL;
      return highest_data;
    }

  for (i = 0; i < chain->num_entries; ++i)
    {
      rsrc_entry *new_entry = bfd_malloc (sizeof (*new_entry));
      if (new_entry == NULL)
        {
          rsrc_entry *node_to_free = head_entry;
          while (node_to_free != NULL)
            {
              rsrc_entry *next_node = node_to_free->next_entry;
              bfd_free (node_to_free);
              node_to_free = next_node;
            }
          chain->first_entry = NULL;
          chain->last_entry = NULL;
          return dataend;
        }

      new_entry->next_entry = NULL;

      if (head_entry == NULL)
        {
          head_entry = new_entry;
          chain->first_entry = new_entry;
        }
      else
        {
          current_entry->next_entry = new_entry;
        }
      current_entry = new_entry;

      bfd_byte *entry_end = rsrc_parse_entry (abfd, is_name, current_entry, datastart,
				    data, dataend, rva_bias, parent);

      data += 8;

      highest_data_result = max (entry_end, highest_data_result);

      if (entry_end > dataend)
        {
          rsrc_entry *node_to_free = head_entry;
          while (node_to_free != NULL)
            {
              rsrc_entry *next_node = node_to_free->next_entry;
              bfd_free (node_to_free);
              node_to_free = next_node;
            }
          chain->first_entry = NULL;
          chain->last_entry = NULL;
          return dataend;
        }
    }

  chain->last_entry = current_entry;

  return highest_data_result;
}

static bfd_byte *
rsrc_parse_directory (bfd *	       abfd,
		      rsrc_directory * table,
		      bfd_byte *       datastart,
		      bfd_byte *       data,
		      bfd_byte *       dataend,
		      bfd_vma	       rva_bias,
		      rsrc_entry *     entry)
{
  bfd_byte * current_highest_data = data;
  const unsigned int RSRC_DIR_HEADER_SIZE = 16;
  const unsigned int RSRC_ENTRY_METADATA_SIZE = 8;

  if (table == NULL)
    return dataend;

  // Ensure there is enough space for the directory header (16 bytes)
  // Check for initial pointer validity (data must be within [datastart, dataend))
  // and for potential pointer arithmetic overflow if (data + RSRC_DIR_HEADER_SIZE) wraps around.
  if (data == NULL || data < datastart || data + RSRC_DIR_HEADER_SIZE > dataend || data + RSRC_DIR_HEADER_SIZE < data)
    return dataend;

  table->characteristics = bfd_get_32 (abfd, data);
  table->time = bfd_get_32 (abfd, data + 4);
  table->major = bfd_get_16 (abfd, data + 8);
  table->minor = bfd_get_16 (abfd, data + 10);
  table->names.num_entries = bfd_get_16 (abfd, data + 12);
  table->ids.num_entries = bfd_get_16 (abfd, data + 14);
  table->entry = entry;

  // Advance data pointer past the directory header
  data += RSRC_DIR_HEADER_SIZE;

  // Parse name entries
  if (table->names.num_entries > 0)
    {
      unsigned int names_entries_total_size = table->names.num_entries * RSRC_ENTRY_METADATA_SIZE;

      // Check if there is enough space for all name entries metadata
      if (data + names_entries_total_size > dataend || data + names_entries_total_size < data)
        return dataend;

      current_highest_data = rsrc_parse_entries (abfd, &table->names, true, data,
                                                 datastart, data, dataend, rva_bias, table);

      // If parsing entries failed, propagate the error (assuming dataend indicates an error)
      if (current_highest_data == dataend)
        return dataend;

      // Advance data pointer past the name entries metadata
      data += names_entries_total_size;
    }

  // Parse ID entries
  if (table->ids.num_entries > 0)
    {
      unsigned int ids_entries_total_size = table->ids.num_entries * RSRC_ENTRY_METADATA_SIZE;

      // Check if there is enough space for all ID entries metadata
      if (data + ids_entries_total_size > dataend || data + ids_entries_total_size < data)
        return dataend;

      // Pass the highest_data pointer from previous parsing steps to ensure it tracks the overall furthest access
      bfd_byte * temp_highest_data = rsrc_parse_entries (abfd, &table->ids, false, current_highest_data,
                                                         datastart, data, dataend, rva_bias, table);

      // If parsing entries failed, propagate the error
      if (temp_highest_data == dataend)
        return dataend;

      current_highest_data = temp_highest_data; // Update the overall highest data pointer
      
      // Advance data pointer past the ID entries metadata
      data += ids_entries_total_size;
    }

  // Return the maximum of the two pointers:
  // current_highest_data tracks the furthest byte accessed within the data content (often pointed to by entries).
  // data tracks the furthest byte accessed within the directory's metadata entries themselves.
  // The function should return the overall furthest byte accessed by this directory.
  return (current_highest_data > data) ? current_highest_data : data;
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
  if (data == NULL || string == NULL) {
    return;
  }

  const size_t length_field_size_bytes = 2;
  const size_t char_size_bytes = 2;

  size_t string_content_bytes = (size_t)string->len * char_size_bytes;

  bfd_put_16 (data->abfd, string->len, data->next_string);
  memcpy (data->next_string + length_field_size_bytes, string->string, string_content_bytes);
  data->next_string += length_field_size_bytes + string_content_bytes;
}

static inline unsigned int
rsrc_compute_rva (rsrc_write_data * data,
		  bfd_byte *	    addr)
{
  ptrdiff_t byte_offset;

  // Calculate the byte offset from the base address.
  // The result of pointer subtraction (addr - data->datastart) is of type ptrdiff_t.
  // This value can be negative if 'addr' is before 'data->datastart'.
  byte_offset = addr - data->datastart;

  // The external functionality requires returning an unsigned int.
  // The original code implicitly converted 'byte_offset' (ptrdiff_t) to 'unsigned int'.
  // This conversion has specific behavior:
  // - If 'byte_offset' is negative, it wraps around to a large positive unsigned value.
  // - If 'byte_offset' is positive and exceeds UINT_MAX, it truncates.
  // To explicitly document and preserve this exact behavior while satisfying SonarCloud
  // for implicit type conversions and potential signed-to-unsigned warnings,
  // we perform an explicit cast.
  return (unsigned int)byte_offset + data->rva_bias;
}

#include <string.h>

#define RSRC_LEAF_RVA_OFFSET     0
#define RSRC_LEAF_SIZE_OFFSET    4
#define RSRC_LEAF_CODEPAGE_OFFSET 8
#define RSRC_LEAF_RESERVED_OFFSET 12
#define RSRC_LEAF_HEADER_SIZE   16

#define RSRC_ALIGNMENT_BYTES    8
#define RSRC_ALIGNMENT_MASK     (RSRC_ALIGNMENT_BYTES - 1)
#define RSRC_ALIGNMENT_NEG_MASK (~RSRC_ALIGNMENT_MASK)

static void
rsrc_write_leaf (rsrc_write_data * data,
		 rsrc_leaf *	   leaf)
{
  bfd_put_32 (data->abfd, rsrc_compute_rva (data, data->next_data),
              data->next_leaf + RSRC_LEAF_RVA_OFFSET);
  bfd_put_32 (data->abfd, leaf->size,
              data->next_leaf + RSRC_LEAF_SIZE_OFFSET);
  bfd_put_32 (data->abfd, leaf->codepage,
              data->next_leaf + RSRC_LEAF_CODEPAGE_OFFSET);
  bfd_put_32 (data->abfd, 0,
              data->next_leaf + RSRC_LEAF_RESERVED_OFFSET);
  data->next_leaf += RSRC_LEAF_HEADER_SIZE;

  memcpy (data->next_data, leaf->data, leaf->size);
  data->next_data += ((leaf->size + RSRC_ALIGNMENT_MASK) & RSRC_ALIGNMENT_NEG_MASK);
}

static void rsrc_write_directory (rsrc_write_data *, rsrc_directory *);

static bfd_boolean
rsrc_write_entry (rsrc_write_data *  data,
		  bfd_byte *	     where,
		  rsrc_entry *	     entry)
{
  const unsigned int FIELD_SIZE = 4;

  if (entry->is_name)
    {
      bfd_put_32 (data->abfd,
		  SetHighBit (data->next_string - data->datastart),
		  where);
      if (!rsrc_write_string (data, &entry->name_id.name))
        return FALSE;
    }
  else
    {
      bfd_put_32 (data->abfd, entry->name_id.id, where);
    }

  if (entry->is_dir)
    {
      bfd_put_32 (data->abfd,
		  SetHighBit (data->next_table - data->datastart),
		  where + FIELD_SIZE);
      if (!rsrc_write_directory (data, entry->value.directory))
        return FALSE;
    }
  else
    {
      bfd_put_32 (data->abfd, data->next_leaf - data->datastart, where + FIELD_SIZE);
      if (!rsrc_write_leaf (data, entry->value.leaf))
        return FALSE;
    }

  return TRUE;
}

#include <stddef.h>
#include <stdbool.h>

typedef struct rsrc_directory rsrc_directory;
typedef struct rsrc_entry rsrc_entry;

typedef struct {
    size_t len;
} rsrc_string;

typedef union {
    rsrc_string name;
    unsigned int id;
} rsrc_name_id;

struct rsrc_entry {
    rsrc_name_id name_id;
    bool is_dir;
    union {
        rsrc_directory *directory;
        void *leaf_data;
    } value;
    rsrc_entry *next_entry;
};

typedef struct {
    rsrc_entry *first_entry;
} rsrc_entry_list_head;

struct rsrc_directory {
    rsrc_entry_list_head names;
    rsrc_entry_list_head ids;
};

static size_t sizeof_tables_and_entries = 0;
static size_t sizeof_strings = 0;
static size_t sizeof_leaves = 0;

#define RSRC_DIRECTORY_HEADER_SIZE 16
#define RSRC_TABLE_ENTRY_SIZE      8
#define RSRC_LEAF_SIZE             16
#define RSRC_STRING_CHAR_SIZE      2

static void rsrc_compute_region_sizes (rsrc_directory * dir);

static void
process_rsrc_entry_list(rsrc_entry * first_entry, bool is_name_list)
{
  rsrc_entry * entry = first_entry;
  while (entry != NULL)
  {
    sizeof_tables_and_entries += RSRC_TABLE_ENTRY_SIZE;

    if (is_name_list)
    {
      sizeof_strings += (entry->name_id.name.len + 1) * RSRC_STRING_CHAR_SIZE;
    }

    if (entry->is_dir)
    {
      rsrc_compute_region_sizes(entry->value.directory);
    }
    else
    {
      sizeof_leaves += RSRC_LEAF_SIZE;
    }
    entry = entry->next_entry;
  }
}

static void
rsrc_compute_region_sizes (rsrc_directory * dir)
{
  if (dir == NULL)
    return;

  sizeof_tables_and_entries += RSRC_DIRECTORY_HEADER_SIZE;

  process_rsrc_entry_list(dir->names.first_entry, true);

  process_rsrc_entry_list(dir->ids.first_entry, false);
}

static void
rsrc_write_directory (rsrc_write_data * data,
		      rsrc_directory *  dir)
{
  rsrc_entry * entry;
  unsigned int num_remaining;
  bfd_byte * next_entry_pos;

  const unsigned int RSRC_DIRECTORY_HEADER_SIZE = 16;
  const unsigned int RSRC_ENTRY_SIZE = 8;

  bfd_put_32 (data->abfd, dir->characteristics, data->next_table);
  bfd_put_32 (data->abfd, 0, data->next_table + 4);
  bfd_put_16 (data->abfd, dir->major, data->next_table + 8);
  bfd_put_16 (data->abfd, dir->minor, data->next_table + 10);
  bfd_put_16 (data->abfd, dir->names.num_entries, data->next_table + 12);
  bfd_put_16 (data->abfd, dir->ids.num_entries, data->next_table + 14);

  next_entry_pos = data->next_table + RSRC_DIRECTORY_HEADER_SIZE;
  data->next_table = next_entry_pos
    + (dir->names.num_entries * RSRC_ENTRY_SIZE)
    + (dir->ids.num_entries * RSRC_ENTRY_SIZE);

  entry = dir->names.first_entry;
  num_remaining = dir->names.num_entries;
  while (num_remaining > 0)
    {
      if (entry == NULL)
        {
          bfd_set_error (bfd_error_bad_value);
          return;
        }
      if (!entry->is_name)
        {
          bfd_set_error (bfd_error_bad_value);
          return;
        }
      rsrc_write_entry (data, next_entry_pos, entry);
      next_entry_pos += RSRC_ENTRY_SIZE;
      entry = entry->next_entry;
      num_remaining--;
    }
  if (entry != NULL)
    {
      bfd_set_error (bfd_error_bad_value);
      return;
    }

  entry = dir->ids.first_entry;
  num_remaining = dir->ids.num_entries;
  while (num_remaining > 0)
    {
      if (entry == NULL)
        {
          bfd_set_error (bfd_error_bad_value);
          return;
        }
      if (entry->is_name)
        {
          bfd_set_error (bfd_error_bad_value);
          return;
        }
      rsrc_write_entry (data, next_entry_pos, entry);
      next_entry_pos += RSRC_ENTRY_SIZE;
      entry = entry->next_entry;
      num_remaining--;
    }
  if (entry != NULL)
    {
      bfd_set_error (bfd_error_bad_value);
      return;
    }

  if (data->next_table != next_entry_pos)
    {
      bfd_set_error (bfd_error_bad_value);
      return;
    }
}

#if ! defined __CYGWIN__ && ! defined __MINGW32__
/* Return the length (number of units) of the first character in S,
   putting its 'ucs4_t' representation in *PUC.  */

#define UTF16_SURROGATE_AREA_START 0xD800
#define UTF16_SURROGATE_AREA_END   0xDFFF
#define UTF16_HIGH_SURROGATE_START 0xD800
#define UTF16_HIGH_SURROGATE_END   0xDBFF
#define UTF16_LOW_SURROGATE_START  0xDC00
#define UTF16_LOW_SURROGATE_END    0xDFFF

#define UNICODE_REPLACEMENT_CHAR 0xFFFD
#define UNICODE_SUPPLEMENTARY_PLANE_OFFSET 0x10000

static unsigned int
u16_mbtouc (wint_t * puc, const unsigned short * s, unsigned int n)
{
  if (n == 0)
    {
      return 0;
    }

  unsigned short c1 = *s;

  if (c1 < UTF16_SURROGATE_AREA_START || c1 > UTF16_SURROGATE_AREA_END)
    {
      *puc = c1;
      return 1;
    }

  if (c1 >= UTF16_HIGH_SURROGATE_START && c1 <= UTF16_HIGH_SURROGATE_END)
    {
      if (n >= 2)
        {
          unsigned short c2 = s[1];
          if (c2 >= UTF16_LOW_SURROGATE_START && c2 <= UTF16_LOW_SURROGATE_END)
            {
              *puc = UNICODE_SUPPLEMENTARY_PLANE_OFFSET +
                     ((c1 - UTF16_HIGH_SURROGATE_START) << 10) +
                     (c2 - UTF16_LOW_SURROGATE_START);
              return 2;
            }
          else
            {
              *puc = UNICODE_REPLACEMENT_CHAR;
              return 1;
            }
        }
      else
        {
          *puc = UNICODE_REPLACEMENT_CHAR;
          return n;
        }
    }

  *puc = UNICODE_REPLACEMENT_CHAR;
  return 1;
}
#endif /* not Cygwin/Mingw */

/* Perform a comparison of two entries.  */
static inline unsigned int min_u(unsigned int a, unsigned int b)
{
  return a < b ? a : b;
}

static signed int
rsrc_cmp (bool is_name, rsrc_entry * a, rsrc_entry * b)
{
  if (!is_name) {
    signed int id_a = (signed int)a->name_id.id;
    signed int id_b = (signed int)b->name_id.id;
    return id_a - id_b;
  }

  const bfd_byte *astring = a->name_id.name.string;
  unsigned int alen = a->name_id.name.len;
  const bfd_byte *bstring = b->name_id.name.string;
  unsigned int blen = b->name_id.name.len;

  signed int res = 0;

#if defined __CYGWIN__
  size_t len_chars = min_u(alen / sizeof(wchar_t), blen / sizeof(wchar_t));
  res = wcsncasecmp((const wchar_t *)astring, (const wchar_t *)bstring, len_chars);
#elif defined __MINGW32__
  size_t len_chars = min_u(alen / sizeof(wchar_t), blen / sizeof(wchar_t));
  res = wcsnicmp((const wchar_t *)astring, (const wchar_t *)bstring, len_chars);
#else
  unsigned int common_byte_len = min_u(alen, blen);

  for (unsigned int i = 0; i < common_byte_len; i += 2) {
    wint_t awc, bwc;
    unsigned int bytes_a, bytes_b;

    bytes_a = u16_mbtouc(&awc, (const unsigned short *)(astring + i), 2);
    bytes_b = u16_mbtouc(&bwc, (const unsigned short *)(bstring + i), 2);

    if (bytes_a != bytes_b) {
      return (signed int)bytes_a - (signed int)bytes_b;
    }

    awc = towlower(awc);
    bwc = towlower(bwc);

    res = (signed int)awc - (signed int)bwc;
    if (res != 0) {
      break;
    }
  }
#endif

  if (res == 0) {
    res = (signed int)alen - (signed int)blen;
  }

  return res;
}

static void
rsrc_print_name (char * buffer, size_t buffer_size, rsrc_string string)
{
  if (buffer == NULL || buffer_size == 0) {
    return;
  }

  size_t current_len = 0;
  bfd_byte * name_ptr = string.string;

  for (unsigned int i = 0; i < string.len; ++i) {
    if (current_len + 1 < buffer_size) {
      buffer[current_len] = (char)name_ptr[0];
      current_len++;
    } else {
      break;
    }
    name_ptr += 2;
  }

  if (current_len < buffer_size) {
    buffer[current_len] = '\0';
  } else {
    buffer[buffer_size - 1] = '\0';
  }
}

static const char *get_resource_type_name(unsigned int id)
{
    switch (id)
    {
        case 1: return "CURSOR";
        case 2: return "BITMAP";
        case 3: return "ICON";
        case 4: return "MENU";
        case 5: return "DIALOG";
        case 6: return "STRING";
        case 7: return "FONTDIR";
        case 8: return "FONT";
        case 9: return "ACCELERATOR";
        case 10: return "RCDATA";
        case 11: return "MESSAGETABLE";
        case 12: return "GROUP_CURSOR";
        case 14: return "GROUP_ICON";
        case 16: return "VERSION";
        case 17: return "DLGINCLUDE";
        case 19: return "PLUGPLAY";
        case 20: return "VXD";
        case 21: return "ANICURSOR";
        case 22: return "ANIICON";
        case 23: return "HTML";
        case 24: return "MANIFEST";
        case 240: return "DLGINIT";
        case 241: return "TOOLBAR";
        default: return NULL;
    }
}

static const char *
rsrc_resource_name (rsrc_entry *entry, rsrc_directory *dir, char *buffer, size_t buffer_size)
{
    bool is_string_resource_type = false;
    size_t offset = 0;
    int written_len = 0;

    if (buffer == NULL || buffer_size == 0) {
        return NULL;
    }
    buffer[0] = '\0';

    #define APPEND_FORMATTED_STRING(fmt, ...) \
        do { \
            if (offset < buffer_size) { \
                size_t remaining_size = buffer_size - offset; \
                written_len = snprintf(buffer + offset, remaining_size, fmt, ##__VA_ARGS__); \
                if (written_len > 0) { \
                    offset += (size_t) (written_len < remaining_size ? written_len : remaining_size - 1); \
                } else if (written_len < 0) { \
                    buffer[offset] = '\0'; \
                    return buffer; \
                } \
            } \
        } while (0)

    rsrc_entry *parent_entry = NULL;
    if (dir != NULL && dir->entry != NULL && dir->entry->parent != NULL)
    {
        parent_entry = dir->entry->parent->entry;
    }

    if (parent_entry != NULL)
    {
        APPEND_FORMATTED_STRING("%s", "type: ");

        if (parent_entry->is_name)
        {
            APPEND_FORMATTED_STRING("%s", parent_entry->name_id.name);
        }
        else
        {
            unsigned int id = parent_entry->name_id.id;
            APPEND_FORMATTED_STRING("%x", id);

            const char *type_name = get_resource_type_name(id);
            if (type_name != NULL)
            {
                APPEND_FORMATTED_STRING(" (%s)", type_name);
                if (id == 6)
                {
                    is_string_resource_type = true;
                }
            }
        }
    }

    if (dir != NULL && dir->entry != NULL)
    {
        APPEND_FORMATTED_STRING("%s", " name: ");

        if (dir->entry->is_name)
        {
            APPEND_FORMATTED_STRING("%s", dir->entry->name_id.name);
        }
        else
        {
            unsigned int id = dir->entry->name_id.id;
            APPEND_FORMATTED_STRING("%x", id);

            if (is_string_resource_type)
            {
                APPEND_FORMATTED_STRING(" (resource id range: %d - %d)",
                                         (id - 1) << 4, (id << 4) - 1);
            }
        }
    }

    if (entry != NULL)
    {
        APPEND_FORMATTED_STRING("%s", " lang: ");

        if (entry->is_name)
        {
            APPEND_FORMATTED_STRING("%s", entry->name_id.name);
        }
        else
        {
            APPEND_FORMATTED_STRING("%x", entry->name_id.id);
        }
    }

    if (offset >= buffer_size) {
        buffer[buffer_size - 1] = '\0';
    } else {
        buffer[offset] = '\0';
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

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

/*
 * Assuming the following types and functions are defined and available:
 *
 * typedef unsigned char bfd_byte;
 *
 * struct rsrc_leaf {
 *   bfd_byte *data;
 *   size_t size;
 * };
 *
 * struct rsrc_entry_name_id {
 *   unsigned int id;
 * };
 *
 * struct rsrc_entry_parent_entry_type {
 *   struct rsrc_entry_name_id name_id;
 *   bool is_name;
 * };
 *
 * struct rsrc_entry {
 *   bool is_dir;
 *   union {
 *     struct rsrc_leaf *leaf;
 *   } value;
 *   struct rsrc_entry *parent;
 *   struct rsrc_entry_parent_entry_type *entry;
 * };
 *
 * extern void *bfd_malloc (size_t);
 * extern void _bfd_error_handler (const char *, ...);
 * #define _(msg) (msg)
 * #define BFD_ASSERT(expr) do { if (!(expr)) abort(); } while (0)
 */

#define RSRC_STRING_SLOTS 16
#define RSRC_UTF16_CHAR_SIZE 2
#define RSRC_LENGTH_FIELD_BYTES RSRC_UTF16_CHAR_SIZE

static inline unsigned int
get_string_length_from_buffer (const bfd_byte *ptr)
{
  return ptr[0] | ((unsigned int)ptr[1] << 8);
}

static inline size_t
get_string_block_byte_size (unsigned int string_len_chars)
{
  return (string_len_chars + 1) * RSRC_UTF16_CHAR_SIZE;
}

static bool
rsrc_merge_string_entries (rsrc_entry * a, rsrc_entry * b)
{
  size_t total_bytes_to_copy_from_b = 0;
  unsigned int i;
  const bfd_byte * astring_cursor;
  const bfd_byte * bstring_cursor;
  bfd_byte * new_data_buffer;
  bfd_byte * merged_data_cursor;

  BFD_ASSERT (! a->is_dir && a->value.leaf != NULL);
  BFD_ASSERT (! b->is_dir && b->value.leaf != NULL);

  astring_cursor = a->value.leaf->data;
  bstring_cursor = b->value.leaf->data;

  for (i = 0; i < RSRC_STRING_SLOTS; i++)
    {
      unsigned int a_len_chars = get_string_length_from_buffer (astring_cursor);
      unsigned int b_len_chars = get_string_length_from_buffer (bstring_cursor);

      if (a_len_chars == 0)
	{
	  if (b_len_chars != 0)
	    {
	      total_bytes_to_copy_from_b += get_string_block_byte_size (b_len_chars);
	    }
	}
      else if (b_len_chars == 0)
	{
	  /* No action needed. */
	}
      else
	{
	  if (a_len_chars != b_len_chars
	      || memcmp (astring_cursor + RSRC_LENGTH_FIELD_BYTES,
			 bstring_cursor + RSRC_LENGTH_FIELD_BYTES,
			 a_len_chars * RSRC_UTF16_CHAR_SIZE) != 0)
	    {
	      if (a->parent != NULL
		  && a->parent->entry != NULL
		  && !a->parent->entry->is_name)
		{
		  _bfd_error_handler (_(".rsrc merge failure: duplicate string resource: %d"),
				      ((a->parent->entry->name_id.id - 1) << 4) + i);
		}
	      return false;
	    }
	}

      astring_cursor += get_string_block_byte_size (a_len_chars);
      bstring_cursor += get_string_block_byte_size (b_len_chars);
    }

  if (total_bytes_to_copy_from_b == 0)
    return true;

  size_t new_total_size = a->value.leaf->size + total_bytes_to_copy_from_b;
  new_data_buffer = bfd_malloc (new_total_size);
  if (new_data_buffer == NULL)
    {
      return false;
    }

  merged_data_cursor = new_data_buffer;
  astring_cursor = a->value.leaf->data;
  bstring_cursor = b->value.leaf->data;

  for (i = 0; i < RSRC_STRING_SLOTS; i++)
    {
      unsigned int a_len_chars = get_string_length_from_buffer (astring_cursor);
      unsigned int b_len_chars = get_string_length_from_buffer (bstring_cursor);
      size_t current_block_byte_size;

      if (a_len_chars != 0)
	{
	  current_block_byte_size = get_string_block_byte_size (a_len_chars);
	  memcpy (merged_data_cursor, astring_cursor, current_block_byte_size);
	  merged_data_cursor += current_block_byte_size;
	}
      else if (b_len_chars != 0)
	{
	  current_block_byte_size = get_string_block_byte_size (b_len_chars);
	  memcpy (merged_data_cursor, bstring_cursor, current_block_byte_size);
	  merged_data_cursor += current_block_byte_size;
	}
      else
	{
	  *merged_data_cursor++ = 0;
	  *merged_data_cursor++ = 0;
	}

      astring_cursor += get_string_block_byte_size (a_len_chars);
      bstring_cursor += get_string_block_byte_size (b_len_chars);
    }

  BFD_ASSERT ((size_t)(merged_data_cursor - new_data_buffer) == new_total_size);

  free (a->value.leaf->data);

  a->value.leaf->data = new_data_buffer;
  a->value.leaf->size = new_total_size;

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
  if (chain == NULL || chain->num_entries < 2)
    return;

  rsrc_entry * entry_current;
  rsrc_entry * entry_next;
  rsrc_entry ** ptr_to_current_entry;
  bool swapped_in_pass;

  do
    {
      swapped_in_pass = false;
      ptr_to_current_entry = & chain->first_entry;
      entry_current = * ptr_to_current_entry;

      if (entry_current == NULL || entry_current->next_entry == NULL) {
          chain->last_entry = entry_current;
          return;
      }
      entry_next  = entry_current->next_entry;

      while (entry_next != NULL)
	{
          current_bfd_error = bfd_error_no_error;

	  signed int cmp = rsrc_cmp (is_name, entry_current, entry_next);

	  if (cmp > 0)
	    {
	      entry_current->next_entry = entry_next->next_entry;
	      entry_next->next_entry = entry_current;
	      *ptr_to_current_entry = entry_next;

	      entry_current = *ptr_to_current_entry;
	      entry_next = entry_current->next_entry;
	      ptr_to_current_entry = & (entry_current->next_entry);
	      swapped_in_pass = true;
	    }
	  else if (cmp == 0)
	    {
              bool error_occurred = false;

	      if (entry_current->is_dir && entry_next->is_dir)
		{
		  error_occurred = process_identical_dir_entries(chain, dir, entry_current, entry_next,
                                                                 ptr_to_current_entry, &swapped_in_pass);
		}
	      else if (entry_current->is_dir != entry_next->is_dir)
		{
		  _bfd_error_handler (_(".rsrc merge failure: a directory matches a leaf"));
		  bfd_set_error (bfd_error_file_truncated);
		  error_occurred = true;
		}
	      else
		{
		  error_occurred = process_identical_leaf_entries(chain, dir, entry_current, entry_next);
		}

              if (error_occurred || bfd_set_error_was_called()) {
                  return;
              }

              if (chain->num_entries < 2) {
                  chain->last_entry = chain->first_entry;
                  return;
              }

              entry_current = *ptr_to_current_entry;
              entry_next = entry_current->next_entry;
	    }
	  else
	    {
	      ptr_to_current_entry = & entry_current->next_entry;
	      entry_current = entry_next;
	      entry_next = entry_next->next_entry;
	    }
	}

      chain->last_entry = entry_current;
    }
  while (swapped_in_pass);
}

/* Attach B's chain onto A.  */
static void
rsrc_attach_chain (rsrc_dir_chain * achain, rsrc_dir_chain * bchain)
{
  if (achain == NULL || bchain == NULL)
    {
      return;
    }

  if (bchain->num_entries == 0)
    {
      return;
    }

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
  bchain->last_entry  = NULL;
}

static void
rsrc_merge (struct rsrc_entry * a, struct rsrc_entry * b)
{
  BFD_ASSERT (a->is_dir);
  BFD_ASSERT (b->is_dir);

  rsrc_directory * adir = a->value.directory;
  rsrc_directory * bdir = b->value.directory;

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

  rsrc_attach_chain (&adir->names, &bdir->names);
  rsrc_attach_chain (&adir->ids, &bdir->ids);

  rsrc_sort_entries (&adir->names, true, adir);
  rsrc_sort_entries (&adir->ids, false, adir);
}

/* Check the .rsrc section.  If it contains multiple concatenated
   resources then we must merge them properly.  Otherwise Windows
   will ignore all but the first set.  */

#include <stddef.h>
#include <stdlib.h>

typedef struct bfd bfd;
typedef struct asection asection;
typedef struct coff_final_link_info coff_final_link_info;
typedef struct pe_data_type pe_data_type;
typedef unsigned long bfd_vma;
typedef unsigned long bfd_size_type;
typedef unsigned char bfd_byte;
typedef unsigned long file_ptr;

typedef struct rsrc_entry rsrc_entry;
typedef struct rsrc_entry_list rsrc_entry_list;
typedef struct rsrc_directory rsrc_directory;
typedef struct rsrc_write_data rsrc_write_data;
typedef struct rsrc_leaf rsrc_leaf;

struct rsrc_entry {
  unsigned int id;
  const char *name;
  void *data;
  struct rsrc_entry *next;
};

struct rsrc_entry_list {
  rsrc_entry *first_entry;
  rsrc_entry *last_entry;
  unsigned int num_entries;
};

struct rsrc_directory {
  unsigned int characteristics;
  unsigned int time;
  unsigned short major;
  unsigned short minor;
  rsrc_entry_list names;
  rsrc_entry_list ids;
};

struct rsrc_leaf {
  bfd_vma offset;
  bfd_size_type size;
  unsigned int codepage;
  unsigned int reserved;
};

struct rsrc_write_data {
  bfd * abfd;
  bfd_byte * datastart;
  bfd_byte * next_table;
  bfd_byte * next_leaf;
  bfd_byte * next_string;
  bfd_byte * next_data;
  bfd_vma rva_bias;
};

struct pe_opthdr {
  bfd_vma ImageBase;
};

struct pe_data_type {
  struct pe_opthdr pe_opthdr;
};

struct bfd_link_info {
    bfd *input_bfds;
};

struct bfd_link_order {
    struct bfd *next;
};

struct bfd {
    struct bfd_link_order link;
};

struct coff_final_link_info {
    struct bfd_link_info *info;
    bfd *output_bfd;
};

extern int bfd_malloc_and_get_section(bfd *, asection *, bfd_byte **);
extern void bfd_free_section_contents(bfd *, bfd_byte *);
extern void *bfd_malloc(bfd_size_type);
extern void *bfd_zalloc(bfd *, bfd_size_type);
extern void bfd_free(bfd *, void *);
extern void *bfd_realloc(void *, bfd_size_type);
extern asection *bfd_get_section_by_name(bfd *, const char *);
extern void bfd_set_error(int);
extern int bfd_error_file_truncated;
extern pe_data_type *pe_data(bfd *);
extern int discarded_section(asection *);
extern void _bfd_error_handler(const char *, ...);
extern void bfd_set_section_contents(bfd *, asection *, const void *, file_ptr, bfd_size_type);

#define _(x) x
#define BFD_ASSERT(x) ((void)((x) || (abort(), 0)))

extern bfd_byte *rsrc_count_directory(bfd *, bfd_byte *, bfd_byte *, bfd_byte *, bfd_vma);
extern bfd_byte *rsrc_parse_directory(bfd *, rsrc_directory *, bfd_byte *, bfd_byte *, bfd_byte *, bfd_vma, void *);
extern void rsrc_attach_chain(rsrc_entry_list *, rsrc_entry_list *);
extern void rsrc_sort_entries(rsrc_entry_list *, int, rsrc_directory *);
extern void rsrc_compute_region_sizes(rsrc_directory *);
extern void rsrc_write_directory(rsrc_write_data *, rsrc_directory *);

enum {
  INITIAL_MAX_INPUT_RSRC = 4,
  RSRC_REALLOC_INCREMENT = 10,
  ALIGNMENT_BYTES = 8,
  ALIGNMENT_MASK = ALIGNMENT_BYTES - 1
};

static bfd_size_type sizeof_leaves;
static bfd_size_type sizeof_strings;
static bfd_size_type sizeof_tables_and_entries;

static void rsrc_free_directory_recursive(rsrc_directory *dir) {
  if (dir == NULL) {
    return;
  }

  rsrc_entry *current = dir->names.first_entry;
  while (current != NULL) {
    rsrc_entry *next = current->next;
    if (current->data != NULL) {
      if ((current->id & 0x80000000) != 0) {
        rsrc_free_directory_recursive((rsrc_directory *)current->data);
      } else {
        free(current->data);
      }
    }
    free(current);
    current = next;
  }
  dir->names.first_entry = NULL;
  dir->names.last_entry = NULL;
  dir->names.num_entries = 0;

  current = dir->ids.first_entry;
  while (current != NULL) {
    rsrc_entry *next = current->next;
    if ((current->id & 0x80000000) != 0) {
      rsrc_free_directory_recursive((rsrc_directory *)current->data);
    } else {
      free(current->data);
    }
    free(current);
    current = next;
  }
  dir->ids.first_entry = NULL;
  dir->ids.last_entry = NULL;
  dir->ids.num_entries = 0;
}


static void
rsrc_process_section (bfd * abfd,
                      struct coff_final_link_info * pfinfo)
{
  rsrc_directory    new_table;
  bfd_size_type     size;
  asection *        sec = NULL;
  pe_data_type *    pe = NULL;
  bfd_vma           rva_bias;
  bfd_byte *        datastart = NULL;
  bfd_byte *        data = NULL;
  bfd_byte *        dataend = NULL;
  bfd_byte *        new_data = NULL;
  unsigned int      num_resource_sets = 0;
  rsrc_directory *  type_tables = NULL;
  rsrc_write_data   write_data;
  unsigned int      indx;
  bfd *             input;
  unsigned int      num_input_rsrc = 0;
  unsigned int      max_num_input_rsrc = INITIAL_MAX_INPUT_RSRC;
  ptrdiff_t *       rsrc_sizes = NULL;

  new_table.names.first_entry = NULL;
  new_table.names.last_entry = NULL;
  new_table.names.num_entries = 0;
  new_table.ids.first_entry = NULL;
  new_table.ids.last_entry = NULL;
  new_table.ids.num_entries = 0;

  sec = bfd_get_section_by_name (abfd, ".rsrc");
  if (sec == NULL || (size = sec->rawsize) == 0) {
    return;
  }

  pe = pe_data (abfd);
  if (pe == NULL) {
    _bfd_error_handler (_("%pB: .rsrc merge failure: PE data not found"), abfd);
    bfd_set_error (bfd_error_file_truncated);
    return;
  }

  rva_bias = sec->vma - pe->pe_opthdr.ImageBase;

  if (! bfd_malloc_and_get_section (abfd, sec, &datastart)) {
    return;
  }
  data = datastart;
  dataend = datastart + size;

  rsrc_sizes = (ptrdiff_t *) bfd_malloc (max_num_input_rsrc * sizeof (*rsrc_sizes));
  if (rsrc_sizes == NULL) {
    goto cleanup;
  }

  for (input = pfinfo->info->input_bfds;
       input != NULL;
       input = input->link.next)
    {
      asection * rsrc_sec = bfd_get_section_by_name (input, ".rsrc");

      if (rsrc_sec != NULL && !discarded_section (rsrc_sec))
	{
	  if (num_input_rsrc == max_num_input_rsrc)
	    {
	      max_num_input_rsrc += RSRC_REALLOC_INCREMENT;
	      ptrdiff_t * new_rsrc_sizes = (ptrdiff_t *) bfd_realloc (rsrc_sizes,
                                                       max_num_input_rsrc * sizeof (*rsrc_sizes));
	      if (new_rsrc_sizes == NULL) {
		    goto cleanup;
	      }
          rsrc_sizes = new_rsrc_sizes;
	    }

	  BFD_ASSERT (rsrc_sec->size > 0);
	  rsrc_sizes [num_input_rsrc ++] = rsrc_sec->size;
	}
    }

  if (num_input_rsrc < 2) {
    goto cleanup;
  }

  num_resource_sets = 0;
  bfd_byte *current_data_pos = datastart;
  bfd_vma current_rva_bias = rva_bias;

  while (current_data_pos < dataend && num_resource_sets < num_input_rsrc)
    {
      bfd_byte * section_start_ptr = current_data_pos;
      bfd_byte * next_resource_start_ptr;

      next_resource_start_ptr = rsrc_count_directory (abfd, current_data_pos, section_start_ptr,
                                                        dataend, current_rva_bias);

      if (next_resource_start_ptr > dataend || next_resource_start_ptr < section_start_ptr) {
        _bfd_error_handler (_("%pB: .rsrc merge failure: corrupt .rsrc section"), abfd);
        bfd_set_error (bfd_error_file_truncated);
        goto cleanup;
      }

      if ((next_resource_start_ptr - section_start_ptr) > rsrc_sizes [num_resource_sets]) {
        _bfd_error_handler (_("%pB: .rsrc merge failure: unexpected .rsrc size"), abfd);
        bfd_set_error (bfd_error_file_truncated);
        goto cleanup;
      }

      current_data_pos = section_start_ptr + rsrc_sizes[num_resource_sets];
      current_rva_bias += (bfd_vma)(current_data_pos - section_start_ptr);
      ++ num_resource_sets;
    }
  BFD_ASSERT (num_resource_sets == num_input_rsrc);

  data = datastart;
  rva_bias = sec->vma - pe->pe_opthdr.ImageBase;

  type_tables = (rsrc_directory *) bfd_malloc (num_resource_sets * sizeof (*type_tables));
  if (type_tables == NULL) {
    goto cleanup;
  }
  for (indx = 0; indx < num_resource_sets; ++indx) {
      type_tables[indx].names.first_entry = NULL;
      type_tables[indx].names.last_entry = NULL;
      type_tables[indx].names.num_entries = 0;
      type_tables[indx].ids.first_entry = NULL;
      type_tables[indx].ids.last_entry = NULL;
      type_tables[indx].ids.num_entries = 0;
  }

  indx = 0;
  while (data < dataend && indx < num_resource_sets)
    {
      bfd_byte * section_start_ptr = data;
      (void) rsrc_parse_directory (abfd, type_tables + indx, data, section_start_ptr,
                                   dataend, rva_bias, NULL);
      data = section_start_ptr + rsrc_sizes[indx];
      rva_bias += (bfd_vma)(data - section_start_ptr);
      ++ indx;
    }
  BFD_ASSERT (indx == num_resource_sets);

  new_table.characteristics = type_tables[0].characteristics;
  new_table.time            = type_tables[0].time;
  new_table.major           = type_tables[0].major;
  new_table.minor           = type_tables[0].minor;

  for (indx = 0; indx < num_resource_sets; indx++) {
    rsrc_attach_chain (&new_table.names, &type_tables[indx].names);
    type_tables[indx].names.first_entry = NULL;
    type_tables[indx].names.last_entry = NULL;
    type_tables[indx].names.num_entries = 0;
  }
  rsrc_sort_entries (&new_table.names, 1, &new_table);

  for (indx = 0; indx < num_resource_sets; indx++) {
    rsrc_attach_chain (&new_table.ids, &type_tables[indx].ids);
    type_tables[indx].ids.first_entry = NULL;
    type_tables[indx].ids.last_entry = NULL;
    type_tables[indx].ids.num_entries = 0;
  }
  rsrc_sort_entries (&new_table.ids, 0, &new_table);

  sizeof_leaves = 0;
  sizeof_strings = 0;
  sizeof_tables_and_entries = 0;
  rsrc_compute_region_sizes (&new_table);
  sizeof_strings = (sizeof_strings + ALIGNMENT_MASK) & ~ ALIGNMENT_MASK;

  new_data = (bfd_byte *) bfd_zalloc (abfd, size);
  if (new_data == NULL) {
    goto cleanup;
  }

  write_data.abfd           = abfd;
  write_data.datastart      = new_data;
  write_data.next_table     = new_data;
  write_data.next_leaf      = new_data + sizeof_tables_and_entries;
  write_data.next_string    = write_data.next_leaf + sizeof_leaves;
  write_data.next_data      = write_data.next_string + sizeof_strings;
  write_data.rva_bias       = sec->vma - pe->pe_opthdr.ImageBase;

  rsrc_write_directory (&write_data, &new_table);

  bfd_set_section_contents (pfinfo->output_bfd, sec, new_data, 0, size);
  sec->size = sec->rawsize = size;

cleanup:
  if (datastart != NULL) {
    bfd_free_section_contents (abfd, datastart);
  }
  if (rsrc_sizes != NULL) {
    free (rsrc_sizes);
  }
  if (type_tables != NULL) {
    free (type_tables);
  }
  rsrc_free_directory_recursive (&new_table);

  if (new_data != NULL) {
    bfd_free (abfd, new_data);
  }
  return;
}

/* Handle the .idata section and other things that need symbol table
   access.  */

static bool
is_valid_symbol_entry_and_get_vma (struct coff_link_hash_entry *h_entry, bfd_vma *out_vma)
{
  if (h_entry != NULL
      && (h_entry->root.type == bfd_link_hash_defined
          || h_entry->root.type == bfd_link_hash_defweak)
      && h_entry->root.u.def.section != NULL
      && h_entry->root.u.def.section->output_section != NULL)
    {
      *out_vma = (h_entry->root.u.def.value
                  + h_entry->root.u.def.section->output_section->vma
                  + h_entry->root.u.def.section->output_offset);
      return true;
    }
  return false;
}

static void
report_data_directory_error (bfd *abfd, int data_dir_index, const char *symbol_name, bool *result_ptr)
{
  _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: %s is missing or not defined correctly"),
                      abfd, data_dir_index, symbol_name);
  *result_ptr = false;
}

static void
report_data_directory_error_custom (bfd *abfd, int data_dir_index, const char *symbol_name, const char *msg_suffix, bool *result_ptr)
{
  _bfd_error_handler (_("%pB: unable to fill in DataDirectory[%d]: %s %s"),
                      abfd, data_dir_index, symbol_name, msg_suffix);
  *result_ptr = false;
}

bool
_bfd_XXi_final_link_postscript (bfd *abfd, struct coff_final_link_info *pfinfo)
{
  struct coff_link_hash_entry *h1;
  struct bfd_link_info *info = pfinfo->info;
  bool result = true;
  bfd_vma tmp_vma;
  bfd_pe_data *ped = pe_data(abfd); // Cache pe_data for repeated access

  /* The import directory and import address table (.idata$N sections).  */
  h1 = coff_link_hash_lookup (coff_hash_table (info), ".idata$2", false, false, true);
  if (h1 != NULL)
    {
      if (is_valid_symbol_entry_and_get_vma(h1, &tmp_vma))
        {
          ped->pe_opthdr.DataDirectory[PE_IMPORT_TABLE].VirtualAddress = tmp_vma;

          h1 = coff_link_hash_lookup (coff_hash_table (info), ".idata$4", false, false, true);
          if (is_valid_symbol_entry_and_get_vma(h1, &tmp_vma))
            ped->pe_opthdr.DataDirectory[PE_IMPORT_TABLE].Size = tmp_vma - ped->pe_opthdr.DataDirectory[PE_IMPORT_TABLE].VirtualAddress;
          else
            report_data_directory_error(abfd, PE_IMPORT_TABLE, ".idata$4", &result);

          h1 = coff_link_hash_lookup (coff_hash_table (info), ".idata$5", false, false, true);
          if (is_valid_symbol_entry_and_get_vma(h1, &tmp_vma))
            ped->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].VirtualAddress = tmp_vma;
          else
            report_data_directory_error(abfd, PE_IMPORT_ADDRESS_TABLE, ".idata$5", &result);

          h1 = coff_link_hash_lookup (coff_hash_table (info), ".idata$6", false, false, true);
          if (is_valid_symbol_entry_and_get_vma(h1, &tmp_vma))
            ped->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].Size = tmp_vma - ped->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].VirtualAddress;
          else
            report_data_directory_error(abfd, PE_IMPORT_ADDRESS_TABLE, ".idata$6", &result);
        }
      else
        report_data_directory_error(abfd, PE_IMPORT_TABLE, ".idata$2", &result);
    }
  else
    {
      /* Fallback to __IAT_start__ / __IAT_end__ if .idata$2 is not found. */
      h1 = coff_link_hash_lookup (coff_hash_table (info), "__IAT_start__", false, false, true);
      if (h1 != NULL)
        {
          bfd_vma iat_va;
          if (is_valid_symbol_entry_and_get_vma(h1, &iat_va))
            {
              h1 = coff_link_hash_lookup (coff_hash_table (info), "__IAT_end__", false, false, true);
              if (is_valid_symbol_entry_and_get_vma(h1, &tmp_vma))
                {
                  ped->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].Size = tmp_vma - iat_va;
                  if (ped->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].Size != 0)
                    ped->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].VirtualAddress = iat_va - ped->pe_opthdr.ImageBase;
                }
              else
                report_data_directory_error(abfd, PE_IMPORT_ADDRESS_TABLE, "__IAT_end__", &result);
            }
          /* Original code did not set result = false if __IAT_start__ was found but invalid. */
        }
      /* Original code did not set result = false if __IAT_start__ lookup returned NULL. */
    }

  /* The delay import directory (__DELAY_IMPORT_DIRECTORY_start__ / __DELAY_IMPORT_DIRECTORY_end__).  */
  h1 = coff_link_hash_lookup (coff_hash_table (info), "__DELAY_IMPORT_DIRECTORY_start__", false, false, true);
  if (h1 != NULL)
    {
      bfd_vma delay_va;
      if (is_valid_symbol_entry_and_get_vma(h1, &delay_va))
        {
          h1 = coff_link_hash_lookup (coff_hash_table (info), "__DELAY_IMPORT_DIRECTORY_end__", false, false, true);
          if (is_valid_symbol_entry_and_get_vma(h1, &tmp_vma))
            {
              ped->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR].Size = tmp_vma - delay_va;
              if (ped->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR].Size != 0)
                ped->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR].VirtualAddress = delay_va - ped->pe_opthdr.ImageBase;
            }
          else
            report_data_directory_error(abfd, PE_DELAY_IMPORT_DESCRIPTOR, "__DELAY_IMPORT_DIRECTORY_end__", &result);
        }
    }

  /* TLS Table (_tls_used).  */
  {
    char name_buf[32];
    size_t offset = 0;
    char leading_char = bfd_get_symbol_leading_char (abfd);
    if (leading_char != '\0') {
        name_buf[0] = leading_char;
        offset = 1;
    }
    strcpy (name_buf + offset, "_tls_used");

    h1 = coff_link_hash_lookup (coff_hash_table (info), name_buf, false, false, true);
    if (h1 != NULL)
      {
        if (is_valid_symbol_entry_and_get_vma(h1, &tmp_vma))
          {
            ped->pe_opthdr.DataDirectory[PE_TLS_TABLE].VirtualAddress = tmp_vma - ped->pe_opthdr.ImageBase;
            /* According to PECOFF specifications by Microsoft version 8.2
               the TLS data directory consists of 4 pointers, followed
               by two 4-byte integer. This implies that the total size
               is different for 32-bit and 64-bit executables.  */
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
            ped->pe_opthdr.DataDirectory[PE_TLS_TABLE].Size = 0x18;
#else
            ped->pe_opthdr.DataDirectory[PE_TLS_TABLE].Size = 0x28;
#endif
          }
        else
          report_data_directory_error(abfd, PE_TLS_TABLE, name_buf, &result);
      }
  }

  /* Load Config Table (_load_config_used).  */
  {
    char name_buf[32];
    size_t offset = 0;
    char leading_char = bfd_get_symbol_leading_char (abfd);
    if (leading_char != '\0') {
        name_buf[0] = leading_char;
        offset = 1;
    }
    strcpy (name_buf + offset, "_load_config_used");

    h1 = coff_link_hash_lookup (coff_hash_table (info), name_buf, false, false, true);
    if (h1 != NULL)
      {
        if (is_valid_symbol_entry_and_get_vma(h1, &tmp_vma))
          {
            ped->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].VirtualAddress = tmp_vma - ped->pe_opthdr.ImageBase;

            /* Alignment check. */
            if (ped->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].VirtualAddress
                & (bfd_arch_bits_per_address (abfd) / bfd_arch_bits_per_byte (abfd) - 1))
              {
                report_data_directory_error_custom(abfd, PE_LOAD_CONFIG_TABLE, name_buf, "not properly aligned", &result);
              }
            else
              {
                char data[4];
                /* The size is stored as the first 4 bytes at _load_config_used.  */
                if (bfd_get_section_contents (abfd,
                                              h1->root.u.def.section->output_section, data,
                                              h1->root.u.def.section->output_offset + h1->root.u.def.value,
                                              4))
                  {
                    uint32_t size = bfd_get_32 (abfd, data);
                    /* The Microsoft PE format documentation says for compatibility
                       with Windows XP and earlier, the size must be 64 for x86
                       images.  */
                    ped->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].Size
                      = (bfd_get_arch (abfd) == bfd_arch_i386
                         && ((bfd_get_mach (abfd) & ~bfd_mach_i386_intel_syntax)
                             == bfd_mach_i386_i386)
                         && ((ped->pe_opthdr.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI)
                             || (ped->pe_opthdr.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI))
                         && (ped->pe_opthdr.MajorSubsystemVersion * 256
                             + ped->pe_opthdr.MinorSubsystemVersion <= 0x0501))
                      ? 64 : size;

                    if (size > h1->root.u.def.section->size - h1->root.u.def.value)
                      {
                        report_data_directory_error_custom(abfd, PE_LOAD_CONFIG_TABLE, name_buf, "size too large for the containing section", &result);
                      }
                  }
                else
                  {
                    report_data_directory_error_custom(abfd, PE_LOAD_CONFIG_TABLE, name_buf, "size can't be read from symbol content", &result);
                  }
              }
          }
        else
          report_data_directory_error(abfd, PE_LOAD_CONFIG_TABLE, name_buf, &result);
      }
  }

/* If there is a .pdata section and we have linked pdata finally, we
   need to sort the entries ascending.  */
#if !defined(COFF_WITH_pep) && (defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined (COFF_WITH_peRiscV64))
  {
    asection *sec = bfd_get_section_by_name (abfd, ".pdata");

    if (sec)
      {
        bfd_size_type x = sec->rawsize;
        bfd_byte *tmp_data;

        if (bfd_malloc_and_get_section (abfd, sec, &tmp_data))
          {
            qsort (tmp_data,
                   (size_t) (x / 12),
                   12, sort_x64_pdata);
            bfd_set_section_contents (pfinfo->output_bfd, sec,
                                      tmp_data, 0, x);
            free (tmp_data);
          }
        else
          result = false;
      }
  }
#endif

  rsrc_process_section (abfd, pfinfo);

  /* If we couldn't find idata$2, we either have an excessively
     trivial program or are in DEEP trouble; we have to assume trivial
     program....  */
  return result;
}
