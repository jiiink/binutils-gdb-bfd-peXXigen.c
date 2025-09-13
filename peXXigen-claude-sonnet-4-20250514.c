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
      in->n_value = 0x0;

      if (in->n_scnum == 0)
        {
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
            }
          else
            {
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

              flagword flags = (SEC_HAS_CONTENTS | SEC_ALLOC | SEC_DATA | SEC_LOAD | SEC_LINKER_CREATED);
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
abs_finder (bfd * abfd, asection * sec, void * data)
{
  const bfd_vma *abs_val_ptr;
  bfd_vma abs_val;
  bfd_vma section_end;

  if (!sec || !data) {
    return false;
  }

  abs_val_ptr = (const bfd_vma *) data;
  abs_val = *abs_val_ptr;
  section_end = sec->vma + (1ULL << 32);

  if (section_end < sec->vma) {
    return false;
  }

  return (sec->vma <= abs_val) && (section_end > abs_val);
}

unsigned int
_bfd_XXi_swap_sym_out (bfd * abfd, void * inp, void * extp)
{
  struct internal_syment *in = (struct internal_syment *) inp;
  SYMENT *ext = (SYMENT *) extp;

  if (!in || !ext || !abfd)
    return 0;

  if (in->_n._n_name[0] == 0)
    {
      H_PUT_32 (abfd, 0, ext->e.e.e_zeroes);
      H_PUT_32 (abfd, in->_n._n_n._n_offset, ext->e.e.e_offset);
    }
  else
    {
      memcpy (ext->e.e_name, in->_n._n_name, SYMNMLEN);
    }

  if (sizeof (in->n_value) > 4 && in->n_scnum == N_ABS)
    {
      const unsigned long long value_limit = (sizeof (in->n_value) > 4) ? (1ULL << 32) - 1 : (1ULL << 31) - 1;
      
      if (in->n_value > value_limit)
        {
          asection * sec = bfd_sections_find_if (abfd, abs_finder, & in->n_value);
          if (sec)
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
_bfd_XXi_swap_aux_in (bfd *abfd,
		      void *ext1,
		      int type,
		      int in_class,
		      int indx ATTRIBUTE_UNUSED,
		      int numaux ATTRIBUTE_UNUSED,
		      void *in1)
{
  AUXENT *ext = (AUXENT *) ext1;
  union internal_auxent *in = (union internal_auxent *) in1;

  if (!ext || !in)
    return;

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
_bfd_XXi_swap_aux_out (bfd *abfd,
                       void *inp,
                       int type,
                       int in_class,
                       int indx ATTRIBUTE_UNUSED,
                       int numaux ATTRIBUTE_UNUSED,
                       void *extp)
{
  union internal_auxent *in = (union internal_auxent *) inp;
  AUXENT *ext = (AUXENT *) extp;

  if (!in || !ext) {
    return 0;
  }

  memset(ext, 0, AUXESZ);

  if (in_class == C_FILE) {
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
  }

  if ((in_class == C_STAT || in_class == C_LEAFSTAT || in_class == C_HIDDEN) && type == T_NULL) {
    PUT_SCN_SCNLEN(abfd, in->x_scn.x_scnlen, ext);
    PUT_SCN_NRELOC(abfd, in->x_scn.x_nreloc, ext);
    PUT_SCN_NLINNO(abfd, in->x_scn.x_nlinno, ext);
    H_PUT_32(abfd, in->x_scn.x_checksum, ext->x_scn.x_checksum);
    H_PUT_16(abfd, in->x_scn.x_associated, ext->x_scn.x_associated);
    H_PUT_8(abfd, in->x_scn.x_comdat, ext->x_scn.x_comdat);
    return AUXESZ;
  }

  H_PUT_32(abfd, in->x_sym.x_tagndx.u32, ext->x_sym.x_tagndx);
  H_PUT_16(abfd, in->x_sym.x_tvndx, ext->x_sym.x_tvndx);

  if (in_class == C_BLOCK || in_class == C_FCN || ISFCN(type) || ISTAG(in_class)) {
    PUT_FCN_LNNOPTR(abfd, in->x_sym.x_fcnary.x_fcn.x_lnnoptr, ext);
    PUT_FCN_ENDNDX(abfd, in->x_sym.x_fcnary.x_fcn.x_endndx.u32, ext);
  } else {
    for (int i = 0; i < 4; i++) {
      H_PUT_16(abfd, in->x_sym.x_fcnary.x_ary.x_dimen[i],
               ext->x_sym.x_fcnary.x_ary.x_dimen[i]);
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

void
_bfd_XXi_swap_lineno_in (bfd * abfd, void * ext1, void * in1)
{
  if (abfd == NULL || ext1 == NULL || in1 == NULL) {
    return;
  }

  LINENO *ext = (LINENO *) ext1;
  struct internal_lineno *in = (struct internal_lineno *) in1;

  in->l_addr.l_symndx = H_GET_32 (abfd, ext->l_addr.l_symndx);
  in->l_lnno = GET_LINENO_LNNO (abfd, ext);
}

unsigned int
_bfd_XXi_swap_lineno_out(bfd *abfd, void *inp, void *outp)
{
    if (!abfd || !inp || !outp) {
        return 0;
    }
    
    struct internal_lineno *in = (struct internal_lineno *)inp;
    struct external_lineno *ext = (struct external_lineno *)outp;
    
    H_PUT_32(abfd, in->l_addr.l_symndx, ext->l_addr.l_symndx);
    PUT_LINENO_LNNO(abfd, in->l_lnno, ext);
    
    return LINESZ;
}

void
_bfd_XXi_swap_aouthdr_in (bfd * abfd,
			  void * aouthdr_ext1,
			  void * aouthdr_int1)
{
  if (!abfd || !aouthdr_ext1 || !aouthdr_int1)
    return;

  PEAOUTHDR * src = (PEAOUTHDR *) aouthdr_ext1;
  AOUTHDR * aouthdr_ext = (AOUTHDR *) aouthdr_ext1;
  struct internal_aouthdr *aouthdr_int = (struct internal_aouthdr *) aouthdr_int1;
  struct internal_extra_pe_aouthdr *a = &aouthdr_int->pe;

#define IS_PE32_PLUS (!defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64))

  aouthdr_int->magic = H_GET_16 (abfd, aouthdr_ext->magic);
  aouthdr_int->vstamp = H_GET_16 (abfd, aouthdr_ext->vstamp);
  aouthdr_int->tsize = GET_AOUTHDR_TSIZE (abfd, aouthdr_ext->tsize);
  aouthdr_int->dsize = GET_AOUTHDR_DSIZE (abfd, aouthdr_ext->dsize);
  aouthdr_int->bsize = GET_AOUTHDR_BSIZE (abfd, aouthdr_ext->bsize);
  aouthdr_int->entry = GET_AOUTHDR_ENTRY (abfd, aouthdr_ext->entry);
  aouthdr_int->text_start = GET_AOUTHDR_TEXT_START (abfd, aouthdr_ext->text_start);

#if IS_PE32_PLUS
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

  unsigned max_entries = (a->NumberOfRvaAndSizes < IMAGE_NUMBEROF_DIRECTORY_ENTRIES) 
                         ? a->NumberOfRvaAndSizes 
                         : IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

  for (unsigned idx = 0; idx < max_entries; idx++)
    {
      int size = H_GET_32 (abfd, src->DataDirectory[idx][1]);
      int vma = size ? H_GET_32 (abfd, src->DataDirectory[idx][0]) : 0;
      a->DataDirectory[idx].Size = size;
      a->DataDirectory[idx].VirtualAddress = vma;
    }

  for (unsigned idx = max_entries; idx < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; idx++)
    {
      a->DataDirectory[idx].Size = 0;
      a->DataDirectory[idx].VirtualAddress = 0;
    }

  if (aouthdr_int->entry)
    {
      aouthdr_int->entry += a->ImageBase;
#if IS_PE32_PLUS
      aouthdr_int->entry &= 0xffffffff;
#endif
    }

  if (aouthdr_int->tsize)
    {
      aouthdr_int->text_start += a->ImageBase;
#if IS_PE32_PLUS
      aouthdr_int->text_start &= 0xffffffff;
#endif
    }

#if IS_PE32_PLUS
  if (aouthdr_int->dsize)
    {
      aouthdr_int->data_start += a->ImageBase;
      aouthdr_int->data_start &= 0xffffffff;
    }
#endif

#undef IS_PE32_PLUS
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

  if (abfd == NULL || aout == NULL || name == NULL || idx < 0)
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

  if (size != 0)
    {
      aout->DataDirectory[idx].VirtualAddress =
        (sec->vma - base) & 0xffffffff;
      sec->flags |= SEC_DATA;
    }
}

unsigned int
_bfd_XXi_swap_aouthdr_out (bfd * abfd, void * in, void * out)
{
  struct internal_aouthdr *aouthdr_in = (struct internal_aouthdr *) in;
  pe_data_type *pe = pe_data (abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
  PEAOUTHDR *aouthdr_out = (PEAOUTHDR *) out;
  bfd_vma sa, fa, ib;
  IMAGE_DATA_DIRECTORY idata2, idata5, didat2, tls, loadcfg;

#define LINKER_VERSION ((short) (BFD_VERSION / 1000000))
#define IS_64BIT_PE (!defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64))

  sa = extra->SectionAlignment;
  fa = extra->FileAlignment;
  ib = extra->ImageBase;

  idata2 = pe->pe_opthdr.DataDirectory[PE_IMPORT_TABLE];
  idata5 = pe->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE];
  didat2 = pe->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR];
  tls = pe->pe_opthdr.DataDirectory[PE_TLS_TABLE];
  loadcfg = pe->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE];

  if (aouthdr_in->tsize)
    {
      aouthdr_in->text_start -= ib;
#if IS_64BIT_PE
      aouthdr_in->text_start &= 0xffffffff;
#endif
    }

  if (aouthdr_in->dsize)
    {
      aouthdr_in->data_start -= ib;
#if IS_64BIT_PE
      aouthdr_in->data_start &= 0xffffffff;
#endif
    }

  if (aouthdr_in->entry)
    {
      aouthdr_in->entry -= ib;
#if IS_64BIT_PE
      aouthdr_in->entry &= 0xffffffff;
#endif
    }

  aouthdr_in->bsize = ((aouthdr_in->bsize + fa - 1) & (- fa));

  extra->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

  add_data_entry (abfd, extra, PE_EXPORT_TABLE, ".edata", ib);
  add_data_entry (abfd, extra, PE_RESOURCE_TABLE, ".rsrc", ib);
  add_data_entry (abfd, extra, PE_EXCEPTION_TABLE, ".pdata", ib);

  extra->DataDirectory[PE_IMPORT_TABLE] = idata2;
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
        int rounded = ((sec->size + fa - 1) & (- fa));

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
          isize = ((sec->vma - extra->ImageBase
                    + ((pei_section_data (abfd, sec)->virt_size + fa - 1) & (- fa)) + sa - 1) & (- sa));
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
      H_PUT_16 (abfd, (LINKER_VERSION / 100 + (LINKER_VERSION % 100) * 256),
                aouthdr_out->standard.vstamp);
    }

  PUT_AOUTHDR_TSIZE (abfd, aouthdr_in->tsize, aouthdr_out->standard.tsize);
  PUT_AOUTHDR_DSIZE (abfd, aouthdr_in->dsize, aouthdr_out->standard.dsize);
  PUT_AOUTHDR_BSIZE (abfd, aouthdr_in->bsize, aouthdr_out->standard.bsize);
  PUT_AOUTHDR_ENTRY (abfd, aouthdr_in->entry, aouthdr_out->standard.entry);
  PUT_AOUTHDR_TEXT_START (abfd, aouthdr_in->text_start,
                          aouthdr_out->standard.text_start);

#if IS_64BIT_PE
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
_bfd_XXi_only_swap_filehdr_out (bfd * abfd, void * in, void * out)
{
  struct internal_filehdr *filehdr_in;
  struct external_PEI_filehdr *filehdr_out;
  int idx;

  if (!abfd || !in || !out)
    return 0;

  filehdr_in = (struct internal_filehdr *) in;
  filehdr_out = (struct external_PEI_filehdr *) out;

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
    H_PUT_32 (abfd, pe_data (abfd)->timestamp, filehdr_out->f_timdat);

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

  for (idx = 0; idx < 4; idx++)
    H_PUT_16 (abfd, filehdr_in->pe.e_res[idx], filehdr_out->e_res[idx]);

  H_PUT_16 (abfd, filehdr_in->pe.e_oemid, filehdr_out->e_oemid);
  H_PUT_16 (abfd, filehdr_in->pe.e_oeminfo, filehdr_out->e_oeminfo);

  for (idx = 0; idx < 10; idx++)
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
  if (!abfd || !in || !out) {
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

  if (!abfd || !scnhdr_int || !scnhdr_ext) {
    bfd_set_error (bfd_error_invalid_operation);
    return 0;
  }

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

  if ((scnhdr_int->s_flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0) {
    if (bfd_pei_p (abfd)) {
      ps = scnhdr_int->s_size;
      ss = 0;
    } else {
      ps = 0;
      ss = scnhdr_int->s_size;
    }
  } else {
    ps = bfd_pei_p (abfd) ? scnhdr_int->s_paddr : 0;
    ss = scnhdr_int->s_size;
  }

  PUT_SCNHDR_SIZE (abfd, ss, scnhdr_ext->s_size);
  PUT_SCNHDR_PADDR (abfd, ps, scnhdr_ext->s_paddr);
  PUT_SCNHDR_SCNPTR (abfd, scnhdr_int->s_scnptr, scnhdr_ext->s_scnptr);
  PUT_SCNHDR_RELPTR (abfd, scnhdr_int->s_relptr, scnhdr_ext->s_relptr);
  PUT_SCNHDR_LNNOPTR (abfd, scnhdr_int->s_lnnoptr, scnhdr_ext->s_lnnoptr);

  apply_section_flags(abfd, scnhdr_int);
  H_PUT_32 (abfd, scnhdr_int->s_flags, scnhdr_ext->s_flags);

  if (is_executable_text_section(abfd, scnhdr_int)) {
    H_PUT_16 (abfd, (scnhdr_int->s_nlnno & 0xffff), scnhdr_ext->s_nlnno);
    H_PUT_16 (abfd, (scnhdr_int->s_nlnno >> 16), scnhdr_ext->s_nreloc);
  } else {
    if (!handle_line_numbers(abfd, scnhdr_int, scnhdr_ext))
      ret = 0;
    handle_relocations(abfd, scnhdr_int, scnhdr_ext);
  }
  
  return ret;
}

static void apply_section_flags(bfd *abfd, struct internal_scnhdr *scnhdr_int)
{
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
    { ".xdata", IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA },
  };

  for (const pe_required_section_flags *p = known_sections;
       p < known_sections + (sizeof(known_sections)/sizeof(known_sections[0]));
       p++) {
    if (memcmp (scnhdr_int->s_name, p->section_name, SCNNMLEN) == 0) {
      if (memcmp (scnhdr_int->s_name, ".text", sizeof ".text") ||
          (bfd_get_file_flags (abfd) & WP_TEXT))
        scnhdr_int->s_flags &= ~IMAGE_SCN_MEM_WRITE;
      scnhdr_int->s_flags |= p->must_have;
      break;
    }
  }
}

static int is_executable_text_section(bfd *abfd, struct internal_scnhdr *scnhdr_int)
{
  return (coff_data (abfd)->link_info &&
          !bfd_link_relocatable (coff_data (abfd)->link_info) &&
          !bfd_link_pic (coff_data (abfd)->link_info) &&
          memcmp (scnhdr_int->s_name, ".text", sizeof ".text") == 0);
}

static int handle_line_numbers(bfd *abfd, struct internal_scnhdr *scnhdr_int, SCNHDR *scnhdr_ext)
{
  if (scnhdr_int->s_nlnno <= 0xffff) {
    H_PUT_16 (abfd, scnhdr_int->s_nlnno, scnhdr_ext->s_nlnno);
    return 1;
  } else {
    _bfd_error_handler (_("%pB: line number overflow: 0x%lx > 0xffff"),
                        abfd, scnhdr_int->s_nlnno);
    bfd_set_error (bfd_error_file_truncated);
    H_PUT_16 (abfd, 0xffff, scnhdr_ext->s_nlnno);
    return 0;
  }
}

static void handle_relocations(bfd *abfd, struct internal_scnhdr *scnhdr_int, SCNHDR *scnhdr_ext)
{
  if (scnhdr_int->s_nreloc < 0xffff) {
    H_PUT_16 (abfd, scnhdr_int->s_nreloc, scnhdr_ext->s_nreloc);
  } else {
    H_PUT_16 (abfd, 0xffff, scnhdr_ext->s_nreloc);
    scnhdr_int->s_flags |= IMAGE_SCN_LNK_NRELOC_OVFL;
    H_PUT_32 (abfd, scnhdr_int->s_flags, scnhdr_ext->s_flags);
  }
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
  if (abfd == NULL || inp == NULL || extp == NULL) {
    return 0;
  }

  struct external_IMAGE_DEBUG_DIRECTORY *ext = (struct external_IMAGE_DEBUG_DIRECTORY *) extp;
  struct internal_IMAGE_DEBUG_DIRECTORY *in = (struct internal_IMAGE_DEBUG_DIRECTORY *) inp;

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
  unsigned long safe_length;
  CV_INFO_PDB70 *cvinfo70;
  CV_INFO_PDB20 *cvinfo20;

  if (!abfd || !cvinfo)
    return NULL;

  if (bfd_seek (abfd, where, SEEK_SET) != 0)
    return NULL;

  if (length <= sizeof (CV_INFO_PDB70) && length <= sizeof (CV_INFO_PDB20))
    return NULL;

  safe_length = (length > 256) ? 256 : length;
  nread = bfd_read (buffer, safe_length, abfd);
  if (safe_length != nread)
    return NULL;

  memset (buffer + nread, 0, sizeof (buffer) - nread);

  cvinfo->CVSignature = H_GET_32 (abfd, buffer);
  cvinfo->Age = 0;

  if (cvinfo->CVSignature == CVINFO_PDB70_CVSIGNATURE && length > sizeof (CV_INFO_PDB70))
    {
      cvinfo70 = (CV_INFO_PDB70 *)(buffer);
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

  if (cvinfo->CVSignature == CVINFO_PDB20_CVSIGNATURE && length > sizeof (CV_INFO_PDB20))
    {
      cvinfo20 = (CV_INFO_PDB20 *)(buffer);
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
  if (!abfd || !cvinfo)
    return 0;

  size_t pdb_len = pdb ? strlen (pdb) : 0;
  const bfd_size_type size = sizeof (CV_INFO_PDB70) + pdb_len + 1;
  bfd_size_type written;
  CV_INFO_PDB70 *cvinfo70;
  char * buffer;

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
    cvinfo70->PdbFileName[0] = '\0';
  else
    memcpy (cvinfo70->PdbFileName, pdb, pdb_len + 1);

  written = bfd_write (buffer, size, abfd);

  free (buffer);

  return written == size ? size : 0;
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
  if (abfd == NULL || section == NULL)
    return false;
  
  if ((section->flags & SEC_HAS_CONTENTS) == 0)
    return false;
  
  if (dataoff > section->size || datasize > section->size - dataoff)
    return false;
  
  ufile_ptr filesize = bfd_get_file_size (abfd);
  if (filesize == 0)
    return true;
  
  ufile_ptr section_end = section->filepos + dataoff + datasize;
  if (section->filepos > filesize || section_end > filesize)
    return false;
  
  return true;
}

static bool
pe_print_idata (bfd * abfd, void * vfile)
{
  FILE *file = (FILE *) vfile;
  bfd_byte *data = NULL;
  asection *section;
  bfd_signed_vma adj;
  bfd_size_type datasize = 0;
  bfd_size_type dataoff;
  bfd_size_type i;
  const int onaline = 20;

  pe_data_type *pe = pe_data (abfd);
  if (!pe)
    return false;

  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
  bfd_vma addr = extra->DataDirectory[PE_IMPORT_TABLE].VirtualAddress;

  if (addr == 0 && extra->DataDirectory[PE_IMPORT_TABLE].Size == 0)
    {
      section = bfd_get_section_by_name (abfd, ".idata");
      if (!section || !(section->flags & SEC_HAS_CONTENTS))
        return true;

      addr = section->vma;
      datasize = section->size;
      if (datasize == 0)
        return true;
    }
  else
    {
      addr += extra->ImageBase;
      section = NULL;
      for (asection *s = abfd->sections; s != NULL; s = s->next)
        {
          if (addr >= s->vma && addr < s->vma + s->size)
            {
              section = s;
              datasize = s->size;
              break;
            }
        }

      if (!section)
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

  fprintf (file, _("\nThere is an import table in %s at 0x%lx\n"), section->name, (unsigned long) addr);

  dataoff = addr - section->vma;

  fprintf (file, _("\nThe Import Tables (interpreted %s section contents)\n"), section->name);
  fprintf (file, _(" vma:            Hint    Time      Forward  DLL       First\n                 Table   Stamp     Chain    Name      Thunk\n"));

  if (!bfd_malloc_and_get_section (abfd, section, &data))
    {
      free (data);
      return false;
    }

  adj = section->vma - extra->ImageBase;

  for (i = dataoff; i + onaline <= datasize; i += onaline)
    {
      fprintf (file, " %08lx\t", (unsigned long) (i + adj));
      
      bfd_vma hint_addr = bfd_get_32 (abfd, data + i);
      bfd_vma time_stamp = bfd_get_32 (abfd, data + i + 4);
      bfd_vma forward_chain = bfd_get_32 (abfd, data + i + 8);
      bfd_vma dll_name = bfd_get_32 (abfd, data + i + 12);
      bfd_vma first_thunk = bfd_get_32 (abfd, data + i + 16);

      fprintf (file, "%08lx %08lx %08lx %08lx %08lx\n",
               (unsigned long) hint_addr, (unsigned long) time_stamp,
               (unsigned long) forward_chain, (unsigned long) dll_name,
               (unsigned long) first_thunk);

      if (hint_addr == 0 && first_thunk == 0)
        break;

      if (dll_name - adj >= datasize)
        break;

      char *dll = (char *) data + dll_name - adj;
      bfd_size_type maxlen = (char *)(data + datasize) - dll - 1;
      fprintf (file, _("\n\tDLL Name: %.*s\n"), (int) maxlen, dll);

      if (hint_addr == 0)
        hint_addr = first_thunk;

      if (hint_addr != 0 && hint_addr - adj < datasize)
        {
          fprintf (file, _("\tvma:     Ordinal  Hint  Member-Name  Bound-To\n"));

          bfd_size_type idx = hint_addr - adj;
          bfd_vma ft_addr = first_thunk + extra->ImageBase;
          bfd_size_type ft_idx = first_thunk - adj;
          bfd_byte *ft_data = data + ft_idx;
          bfd_size_type ft_datasize = datasize - ft_idx;
          int ft_allocated = 0;

          if (first_thunk != hint_addr)
            {
              asection *ft_section = NULL;
              for (asection *s = abfd->sections; s != NULL; s = s->next)
                {
                  if (ft_addr >= s->vma && ft_addr < s->vma + s->size)
                    {
                      ft_section = s;
                      break;
                    }
                }

              if (!ft_section)
                {
                  fprintf (file, _("\nThere is a first thunk, but the section containing it could not be found\n"));
                  continue;
                }

              if (ft_section != section)
                {
                  ft_idx = first_thunk - (ft_section->vma - extra->ImageBase);
                  ft_datasize = ft_section->size - ft_idx;
                  
                  if (!get_contents_sanity_check (abfd, ft_section, ft_idx, ft_datasize))
                    continue;
                    
                  ft_data = (bfd_byte *) bfd_malloc (ft_datasize);
                  if (!ft_data)
                    continue;

                  if (!bfd_get_section_contents (abfd, ft_section, ft_data, (bfd_vma) ft_idx, ft_datasize))
                    {
                      free (ft_data);
                      continue;
                    }
                  ft_allocated = 1;
                }
            }

#ifdef COFF_WITH_pex64
          const bfd_size_type entry_size = 8;
#else
          const bfd_size_type entry_size = 4;
#endif

          for (bfd_size_type j = 0; idx + j + entry_size <= datasize; j += entry_size)
            {
              unsigned long member = bfd_get_32 (abfd, data + idx + j);
#ifdef COFF_WITH_pex64
              unsigned long member_high = bfd_get_32 (abfd, data + idx + j + 4);
              
              if (!member && !member_high)
                break;
#else
              if (member == 0)
                break;
#endif

              bfd_size_type amt = member - adj;

#ifdef COFF_WITH_pex64
              if (HighBitSet (member_high))
#else
              if (HighBitSet (member))
#endif
                {
                  unsigned int ordinal = member & 0xffff;
                  fprintf (file, "\t%08lx  %5u  <none> <none>", (unsigned long)(first_thunk + j), ordinal);
                }
              else if (amt >= datasize || amt + 2 >= datasize)
                {
                  fprintf (file, _("\t<corrupt: 0x%08lx>"), member);
                }
              else
                {
                  unsigned int hint = bfd_get_16 (abfd, data + amt);
                  char *member_name = (char *) data + amt + 2;
                  fprintf (file, "\t%08lx  <none>  %04x  %.*s",
                           (unsigned long)(first_thunk + j), hint,
                           (int) (datasize - (amt + 2)), member_name);
                }

              if (time_stamp != 0 && first_thunk != 0 && first_thunk != hint_addr && 
                  j + 4 <= ft_datasize)
                {
                  fprintf (file, "\t%08lx", (unsigned long) bfd_get_32 (abfd, ft_data + j));
                }

              fprintf (file, "\n");
            }

          if (ft_allocated)
            free (ft_data);
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
  asection *section;
  bfd_size_type datasize = 0;
  bfd_size_type dataoff;
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
          fprintf (file, _("\nThere is an export table, but the section containing it could not be found\n"));
          return true;
        }

      dataoff = addr - section->vma;
      datasize = extra->DataDirectory[PE_EXPORT_TABLE].Size;
    }

  if (datasize < 40)
    {
      fprintf (file, _("\nThere is an export table in %s, but it is too small (%d)\n"),
               section->name, (int) datasize);
      return true;
    }

  if (!get_contents_sanity_check (abfd, section, dataoff, datasize))
    {
      fprintf (file, _("\nThere is an export table in %s, but contents cannot be read\n"),
               section->name);
      return true;
    }

  fprintf (file, _("\nThere is an export table in %s at 0x%lx\n"),
           section->name, (unsigned long) addr);

  data = (bfd_byte *) bfd_malloc (datasize);
  if (data == NULL)
    return false;

  if (!bfd_get_section_contents (abfd, section, data, (file_ptr) dataoff, datasize))
    {
      free (data);
      return false;
    }

  edt.export_flags = bfd_get_32 (abfd, data + 0);
  edt.time_stamp = bfd_get_32 (abfd, data + 4);
  edt.major_ver = bfd_get_16 (abfd, data + 8);
  edt.minor_ver = bfd_get_16 (abfd, data + 10);
  edt.name = bfd_get_32 (abfd, data + 12);
  edt.base = bfd_get_32 (abfd, data + 16);
  edt.num_functions = bfd_get_32 (abfd, data + 20);
  edt.num_names = bfd_get_32 (abfd, data + 24);
  edt.eat_addr = bfd_get_32 (abfd, data + 28);
  edt.npt_addr = bfd_get_32 (abfd, data + 32);
  edt.ot_addr = bfd_get_32 (abfd, data + 36);

  adj = section->vma - extra->ImageBase + dataoff;

  fprintf (file, _("\nThe Export Tables (interpreted %s section contents)\n\n"), section->name);
  fprintf (file, _("Export Flags \t\t\t%lx\n"), (unsigned long) edt.export_flags);
  fprintf (file, _("Time/Date stamp \t\t%lx\n"), (unsigned long) edt.time_stamp);
  fprintf (file, _("Major/Minor \t\t\t%d/%d\n"), edt.major_ver, edt.minor_ver);

  fprintf (file, _("Name \t\t\t\t"));
  bfd_fprintf_vma (abfd, file, edt.name);

  if ((edt.name >= adj) && (edt.name < adj + datasize))
    fprintf (file, " %.*s\n", (int) (datasize - (edt.name - adj)), data + edt.name - adj);
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

  if (edt.eat_addr - adj >= datasize ||
      (edt.num_functions + 1) * 4 < edt.num_functions ||
      edt.eat_addr - adj + (edt.num_functions + 1) * 4 > datasize)
    {
      fprintf (file, _("\tInvalid Export Address Table rva (0x%lx) or entry count (0x%lx)\n"),
               (long) edt.eat_addr, (long) edt.num_functions);
    }
  else
    {
      for (i = 0; i < edt.num_functions; ++i)
        {
          bfd_vma eat_member = bfd_get_32 (abfd, data + edt.eat_addr + (i * 4) - adj);
          if (eat_member == 0)
            continue;

          if (eat_member - adj <= datasize)
            {
              fprintf (file, "\t[%4ld] +base[%4ld] %08lx %s -- %.*s\n",
                       (long) i, (long) (i + edt.base), (unsigned long) eat_member,
                       _("Forwarder RVA"), (int)(datasize - (eat_member - adj)),
                       data + eat_member - adj);
            }
          else
            {
              fprintf (file, "\t[%4ld] +base[%4ld] %08lx %s\n",
                       (long) i, (long) (i + edt.base), (unsigned long) eat_member,
                       _("Export RVA"));
            }
        }
    }

  fprintf (file, _("\n[Ordinal/Name Pointer] Table -- Ordinal Base %ld\n"), edt.base);
  fprintf (file, "\t          Ordinal   Hint Name\n");

  if (edt.npt_addr + (edt.num_names * 4) - adj >= datasize ||
      edt.num_names * 4 < edt.num_names ||
      (data + edt.npt_addr - adj) < data)
    {
      fprintf (file, _("\tInvalid Name Pointer Table rva (0x%lx) or entry count (0x%lx)\n"),
               (long) edt.npt_addr, (long) edt.num_names);
    }
  else if (edt.ot_addr + (edt.num_names * 2) - adj >= datasize ||
           data + edt.ot_addr - adj < data)
    {
      fprintf (file, _("\tInvalid Ordinal Table rva (0x%lx) or entry count (0x%lx)\n"),
               (long) edt.ot_addr, (long) edt.num_names);
    }
  else
    {
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
              char * name = (char *) data + name_ptr - adj;
              fprintf (file, "\t[%4ld] +base[%4ld]  %04lx %.*s\n",
                       (long) ord, (long) (ord + edt.base), (long) i,
                       (int)((char *)(data + datasize) - name), name);
            }
        }
    }

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
# define PDATA_ROW_SIZE	(3 * 8)
#else
# define PDATA_ROW_SIZE	(5 * 4)
#endif
  FILE *file = (FILE *) vfile;
  bfd_byte *data = NULL;
  asection *section;
  bfd_size_type datasize;
  bfd_size_type i;
  bfd_size_type start, stop;
  int onaline = PDATA_ROW_SIZE;

  if (file == NULL || abfd == NULL)
    return false;

  section = bfd_get_section_by_name (abfd, ".pdata");
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

  if (!bfd_malloc_and_get_section (abfd, section, &data) || data == NULL)
    {
      free (data);
      return false;
    }

  start = 0;

  for (i = start; i < stop; i += onaline)
    {
      bfd_vma begin_addr;
      bfd_vma end_addr;
      bfd_vma eh_handler;
      bfd_vma eh_data;
      bfd_vma prolog_end_addr;
#if !defined(COFF_WITH_pep) || defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined (COFF_WITH_peRiscV64)
      int em_data;
#endif

      if (i + PDATA_ROW_SIZE > stop)
	break;

      begin_addr      = GET_PDATA_ENTRY (abfd, data + i	    );
      end_addr	      = GET_PDATA_ENTRY (abfd, data + i +  4);
      eh_handler      = GET_PDATA_ENTRY (abfd, data + i +  8);
      eh_data	      = GET_PDATA_ENTRY (abfd, data + i + 12);
      prolog_end_addr = GET_PDATA_ENTRY (abfd, data + i + 16);

      if (begin_addr == 0 && end_addr == 0 && eh_handler == 0
	  && eh_data == 0 && prolog_end_addr == 0)
	break;

#if !defined(COFF_WITH_pep) || defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined (COFF_WITH_peRiscV64)
      em_data = ((eh_handler & 0x1) << 2) | (prolog_end_addr & 0x3);
#endif
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

  if (!abfd || !psc)
    return NULL;

  if (!(bfd_get_file_flags(abfd) & HAS_SYMS))
    {
      psc->symcount = 0;
      return NULL;
    }

  storage = bfd_get_symtab_upper_bound(abfd);
  if (storage < 0)
    return NULL;

  if (storage > 0)
    {
      sy = (asymbol **)bfd_malloc(storage);
      if (!sy)
        return NULL;
    }

  psc->symcount = bfd_canonicalize_symtab(abfd, sy);
  if (psc->symcount < 0)
    {
      if (sy)
        {
          free(sy);
        }
      return NULL;
    }

  return sy;
}

static const char *
my_symbol_for_address (bfd *abfd, bfd_vma func, sym_cache *psc)
{
  if (!abfd || !psc) {
    return NULL;
  }

  if (psc->syms == NULL) {
    psc->syms = slurp_symtab (abfd, psc);
    if (!psc->syms) {
      return NULL;
    }
  }

  for (int i = 0; i < psc->symcount; i++) {
    if (!psc->syms[i] || !psc->syms[i]->section) {
      continue;
    }
    
    if (psc->syms[i]->section->vma + psc->syms[i]->value == func) {
      return psc->syms[i]->name;
    }
  }

  return NULL;
}

static void
cleanup_syms(sym_cache *psc)
{
    if (psc == NULL) {
        return;
    }
    
    psc->symcount = 0;
    if (psc->syms != NULL) {
        free(psc->syms);
        psc->syms = NULL;
    }
}

/* This is the version for "compressed" pdata.  */

bool
_bfd_XX_print_ce_compressed_pdata (bfd * abfd, void * vfile)
{
#define PDATA_ROW_SIZE (2 * 4)
  FILE *file = (FILE *) vfile;
  bfd_byte *data = NULL;
  asection *section;
  bfd_size_type datasize;
  bfd_size_type i;
  bfd_size_type start, stop;
  int onaline = PDATA_ROW_SIZE;
  struct sym_cache cache = {0, 0};

  if (!file)
    return false;

  section = bfd_get_section_by_name (abfd, ".pdata");
  if (!section || 
      !(section->flags & SEC_HAS_CONTENTS) ||
      !coff_section_data (abfd, section) ||
      !pei_section_data (abfd, section))
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

      if (i + PDATA_ROW_SIZE > stop)
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
      if (tsection && 
          coff_section_data (abfd, tsection) &&
          pei_section_data (abfd, tsection))
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
pe_print_reloc (bfd * abfd, void * vfile)
{
  FILE *file = (FILE *) vfile;
  bfd_byte *data = NULL;
  asection *section = bfd_get_section_by_name (abfd, ".reloc");
  bfd_byte *p, *end;

  if (section == NULL
      || section->size == 0
      || (section->flags & SEC_HAS_CONTENTS) == 0)
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
  while (p + 8 <= end)
    {
      int j;
      bfd_vma virtual_address;
      unsigned long number, size;
      bfd_byte *chunk_end;

      virtual_address = bfd_get_32 (abfd, p);
      size = bfd_get_32 (abfd, p + 4);
      p += 8;
      
      if (size == 0)
	break;
      
      if (size < 8)
	{
	  free (data);
	  return false;
	}
      
      number = (size - 8) / 2;

      fprintf (file,
	       _("\nVirtual Address: %08lx Chunk size %ld (0x%lx) Number of fixups %ld\n"),
	       (unsigned long) virtual_address, size, size, number);

      chunk_end = p - 8 + size;
      if (chunk_end > end)
	chunk_end = end;
      j = 0;
      while (p + 2 <= chunk_end)
	{
	  unsigned short e = bfd_get_16 (abfd, p);
	  unsigned int t = (e & 0xF000) >> 12;
	  int off = e & 0x0FFF;

	  if (t >= sizeof (tbl) / sizeof (tbl[0]))
	    t = (sizeof (tbl) / sizeof (tbl[0])) - 1;

	  fprintf (file,
		   _("\treloc %4d offset %4x [%4lx] %s"),
		   j, off, (unsigned long) (off + virtual_address), tbl[t]);

	  p += 2;
	  j++;

	  if (t == IMAGE_REL_BASED_HIGHADJ && p + 2 <= chunk_end)
	    {
	      fprintf (file, " (%4x)", (unsigned int) bfd_get_16 (abfd, p));
	      p += 2;
	      j++;
	    }

	  fprintf (file, "\n");
	}
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
  unsigned long entry, addr, size;
  bfd_byte * leaf;

  if (data + 8 >= regions->section_end)
    return regions->section_end + 1;

  fprintf (file, _("%03x %*.s Entry: "), (int)(data - regions->section_start), indent, " ");

  entry = (unsigned long) bfd_get_32 (abfd, data);
  if (is_name)
    {
      bfd_byte *name = rsrc_get_name_pointer(entry, regions, rva_bias);
      if (!name)
	{
	  fprintf (file, _("<corrupt string offset: %#lx>\n"), entry);
	  return regions->section_end + 1;
	}
      
      if (!rsrc_print_name_string(file, abfd, name, entry, regions))
	return regions->section_end + 1;
    }
  else
    fprintf (file, _("ID: %#08lx"), entry);

  entry = (long) bfd_get_32 (abfd, data + 4);
  fprintf (file, _(", Value: %#08lx\n"), entry);

  if (HighBitSet(entry))
    {
      data = regions->section_start + WithoutHighBit (entry);
      if (data <= regions->section_start || data > regions->section_end)
	return regions->section_end + 1;

      return rsrc_print_resource_directory (file, abfd, indent + 1, data,
					    regions, rva_bias);
    }

  return rsrc_process_leaf_entry(file, abfd, entry, indent, regions, rva_bias);
}

static bfd_byte *
rsrc_get_name_pointer(unsigned long entry, rsrc_regions *regions, bfd_vma rva_bias)
{
  bfd_byte *name;
  
  if (HighBitSet(entry))
    name = regions->section_start + WithoutHighBit(entry);
  else
    name = regions->section_start + entry - rva_bias;

  if (name + 2 >= regions->section_end || name <= regions->section_start)
    return NULL;
    
  return name;
}

static bool
rsrc_print_name_string(FILE *file, bfd *abfd, bfd_byte *name, unsigned long entry, rsrc_regions *regions)
{
  unsigned int len = bfd_get_16(abfd, name);
  
  if (regions->strings_start == NULL)
    regions->strings_start = name;

  fprintf (file, _("name: [val: %08lx len %d]: "), entry, len);

  if (name + 2 + len * 2 >= regions->section_end)
    {
      fprintf (file, _("<corrupt string length: %#x>\n"), len);
      return false;
    }

  while (len--)
    {
      name += 2;
      char c = *name;
      if (c > 0 && c < 32)
	fprintf (file, "^%c", c + 64);
      else
	fprintf (file, "%.1s", name);
    }
  return true;
}

static bfd_byte *
rsrc_process_leaf_entry(FILE *file, bfd *abfd, unsigned long entry, unsigned int indent, rsrc_regions *regions, bfd_vma rva_bias)
{
  bfd_byte *leaf = regions->section_start + entry;

  if (leaf + 16 >= regions->section_end || leaf < regions->section_start)
    return regions->section_end + 1;

  unsigned long addr = (long) bfd_get_32(abfd, leaf);
  unsigned long size = (long) bfd_get_32(abfd, leaf + 4);
  
  fprintf (file, _("%03x %*.s  Leaf: Addr: %#08lx, Size: %#08lx, Codepage: %d\n"),
	   (int) entry, indent, " ", addr, size, (int) bfd_get_32(abfd, leaf + 8));

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
  unsigned int i;

  if (data + 16 >= regions->section_end)
    return regions->section_end + 1;

  fprintf (file, "%03x %*.s ", (int)(data - regions->section_start), indent, " ");
  
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

  num_names = (unsigned int) bfd_get_16 (abfd, data + 12);
  num_ids = (unsigned int) bfd_get_16 (abfd, data + 14);

  fprintf (file, _(" Table: Char: %d, Time: %08lx, Ver: %d/%d, Num Names: %d, IDs: %d\n"),
	   (int) bfd_get_32 (abfd, data),
	   (long) bfd_get_32 (abfd, data + 4),
	   (int)  bfd_get_16 (abfd, data + 8),
	   (int)  bfd_get_16 (abfd, data + 10),
	   num_names,
	   num_ids);
  data += 16;

  for (i = 0; i < num_names; i++)
    {
      entry_end = rsrc_print_resource_entries (file, abfd, indent + 1, true,
					       data, regions, rva_bias);
      data += 8;
      if (entry_end > highest_data)
        highest_data = entry_end;
      if (entry_end >= regions->section_end)
	return entry_end;
    }

  for (i = 0; i < num_ids; i++)
    {
      entry_end = rsrc_print_resource_entries (file, abfd, indent + 1, false,
					       data, regions, rva_bias);
      data += 8;
      if (entry_end > highest_data)
        highest_data = entry_end;
      if (entry_end >= regions->section_end)
	return entry_end;
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
  bfd_byte * data;
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

      data = rsrc_print_resource_directory (file, abfd, 0, data, & regions, rva_bias);

      if (data == regions.section_end + 1)
        {
          fprintf (file, _("Corrupt .rsrc section detected!\n"));
          break;
        }

      int align = (1 << section->alignment_power) - 1;
      data = (bfd_byte *) (((ptrdiff_t) (data + align)) & ~ align);
      rva_bias += data - p;

      if (data == (regions.section_end - 4))
        {
          data = regions.section_end;
        }
      else if (data < regions.section_end)
        {
          bfd_byte * check_data = data;
          while (check_data < regions.section_end && *check_data == 0)
            check_data++;
          
          if (check_data < regions.section_end)
            fprintf (file, _("\nWARNING: Extra data in .rsrc section - it will be ignored by Windows:\n"));
          
          data = regions.section_end;
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
pe_print_debugdata(bfd *abfd, void *vfile)
{
    FILE *file = (FILE *)vfile;
    pe_data_type *pe = pe_data(abfd);
    struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
    asection *section;
    bfd_byte *data = NULL;
    bfd_size_type dataoff;
    unsigned int i, j;

    bfd_vma addr = extra->DataDirectory[PE_DEBUG_DATA].VirtualAddress;
    bfd_size_type size = extra->DataDirectory[PE_DEBUG_DATA].Size;

    if (size == 0)
        return true;

    addr += extra->ImageBase;
    section = find_section_containing_address(abfd, addr);

    if (section == NULL) {
        fprintf(file, _("\nThere is a debug directory, but the section containing it could not be found\n"));
        return true;
    }

    if (!validate_section_for_debug_data(file, section, size)) {
        return !(section->flags & SEC_HAS_CONTENTS) || (section->size >= size);
    }

    fprintf(file, _("\nThere is a debug directory in %s at 0x%lx\n\n"), section->name, (unsigned long)addr);

    dataoff = addr - section->vma;

    if (size > (section->size - dataoff)) {
        fprintf(file, _("The debug data size field in the data directory is too big for the section"));
        return false;
    }

    fprintf(file, _("Type                Size     Rva      Offset\n"));

    if (!bfd_malloc_and_get_section(abfd, section, &data)) {
        free(data);
        return false;
    }

    process_debug_directory_entries(file, abfd, data, dataoff, size);

    free(data);

    if (size % sizeof(struct external_IMAGE_DEBUG_DIRECTORY) != 0) {
        fprintf(file, _("The debug directory size is not a multiple of the debug directory entry size\n"));
    }

    return true;
}

static asection *
find_section_containing_address(bfd *abfd, bfd_vma addr)
{
    asection *section;
    for (section = abfd->sections; section != NULL; section = section->next) {
        if ((addr >= section->vma) && (addr < (section->vma + section->size))) {
            break;
        }
    }
    return section;
}

static bool
validate_section_for_debug_data(FILE *file, asection *section, bfd_size_type size)
{
    if (!(section->flags & SEC_HAS_CONTENTS)) {
        fprintf(file, _("\nThere is a debug directory in %s, but that section has no contents\n"), section->name);
        return false;
    }
    
    if (section->size < size) {
        fprintf(file, _("\nError: section %s contains the debug data starting address but it is too small\n"), section->name);
        return false;
    }
    
    return true;
}

static void
process_debug_directory_entries(FILE *file, bfd *abfd, bfd_byte *data, bfd_size_type dataoff, bfd_size_type size)
{
    unsigned int i;
    unsigned int num_entries = size / sizeof(struct external_IMAGE_DEBUG_DIRECTORY);
    
    for (i = 0; i < num_entries; i++) {
        struct external_IMAGE_DEBUG_DIRECTORY *ext = &((struct external_IMAGE_DEBUG_DIRECTORY *)(data + dataoff))[i];
        struct internal_IMAGE_DEBUG_DIRECTORY idd;
        const char *type_name;

        _bfd_XXi_swap_debugdir_in(abfd, ext, &idd);

        type_name = (idd.Type >= IMAGE_NUMBEROF_DEBUG_TYPES) ? debug_type_names[0] : debug_type_names[idd.Type];

        fprintf(file, " %2ld  %14s %08lx %08lx %08lx\n", idd.Type, type_name, idd.SizeOfData, idd.AddressOfRawData, idd.PointerToRawData);

        if (idd.Type == PE_IMAGE_DEBUG_TYPE_CODEVIEW) {
            process_codeview_debug_entry(file, abfd, &idd);
        }
    }
}

static void
process_codeview_debug_entry(FILE *file, bfd *abfd, struct internal_IMAGE_DEBUG_DIRECTORY *idd)
{
    char signature[CV_INFO_SIGNATURE_LENGTH * 2 + 1];
    char buffer[256 + 1] ATTRIBUTE_ALIGNED_ALIGNOF(CODEVIEW_INFO);
    char *pdb;
    CODEVIEW_INFO *cvinfo = (CODEVIEW_INFO *)buffer;
    unsigned int j;

    if (!_bfd_XXi_slurp_codeview_record(abfd, (file_ptr)idd->PointerToRawData, idd->SizeOfData, cvinfo, &pdb)) {
        return;
    }

    for (j = 0; j < cvinfo->SignatureLength; j++) {
        sprintf(&signature[j * 2], "%02x", cvinfo->Signature[j] & 0xff);
    }

    fprintf(file, _("(format %c%c%c%c signature %s age %ld pdb %s)\n"),
            buffer[0], buffer[1], buffer[2], buffer[3],
            signature, cvinfo->Age, pdb[0] ? pdb : "(none)");

    free(pdb);
}

static bool
pe_is_repro(bfd *abfd)
{
  pe_data_type *pe = pe_data(abfd);
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
  
  section = abfd->sections;
  while (section != NULL)
    {
      if (addr >= section->vma && addr < section->vma + section->size)
        break;
      section = section->next;
    }

  if (section == NULL || 
      !(section->flags & SEC_HAS_CONTENTS) || 
      section->size < size)
    return false;

  dataoff = addr - section->vma;

  if (size > section->size - dataoff)
    return false;

  if (!bfd_malloc_and_get_section(abfd, section, &data))
    {
      if (data != NULL)
        free(data);
      return false;
    }

  for (i = 0; i < size / sizeof(struct external_IMAGE_DEBUG_DIRECTORY); i++)
    {
      struct external_IMAGE_DEBUG_DIRECTORY *ext = 
        &((struct external_IMAGE_DEBUG_DIRECTORY *)(data + dataoff))[i];
      struct internal_IMAGE_DEBUG_DIRECTORY idd;

      _bfd_XXi_swap_debugdir_in(abfd, ext, &idd);

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

#ifndef IMAGE_NT_OPTIONAL_HDR_MAGIC
# define IMAGE_NT_OPTIONAL_HDR_MAGIC 0x10b
#endif
#ifndef IMAGE_NT_OPTIONAL_HDR64_MAGIC
# define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#endif
#ifndef IMAGE_NT_OPTIONAL_HDRROM_MAGIC
# define IMAGE_NT_OPTIONAL_HDRROM_MAGIC 0x107
#endif

static void
print_characteristics(FILE *file, unsigned long flags)
{
  struct {
    unsigned long flag;
    const char *description;
  } flag_table[] = {
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
    {0, NULL}
  };

  fprintf(file, _("\nCharacteristics 0x%x\n"), flags);
  
  for (int i = 0; flag_table[i].description != NULL; i++) {
    if (flags & flag_table[i].flag) {
      fprintf(file, "\t%s\n", flag_table[i].description);
    }
  }
}

static void
print_timestamp(FILE *file, bfd *abfd, pe_data_type *pe)
{
  if (pe_is_repro(abfd)) {
    fprintf(file, "\nTime/Date\t\t%08lx", pe->coff.timestamp);
    fprintf(file, "\t(This is a reproducible build file hash, not a timestamp)\n");
  } else {
    time_t t = pe->coff.timestamp;
    fprintf(file, "\nTime/Date\t\t%s", ctime(&t));
  }
}

static const char *
get_magic_name(unsigned short magic)
{
  switch (magic) {
    case IMAGE_NT_OPTIONAL_HDR_MAGIC:
      return "PE32";
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
      return "PE32+";
    case IMAGE_NT_OPTIONAL_HDRROM_MAGIC:
      return "ROM";
    default:
      return NULL;
  }
}

static const char *
get_subsystem_name(unsigned short subsystem)
{
  switch (subsystem) {
    case IMAGE_SUBSYSTEM_UNKNOWN:
      return "unspecified";
    case IMAGE_SUBSYSTEM_NATIVE:
      return "NT native";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
      return "Windows GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:
      return "Windows CUI";
    case IMAGE_SUBSYSTEM_POSIX_CUI:
      return "POSIX CUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
      return "Wince CUI";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:
      return "EFI application";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
      return "EFI boot service driver";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
      return "EFI runtime driver";
    case IMAGE_SUBSYSTEM_SAL_RUNTIME_DRIVER:
      return "SAL runtime driver";
    case IMAGE_SUBSYSTEM_XBOX:
      return "XBOX";
    default:
      return NULL;
  }
}

static void
print_dll_characteristics(FILE *file, unsigned short dllch)
{
  if (!dllch) {
    return;
  }

  struct {
    unsigned short flag;
    const char *name;
  } dll_flags[] = {
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
    {0, NULL}
  };

  const char *indent = "\t\t\t\t\t";
  for (int i = 0; dll_flags[i].name != NULL; i++) {
    if (dllch & dll_flags[i].flag) {
      fprintf(file, "%s%s\n", indent, dll_flags[i].name);
    }
  }
}

static void
print_basic_info(FILE *file, bfd *abfd, struct internal_extra_pe_aouthdr *i)
{
  const char *name = get_magic_name(i->Magic);
  
  fprintf(file, "Magic\t\t\t%04x", i->Magic);
  if (name) {
    fprintf(file, "\t(%s)", name);
  }
  fprintf(file, "\nMajorLinkerVersion\t%d\n", i->MajorLinkerVersion);
  fprintf(file, "MinorLinkerVersion\t%d\n", i->MinorLinkerVersion);
  
  fprintf(file, "SizeOfCode\t\t");
  bfd_fprintf_vma(abfd, file, i->SizeOfCode);
  fprintf(file, "\nSizeOfInitializedData\t");
  bfd_fprintf_vma(abfd, file, i->SizeOfInitializedData);
  fprintf(file, "\nSizeOfUninitializedData\t");
  bfd_fprintf_vma(abfd, file, i->SizeOfUninitializedData);
  fprintf(file, "\nAddressOfEntryPoint\t");
  bfd_fprintf_vma(abfd, file, i->AddressOfEntryPoint);
  fprintf(file, "\nBaseOfCode\t\t");
  bfd_fprintf_vma(abfd, file, i->BaseOfCode);

#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined(COFF_WITH_peRiscV64)
  fprintf(file, "\nBaseOfData\t\t");
  bfd_fprintf_vma(abfd, file, i->BaseOfData);
#endif

  fprintf(file, "\nImageBase\t\t");
  bfd_fprintf_vma(abfd, file, i->ImageBase);
}

static void
print_version_info(FILE *file, struct internal_extra_pe_aouthdr *i)
{
  fprintf(file, "\nSectionAlignment\t%08x\n", i->SectionAlignment);
  fprintf(file, "FileAlignment\t\t%08x\n", i->FileAlignment);
  fprintf(file, "MajorOSystemVersion\t%d\n", i->MajorOperatingSystemVersion);
  fprintf(file, "MinorOSystemVersion\t%d\n", i->MinorOperatingSystemVersion);
  fprintf(file, "MajorImageVersion\t%d\n", i->MajorImageVersion);
  fprintf(file, "MinorImageVersion\t%d\n", i->MinorImageVersion);
  fprintf(file, "MajorSubsystemVersion\t%d\n", i->MajorSubsystemVersion);
  fprintf(file, "MinorSubsystemVersion\t%d\n", i->MinorSubsystemVersion);
  fprintf(file, "Win32Version\t\t%08x\n", i->Win32Version);
  fprintf(file, "SizeOfImage\t\t%08x\n", i->SizeOfImage);
  fprintf(file, "SizeOfHeaders\t\t%08x\n", i->SizeOfHeaders);
  fprintf(file, "CheckSum\t\t%08x\n", i->CheckSum);
}

static void
print_subsystem_info(FILE *file, struct internal_extra_pe_aouthdr *i)
{
  const char *subsystem_name = get_subsystem_name(i->Subsystem);
  
  fprintf(file, "Subsystem\t\t%08x", i->Subsystem);
  if (subsystem_name) {
    fprintf(file, "\t(%s)", subsystem_name);
  }
  fprintf(file, "\nDllCharacteristics\t%08x\n", i->DllCharacteristics);
  print_dll_characteristics(file, i->DllCharacteristics);
}

static void
print_memory_info(FILE *file, bfd *abfd, struct internal_extra_pe_aouthdr *i)
{
  fprintf(file, "SizeOfStackReserve\t");
  bfd_fprintf_vma(abfd, file, i->SizeOfStackReserve);
  fprintf(file, "\nSizeOfStackCommit\t");
  bfd_fprintf_vma(abfd, file, i->SizeOfStackCommit);
  fprintf(file, "\nSizeOfHeapReserve\t");
  bfd_fprintf_vma(abfd, file, i->SizeOfHeapReserve);
  fprintf(file, "\nSizeOfHeapCommit\t");
  bfd_fprintf_vma(abfd, file, i->SizeOfHeapCommit);
}

static void
print_data_directory(FILE *file, bfd *abfd, struct internal_extra_pe_aouthdr *i)
{
  fprintf(file, "LoaderFlags\t\t%08lx\n", (unsigned long) i->LoaderFlags);
  fprintf(file, "NumberOfRvaAndSizes\t%08lx\n", (unsigned long) i->NumberOfRvaAndSizes);

  fprintf(file, "\nThe Data Directory\n");
  for (int j = 0; j < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; j++) {
    fprintf(file, "Entry %1x ", j);
    bfd_fprintf_vma(abfd, file, i->DataDirectory[j].VirtualAddress);
    fprintf(file, " %08lx ", (unsigned long) i->DataDirectory[j].Size);
    fprintf(file, "%s\n", dir_names[j]);
  }
}

bool
_bfd_XX_print_private_bfd_data_common(bfd *abfd, void *vfile)
{
  FILE *file = (FILE *) vfile;
  pe_data_type *pe;
  struct internal_extra_pe_aouthdr *i;

  if (!abfd || !vfile) {
    return false;
  }

  pe = pe_data(abfd);
  if (!pe) {
    return false;
  }

  i = &pe->pe_opthdr;

  print_characteristics(file, pe->real_flags);
  print_timestamp(file, abfd, pe);
  print_basic_info(file, abfd, i);
  print_version_info(file, i);
  print_subsystem_info(file, i);
  print_memory_info(file, abfd, i);
  print_data_directory(file, abfd, i);

  pe_print_idata(abfd, vfile);
  pe_print_edata(abfd, vfile);
  
  if (bfd_coff_have_print_pdata(abfd)) {
    bfd_coff_print_pdata(abfd, vfile);
  } else {
    pe_print_pdata(abfd, vfile);
  }
  
  pe_print_reloc(abfd, vfile);
  pe_print_debugdata(abfd, file);
  rsrc_print_section(abfd, vfile);

  return true;
}

static bool
is_vma_in_section(bfd *abfd ATTRIBUTE_UNUSED, asection *sect, void *obj)
{
    if (sect == NULL || obj == NULL) {
        return false;
    }
    
    bfd_vma addr = *(bfd_vma *)obj;
    bfd_vma section_start = sect->vma;
    bfd_vma section_end = section_start + sect->size;
    
    if (section_end < section_start) {
        return false;
    }
    
    return (addr >= section_start) && (addr < section_end);
}

static asection *
find_section_by_vma (bfd *abfd, bfd_vma addr)
{
  if (!abfd) {
    return NULL;
  }
  
  return bfd_sections_find_if (abfd, is_vma_in_section, (void *) &addr);
}

/* Copy any private info we understand from the input bfd
   to the output bfd.  */

bool
_bfd_XX_bfd_copy_private_bfd_data_common (bfd * ibfd, bfd * obfd)
{
  pe_data_type *ipe, *ope;
  bfd_size_type size;

  if (!ibfd || !obfd)
    return false;

  if (ibfd->xvec->flavour != bfd_target_coff_flavour
      || obfd->xvec->flavour != bfd_target_coff_flavour)
    return true;

  ipe = pe_data (ibfd);
  ope = pe_data (obfd);

  if (!ipe || !ope)
    return false;

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

  size = ope->pe_opthdr.DataDirectory[PE_DEBUG_DATA].Size;
  if (size == 0)
    return true;

  bfd_vma addr = ope->pe_opthdr.DataDirectory[PE_DEBUG_DATA].VirtualAddress
    + ope->pe_opthdr.ImageBase;
  bfd_vma last = addr + size - 1;
  asection *section = find_section_by_vma (obfd, last);

  if (!section)
    return true;

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

  if (!(section->flags & SEC_HAS_CONTENTS))
    return true;

  bfd_byte *data;
  if (!bfd_malloc_and_get_section (obfd, section, &data))
    {
      _bfd_error_handler (_("%pB: failed to read debug data section"), obfd);
      return false;
    }

  struct external_IMAGE_DEBUG_DIRECTORY *dd =
    (struct external_IMAGE_DEBUG_DIRECTORY *)(data + dataoff);

  unsigned int num_entries = size / sizeof (struct external_IMAGE_DEBUG_DIRECTORY);
  for (unsigned int i = 0; i < num_entries; i++)
    {
      struct external_IMAGE_DEBUG_DIRECTORY *edd = &(dd[i]);
      struct internal_IMAGE_DEBUG_DIRECTORY idd;

      _bfd_XXi_swap_debugdir_in (obfd, edd, &idd);

      if (idd.AddressOfRawData == 0)
        continue;

      bfd_vma idd_vma = idd.AddressOfRawData + ope->pe_opthdr.ImageBase;
      asection *ddsection = find_section_by_vma (obfd, idd_vma);
      if (!ddsection)
        continue;

      idd.PointerToRawData = ddsection->filepos + idd_vma - ddsection->vma;
      _bfd_XXi_swap_debugdir_out (obfd, &idd, edd);
    }

  bool success = bfd_set_section_contents (obfd, section, data, 0, section->size);
  free (data);

  if (!success)
    {
      _bfd_error_handler (_("failed to update file offsets in debug directory"));
      return false;
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
  struct coff_section_tdata *icoff_data, *ocoff_data;
  struct pei_section_tdata *ipei_data, *opei_data;
  size_t amt;

  if (link_info != NULL
      || bfd_get_flavour (ibfd) != bfd_target_coff_flavour
      || bfd_get_flavour (obfd) != bfd_target_coff_flavour)
    return true;

  icoff_data = coff_section_data (ibfd, isec);
  ipei_data = pei_section_data (ibfd, isec);

  if (icoff_data == NULL || ipei_data == NULL)
    return true;

  ocoff_data = coff_section_data (obfd, osec);
  if (ocoff_data == NULL)
    {
      amt = sizeof (struct coff_section_tdata);
      osec->used_by_bfd = bfd_zalloc (obfd, amt);
      if (osec->used_by_bfd == NULL)
        return false;
      ocoff_data = coff_section_data (obfd, osec);
    }

  opei_data = pei_section_data (obfd, osec);
  if (opei_data == NULL)
    {
      amt = sizeof (struct pei_section_tdata);
      ocoff_data->tdata = bfd_zalloc (obfd, amt);
      if (ocoff_data->tdata == NULL)
        return false;
      opei_data = pei_section_data (obfd, osec);
    }

  opei_data->virt_size = ipei_data->virt_size;
  opei_data->pe_flags = ipei_data->pe_flags;

  return true;
}

void
_bfd_XX_get_symbol_info (bfd *abfd, asymbol *symbol, symbol_info *ret)
{
  if (abfd == NULL || symbol == NULL || ret == NULL) {
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
  unsigned long entry, addr, size;
  bfd_byte *result_ptr;

  if (data == NULL || datastart == NULL || dataend == NULL || abfd == NULL)
    return dataend + 1;

  if (data + 8 >= dataend)
    return dataend + 1;

  if (is_name)
    {
      bfd_byte *name;

      entry = bfd_get_32 (abfd, data);

      if (HighBitSet (entry))
	name = datastart + WithoutHighBit (entry);
      else
	{
	  if (entry < rva_bias)
	    return dataend + 1;
	  name = datastart + entry - rva_bias;
	}

      if (name + 2 >= dataend || name < datastart)
	return dataend + 1;

      unsigned int len = bfd_get_16 (abfd, name);
      if (len == 0 || len > 256)
	return dataend + 1;
    }

  entry = bfd_get_32 (abfd, data + 4);

  if (HighBitSet (entry))
    {
      unsigned long offset = WithoutHighBit (entry);
      if (offset > (unsigned long)(dataend - datastart))
	return dataend + 1;
      
      data = datastart + offset;

      if (data <= datastart || data >= dataend)
	return dataend + 1;

      return rsrc_count_directory (abfd, datastart, data, dataend, rva_bias);
    }

  if (entry > (unsigned long)(dataend - datastart) || 
      datastart + entry + 16 >= dataend)
    return dataend + 1;

  addr = bfd_get_32 (abfd, datastart + entry);
  size = bfd_get_32 (abfd, datastart + entry + 4);

  if (addr < rva_bias)
    return dataend + 1;

  result_ptr = datastart + addr - rva_bias;
  
  if (result_ptr < datastart || 
      result_ptr >= dataend ||
      size > (unsigned long)(dataend - result_ptr))
    return dataend + 1;

  return result_ptr + size;
}

static bfd_byte *
rsrc_count_directory (bfd *	     abfd,
		      bfd_byte *     datastart,
		      bfd_byte *     data,
		      bfd_byte *     dataend,
		      bfd_vma	     rva_bias)
{
  unsigned int  num_entries, num_ids;
  bfd_byte *    highest_data = data;

  if (data == NULL || datastart == NULL || dataend == NULL)
    return dataend + 1;

  if (data + 16 >= dataend)
    return dataend + 1;

  num_entries  = bfd_get_16 (abfd, data + 12);
  num_ids      = bfd_get_16 (abfd, data + 14);

  if (num_entries > (dataend - data - 16) / 8)
    return dataend + 1;
  if (num_ids > (dataend - data - 16) / 8)
    return dataend + 1;

  num_entries += num_ids;

  data += 16;

  while (num_entries > 0)
    {
      bfd_byte * entry_end;

      if (data + 8 > dataend)
        break;

      entry_end = rsrc_count_entries (abfd, num_entries >= num_ids,
				      datastart, data, dataend, rva_bias);
      data += 8;
      
      if (entry_end > highest_data)
        highest_data = entry_end;
        
      if (entry_end >= dataend)
	break;
	
      num_entries--;
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
  unsigned long val, addr, size;
  bfd_byte *address;

  if (!entry || !data || !datastart || !dataend || data + 8 > dataend)
    return dataend;

  val = bfd_get_32 (abfd, data);

  entry->parent = parent;
  entry->is_name = is_name;

  if (is_name)
    {
      if (HighBitSet (val))
	{
	  val = WithoutHighBit (val);
	  address = datastart + val;
	}
      else
	{
	  address = datastart + val - rva_bias;
	}

      if (address < datastart || address + 3 > dataend)
	return dataend;

      entry->name_id.name.len    = bfd_get_16 (abfd, address);
      entry->name_id.name.string = address + 2;
    }
  else
    entry->name_id.id = val;

  val = bfd_get_32 (abfd, data + 4);

  if (HighBitSet (val))
    {
      entry->is_dir = true;
      entry->value.directory = bfd_malloc (sizeof (*entry->value.directory));
      if (entry->value.directory == NULL)
	return dataend;

      return rsrc_parse_directory (abfd, entry->value.directory,
				   datastart,
				   datastart + WithoutHighBit (val),
				   dataend, rva_bias, entry);
    }

  entry->is_dir = false;
  entry->value.leaf = bfd_malloc (sizeof (*entry->value.leaf));
  if (entry->value.leaf == NULL)
    return dataend;

  data = datastart + val;
  if (data < datastart || data + 12 > dataend)
    {
      free (entry->value.leaf);
      entry->value.leaf = NULL;
      return dataend;
    }

  addr = bfd_get_32 (abfd, data);
  size = bfd_get_32 (abfd, data + 4);
  entry->value.leaf->size = size;
  entry->value.leaf->codepage = bfd_get_32 (abfd, data + 8);

  if (addr < rva_bias || size > dataend - datastart - (addr - rva_bias))
    {
      free (entry->value.leaf);
      entry->value.leaf = NULL;
      return dataend;
    }

  entry->value.leaf->data = bfd_malloc (size);
  if (entry->value.leaf->data == NULL)
    {
      free (entry->value.leaf);
      entry->value.leaf = NULL;
      return dataend;
    }

  memcpy (entry->value.leaf->data, datastart + addr - rva_bias, size);
  return datastart + (addr - rva_bias) + size;
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

  if (chain->num_entries == 0)
    {
      chain->first_entry = chain->last_entry = NULL;
      return highest_data;
    }

  for (i = 0; i < chain->num_entries; i++)
    {
      bfd_byte *entry_end;

      entry = bfd_malloc (sizeof (*entry));
      if (entry == NULL)
	return dataend;

      if (prev_entry == NULL)
	chain->first_entry = entry;
      else
	prev_entry->next_entry = entry;

      entry->next_entry = NULL;

      entry_end = rsrc_parse_entry (abfd, is_name, entry, datastart,
				    data, dataend, rva_bias, parent);
      data += 8;
      highest_data = (entry_end > highest_data) ? entry_end : highest_data;
      
      if (entry_end > dataend)
	return dataend;

      prev_entry = entry;
    }

  chain->last_entry = entry;

  return highest_data;
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
  bfd_byte * highest_data = data;

  if (table == NULL)
    return dataend;

  if (data + 16 > dataend)
    return dataend;

  table->characteristics = bfd_get_32 (abfd, data);
  table->time = bfd_get_32 (abfd, data + 4);
  table->major = bfd_get_16 (abfd, data + 8);
  table->minor = bfd_get_16 (abfd, data + 10);
  table->names.num_entries = bfd_get_16 (abfd, data + 12);
  table->ids.num_entries = bfd_get_16 (abfd, data + 14);
  table->entry = entry;

  data += 16;

  if (data + table->names.num_entries * 8 > dataend)
    return dataend;

  highest_data = rsrc_parse_entries (abfd, & table->names, true, data,
				     datastart, data, dataend, rva_bias, table);
  data += table->names.num_entries * 8;

  if (data + table->ids.num_entries * 8 > dataend)
    return dataend;

  highest_data = rsrc_parse_entries (abfd, & table->ids, false, highest_data,
				     datastart, data, dataend, rva_bias, table);
  data += table->ids.num_entries * 8;

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
  if (data == NULL || string == NULL || data->next_string == NULL) {
    return;
  }
  
  bfd_put_16 (data->abfd, string->len, data->next_string);
  memcpy (data->next_string + 2, string->string, string->len * 2);
  data->next_string += (string->len + 1) * 2;
}

static inline unsigned int
rsrc_compute_rva(rsrc_write_data *data, bfd_byte *addr)
{
    if (!data || !addr || !data->datastart) {
        return 0;
    }
    
    if (addr < data->datastart) {
        return 0;
    }
    
    return (addr - data->datastart) + data->rva_bias;
}

static void
rsrc_write_leaf (rsrc_write_data * data, rsrc_leaf * leaf)
{
  if (data == NULL || leaf == NULL || data->next_leaf == NULL || data->next_data == NULL) {
    return;
  }

  bfd_put_32 (data->abfd, rsrc_compute_rva (data, data->next_data), data->next_leaf);
  bfd_put_32 (data->abfd, leaf->size, data->next_leaf + 4);
  bfd_put_32 (data->abfd, leaf->codepage, data->next_leaf + 8);
  bfd_put_32 (data->abfd, 0, data->next_leaf + 12);
  data->next_leaf += 16;

  if (leaf->data != NULL && leaf->size > 0) {
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
  if (!data || !where || !entry) {
    return;
  }

  if (entry->is_name) {
    if (data->next_string >= data->datastart) {
      bfd_put_32 (data->abfd,
		  SetHighBit (data->next_string - data->datastart),
		  where);
      rsrc_write_string (data, & entry->name_id.name);
    }
  } else {
    bfd_put_32 (data->abfd, entry->name_id.id, where);
  }

  if (entry->is_dir) {
    if (data->next_table >= data->datastart) {
      bfd_put_32 (data->abfd,
		  SetHighBit (data->next_table - data->datastart),
		  where + 4);
      rsrc_write_directory (data, entry->value.directory);
    }
  } else {
    if (data->next_leaf >= data->datastart) {
      bfd_put_32 (data->abfd, data->next_leaf - data->datastart, where + 4);
      rsrc_write_leaf (data, entry->value.leaf);
    }
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
  rsrc_entry * entry;
  unsigned int i;
  bfd_byte * next_entry;
  bfd_byte * nt;
  unsigned int total_entries;

  if (data == NULL || dir == NULL || data->abfd == NULL || data->next_table == NULL) {
    return;
  }

  bfd_put_32 (data->abfd, dir->characteristics, data->next_table);
  bfd_put_32 (data->abfd, 0, data->next_table + 4);
  bfd_put_16 (data->abfd, dir->major, data->next_table + 8);
  bfd_put_16 (data->abfd, dir->minor, data->next_table + 10);
  bfd_put_16 (data->abfd, dir->names.num_entries, data->next_table + 12);
  bfd_put_16 (data->abfd, dir->ids.num_entries, data->next_table + 14);

  total_entries = dir->names.num_entries + dir->ids.num_entries;
  next_entry = data->next_table + 16;
  data->next_table = next_entry + (total_entries * 8);
  nt = data->next_table;

  for (i = 0, entry = dir->names.first_entry; 
       i < dir->names.num_entries && entry != NULL; 
       i++, entry = entry->next_entry)
    {
      rsrc_write_entry (data, next_entry, entry);
      next_entry += 8;
    }

  for (i = 0, entry = dir->ids.first_entry; 
       i < dir->ids.num_entries && entry != NULL; 
       i++, entry = entry->next_entry)
    {
      rsrc_write_entry (data, next_entry, entry);
      next_entry += 8;
    }
}

#if ! defined __CYGWIN__ && ! defined __MINGW32__
/* Return the length (number of units) of the first character in S,
   putting its 'ucs4_t' representation in *PUC.  */

static unsigned int
u16_mbtouc(wint_t *puc, const unsigned short *s, unsigned int n)
{
    if (!puc || !s || n == 0) {
        if (puc) *puc = 0xfffd;
        return 0;
    }

    unsigned short c = *s;

    if (c < 0xd800 || c >= 0xe000) {
        *puc = c;
        return 1;
    }

    if (c < 0xdc00) {
        if (n >= 2 && s[1] >= 0xdc00 && s[1] < 0xe000) {
            *puc = 0x10000 + ((c - 0xd800) << 10) + (s[1] - 0xdc00);
            return 2;
        }
        *puc = 0xfffd;
        return (n < 2) ? n : 1;
    }

    *puc = 0xfffd;
    return 1;
}
#endif /* not Cygwin/Mingw */

/* Perform a comparison of two entries.  */
static signed int
rsrc_cmp (bool is_name, rsrc_entry * a, rsrc_entry * b)
{
  if (!a || !b)
    return 0;

  if (!is_name)
    return a->name_id.id - b->name_id.id;

  bfd_byte *astring = a->name_id.name.string;
  unsigned int alen = a->name_id.name.len;
  bfd_byte *bstring = b->name_id.name.string;
  unsigned int blen = b->name_id.name.len;

  if (!astring || !bstring)
    return astring ? 1 : (bstring ? -1 : 0);

  signed int res = 0;
  unsigned int min_len = (alen < blen) ? alen : blen;

#if defined __CYGWIN__ || defined __MINGW32__
#ifdef __CYGWIN__
  res = wcsncasecmp((const wchar_t *)astring, (const wchar_t *)bstring, min_len);
#endif
#ifdef __MINGW32__
  res = wcsnicmp((const wchar_t *)astring, (const wchar_t *)bstring, min_len);
#endif
#else
  for (unsigned int i = 0; i < min_len && res == 0; i++, astring += 2, bstring += 2)
    {
      wint_t awc, bwc;
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
rsrc_print_name(char *buffer, rsrc_string string)
{
    bfd_byte *name = string.string;
    size_t buffer_len = strlen(buffer);
    
    if (!buffer || !name) {
        return;
    }
    
    for (unsigned int i = 0; i < string.len; i++) {
        buffer[buffer_len + i] = (char)name[i * 2];
    }
    buffer[buffer_len + string.len] = '\0';
}

static const char *
rsrc_resource_name (rsrc_entry *entry, rsrc_directory *dir, char *buffer)
{
  typedef struct {
    unsigned int id;
    const char *name;
  } resource_type;

  static const resource_type resource_types[] = {
    {1, " (CURSOR)"},
    {2, " (BITMAP)"},
    {3, " (ICON)"},
    {4, " (MENU)"},
    {5, " (DIALOG)"},
    {6, " (STRING)"},
    {7, " (FONTDIR)"},
    {8, " (FONT)"},
    {9, " (ACCELERATOR)"},
    {10, " (RCDATA)"},
    {11, " (MESSAGETABLE)"},
    {12, " (GROUP_CURSOR)"},
    {14, " (GROUP_ICON)"},
    {16, " (VERSION)"},
    {17, " (DLGINCLUDE)"},
    {19, " (PLUGPLAY)"},
    {20, " (VXD)"},
    {21, " (ANICURSOR)"},
    {22, " (ANIICON)"},
    {23, " (HTML)"},
    {24, " (MANIFEST)"},
    {240, " (DLGINIT)"},
    {241, " (TOOLBAR)"}
  };

  bool is_string = false;
  size_t pos = 0;

  buffer[0] = '\0';

  if (dir && dir->entry && dir->entry->parent && dir->entry->parent->entry) {
    pos += snprintf(buffer + pos, 1024 - pos, "type: ");
    if (dir->entry->parent->entry->is_name) {
      rsrc_print_name(buffer + pos, dir->entry->parent->entry->name_id.name);
      pos = strlen(buffer);
    } else {
      unsigned int id = dir->entry->parent->entry->name_id.id;
      pos += snprintf(buffer + pos, 1024 - pos, "%x", id);
      
      for (size_t i = 0; i < sizeof(resource_types) / sizeof(resource_types[0]); i++) {
        if (resource_types[i].id == id) {
          pos += snprintf(buffer + pos, 1024 - pos, "%s", resource_types[i].name);
          if (id == 6) {
            is_string = true;
          }
          break;
        }
      }
    }
  }

  if (dir && dir->entry) {
    pos += snprintf(buffer + pos, 1024 - pos, " name: ");
    if (dir->entry->is_name) {
      rsrc_print_name(buffer + pos, dir->entry->name_id.name);
      pos = strlen(buffer);
    } else {
      unsigned int id = dir->entry->name_id.id;
      pos += snprintf(buffer + pos, 1024 - pos, "%x", id);

      if (is_string) {
        pos += snprintf(buffer + pos, 1024 - pos, " (resource id range: %d - %d)",
                       (id - 1) << 4, (id << 4) - 1);
      }
    }
  }

  if (entry) {
    pos += snprintf(buffer + pos, 1024 - pos, " lang: ");

    if (entry->is_name) {
      rsrc_print_name(buffer + pos, entry->name_id.name);
    } else {
      snprintf(buffer + pos, 1024 - pos, "%x", entry->name_id.id);
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

static bool
rsrc_merge_string_entries (rsrc_entry * a ATTRIBUTE_UNUSED,
                           rsrc_entry * b ATTRIBUTE_UNUSED)
{
  if (a == NULL || b == NULL || a->is_dir || b->is_dir)
    return false;

  if (a->value.leaf == NULL || b->value.leaf == NULL)
    return false;

  unsigned int copy_needed = 0;
  bfd_byte * astring = a->value.leaf->data;
  bfd_byte * bstring = b->value.leaf->data;

  if (astring == NULL || bstring == NULL)
    return false;

  for (unsigned int i = 0; i < 16; i++)
    {
      if ((size_t)(astring - a->value.leaf->data) + 2 > a->value.leaf->size ||
          (size_t)(bstring - b->value.leaf->data) + 2 > b->value.leaf->size)
        return false;

      unsigned int alen = astring[0] + (astring[1] << 8);
      unsigned int blen = bstring[0] + (bstring[1] << 8);

      if (alen > 32767 || blen > 32767)
        return false;

      if ((size_t)(astring - a->value.leaf->data) + (alen + 1) * 2 > a->value.leaf->size ||
          (size_t)(bstring - b->value.leaf->data) + (blen + 1) * 2 > b->value.leaf->size)
        return false;

      if (alen == 0)
        {
          if (SIZE_MAX - copy_needed < blen * 2)
            return false;
          copy_needed += blen * 2;
        }
      else if (blen == 0)
        {
        }
      else if (alen != blen)
        {
          if (a->parent != NULL && a->parent->entry != NULL && !a->parent->entry->is_name)
            _bfd_error_handler (_(".rsrc merge failure: duplicate string resource: %d"),
                                ((a->parent->entry->name_id.id - 1) << 4) + i);
          return false;
        }
      else if (memcmp (astring + 2, bstring + 2, alen * 2) != 0)
        {
          if (a->parent != NULL && a->parent->entry != NULL && !a->parent->entry->is_name)
            _bfd_error_handler (_(".rsrc merge failure: duplicate string resource: %d"),
                                ((a->parent->entry->name_id.id - 1) << 4) + i);
          return false;
        }

      astring += (alen + 1) * 2;
      bstring += (blen + 1) * 2;
    }

  if (copy_needed == 0)
    return true;

  if (SIZE_MAX - a->value.leaf->size < copy_needed)
    return false;

  bfd_byte * new_data = bfd_malloc (a->value.leaf->size + copy_needed);
  if (new_data == NULL)
    return false;

  bfd_byte * nstring = new_data;
  astring = a->value.leaf->data;
  bstring = b->value.leaf->data;

  for (unsigned int i = 0; i < 16; i++)
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
          * nstring++ = 0;
          * nstring++ = 0;
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

static bool
is_default_manifest(rsrc_entry *entry, rsrc_directory *dir)
{
  return !entry->is_name
    && entry->name_id.id == 1
    && dir != NULL
    && dir->entry != NULL
    && !dir->entry->is_name
    && dir->entry->name_id.id == 0x18;
}

static bool
is_zero_lang_manifest(rsrc_entry *entry)
{
  return entry->value.directory->names.num_entries == 0
    && entry->value.directory->ids.num_entries == 1
    && !entry->value.directory->ids.first_entry->is_name
    && entry->value.directory->ids.first_entry->name_id.id == 0;
}

static bool
is_manifest_leaf(rsrc_entry *entry, rsrc_directory *dir)
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
is_string_resource(rsrc_directory *dir)
{
  return dir != NULL
    && dir->entry != NULL
    && dir->entry->parent != NULL
    && dir->entry->parent->entry != NULL
    && !dir->entry->parent->entry->is_name
    && dir->entry->parent->entry->name_id.id == 0x6;
}

static bool
handle_manifest_merge(rsrc_entry *entry, rsrc_entry *next, rsrc_dir_chain *chain,
                     rsrc_entry ***points_to_entry, bool *swapped)
{
  if (is_zero_lang_manifest(next)) {
    /* Fall through to drop NEXT */
  } else if (is_zero_lang_manifest(entry)) {
    /* Swap ENTRY and NEXT, then drop old ENTRY */
    entry->next_entry = next->next_entry;
    next->next_entry = entry;
    **points_to_entry = next;
    *points_to_entry = &next->next_entry;
    next = entry->next_entry;
    *swapped = true;
  } else {
    _bfd_error_handler(_(".rsrc merge failure: multiple non-default manifests"));
    bfd_set_error(bfd_error_file_truncated);
    return false;
  }

  entry->next_entry = next->next_entry;
  chain->num_entries--;
  return true;
}

static bool
handle_leaf_merge(rsrc_entry *entry, rsrc_entry *next, rsrc_dir_chain *chain,
                 rsrc_directory *dir)
{
  if (is_manifest_leaf(entry, dir)) {
    /* Drop manifest leaf */
  } else if (is_string_resource(dir)) {
    if (!rsrc_merge_string_entries(entry, next)) {
      bfd_set_error(bfd_error_file_truncated);
      return false;
    }
  } else {
    if (dir == NULL || dir->entry == NULL || dir->entry->parent == NULL 
        || dir->entry->parent->entry == NULL) {
      _bfd_error_handler(_(".rsrc merge failure: duplicate leaf"));
    } else {
      char buff[256];
      _bfd_error_handler(_(".rsrc merge failure: duplicate leaf: %s"),
                        rsrc_resource_name(entry, dir, buff));
    }
    bfd_set_error(bfd_error_file_truncated);
    return false;
  }

  entry->next_entry = next->next_entry;
  chain->num_entries--;
  return true;
}

static void
rsrc_sort_entries(rsrc_dir_chain *chain, bool is_name, rsrc_directory *dir)
{
  rsrc_entry *entry;
  rsrc_entry *next;
  rsrc_entry **points_to_entry;
  bool swapped;

  if (chain->num_entries < 2)
    return;

  do {
    swapped = false;
    points_to_entry = &chain->first_entry;
    entry = *points_to_entry;
    next = entry->next_entry;

    do {
      signed int cmp = rsrc_cmp(is_name, entry, next);

      if (cmp > 0) {
        entry->next_entry = next->next_entry;
        next->next_entry = entry;
        *points_to_entry = next;
        points_to_entry = &next->next_entry;
        next = entry->next_entry;
        swapped = true;
      } else if (cmp == 0) {
        if (entry->is_dir && next->is_dir) {
          if (is_default_manifest(entry, dir)) {
            if (!handle_manifest_merge(entry, next, chain, &points_to_entry, &swapped))
              return;
            if (chain->num_entries < 2)
              return;
            next = entry->next_entry;
          } else {
            rsrc_merge(entry, next);
          }
        } else if (entry->is_dir != next->is_dir) {
          _bfd_error_handler(_(".rsrc merge failure: a directory matches a leaf"));
          bfd_set_error(bfd_error_file_truncated);
          return;
        } else {
          if (!handle_leaf_merge(entry, next, chain, dir))
            return;
          if (chain->num_entries < 2)
            return;
          next = entry->next_entry;
        }
      } else {
        points_to_entry = &entry->next_entry;
        entry = next;
        next = next->next_entry;
      }
    } while (next);

    chain->last_entry = entry;
  } while (swapped);
}

/* Attach B's chain onto A.  */
static void
rsrc_attach_chain (rsrc_dir_chain * achain, rsrc_dir_chain * bchain)
{
  if (!achain || !bchain || bchain->num_entries == 0)
    return;

  achain->num_entries += bchain->num_entries;

  if (achain->first_entry == NULL)
    {
      achain->first_entry = bchain->first_entry;
      achain->last_entry = bchain->last_entry;
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

  if (!a || !b || !a->is_dir || !b->is_dir)
    {
      bfd_set_error (bfd_error_invalid_operation);
      return;
    }

  adir = a->value.directory;
  bdir = b->value.directory;

  if (!adir || !bdir)
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
rsrc_process_section(bfd *abfd, struct coff_final_link_info *pfinfo)
{
    rsrc_directory new_table;
    bfd_size_type size;
    asection *sec;
    pe_data_type *pe;
    bfd_vma rva_bias;
    bfd_byte *data;
    bfd_byte *datastart;
    bfd_byte *dataend;
    bfd_byte *new_data;
    unsigned int num_resource_sets;
    rsrc_directory *type_tables;
    rsrc_write_data write_data;
    unsigned int indx;
    bfd *input;
    unsigned int num_input_rsrc = 0;
    unsigned int max_num_input_rsrc = 4;
    ptrdiff_t *rsrc_sizes = NULL;

    new_table.names.num_entries = 0;
    new_table.ids.num_entries = 0;

    sec = bfd_get_section_by_name(abfd, ".rsrc");
    if (sec == NULL || (size = sec->rawsize) == 0)
        return;

    pe = pe_data(abfd);
    if (pe == NULL)
        return;

    rva_bias = sec->vma - pe->pe_opthdr.ImageBase;

    if (!bfd_malloc_and_get_section(abfd, sec, &datastart))
        goto cleanup;

    data = datastart;
    rsrc_sizes = bfd_malloc(max_num_input_rsrc * sizeof(*rsrc_sizes));
    if (rsrc_sizes == NULL)
        goto cleanup;

    for (input = pfinfo->info->input_bfds; input != NULL; input = input->link.next) {
        asection *rsrc_sec = bfd_get_section_by_name(input, ".rsrc");

        if (rsrc_sec != NULL && !discarded_section(rsrc_sec)) {
            if (num_input_rsrc == max_num_input_rsrc) {
                max_num_input_rsrc += 10;
                ptrdiff_t *new_rsrc_sizes = bfd_realloc(rsrc_sizes, 
                    max_num_input_rsrc * sizeof(*rsrc_sizes));
                if (new_rsrc_sizes == NULL)
                    goto cleanup;
                rsrc_sizes = new_rsrc_sizes;
            }

            BFD_ASSERT(rsrc_sec->size > 0);
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

        if (num_resource_sets >= num_input_rsrc || 
            (data - p) > rsrc_sizes[num_resource_sets]) {
            _bfd_error_handler(_("%pB: .rsrc merge failure: unexpected .rsrc size"), abfd);
            bfd_set_error(bfd_error_file_truncated);
            goto cleanup;
        }

        data = p + rsrc_sizes[num_resource_sets];
        rva_bias += data - p;
        num_resource_sets++;
    }
    BFD_ASSERT(num_resource_sets == num_input_rsrc);

    data = datastart;
    rva_bias = sec->vma - pe->pe_opthdr.ImageBase;

    type_tables = bfd_malloc(num_resource_sets * sizeof(*type_tables));
    if (type_tables == NULL)
        goto cleanup;

    indx = 0;
    while (data < dataend) {
        bfd_byte *p = data;

        rsrc_parse_directory(abfd, type_tables + indx, data, data, dataend, rva_bias, NULL);
        data = p + rsrc_sizes[indx];
        rva_bias += data - p;
        indx++;
    }
    BFD_ASSERT(indx == num_resource_sets);

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

    sizeof_leaves = sizeof_strings = sizeof_tables_and_entries = 0;
    rsrc_compute_region_sizes(&new_table);
    sizeof_strings = (sizeof_strings + 7) & ~7;

    new_data = bfd_zalloc(abfd, size);
    if (new_data == NULL)
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
    free(datastart);
    free(rsrc_sizes);
    free(type_tables);
}

/* Handle the .idata section and other things that need symbol table
   access.  */

bool
_bfd_XXi_final_link_postscript (bfd * abfd, struct coff_final_link_info *pfinfo)
{
  struct coff_link_hash_entry *h1;
  struct bfd_link_info *info = pfinfo->info;
  bool result = true;
  char name[20];

  h1 = coff_link_hash_lookup (coff_hash_table (info),
                              ".idata$2", false, false, true);
  if (h1 != NULL)
    {
      if (!fill_idata_directory(abfd, info, &result))
        return result;
    }
  else
    {
      if (!fill_iat_directory(abfd, info, &result))
        return result;
    }

  if (!fill_delay_import_directory(abfd, info, &result))
    return result;

  if (!fill_tls_directory(abfd, info, name, &result))
    return result;

  if (!fill_load_config_directory(abfd, info, name, &result))
    return result;

  if (!sort_pdata_section(abfd, pfinfo, &result))
    return result;

  rsrc_process_section (abfd, pfinfo);

  return result;
}

static bool
is_symbol_defined(struct coff_link_hash_entry *h)
{
  return h != NULL &&
         (h->root.type == bfd_link_hash_defined ||
          h->root.type == bfd_link_hash_defweak) &&
         h->root.u.def.section != NULL &&
         h->root.u.def.section->output_section != NULL;
}

static bfd_vma
get_symbol_address(struct coff_link_hash_entry *h)
{
  return h->root.u.def.value +
         h->root.u.def.section->output_section->vma +
         h->root.u.def.section->output_offset;
}

static bool
fill_idata_directory(bfd *abfd, struct bfd_link_info *info, bool *result)
{
  struct coff_link_hash_entry *h1;

  h1 = coff_link_hash_lookup (coff_hash_table (info),
                              ".idata$2", false, false, true);
  if (is_symbol_defined(h1))
    {
      pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_TABLE].VirtualAddress =
        get_symbol_address(h1);
    }
  else
    {
      _bfd_error_handler
        (_("%pB: unable to fill in DataDirectory[%d]: %s is missing"),
         abfd, PE_IMPORT_TABLE, ".idata$2");
      *result = false;
      return false;
    }

  h1 = coff_link_hash_lookup (coff_hash_table (info),
                              ".idata$4", false, false, true);
  if (is_symbol_defined(h1))
    {
      pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_TABLE].Size =
        get_symbol_address(h1) - 
        pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_TABLE].VirtualAddress;
    }
  else
    {
      _bfd_error_handler
        (_("%pB: unable to fill in DataDirectory[%d]: %s is missing"),
         abfd, PE_IMPORT_TABLE, ".idata$4");
      *result = false;
      return false;
    }

  h1 = coff_link_hash_lookup (coff_hash_table (info),
                              ".idata$5", false, false, true);
  if (is_symbol_defined(h1))
    {
      pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].VirtualAddress =
        get_symbol_address(h1);
    }
  else
    {
      _bfd_error_handler
        (_("%pB: unable to fill in DataDirectory[%d]: %s is missing"),
         abfd, PE_IMPORT_ADDRESS_TABLE, ".idata$5");
      *result = false;
      return false;
    }

  h1 = coff_link_hash_lookup (coff_hash_table (info),
                              ".idata$6", false, false, true);
  if (is_symbol_defined(h1))
    {
      pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].Size =
        get_symbol_address(h1) -
        pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].VirtualAddress;
    }
  else
    {
      _bfd_error_handler
        (_("%pB: unable to fill in DataDirectory[%d]: %s is missing"),
         abfd, PE_IMPORT_ADDRESS_TABLE, ".idata$6");
      *result = false;
      return false;
    }

  return true;
}

static bool
fill_iat_directory(bfd *abfd, struct bfd_link_info *info, bool *result)
{
  struct coff_link_hash_entry *h1;
  bfd_vma iat_va;

  h1 = coff_link_hash_lookup (coff_hash_table (info),
                              "__IAT_start__", false, false, true);
  if (!is_symbol_defined(h1))
    return true;

  iat_va = get_symbol_address(h1);

  h1 = coff_link_hash_lookup (coff_hash_table (info),
                              "__IAT_end__", false, false, true);
  if (is_symbol_defined(h1))
    {
      pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].Size =
        get_symbol_address(h1) - iat_va;
      if (pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].Size != 0)
        pe_data (abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].VirtualAddress =
          iat_va - pe_data (abfd)->pe_opthdr.ImageBase;
    }
  else
    {
      _bfd_error_handler
        (_("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
         abfd, PE_IMPORT_ADDRESS_TABLE, "__IAT_end__");
      *result = false;
      return false;
    }

  return true;
}

static bool
fill_delay_import_directory(bfd *abfd, struct bfd_link_info *info, bool *result)
{
  struct coff_link_hash_entry *h1;
  bfd_vma delay_va;

  h1 = coff_link_hash_lookup (coff_hash_table (info),
                              "__DELAY_IMPORT_DIRECTORY_start__", false, false, true);
  if (!is_symbol_defined(h1))
    return true;

  delay_va = get_symbol_address(h1);

  h1 = coff_link_hash_lookup (coff_hash_table (info),
                              "__DELAY_IMPORT_DIRECTORY_end__", false, false, true);
  if (is_symbol_defined(h1))
    {
      pe_data (abfd)->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR].Size =
        get_symbol_address(h1) - delay_va;
      if (pe_data (abfd)->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR].Size != 0)
        pe_data (abfd)->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR].VirtualAddress =
          delay_va - pe_data (abfd)->pe_opthdr.ImageBase;
    }
  else
    {
      _bfd_error_handler
        (_("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
         abfd, PE_DELAY_IMPORT_DESCRIPTOR, "__DELAY_IMPORT_DIRECTORY_end__");
      *result = false;
      return false;
    }

  return true;
}

static bool
fill_tls_directory(bfd *abfd, struct bfd_link_info *info, char *name, bool *result)
{
  struct coff_link_hash_entry *h1;

  name[0] = bfd_get_symbol_leading_char (abfd);
  strcpy (name + !!name[0], "_tls_used");
  h1 = coff_link_hash_lookup (coff_hash_table (info), name, false, false, true);
  
  if (h1 == NULL)
    return true;

  if (is_symbol_defined(h1))
    {
      pe_data (abfd)->pe_opthdr.DataDirectory[PE_TLS_TABLE].VirtualAddress =
        get_symbol_address(h1) - pe_data (abfd)->pe_opthdr.ImageBase;

#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
      pe_data (abfd)->pe_opthdr.DataDirectory[PE_TLS_TABLE].Size = 0x18;
#else
      pe_data (abfd)->pe_opthdr.DataDirectory[PE_TLS_TABLE].Size = 0x28;
#endif
    }
  else
    {
      _bfd_error_handler
        (_("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
         abfd, PE_TLS_TABLE, name);
      *result = false;
      return false;
    }

  return true;
}

static bool
is_compatible_x86_version(bfd *abfd)
{
  return bfd_get_arch (abfd) == bfd_arch_i386 &&
         ((bfd_get_mach (abfd) & ~bfd_mach_i386_intel_syntax) == bfd_mach_i386_i386) &&
         ((pe_data (abfd)->pe_opthdr.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) ||
          (pe_data (abfd)->pe_opthdr.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI)) &&
         (pe_data (abfd)->pe_opthdr.MajorSubsystemVersion * 256 +
          pe_data (abfd)->pe_opthdr.MinorSubsystemVersion <= 0x0501);
}

static bool
fill_load_config_directory(bfd *abfd, struct bfd_link_info *info, char *name, bool *result)
{
  struct coff_link_hash_entry *h1;
  char data[4];

  name[0] = bfd_get_symbol_leading_char (abfd);
  strcpy (name + !!name[0], "_load_config_used");
  h1 = coff_link_hash_lookup (coff_hash_table (info), name, false, false, true);
  
  if (h1 == NULL)
    return true;

  if (!is_symbol_defined(h1))
    {
      _bfd_error_handler
        (_("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
         abfd, PE_LOAD_CONFIG_TABLE, name);
      *result = false;
      return false;
    }

  pe_data (abfd)->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].VirtualAddress =
    get_symbol_address(h1) - pe_data (abfd)->pe_opthdr.ImageBase;

  if (pe_data (abfd)->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].VirtualAddress
      & (bfd_arch_bits_per_address (abfd) / bfd_arch_bits_per_byte (abfd) - 1))
    {
      _bfd_error_handler
        (_("%pB: unable to fill in DataDirectory[%d]: %s not properly aligned"),
         abfd, PE_LOAD_CONFIG_TABLE, name);
      *result = false;
      return false;
    }

  if (!bfd_get_section_contents (abfd,
      h1->root.u.def.section->output_section, data,
      h1->root.u.def.section->output_offset + h1->root.u.def.value, 4))
    {
      _bfd_error_handler
        (_("%pB: unable to fill in DataDirectory[%d]: size can't be read from %s"),
         abfd, PE_LOAD_CONFIG_TABLE, name);
      *result = false;
      return false;
    }

  uint32_t size = bfd_get_32 (abfd, data);
  pe_data (abfd)->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].Size =
    is_compatible_x86_version(abfd) ? 64 : size;

  if (size > h1->root.u.def.section->size - h1->root.u.def.value)
    {
      _bfd_error_handler
        (_("%pB: unable to fill in DataDirectory[%d]: size too large for the containing section"),
         abfd, PE_LOAD_CONFIG_TABLE);
      *result = false;
      return false;
    }

  return true;
}

static bool
sort_pdata_section(bfd *abfd, struct coff_final_link_info *pfinfo, bool *result)
{
#if !defined(COFF_WITH_pep) && (defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined (COFF_WITH_peRiscV64))
  asection *sec = bfd_get_section_by_name (abfd, ".pdata");
  if (sec == NULL)
    return true;

  bfd_size_type x = sec->rawsize;
  bfd_byte *tmp_data;

  if (!bfd_malloc_and_get_section (abfd, sec, &tmp_data))
    {
      *result = false;
      return false;
    }

  qsort (tmp_data, (size_t) (x / 12), 12, sort_x64_pdata);
  bfd_set_section_contents (pfinfo->output_bfd, sec, tmp_data, 0, x);
  free (tmp_data);
#endif

  return true;
}
