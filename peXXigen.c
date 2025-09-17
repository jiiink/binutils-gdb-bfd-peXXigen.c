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
    handle_section_symbol(abfd, in);
#endif
}

#ifndef STRICT_PE_FORMAT
static const char *
get_section_name(bfd *abfd, struct internal_syment *in, char *namebuf)
{
  const char *name = _bfd_coff_internal_syment_name(abfd, in, namebuf);
  if (name == NULL)
    {
      _bfd_error_handler(_("%pB: unable to find name for empty section"), abfd);
      bfd_set_error(bfd_error_invalid_target);
    }
  return name;
}

static int
find_unused_section_number(bfd *abfd)
{
  int unused_section_number = 0;
  asection *sec;
  
  for (sec = abfd->sections; sec; sec = sec->next)
    if (unused_section_number <= sec->target_index)
      unused_section_number = sec->target_index + 1;
  
  return unused_section_number;
}

static char *
allocate_section_name(bfd *abfd, const char *name)
{
  size_t name_len = strlen(name) + 1;
  char *sec_name = bfd_alloc(abfd, name_len);
  
  if (sec_name == NULL)
    {
      _bfd_error_handler(_("%pB: out of memory creating name for empty section"), abfd);
      return NULL;
    }
  
  memcpy(sec_name, name, name_len);
  return sec_name;
}

static asection *
create_fake_section(bfd *abfd, char *sec_name, int unused_section_number)
{
  #define FAKE_SECTION_FLAGS (SEC_HAS_CONTENTS | SEC_ALLOC | SEC_DATA | SEC_LOAD | SEC_LINKER_CREATED)
  #define SECTION_ALIGNMENT_POWER 2
  
  asection *sec = bfd_make_section_anyway_with_flags(abfd, sec_name, FAKE_SECTION_FLAGS);
  
  if (sec == NULL)
    {
      _bfd_error_handler(_("%pB: unable to create fake empty section"), abfd);
      return NULL;
    }
  
  sec->alignment_power = SECTION_ALIGNMENT_POWER;
  sec->target_index = unused_section_number;
  
  return sec;
}

static void
handle_section_symbol(bfd *abfd, struct internal_syment *in)
{
  char namebuf[SYMNMLEN + 1];
  const char *name;
  asection *sec;
  
  in->n_value = 0x0;
  
  if (in->n_scnum != 0)
    {
      in->n_sclass = C_STAT;
      return;
    }
  
  name = get_section_name(abfd, in, namebuf);
  if (name == NULL)
    return;
  
  sec = bfd_get_section_by_name(abfd, name);
  if (sec != NULL)
    {
      in->n_scnum = sec->target_index;
      in->n_sclass = C_STAT;
      return;
    }
  
  int unused_section_number = find_unused_section_number(abfd);
  char *sec_name = allocate_section_name(abfd, name);
  
  if (sec_name == NULL)
    return;
  
  sec = create_fake_section(abfd, sec_name, unused_section_number);
  if (sec != NULL)
    in->n_scnum = unused_section_number;
  
  in->n_sclass = C_STAT;
}
#endif

static bool
abs_finder(bfd *abfd ATTRIBUTE_UNUSED, asection *sec, void *data)
{
  #define SECTION_SIZE_LIMIT (1ULL << 32)
  
  bfd_vma abs_val = *(bfd_vma *)data;
  bfd_vma section_end = sec->vma + SECTION_SIZE_LIMIT;
  
  return (sec->vma <= abs_val) && (section_end > abs_val);
}

unsigned int
_bfd_XXi_swap_sym_out (bfd * abfd, void * inp, void * extp)
{
  struct internal_syment *in = (struct internal_syment *) inp;
  SYMENT *ext = (SYMENT *) extp;

  write_symbol_name(abfd, in, ext);
  handle_large_absolute_symbols(abfd, in);
  write_symbol_fields(abfd, in, ext);

  return SYMESZ;
}

static void
write_symbol_name(bfd * abfd, struct internal_syment *in, SYMENT *ext)
{
  if (in->_n._n_name[0] == 0)
    {
      H_PUT_32 (abfd, 0, ext->e.e.e_zeroes);
      H_PUT_32 (abfd, in->_n._n_n._n_offset, ext->e.e.e_offset);
    }
  else
    {
      memcpy (ext->e.e_name, in->_n._n_name, SYMNMLEN);
    }
}

static int
is_large_absolute_symbol(struct internal_syment *in)
{
  #define VALUE_32BIT_LIMIT ((1ULL << 32) - 1)
  #define VALUE_31BIT_LIMIT ((1ULL << 31) - 1)
  
  if (sizeof (in->n_value) <= 4)
    return 0;
    
  if (in->n_scnum != N_ABS)
    return 0;
    
  unsigned long long limit = sizeof (in->n_value) > 4 ? VALUE_32BIT_LIMIT : VALUE_31BIT_LIMIT;
  return in->n_value > limit;
}

static void
handle_large_absolute_symbols(bfd * abfd, struct internal_syment *in)
{
  if (!is_large_absolute_symbol(in))
    return;

  asection * sec = bfd_sections_find_if (abfd, abs_finder, & in->n_value);
  if (sec)
    {
      in->n_value -= sec->vma;
      in->n_scnum = sec->target_index;
    }
}

static void
write_symbol_fields(bfd * abfd, struct internal_syment *in, SYMENT *ext)
{
  H_PUT_32 (abfd, in->n_value, ext->e_value);
  H_PUT_16 (abfd, in->n_scnum, ext->e_scnum);

  if (sizeof (ext->e_type) == 2)
    H_PUT_16 (abfd, in->n_type, ext->e_type);
  else
    H_PUT_32 (abfd, in->n_type, ext->e_type);

  H_PUT_8 (abfd, in->n_sclass, ext->e_sclass);
  H_PUT_8 (abfd, in->n_numaux, ext->e_numaux);
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

  memset (ext, 0, AUXESZ);

  if (_bfd_XXi_handle_file_class(abfd, in, ext, in_class))
    return AUXESZ;

  if (_bfd_XXi_handle_section_class(abfd, in, ext, in_class, type))
    return AUXESZ;

  _bfd_XXi_write_symbol_base(abfd, in, ext);
  _bfd_XXi_write_fcnary(abfd, in, ext, in_class, type);
  _bfd_XXi_write_misc(abfd, in, ext, type);

  return AUXESZ;
}

static int
_bfd_XXi_handle_file_class(bfd *abfd, union internal_auxent *in, AUXENT *ext, int in_class)
{
  if (in_class != C_FILE)
    return 0;

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

  return 1;
}

static int
_bfd_XXi_handle_section_class(bfd *abfd, union internal_auxent *in, AUXENT *ext, int in_class, int type)
{
  if (type != T_NULL)
    return 0;

  if (in_class != C_STAT && in_class != C_LEAFSTAT && in_class != C_HIDDEN)
    return 0;

  PUT_SCN_SCNLEN (abfd, in->x_scn.x_scnlen, ext);
  PUT_SCN_NRELOC (abfd, in->x_scn.x_nreloc, ext);
  PUT_SCN_NLINNO (abfd, in->x_scn.x_nlinno, ext);
  H_PUT_32 (abfd, in->x_scn.x_checksum, ext->x_scn.x_checksum);
  H_PUT_16 (abfd, in->x_scn.x_associated, ext->x_scn.x_associated);
  H_PUT_8 (abfd, in->x_scn.x_comdat, ext->x_scn.x_comdat);
  return 1;
}

static void
_bfd_XXi_write_symbol_base(bfd *abfd, union internal_auxent *in, AUXENT *ext)
{
  H_PUT_32 (abfd, in->x_sym.x_tagndx.u32, ext->x_sym.x_tagndx);
  H_PUT_16 (abfd, in->x_sym.x_tvndx, ext->x_sym.x_tvndx);
}

static int
_bfd_XXi_is_function_type(int in_class, int type)
{
  return in_class == C_BLOCK || in_class == C_FCN || ISFCN (type) || ISTAG (in_class);
}

static void
_bfd_XXi_write_fcnary(bfd *abfd, union internal_auxent *in, AUXENT *ext, int in_class, int type)
{
  if (_bfd_XXi_is_function_type(in_class, type))
    {
      PUT_FCN_LNNOPTR (abfd, in->x_sym.x_fcnary.x_fcn.x_lnnoptr, ext);
      PUT_FCN_ENDNDX (abfd, in->x_sym.x_fcnary.x_fcn.x_endndx.u32, ext);
    }
  else
    {
      _bfd_XXi_write_array_dimensions(abfd, in, ext);
    }
}

static void
_bfd_XXi_write_array_dimensions(bfd *abfd, union internal_auxent *in, AUXENT *ext)
{
  int i;
  for (i = 0; i < 4; i++)
    {
      H_PUT_16 (abfd, in->x_sym.x_fcnary.x_ary.x_dimen[i],
                ext->x_sym.x_fcnary.x_ary.x_dimen[i]);
    }
}

static void
_bfd_XXi_write_misc(bfd *abfd, union internal_auxent *in, AUXENT *ext, int type)
{
  if (ISFCN (type))
    H_PUT_32 (abfd, in->x_sym.x_misc.x_fsize, ext->x_sym.x_misc.x_fsize);
  else
    {
      PUT_LNSZ_LNNO (abfd, in->x_sym.x_misc.x_lnsz.x_lnno, ext);
      PUT_LNSZ_SIZE (abfd, in->x_sym.x_misc.x_lnsz.x_size, ext);
    }
}

void
_bfd_XXi_swap_lineno_in (bfd * abfd, void * ext1, void * in1)
{
  LINENO *ext = (LINENO *) ext1;
  struct internal_lineno *in = (struct internal_lineno *) in1;

  in->l_addr.l_symndx = H_GET_32 (abfd, ext->l_addr.l_symndx);
  in->l_lnno = GET_LINENO_LNNO (abfd, ext);
}

unsigned int
_bfd_XXi_swap_lineno_out (bfd * abfd, void * inp, void * outp)
{
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

  _bfd_XXi_read_standard_fields(abfd, aouthdr_ext, aouthdr_int);
  _bfd_XXi_read_pe_fields(abfd, src, aouthdr_int, a);
  _bfd_XXi_read_data_directories(abfd, src, a);
  _bfd_XXi_adjust_addresses(aouthdr_int, a);
}

static void
_bfd_XXi_read_standard_fields(bfd * abfd, AOUTHDR * aouthdr_ext, 
                               struct internal_aouthdr *aouthdr_int)
{
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
#endif
}

static void
_bfd_XXi_read_pe_fields(bfd * abfd, PEAOUTHDR * src, 
                        struct internal_aouthdr *aouthdr_int,
                        struct internal_extra_pe_aouthdr *a)
{
  AOUTHDR * aouthdr_ext = (AOUTHDR *) src;
  
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
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
  
  _bfd_XXi_read_pe_header_fields(abfd, src, a);
  _bfd_XXi_read_pe_size_fields(abfd, src, a);
}

static void
_bfd_XXi_read_pe_header_fields(bfd * abfd, PEAOUTHDR * src,
                                struct internal_extra_pe_aouthdr *a)
{
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
}

static void
_bfd_XXi_read_pe_size_fields(bfd * abfd, PEAOUTHDR * src,
                              struct internal_extra_pe_aouthdr *a)
{
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
}

static void
_bfd_XXi_read_data_directories(bfd * abfd, PEAOUTHDR * src,
                                struct internal_extra_pe_aouthdr *a)
{
  unsigned idx;
  
  for (idx = 0;
       idx < a->NumberOfRvaAndSizes && idx < IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
       idx++)
    {
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
}

static void
_bfd_XXi_adjust_addresses(struct internal_aouthdr *aouthdr_int,
                           struct internal_extra_pe_aouthdr *a)
{
  _bfd_XXi_adjust_entry_address(aouthdr_int, a);
  _bfd_XXi_adjust_text_address(aouthdr_int, a);
  _bfd_XXi_adjust_data_address(aouthdr_int, a);
}

static void
_bfd_XXi_adjust_entry_address(struct internal_aouthdr *aouthdr_int,
                               struct internal_extra_pe_aouthdr *a)
{
  if (aouthdr_int->entry)
    {
      aouthdr_int->entry += a->ImageBase;
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
      aouthdr_int->entry &= 0xffffffff;
#endif
    }
}

static void
_bfd_XXi_adjust_text_address(struct internal_aouthdr *aouthdr_int,
                              struct internal_extra_pe_aouthdr *a)
{
  if (aouthdr_int->tsize)
    {
      aouthdr_int->text_start += a->ImageBase;
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
      aouthdr_int->text_start &= 0xffffffff;
#endif
    }
}

static void
_bfd_XXi_adjust_data_address(struct internal_aouthdr *aouthdr_int,
                              struct internal_extra_pe_aouthdr *a)
{
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
add_data_entry (bfd * abfd,
		struct internal_extra_pe_aouthdr *aout,
		int idx,
		char *name,
		bfd_vma base)
{
  asection *sec = bfd_get_section_by_name (abfd, name);

  if (sec == NULL)
    return;

  if (coff_section_data (abfd, sec) == NULL)
    return;

  if (pei_section_data (abfd, sec) == NULL)
    return;

  int size = pei_section_data (abfd, sec)->virt_size;
  aout->DataDirectory[idx].Size = size;

  if (size == 0)
    return;

  const bfd_vma ADDRESS_MASK = 0xffffffff;
  aout->DataDirectory[idx].VirtualAddress = (sec->vma - base) & ADDRESS_MASK;
  sec->flags |= SEC_DATA;
}

#define IS_32BIT_PE (!defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined(COFF_WITH_peRiscV64))
#define MASK_32BIT 0xffffffff
#define LINKER_VERSION_MAJOR (BFD_VERSION / 1000000)
#define LINKER_VERSION_HIGH (LINKER_VERSION_MAJOR / 100)
#define LINKER_VERSION_LOW ((LINKER_VERSION_MAJOR % 100) * 256)
#define FA(x) (((x) + fa - 1) & (-fa))
#define SA(x) (((x) + sa - 1) & (-sa))

static void adjust_address_for_image_base(bfd_vma *address, bfd_vma image_base, int condition)
{
    if (condition)
    {
        *address -= image_base;
#if IS_32BIT_PE
        *address &= MASK_32BIT;
#endif
    }
}

static void copy_data_directories(struct internal_extra_pe_aouthdr *extra, pe_data_type *pe)
{
    extra->DataDirectory[PE_IMPORT_TABLE] = pe->pe_opthdr.DataDirectory[PE_IMPORT_TABLE];
    extra->DataDirectory[PE_IMPORT_ADDRESS_TABLE] = pe->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE];
    extra->DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR] = pe->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR];
    extra->DataDirectory[PE_TLS_TABLE] = pe->pe_opthdr.DataDirectory[PE_TLS_TABLE];
    extra->DataDirectory[PE_LOAD_CONFIG_TABLE] = pe->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE];
}

static void add_standard_data_entries(bfd *abfd, struct internal_extra_pe_aouthdr *extra, bfd_vma ib)
{
    add_data_entry(abfd, extra, PE_EXPORT_TABLE, ".edata", ib);
    add_data_entry(abfd, extra, PE_RESOURCE_TABLE, ".rsrc", ib);
    add_data_entry(abfd, extra, PE_EXCEPTION_TABLE, ".pdata", ib);
}

static void calculate_section_sizes(bfd *abfd, struct internal_extra_pe_aouthdr *extra, 
                                   bfd_vma *dsize, bfd_vma *tsize, bfd_vma *hsize, bfd_vma fa)
{
    asection *sec;
    bfd_vma isize = 0;
    
    *dsize = 0;
    *tsize = 0;
    *hsize = 0;

    for (sec = abfd->sections; sec; sec = sec->next)
    {
        int rounded = FA(sec->size);
        
        if (rounded == 0)
            continue;

        if (*hsize == 0)
            *hsize = sec->filepos;
            
        if (sec->flags & SEC_DATA)
            *dsize += rounded;
            
        if (sec->flags & SEC_CODE)
            *tsize += rounded;

        if (coff_section_data(abfd, sec) != NULL && pei_section_data(abfd, sec) != NULL)
            isize = SA(sec->vma - extra->ImageBase + FA(pei_section_data(abfd, sec)->virt_size));
    }
    
    extra->SizeOfHeaders = *hsize;
    extra->SizeOfImage = isize;
}

static void write_linker_version(bfd *abfd, struct internal_extra_pe_aouthdr *extra, PEAOUTHDR *aouthdr_out)
{
    if (extra->MajorLinkerVersion || extra->MinorLinkerVersion)
    {
        H_PUT_8(abfd, extra->MajorLinkerVersion, aouthdr_out->standard.vstamp);
        H_PUT_8(abfd, extra->MinorLinkerVersion, aouthdr_out->standard.vstamp + 1);
    }
    else
    {
        H_PUT_16(abfd, LINKER_VERSION_HIGH + LINKER_VERSION_LOW, aouthdr_out->standard.vstamp);
    }
}

static void write_standard_fields(bfd *abfd, struct internal_aouthdr *aouthdr_in, PEAOUTHDR *aouthdr_out)
{
    PUT_AOUTHDR_TSIZE(abfd, aouthdr_in->tsize, aouthdr_out->standard.tsize);
    PUT_AOUTHDR_DSIZE(abfd, aouthdr_in->dsize, aouthdr_out->standard.dsize);
    PUT_AOUTHDR_BSIZE(abfd, aouthdr_in->bsize, aouthdr_out->standard.bsize);
    PUT_AOUTHDR_ENTRY(abfd, aouthdr_in->entry, aouthdr_out->standard.entry);
    PUT_AOUTHDR_TEXT_START(abfd, aouthdr_in->text_start, aouthdr_out->standard.text_start);

#if IS_32BIT_PE
    PUT_AOUTHDR_DATA_START(abfd, aouthdr_in->data_start, aouthdr_out->standard.data_start);
#endif
}

static void write_extra_fields(bfd *abfd, struct internal_extra_pe_aouthdr *extra, PEAOUTHDR *aouthdr_out)
{
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
}

static void write_data_directories(bfd *abfd, struct internal_extra_pe_aouthdr *extra, PEAOUTHDR *aouthdr_out)
{
    int idx;
    
    for (idx = 0; idx < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; idx++)
    {
        H_PUT_32(abfd, extra->DataDirectory[idx].VirtualAddress, aouthdr_out->DataDirectory[idx][0]);
        H_PUT_32(abfd, extra->DataDirectory[idx].Size, aouthdr_out->DataDirectory[idx][1]);
    }
}

unsigned int _bfd_XXi_swap_aouthdr_out(bfd *abfd, void *in, void *out)
{
    struct internal_aouthdr *aouthdr_in = (struct internal_aouthdr *)in;
    pe_data_type *pe = pe_data(abfd);
    struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
    PEAOUTHDR *aouthdr_out = (PEAOUTHDR *)out;
    bfd_vma sa, fa, ib;
    bfd_vma dsize, tsize, hsize;

    sa = extra->SectionAlignment;
    fa = extra->FileAlignment;
    ib = extra->ImageBase;

    adjust_address_for_image_base(&aouthdr_in->text_start, ib, aouthdr_in->tsize);
    adjust_address_for_image_base(&aouthdr_in->data_start, ib, aouthdr_in->dsize);
    adjust_address_for_image_base(&aouthdr_in->entry, ib, aouthdr_in->entry);

    aouthdr_in->bsize = FA(aouthdr_in->bsize);
    extra->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    add_standard_data_entries(abfd, extra, ib);
    copy_data_directories(extra, pe);

    if (extra->DataDirectory[PE_IMPORT_TABLE].VirtualAddress == 0)
        add_data_entry(abfd, extra, PE_IMPORT_TABLE, ".idata", ib);

    if (pe->has_reloc_section)
        add_data_entry(abfd, extra, PE_BASE_RELOCATION_TABLE, ".reloc", ib);

    calculate_section_sizes(abfd, extra, &dsize, &tsize, &hsize, fa);
    aouthdr_in->dsize = dsize;
    aouthdr_in->tsize = tsize;

    H_PUT_16(abfd, aouthdr_in->magic, aouthdr_out->standard.magic);
    write_linker_version(abfd, extra, aouthdr_out);
    write_standard_fields(abfd, aouthdr_in, aouthdr_out);
    write_extra_fields(abfd, extra, aouthdr_out);
    write_data_directories(abfd, extra, aouthdr_out);

    return AOUTSZ;
}

#define DOS_HEADER_E_MAGIC    IMAGE_DOS_SIGNATURE
#define DOS_HEADER_E_CBLP     0x90
#define DOS_HEADER_E_CP       0x3
#define DOS_HEADER_E_CRLC     0x0
#define DOS_HEADER_E_CPARHDR  0x4
#define DOS_HEADER_E_MINALLOC 0x0
#define DOS_HEADER_E_MAXALLOC 0xffff
#define DOS_HEADER_E_SS       0x0
#define DOS_HEADER_E_SP       0xb8
#define DOS_HEADER_E_CSUM     0x0
#define DOS_HEADER_E_IP       0x0
#define DOS_HEADER_E_CS       0x0
#define DOS_HEADER_E_LFARLC   0x40
#define DOS_HEADER_E_OVNO     0x0
#define DOS_HEADER_E_OEMID    0x0
#define DOS_HEADER_E_OEMINFO  0x0
#define DOS_HEADER_E_LFANEW   0x80
#define TIMESTAMP_NOT_SET     -1
#define E_RES_SIZE            4
#define E_RES2_SIZE           10

static void update_file_flags(bfd *abfd, struct internal_filehdr *filehdr_in)
{
  if (pe_data(abfd)->has_reloc_section || pe_data(abfd)->dont_strip_reloc)
    filehdr_in->f_flags &= ~F_RELFLG;

  if (pe_data(abfd)->dll)
    filehdr_in->f_flags |= F_DLL;
}

static void initialize_dos_header(struct internal_filehdr *filehdr_in)
{
  int idx;
  
  filehdr_in->pe.e_magic    = DOS_HEADER_E_MAGIC;
  filehdr_in->pe.e_cblp     = DOS_HEADER_E_CBLP;
  filehdr_in->pe.e_cp       = DOS_HEADER_E_CP;
  filehdr_in->pe.e_crlc     = DOS_HEADER_E_CRLC;
  filehdr_in->pe.e_cparhdr  = DOS_HEADER_E_CPARHDR;
  filehdr_in->pe.e_minalloc = DOS_HEADER_E_MINALLOC;
  filehdr_in->pe.e_maxalloc = DOS_HEADER_E_MAXALLOC;
  filehdr_in->pe.e_ss       = DOS_HEADER_E_SS;
  filehdr_in->pe.e_sp       = DOS_HEADER_E_SP;
  filehdr_in->pe.e_csum     = DOS_HEADER_E_CSUM;
  filehdr_in->pe.e_ip       = DOS_HEADER_E_IP;
  filehdr_in->pe.e_cs       = DOS_HEADER_E_CS;
  filehdr_in->pe.e_lfarlc   = DOS_HEADER_E_LFARLC;
  filehdr_in->pe.e_ovno     = DOS_HEADER_E_OVNO;
  filehdr_in->pe.e_oemid    = DOS_HEADER_E_OEMID;
  filehdr_in->pe.e_oeminfo  = DOS_HEADER_E_OEMINFO;
  filehdr_in->pe.e_lfanew   = DOS_HEADER_E_LFANEW;

  for (idx = 0; idx < E_RES_SIZE; idx++)
    filehdr_in->pe.e_res[idx] = 0x0;

  for (idx = 0; idx < E_RES2_SIZE; idx++)
    filehdr_in->pe.e_res2[idx] = 0x0;
}

static void write_timestamp(bfd *abfd, struct external_PEI_filehdr *filehdr_out)
{
  if (pe_data(abfd)->timestamp == TIMESTAMP_NOT_SET)
  {
    time_t now = bfd_get_current_time(0);
    H_PUT_32(abfd, now, filehdr_out->f_timdat);
  }
  else
  {
    H_PUT_32(abfd, pe_data(abfd)->timestamp, filehdr_out->f_timdat);
  }
}

static void write_file_header(bfd *abfd, struct internal_filehdr *filehdr_in,
                              struct external_PEI_filehdr *filehdr_out)
{
  H_PUT_16(abfd, filehdr_in->f_magic, filehdr_out->f_magic);
  H_PUT_16(abfd, filehdr_in->f_nscns, filehdr_out->f_nscns);
  write_timestamp(abfd, filehdr_out);
  PUT_FILEHDR_SYMPTR(abfd, filehdr_in->f_symptr, filehdr_out->f_symptr);
  H_PUT_32(abfd, filehdr_in->f_nsyms, filehdr_out->f_nsyms);
  H_PUT_16(abfd, filehdr_in->f_opthdr, filehdr_out->f_opthdr);
  H_PUT_16(abfd, filehdr_in->f_flags, filehdr_out->f_flags);
}

static void write_dos_header_fields(bfd *abfd, struct internal_filehdr *filehdr_in,
                                    struct external_PEI_filehdr *filehdr_out)
{
  H_PUT_16(abfd, filehdr_in->pe.e_magic, filehdr_out->e_magic);
  H_PUT_16(abfd, filehdr_in->pe.e_cblp, filehdr_out->e_cblp);
  H_PUT_16(abfd, filehdr_in->pe.e_cp, filehdr_out->e_cp);
  H_PUT_16(abfd, filehdr_in->pe.e_crlc, filehdr_out->e_crlc);
  H_PUT_16(abfd, filehdr_in->pe.e_cparhdr, filehdr_out->e_cparhdr);
  H_PUT_16(abfd, filehdr_in->pe.e_minalloc, filehdr_out->e_minalloc);
  H_PUT_16(abfd, filehdr_in->pe.e_maxalloc, filehdr_out->e_maxalloc);
  H_PUT_16(abfd, filehdr_in->pe.e_ss, filehdr_out->e_ss);
  H_PUT_16(abfd, filehdr_in->pe.e_sp, filehdr_out->e_sp);
  H_PUT_16(abfd, filehdr_in->pe.e_csum, filehdr_out->e_csum);
  H_PUT_16(abfd, filehdr_in->pe.e_ip, filehdr_out->e_ip);
  H_PUT_16(abfd, filehdr_in->pe.e_cs, filehdr_out->e_cs);
  H_PUT_16(abfd, filehdr_in->pe.e_lfarlc, filehdr_out->e_lfarlc);
  H_PUT_16(abfd, filehdr_in->pe.e_ovno, filehdr_out->e_ovno);
  H_PUT_16(abfd, filehdr_in->pe.e_oemid, filehdr_out->e_oemid);
  H_PUT_16(abfd, filehdr_in->pe.e_oeminfo, filehdr_out->e_oeminfo);
  H_PUT_32(abfd, filehdr_in->pe.e_lfanew, filehdr_out->e_lfanew);
}

static void write_dos_reserved_arrays(bfd *abfd, struct internal_filehdr *filehdr_in,
                                      struct external_PEI_filehdr *filehdr_out)
{
  int idx;
  
  for (idx = 0; idx < E_RES_SIZE; idx++)
    H_PUT_16(abfd, filehdr_in->pe.e_res[idx], filehdr_out->e_res[idx]);

  for (idx = 0; idx < E_RES2_SIZE; idx++)
    H_PUT_16(abfd, filehdr_in->pe.e_res2[idx], filehdr_out->e_res2[idx]);
}

unsigned int
_bfd_XXi_only_swap_filehdr_out(bfd *abfd, void *in, void *out)
{
  struct internal_filehdr *filehdr_in = (struct internal_filehdr *)in;
  struct external_PEI_filehdr *filehdr_out = (struct external_PEI_filehdr *)out;

  update_file_flags(abfd, filehdr_in);
  initialize_dos_header(filehdr_in);
  
  memcpy(filehdr_in->pe.dos_message, pe_data(abfd)->dos_message,
         sizeof(filehdr_in->pe.dos_message));
  
  filehdr_in->pe.nt_signature = IMAGE_NT_SIGNATURE;

  write_file_header(abfd, filehdr_in, filehdr_out);
  write_dos_header_fields(abfd, filehdr_in, filehdr_out);
  write_dos_reserved_arrays(abfd, filehdr_in, filehdr_out);
  
  memcpy(filehdr_out->dos_message, filehdr_in->pe.dos_message,
         sizeof(filehdr_out->dos_message));
  
  H_PUT_32(abfd, filehdr_in->pe.nt_signature, filehdr_out->nt_signature);

  return FILHSZ;
}

unsigned int
_bfd_XX_only_swap_filehdr_out (bfd * abfd, void * in, void * out)
{
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

#define MAX_RELOC_COUNT 0xffff
#define MAX_LINE_COUNT 0xffff
#define TEXT_SECTION ".text"
#define RVA_MASK 0xffffffff

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
    { ".text" , IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE },
    { ".tls",   IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_WRITE },
    { ".xdata", IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA },
};

static void validate_and_set_vaddr(bfd *abfd, struct internal_scnhdr *scnhdr_int, SCNHDR *scnhdr_ext)
{
    bfd_vma ss = scnhdr_int->s_vaddr - pe_data(abfd)->pe_opthdr.ImageBase;
    
    if (scnhdr_int->s_vaddr < pe_data(abfd)->pe_opthdr.ImageBase) {
        _bfd_error_handler(_("%pB:%.8s: section below image base"), abfd, scnhdr_int->s_name);
    }
#if !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined(COFF_WITH_peRiscV64)
    else if (ss != (ss & RVA_MASK)) {
        _bfd_error_handler(_("%pB:%.8s: RVA truncated"), abfd, scnhdr_int->s_name);
    }
    PUT_SCNHDR_VADDR(abfd, ss & RVA_MASK, scnhdr_ext->s_vaddr);
#else
    PUT_SCNHDR_VADDR(abfd, ss, scnhdr_ext->s_vaddr);
#endif
}

static void calculate_sizes(bfd *abfd, struct internal_scnhdr *scnhdr_int, bfd_vma *ps, bfd_vma *ss)
{
    if ((scnhdr_int->s_flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0) {
        if (bfd_pei_p(abfd)) {
            *ps = scnhdr_int->s_size;
            *ss = 0;
        } else {
            *ps = 0;
            *ss = scnhdr_int->s_size;
        }
    } else {
        *ps = bfd_pei_p(abfd) ? scnhdr_int->s_paddr : 0;
        *ss = scnhdr_int->s_size;
    }
}

static int is_text_section(const char *name)
{
    return memcmp(name, TEXT_SECTION, sizeof(TEXT_SECTION)) == 0;
}

static int should_clear_write_flag(bfd *abfd, const char *section_name)
{
    return !is_text_section(section_name) || (bfd_get_file_flags(abfd) & WP_TEXT);
}

static void apply_section_flags(bfd *abfd, struct internal_scnhdr *scnhdr_int)
{
    const pe_required_section_flags *p;
    
    for (p = known_sections; p < known_sections + ARRAY_SIZE(known_sections); p++) {
        if (memcmp(scnhdr_int->s_name, p->section_name, SCNNMLEN) == 0) {
            if (should_clear_write_flag(abfd, scnhdr_int->s_name)) {
                scnhdr_int->s_flags &= ~IMAGE_SCN_MEM_WRITE;
            }
            scnhdr_int->s_flags |= p->must_have;
            break;
        }
    }
}

static int is_executable_text_section(bfd *abfd, struct internal_scnhdr *scnhdr_int)
{
    return coff_data(abfd)->link_info &&
           !bfd_link_relocatable(coff_data(abfd)->link_info) &&
           !bfd_link_pic(coff_data(abfd)->link_info) &&
           is_text_section(scnhdr_int->s_name);
}

static void write_line_numbers(bfd *abfd, struct internal_scnhdr *scnhdr_int, SCNHDR *scnhdr_ext)
{
    H_PUT_16(abfd, (scnhdr_int->s_nlnno & MAX_LINE_COUNT), scnhdr_ext->s_nlnno);
    H_PUT_16(abfd, (scnhdr_int->s_nlnno >> 16), scnhdr_ext->s_nreloc);
}

static unsigned int write_standard_counts(bfd *abfd, struct internal_scnhdr *scnhdr_int, SCNHDR *scnhdr_ext)
{
    unsigned int ret = SCNHSZ;
    
    if (scnhdr_int->s_nlnno <= MAX_LINE_COUNT) {
        H_PUT_16(abfd, scnhdr_int->s_nlnno, scnhdr_ext->s_nlnno);
    } else {
        _bfd_error_handler(_("%pB: line number overflow: 0x%lx > 0xffff"), abfd, scnhdr_int->s_nlnno);
        bfd_set_error(bfd_error_file_truncated);
        H_PUT_16(abfd, MAX_LINE_COUNT, scnhdr_ext->s_nlnno);
        ret = 0;
    }
    
    if (scnhdr_int->s_nreloc < MAX_RELOC_COUNT) {
        H_PUT_16(abfd, scnhdr_int->s_nreloc, scnhdr_ext->s_nreloc);
    } else {
        H_PUT_16(abfd, MAX_RELOC_COUNT, scnhdr_ext->s_nreloc);
        scnhdr_int->s_flags |= IMAGE_SCN_LNK_NRELOC_OVFL;
        H_PUT_32(abfd, scnhdr_int->s_flags, scnhdr_ext->s_flags);
    }
    
    return ret;
}

unsigned int _bfd_XXi_swap_scnhdr_out(bfd *abfd, void *in, void *out)
{
    struct internal_scnhdr *scnhdr_int = (struct internal_scnhdr *)in;
    SCNHDR *scnhdr_ext = (SCNHDR *)out;
    unsigned int ret = SCNHSZ;
    bfd_vma ps, ss;
    
    memcpy(scnhdr_ext->s_name, scnhdr_int->s_name, sizeof(scnhdr_int->s_name));
    
    validate_and_set_vaddr(abfd, scnhdr_int, scnhdr_ext);
    calculate_sizes(abfd, scnhdr_int, &ps, &ss);
    
    PUT_SCNHDR_SIZE(abfd, ss, scnhdr_ext->s_size);
    PUT_SCNHDR_PADDR(abfd, ps, scnhdr_ext->s_paddr);
    PUT_SCNHDR_SCNPTR(abfd, scnhdr_int->s_scnptr, scnhdr_ext->s_scnptr);
    PUT_SCNHDR_RELPTR(abfd, scnhdr_int->s_relptr, scnhdr_ext->s_relptr);
    PUT_SCNHDR_LNNOPTR(abfd, scnhdr_int->s_lnnoptr, scnhdr_ext->s_lnnoptr);
    
    apply_section_flags(abfd, scnhdr_int);
    H_PUT_32(abfd, scnhdr_int->s_flags, scnhdr_ext->s_flags);
    
    if (is_executable_text_section(abfd, scnhdr_int)) {
        write_line_numbers(abfd, scnhdr_int, scnhdr_ext);
    } else {
        ret = write_standard_counts(abfd, scnhdr_int, scnhdr_ext);
    }
    
    return ret;
}

void
_bfd_XXi_swap_debugdir_in (bfd * abfd, void * ext1, void * in1)
{
  struct external_IMAGE_DEBUG_DIRECTORY *ext = (struct external_IMAGE_DEBUG_DIRECTORY *) ext1;
  struct internal_IMAGE_DEBUG_DIRECTORY *in = (struct internal_IMAGE_DEBUG_DIRECTORY *) in1;

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

#define BUFFER_SIZE 256
#define MAX_READ_LENGTH 256

static bfd_bool read_codeview_data(bfd *abfd, file_ptr where, unsigned long length, char *buffer, bfd_size_type *nread)
{
  if (bfd_seek(abfd, where, SEEK_SET) != 0)
    return FALSE;
    
  if (length > MAX_READ_LENGTH)
    length = MAX_READ_LENGTH;
    
  *nread = bfd_read(buffer, length, abfd);
  return (length == *nread);
}

static bfd_bool validate_length(unsigned long length)
{
  return (length > sizeof(CV_INFO_PDB70) || length > sizeof(CV_INFO_PDB20));
}

static void convert_guid_to_big_endian(bfd *abfd, unsigned char *source, unsigned char *dest)
{
  bfd_putb32(bfd_getl32(source), dest);
  bfd_putb16(bfd_getl16(&source[4]), &dest[4]);
  bfd_putb16(bfd_getl16(&source[6]), &dest[6]);
  memcpy(&dest[8], &source[8], 8);
}

static CODEVIEW_INFO *process_pdb70(bfd *abfd, char *buffer, CODEVIEW_INFO *cvinfo, char **pdb)
{
  CV_INFO_PDB70 *cvinfo70 = (CV_INFO_PDB70 *)buffer;
  
  cvinfo->Age = H_GET_32(abfd, cvinfo70->Age);
  convert_guid_to_big_endian(abfd, cvinfo70->Signature, cvinfo->Signature);
  cvinfo->SignatureLength = CV_INFO_SIGNATURE_LENGTH;
  
  if (pdb)
    *pdb = xstrdup(cvinfo70->PdbFileName);
    
  return cvinfo;
}

static CODEVIEW_INFO *process_pdb20(bfd *abfd, char *buffer, CODEVIEW_INFO *cvinfo, char **pdb)
{
  CV_INFO_PDB20 *cvinfo20 = (CV_INFO_PDB20 *)buffer;
  
  cvinfo->Age = H_GET_32(abfd, cvinfo20->Age);
  memcpy(cvinfo->Signature, cvinfo20->Signature, 4);
  cvinfo->SignatureLength = 4;
  
  if (pdb)
    *pdb = xstrdup(cvinfo20->PdbFileName);
    
  return cvinfo;
}

CODEVIEW_INFO *
_bfd_XXi_slurp_codeview_record(bfd *abfd, file_ptr where, unsigned long length, CODEVIEW_INFO *cvinfo,
                               char **pdb)
{
  char buffer[BUFFER_SIZE + 1];
  bfd_size_type nread;
  
  if (!validate_length(length))
    return NULL;
    
  if (!read_codeview_data(abfd, where, length, buffer, &nread))
    return NULL;
  
  memset(buffer + nread, 0, sizeof(buffer) - nread);
  
  cvinfo->CVSignature = H_GET_32(abfd, buffer);
  cvinfo->Age = 0;
  
  if (cvinfo->CVSignature == CVINFO_PDB70_CVSIGNATURE && length > sizeof(CV_INFO_PDB70))
    return process_pdb70(abfd, buffer, cvinfo, pdb);
    
  if (cvinfo->CVSignature == CVINFO_PDB20_CVSIGNATURE && length > sizeof(CV_INFO_PDB20))
    return process_pdb20(abfd, buffer, cvinfo, pdb);
  
  return NULL;
}

unsigned int
_bfd_XXi_write_codeview_record (bfd * abfd, file_ptr where, CODEVIEW_INFO *cvinfo,
				const char *pdb)
{
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
  
  fill_cvinfo70_data(abfd, cvinfo70, cvinfo);
  copy_pdb_filename(cvinfo70, pdb, pdb_len);

  written = bfd_write (buffer, size, abfd);

  free (buffer);

  return written == size ? size : 0;
}

static void
fill_cvinfo70_data(bfd *abfd, CV_INFO_PDB70 *cvinfo70, CODEVIEW_INFO *cvinfo)
{
  H_PUT_32 (abfd, CVINFO_PDB70_CVSIGNATURE, cvinfo70->CvSignature);
  
  convert_guid_to_little_endian(cvinfo70, cvinfo);
  
  H_PUT_32 (abfd, cvinfo->Age, cvinfo70->Age);
}

static void
convert_guid_to_little_endian(CV_INFO_PDB70 *cvinfo70, CODEVIEW_INFO *cvinfo)
{
  #define GUID_FIRST_PART_SIZE 4
  #define GUID_SECOND_PART_SIZE 2
  #define GUID_THIRD_PART_SIZE 2
  #define GUID_LAST_PART_SIZE 8
  #define GUID_SECOND_PART_OFFSET 4
  #define GUID_THIRD_PART_OFFSET 6
  #define GUID_LAST_PART_OFFSET 8
  
  bfd_putl32 (bfd_getb32 (cvinfo->Signature), cvinfo70->Signature);
  bfd_putl16 (bfd_getb16 (&(cvinfo->Signature[GUID_SECOND_PART_OFFSET])), 
              &(cvinfo70->Signature[GUID_SECOND_PART_OFFSET]));
  bfd_putl16 (bfd_getb16 (&(cvinfo->Signature[GUID_THIRD_PART_OFFSET])), 
              &(cvinfo70->Signature[GUID_THIRD_PART_OFFSET]));
  memcpy (&(cvinfo70->Signature[GUID_LAST_PART_OFFSET]), 
          &(cvinfo->Signature[GUID_LAST_PART_OFFSET]), 
          GUID_LAST_PART_SIZE);
}

static void
copy_pdb_filename(CV_INFO_PDB70 *cvinfo70, const char *pdb, size_t pdb_len)
{
  if (pdb == NULL)
    cvinfo70->PdbFileName[0] = '\0';
  else
    memcpy (cvinfo70->PdbFileName, pdb, pdb_len + 1);
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

static bool has_section_contents(asection *section)
{
  return (section->flags & SEC_HAS_CONTENTS) != 0;
}

static bool is_data_within_section_bounds(asection *section, bfd_size_type dataoff, bfd_size_type datasize)
{
  if (dataoff > section->size)
    return false;
  if (datasize > section->size - dataoff)
    return false;
  return true;
}

static bool is_data_within_file_bounds(asection *section, bfd_size_type dataoff, bfd_size_type datasize, ufile_ptr filesize)
{
  if ((ufile_ptr) section->filepos > filesize)
    return false;
  if (dataoff > filesize - section->filepos)
    return false;
  if (datasize > filesize - section->filepos - dataoff)
    return false;
  return true;
}

static bool
get_contents_sanity_check (bfd *abfd, asection *section,
			   bfd_size_type dataoff, bfd_size_type datasize)
{
  if (!has_section_contents(section))
    return false;
  
  if (!is_data_within_section_bounds(section, dataoff, datasize))
    return false;
  
  ufile_ptr filesize = bfd_get_file_size (abfd);
  if (filesize != 0 && !is_data_within_file_bounds(section, dataoff, datasize, filesize))
    return false;
  
  return true;
}

static asection* find_import_section(bfd *abfd, struct internal_extra_pe_aouthdr *extra, bfd_vma *addr, bfd_size_type *datasize)
{
    asection *section;
    
    if (*addr == 0 && extra->DataDirectory[PE_IMPORT_TABLE].Size == 0) {
        section = bfd_get_section_by_name(abfd, ".idata");
        if (section == NULL || (section->flags & SEC_HAS_CONTENTS) == 0)
            return NULL;
        *addr = section->vma;
        *datasize = section->size;
        return (*datasize == 0) ? NULL : section;
    }
    
    *addr += extra->ImageBase;
    for (section = abfd->sections; section != NULL; section = section->next) {
        *datasize = section->size;
        if (*addr >= section->vma && *addr < section->vma + *datasize)
            return section;
    }
    return section;
}

static bool validate_import_section(asection *section, FILE *file)
{
    if (section == NULL) {
        fprintf(file, _("\nThere is an import table, but the section containing it could not be found\n"));
        return false;
    }
    if (!(section->flags & SEC_HAS_CONTENTS)) {
        fprintf(file, _("\nThere is an import table in %s, but that section has no contents\n"), section->name);
        return false;
    }
    return true;
}

static void print_import_table_header(FILE *file, asection *section, bfd_vma addr)
{
    fprintf(file, _("\nThere is an import table in %s at 0x%lx\n"), section->name, (unsigned long) addr);
    fprintf(file, _("\nThe Import Tables (interpreted %s section contents)\n"), section->name);
    fprintf(file, _(" vma:            Hint    Time      Forward  DLL       First\n"
                    "                 Table   Stamp     Chain    Name      Thunk\n"));
}

static bool load_first_thunk_data(bfd *abfd, asection *section, asection **ft_section, 
                                  bfd_byte **ft_data, bfd_size_type *ft_datasize, 
                                  bfd_vma first_thunk, struct internal_extra_pe_aouthdr *extra,
                                  int *ft_allocated)
{
    bfd_vma ft_addr = first_thunk + extra->ImageBase;
    bfd_size_type ft_idx;
    
    for (*ft_section = abfd->sections; *ft_section != NULL; *ft_section = (*ft_section)->next) {
        if (ft_addr >= (*ft_section)->vma && ft_addr < (*ft_section)->vma + (*ft_section)->size)
            break;
    }
    
    if (*ft_section == NULL)
        return false;
    
    if (*ft_section != section) {
        ft_idx = first_thunk - ((*ft_section)->vma - extra->ImageBase);
        *ft_datasize = (*ft_section)->size - ft_idx;
        if (!get_contents_sanity_check(abfd, *ft_section, ft_idx, *ft_datasize))
            return false;
        *ft_data = (bfd_byte *) bfd_malloc(*ft_datasize);
        if (*ft_data == NULL)
            return false;
        if (!bfd_get_section_contents(abfd, *ft_section, *ft_data, (bfd_vma) ft_idx, *ft_datasize)) {
            free(*ft_data);
            return false;
        }
        *ft_allocated = 1;
    }
    return true;
}

static void print_import_member(FILE *file, bfd *abfd, bfd_byte *data, bfd_size_type datasize,
                               unsigned long member, bfd_vma first_thunk, bfd_size_type j, bfd_signed_vma adj)
{
    bfd_size_type amt = member - adj;
    
    if (HighBitSet(member)) {
        unsigned int ordinal = member & 0xffff;
        fprintf(file, "\t%08lx  %5u  <none> <none>", (unsigned long)(first_thunk + j), ordinal);
    } else if (amt >= datasize || amt + 2 >= datasize) {
        fprintf(file, _("\t<corrupt: 0x%08lx>"), member);
    } else {
        unsigned int hint = bfd_get_16(abfd, data + amt);
        char *member_name = (char *) data + amt + 2;
        fprintf(file, "\t%08lx  <none>  %04x  %.*s",
               (unsigned long)(first_thunk + j), hint,
               (int) (datasize - (amt + 2)), member_name);
    }
}

static void print_bound_address(FILE *file, bfd *abfd, bfd_byte *ft_data, bfd_size_type ft_datasize,
                               bfd_size_type j, bfd_vma time_stamp, bfd_vma first_thunk, bfd_vma hint_addr)
{
    if (time_stamp != 0 && first_thunk != 0 && first_thunk != hint_addr && j + 4 <= ft_datasize)
        fprintf(file, "\t%08lx", (unsigned long) bfd_get_32(abfd, ft_data + j));
}

static void print_hint_name_entries_32(FILE *file, bfd *abfd, bfd_byte *data, bfd_size_type datasize,
                                       int idx, bfd_vma first_thunk, bfd_vma time_stamp, bfd_vma hint_addr,
                                       bfd_byte *ft_data, bfd_size_type ft_datasize, bfd_signed_vma adj)
{
    bfd_size_type j;
    
    for (j = 0; idx + j + 4 <= datasize; j += 4) {
        unsigned long member = bfd_get_32(abfd, data + idx + j);
        if (member == 0)
            break;
        print_import_member(file, abfd, data, datasize, member, first_thunk, j, adj);
        print_bound_address(file, abfd, ft_data, ft_datasize, j, time_stamp, first_thunk, hint_addr);
        fprintf(file, "\n");
    }
}

#ifdef COFF_WITH_pex64
static void print_hint_name_entries_64(FILE *file, bfd *abfd, bfd_byte *data, bfd_size_type datasize,
                                       int idx, bfd_vma first_thunk, bfd_vma time_stamp, bfd_vma hint_addr,
                                       bfd_byte *ft_data, bfd_size_type ft_datasize, bfd_signed_vma adj)
{
    bfd_size_type j;
    
    for (j = 0; idx + j + 8 <= datasize; j += 8) {
        unsigned long member = bfd_get_32(abfd, data + idx + j);
        unsigned long member_high = bfd_get_32(abfd, data + idx + j + 4);
        if (!member && !member_high)
            break;
        
        bfd_size_type amt = member - adj;
        if (HighBitSet(member_high)) {
            unsigned int ordinal = member & 0xffff;
            fprintf(file, "\t%08lx  %5u  <none> <none>", (unsigned long)(first_thunk + j), ordinal);
        } else if (amt >= datasize || amt + 2 >= datasize) {
            fprintf(file, _("\t<corrupt: 0x%08lx>"), member);
        } else {
            unsigned int hint = bfd_get_16(abfd, data + amt);
            char *member_name = (char *) data + amt + 2;
            fprintf(file, "\t%08lx  <none>  %04x  %.*s",
                   (unsigned long)(first_thunk + j), hint,
                   (int) (datasize - (amt + 2)), member_name);
        }
        print_bound_address(file, abfd, ft_data, ft_datasize, j, time_stamp, first_thunk, hint_addr);
        fprintf(file, "\n");
    }
}
#endif

static void print_hint_name_vector(FILE *file, bfd *abfd, bfd_byte *data, bfd_size_type datasize,
                                   bfd_vma hint_addr, bfd_vma first_thunk, bfd_vma time_stamp,
                                   struct internal_extra_pe_aouthdr *extra, asection *section,
                                   bfd_signed_vma adj)
{
    bfd_byte *ft_data;
    asection *ft_section;
    bfd_size_type ft_datasize;
    int ft_allocated = 0;
    int idx = hint_addr - adj;
    
    fprintf(file, _("\tvma:     Ordinal  Hint  Member-Name  Bound-To\n"));
    
    int ft_idx = first_thunk - adj;
    ft_data = data + ft_idx;
    ft_datasize = datasize - ft_idx;
    
    if (first_thunk != hint_addr) {
        if (!load_first_thunk_data(abfd, section, &ft_section, &ft_data, &ft_datasize, 
                                   first_thunk, extra, &ft_allocated)) {
            if (!ft_section)
                fprintf(file, _("\nThere is a first thunk, but the section containing it could not be found\n"));
            return;
        }
    }
    
#ifdef COFF_WITH_pex64
    print_hint_name_entries_64(file, abfd, data, datasize, idx, first_thunk, time_stamp, 
                               hint_addr, ft_data, ft_datasize, adj);
#else
    print_hint_name_entries_32(file, abfd, data, datasize, idx, first_thunk, time_stamp,
                               hint_addr, ft_data, ft_datasize, adj);
#endif
    
    if (ft_allocated)
        free(ft_data);
}

static void process_import_descriptor(FILE *file, bfd *abfd, bfd_byte *data, bfd_size_type datasize,
                                      bfd_size_type i, bfd_signed_vma adj, asection *section,
                                      struct internal_extra_pe_aouthdr *extra)
{
    #define IMPORT_DESCRIPTOR_SIZE 20
    bfd_vma hint_addr = bfd_get_32(abfd, data + i);
    bfd_vma time_stamp = bfd_get_32(abfd, data + i + 4);
    bfd_vma forward_chain = bfd_get_32(abfd, data + i + 8);
    bfd_vma dll_name = bfd_get_32(abfd, data + i + 12);
    bfd_vma first_thunk = bfd_get_32(abfd, data + i + 16);
    
    fprintf(file, " %08lx\t", (unsigned long)(i + adj));
    fprintf(file, "%08lx %08lx %08lx %08lx %08lx\n",
           (unsigned long)hint_addr, (unsigned long)time_stamp,
           (unsigned long)forward_chain, (unsigned long)dll_name,
           (unsigned long)first_thunk);
    
    if ((hint_addr == 0 && first_thunk == 0) || (dll_name - adj >= section->size))
        return;
    
    char *dll = (char *)data + dll_name - adj;
    bfd_size_type maxlen = (char *)(data + datasize) - dll - 1;
    fprintf(file, _("\n\tDLL Name: %.*s\n"), (int)maxlen, dll);
    
    if (hint_addr == 0)
        hint_addr = first_thunk;
    
    if (hint_addr != 0 && hint_addr - adj < datasize) {
        print_hint_name_vector(file, abfd, data, datasize, hint_addr, first_thunk,
                              time_stamp, extra, section, adj);
    }
    
    fprintf(file, "\n");
}

static bool pe_print_idata(bfd *abfd, void *vfile)
{
    #define IMPORT_DESCRIPTOR_SIZE 20
    FILE *file = (FILE *)vfile;
    bfd_byte *data;
    asection *section;
    bfd_signed_vma adj;
    bfd_size_type datasize = 0;
    bfd_size_type dataoff;
    bfd_size_type i;
    
    pe_data_type *pe = pe_data(abfd);
    struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
    bfd_vma addr = extra->DataDirectory[PE_IMPORT_TABLE].VirtualAddress;
    
    section = find_import_section(abfd, extra, &addr, &datasize);
    if (section == NULL)
        return true;
    
    if (!validate_import_section(section, file))
        return true;
    
    print_import_table_header(file, section, addr);
    dataoff = addr - section->vma;
    
    if (!bfd_malloc_and_get_section(abfd, section, &data)) {
        free(data);
        return false;
    }
    
    adj = section->vma - extra->ImageBase;
    
    for (i = dataoff; i + IMPORT_DESCRIPTOR_SIZE <= datasize; i += IMPORT_DESCRIPTOR_SIZE) {
        bfd_vma hint_addr = bfd_get_32(abfd, data + i);
        bfd_vma first_thunk = bfd_get_32(abfd, data + i + 16);
        
        if (hint_addr == 0 && first_thunk == 0)
            break;
        
        process_import_descriptor(file, abfd, data, datasize, i, adj, section, extra);
    }
    
    free(data);
    return true;
}

#define MIN_EXPORT_TABLE_SIZE 40
#define EXPORT_TABLE_HEADER_SIZE 40
#define EXPORT_ADDRESS_ENTRY_SIZE 4
#define NAME_POINTER_ENTRY_SIZE 4
#define ORDINAL_ENTRY_SIZE 2

static asection* find_export_section(bfd *abfd, bfd_vma *addr, bfd_size_type *dataoff, bfd_size_type *datasize)
{
    pe_data_type *pe = pe_data(abfd);
    struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
    asection *section;
    
    *addr = extra->DataDirectory[PE_EXPORT_TABLE].VirtualAddress;
    
    if (*addr == 0 && extra->DataDirectory[PE_EXPORT_TABLE].Size == 0) {
        section = bfd_get_section_by_name(abfd, ".edata");
        if (section == NULL)
            return NULL;
        
        *addr = section->vma;
        *dataoff = 0;
        *datasize = section->size;
        if (*datasize == 0)
            return NULL;
    } else {
        *addr += extra->ImageBase;
        
        for (section = abfd->sections; section != NULL; section = section->next)
            if (*addr >= section->vma && *addr < section->vma + section->size)
                break;
        
        if (section == NULL)
            return NULL;
        
        *dataoff = *addr - section->vma;
        *datasize = extra->DataDirectory[PE_EXPORT_TABLE].Size;
    }
    
    return section;
}

static void read_export_directory_table(bfd *abfd, bfd_byte *data, struct EDT_type *edt)
{
    edt->export_flags = bfd_get_32(abfd, data + 0);
    edt->time_stamp = bfd_get_32(abfd, data + 4);
    edt->major_ver = bfd_get_16(abfd, data + 8);
    edt->minor_ver = bfd_get_16(abfd, data + 10);
    edt->name = bfd_get_32(abfd, data + 12);
    edt->base = bfd_get_32(abfd, data + 16);
    edt->num_functions = bfd_get_32(abfd, data + 20);
    edt->num_names = bfd_get_32(abfd, data + 24);
    edt->eat_addr = bfd_get_32(abfd, data + 28);
    edt->npt_addr = bfd_get_32(abfd, data + 32);
    edt->ot_addr = bfd_get_32(abfd, data + 36);
}

static void print_export_directory_header(FILE *file, bfd *abfd, asection *section, struct EDT_type *edt, bfd_vma adj, bfd_byte *data, bfd_size_type datasize)
{
    fprintf(file, _("\nThe Export Tables (interpreted %s section contents)\n\n"), section->name);
    fprintf(file, _("Export Flags \t\t\t%lx\n"), (unsigned long) edt->export_flags);
    fprintf(file, _("Time/Date stamp \t\t%lx\n"), (unsigned long) edt->time_stamp);
    fprintf(file, _("Major/Minor \t\t\t%d/%d\n"), edt->major_ver, edt->minor_ver);
    fprintf(file, _("Name \t\t\t\t"));
    bfd_fprintf_vma(abfd, file, edt->name);
    
    if ((edt->name >= adj) && (edt->name < adj + datasize))
        fprintf(file, " %.*s\n", (int)(datasize - (edt->name - adj)), data + edt->name - adj);
    else
        fprintf(file, "(outside .edata section)\n");
    
    fprintf(file, _("Ordinal Base \t\t\t%ld\n"), edt->base);
    fprintf(file, _("Number in:\n"));
    fprintf(file, _("\tExport Address Table \t\t%08lx\n"), edt->num_functions);
    fprintf(file, _("\t[Name Pointer/Ordinal] Table\t%08lx\n"), edt->num_names);
    fprintf(file, _("Table Addresses\n"));
    fprintf(file, _("\tExport Address Table \t\t"));
    bfd_fprintf_vma(abfd, file, edt->eat_addr);
    fprintf(file, "\n");
    fprintf(file, _("\tName Pointer Table \t\t"));
    bfd_fprintf_vma(abfd, file, edt->npt_addr);
    fprintf(file, "\n");
    fprintf(file, _("\tOrdinal Table \t\t\t"));
    bfd_fprintf_vma(abfd, file, edt->ot_addr);
    fprintf(file, "\n");
}

static bool is_export_address_table_valid(struct EDT_type *edt, bfd_vma adj, bfd_size_type datasize)
{
    return !(edt->eat_addr - adj >= datasize ||
             (edt->num_functions + 1) * EXPORT_ADDRESS_ENTRY_SIZE < edt->num_functions ||
             edt->eat_addr - adj + (edt->num_functions + 1) * EXPORT_ADDRESS_ENTRY_SIZE > datasize);
}

static void print_single_export_address(FILE *file, bfd *abfd, bfd_byte *data, struct EDT_type *edt, bfd_vma adj, bfd_size_type datasize, bfd_size_type i)
{
    bfd_vma eat_member = bfd_get_32(abfd, data + edt->eat_addr + (i * EXPORT_ADDRESS_ENTRY_SIZE) - adj);
    
    if (eat_member == 0)
        return;
    
    if (eat_member - adj <= datasize) {
        fprintf(file, "\t[%4ld] +base[%4ld] %08lx %s -- %.*s\n",
                (long)i, (long)(i + edt->base), (unsigned long)eat_member,
                _("Forwarder RVA"),
                (int)(datasize - (eat_member - adj)),
                data + eat_member - adj);
    } else {
        fprintf(file, "\t[%4ld] +base[%4ld] %08lx %s\n",
                (long)i, (long)(i + edt->base), (unsigned long)eat_member,
                _("Export RVA"));
    }
}

static void print_export_address_table(FILE *file, bfd *abfd, bfd_byte *data, struct EDT_type *edt, bfd_vma adj, bfd_size_type datasize)
{
    bfd_size_type i;
    
    fprintf(file, _("\nExport Address Table -- Ordinal Base %ld\n"), edt->base);
    fprintf(file, "\t          Ordinal  Address  Type\n");
    
    if (!is_export_address_table_valid(edt, adj, datasize)) {
        fprintf(file, _("\tInvalid Export Address Table rva (0x%lx) or entry count (0x%lx)\n"),
                (long)edt->eat_addr, (long)edt->num_functions);
        return;
    }
    
    for (i = 0; i < edt->num_functions; ++i) {
        print_single_export_address(file, abfd, data, edt, adj, datasize, i);
    }
}

static bool is_name_pointer_table_valid(struct EDT_type *edt, bfd_vma adj, bfd_byte *data, bfd_size_type datasize)
{
    return !(edt->npt_addr + (edt->num_names * NAME_POINTER_ENTRY_SIZE) - adj >= datasize ||
             edt->num_names * NAME_POINTER_ENTRY_SIZE < edt->num_names ||
             (data + edt->npt_addr - adj) < data);
}

static bool is_ordinal_table_valid(struct EDT_type *edt, bfd_vma adj, bfd_byte *data, bfd_size_type datasize)
{
    return !(edt->ot_addr + (edt->num_names * ORDINAL_ENTRY_SIZE) - adj >= datasize ||
             data + edt->ot_addr - adj < data);
}

static void print_single_name_ordinal(FILE *file, bfd *abfd, bfd_byte *data, struct EDT_type *edt, bfd_vma adj, bfd_size_type datasize, bfd_size_type i)
{
    bfd_vma ord = bfd_get_16(abfd, data + edt->ot_addr + (i * ORDINAL_ENTRY_SIZE) - adj);
    bfd_vma name_ptr = bfd_get_32(abfd, data + edt->npt_addr + (i * NAME_POINTER_ENTRY_SIZE) - adj);
    
    if ((name_ptr - adj) >= datasize) {
        fprintf(file, _("\t[%4ld] +base[%4ld]  %04lx <corrupt offset: %lx>\n"),
                (long)ord, (long)(ord + edt->base), (long)i, (long)name_ptr);
    } else {
        char *name = (char *)data + name_ptr - adj;
        fprintf(file, "\t[%4ld] +base[%4ld]  %04lx %.*s\n",
                (long)ord, (long)(ord + edt->base), (long)i,
                (int)((char *)(data + datasize) - name), name);
    }
}

static void print_name_ordinal_table(FILE *file, bfd *abfd, bfd_byte *data, struct EDT_type *edt, bfd_vma adj, bfd_size_type datasize)
{
    bfd_size_type i;
    
    fprintf(file, _("\n[Ordinal/Name Pointer] Table -- Ordinal Base %ld\n"), edt->base);
    fprintf(file, "\t          Ordinal   Hint Name\n");
    
    if (!is_name_pointer_table_valid(edt, adj, data, datasize)) {
        fprintf(file, _("\tInvalid Name Pointer Table rva (0x%lx) or entry count (0x%lx)\n"),
                (long)edt->npt_addr, (long)edt->num_names);
        return;
    }
    
    if (!is_ordinal_table_valid(edt, adj, data, datasize)) {
        fprintf(file, _("\tInvalid Ordinal Table rva (0x%lx) or entry count (0x%lx)\n"),
                (long)edt->ot_addr, (long)edt->num_names);
        return;
    }
    
    for (i = 0; i < edt->num_names; ++i) {
        print_single_name_ordinal(file, abfd, data, edt, adj, datasize, i);
    }
}

static bool pe_print_edata(bfd *abfd, void *vfile)
{
    FILE *file = (FILE *)vfile;
    bfd_byte *data;
    asection *section;
    bfd_size_type datasize = 0;
    bfd_size_type dataoff;
    bfd_vma adj;
    struct EDT_type {
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
    
    section = find_export_section(abfd, &addr, &dataoff, &datasize);
    if (section == NULL) {
        if (extra->DataDirectory[PE_EXPORT_TABLE].VirtualAddress != 0) {
            fprintf(file, _("\nThere is an export table, but the section containing it could not be found\n"));
        }
        return true;
    }
    
    if (datasize < MIN_EXPORT_TABLE_SIZE) {
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
    
    read_export_directory_table(abfd, data, &edt);
    adj = section->vma - extra->ImageBase + dataoff;
    
    print_export_directory_header(file, abfd, section, &edt, adj, data, datasize);
    print_export_address_table(file, abfd, data, &edt, adj, datasize);
    print_name_ordinal_table(file, abfd, data, &edt, adj, datasize);
    
    free(data);
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

static bool is_pdata_section_valid(asection *section)
{
    return section != NULL
        && (section->flags & SEC_HAS_CONTENTS) != 0
        && coff_section_data (section->owner, section) != NULL
        && pei_section_data (section->owner, section) != NULL;
}

static void print_size_warning(FILE *file, bfd_size_type stop, int onaline)
{
    if ((stop % onaline) != 0)
        fprintf (file,
                 _("warning, .pdata section size (%ld) is not a multiple of %d\n"),
                 (long) stop, onaline);
}

static void print_pdata_header(FILE *file)
{
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
}

static bool validate_section_size(FILE *file, bfd_size_type datasize, bfd_size_type stop)
{
    if (datasize < stop)
    {
        fprintf (file, _("Virtual size of .pdata section (%ld) larger than real size (%ld)\n"),
                 (long) stop, (long) datasize);
        return false;
    }
    return true;
}

static bool is_padding_entry(bfd_vma begin_addr, bfd_vma end_addr, bfd_vma eh_handler,
                              bfd_vma eh_data, bfd_vma prolog_end_addr)
{
    return begin_addr == 0 && end_addr == 0 && eh_handler == 0
        && eh_data == 0 && prolog_end_addr == 0;
}

static void print_vma_with_separator(bfd *abfd, FILE *file, bfd_vma value, char separator)
{
    bfd_fprintf_vma (abfd, file, value);
    fputc (separator, file);
}

static void print_pdata_entry_common(bfd *abfd, FILE *file, bfd_size_type i, 
                                      asection *section, bfd_vma begin_addr, 
                                      bfd_vma end_addr, bfd_vma eh_handler)
{
    fputc (' ', file);
    print_vma_with_separator(abfd, file, i + section->vma, '\t');
    print_vma_with_separator(abfd, file, begin_addr, ' ');
    print_vma_with_separator(abfd, file, end_addr, ' ');
    bfd_fprintf_vma (abfd, file, eh_handler);
}

static void print_pdata_entry_extended(bfd *abfd, FILE *file, bfd_vma eh_data,
                                        bfd_vma prolog_end_addr, int em_data)
{
#if !defined(COFF_WITH_pep) || defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined (COFF_WITH_peRiscV64)
    fputc (' ', file);
    print_vma_with_separator(abfd, file, eh_data, ' ');
    bfd_fprintf_vma (abfd, file, prolog_end_addr);
    fprintf (file, "   %x", em_data);
#endif
}

static void process_pdata_entry(bfd *abfd, FILE *file, bfd_byte *data,
                                 bfd_size_type i, asection *section)
{
    bfd_vma begin_addr = GET_PDATA_ENTRY (abfd, data + i);
    bfd_vma end_addr = GET_PDATA_ENTRY (abfd, data + i + 4);
    bfd_vma eh_handler = GET_PDATA_ENTRY (abfd, data + i + 8);
    bfd_vma eh_data = GET_PDATA_ENTRY (abfd, data + i + 12);
    bfd_vma prolog_end_addr = GET_PDATA_ENTRY (abfd, data + i + 16);
    
#if !defined(COFF_WITH_pep) || defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined (COFF_WITH_peRiscV64)
    int em_data = ((eh_handler & 0x1) << 2) | (prolog_end_addr & 0x3);
#else
    int em_data = 0;
#endif
    
    eh_handler &= ~(bfd_vma) 0x3;
    prolog_end_addr &= ~(bfd_vma) 0x3;
    
    print_pdata_entry_common(abfd, file, i, section, begin_addr, end_addr, eh_handler);
    print_pdata_entry_extended(abfd, file, eh_data, prolog_end_addr, em_data);
    fprintf (file, "\n");
}

static bool
pe_print_pdata (bfd * abfd, void * vfile)
{
#if defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined (COFF_WITH_peRiscV64)
#define PDATA_ROW_SIZE (3 * 8)
#else
#define PDATA_ROW_SIZE (5 * 4)
#endif
    FILE *file = (FILE *) vfile;
    bfd_byte *data = 0;
    asection *section = bfd_get_section_by_name (abfd, ".pdata");
    bfd_size_type datasize = 0;
    bfd_size_type i;
    bfd_size_type start, stop;
    int onaline = PDATA_ROW_SIZE;
    
    if (!is_pdata_section_valid(section))
        return true;
    
    stop = pei_section_data (abfd, section)->virt_size;
    print_size_warning(file, stop, onaline);
    print_pdata_header(file);
    
    datasize = section->size;
    if (datasize == 0)
        return true;
    
    if (!validate_section_size(file, datasize, stop))
        return false;
    
    if (!bfd_malloc_and_get_section (abfd, section, &data))
    {
        free (data);
        return false;
    }
    
    start = 0;
    
    for (i = start; i < stop; i += onaline)
    {
        if (i + PDATA_ROW_SIZE > stop)
            break;
        
        bfd_vma begin_addr = GET_PDATA_ENTRY (abfd, data + i);
        bfd_vma end_addr = GET_PDATA_ENTRY (abfd, data + i + 4);
        bfd_vma eh_handler = GET_PDATA_ENTRY (abfd, data + i + 8);
        bfd_vma eh_data = GET_PDATA_ENTRY (abfd, data + i + 12);
        bfd_vma prolog_end_addr = GET_PDATA_ENTRY (abfd, data + i + 16);
        
        if (is_padding_entry(begin_addr, end_addr, eh_handler, eh_data, prolog_end_addr))
            break;
        
        process_pdata_entry(abfd, file, data, i, section);
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
  if (!(bfd_get_file_flags (abfd) & HAS_SYMS))
    {
      psc->symcount = 0;
      return NULL;
    }

  long storage = bfd_get_symtab_upper_bound (abfd);
  if (storage < 0)
    return NULL;
  
  if (storage == 0)
    return NULL;

  asymbol **sy = (asymbol **) bfd_malloc (storage);
  if (sy == NULL)
    return NULL;

  psc->symcount = bfd_canonicalize_symtab (abfd, sy);
  if (psc->symcount < 0)
    return NULL;
    
  return sy;
}

static const char *
my_symbol_for_address (bfd *abfd, bfd_vma func, sym_cache *psc)
{
  if (psc->syms == 0)
    psc->syms = slurp_symtab (abfd, psc);

  return find_symbol_by_address(psc, func);
}

static const char *
find_symbol_by_address(sym_cache *psc, bfd_vma func)
{
  int i;
  
  for (i = 0; i < psc->symcount; i++)
    {
      if (get_symbol_address(psc->syms[i]) == func)
        return psc->syms[i]->name;
    }
  
  return NULL;
}

static bfd_vma
get_symbol_address(asymbol *sym)
{
  return sym->section->vma + sym->value;
}

static void cleanup_syms(sym_cache *psc)
{
    psc->symcount = 0;
    free(psc->syms);
    psc->syms = NULL;
}

/* This is the version for "compressed" pdata.  */

#define PDATA_ROW_SIZE (2 * 4)
#define PROLOG_LENGTH_MASK 0x000000FF
#define FUNCTION_LENGTH_MASK 0x3FFFFF00
#define FUNCTION_LENGTH_SHIFT 8
#define FLAG32BIT_MASK 0x40000000
#define FLAG32BIT_SHIFT 30
#define EXCEPTION_FLAG_MASK 0x80000000
#define EXCEPTION_FLAG_SHIFT 31
#define EH_DATA_SIZE 8
#define EH_OFFSET_ADJUSTMENT 8

static bool validate_pdata_section(bfd *abfd, asection *section)
{
    return section != NULL
        && (section->flags & SEC_HAS_CONTENTS) != 0
        && coff_section_data(abfd, section) != NULL
        && pei_section_data(abfd, section) != NULL;
}

static void print_pdata_header(FILE *file)
{
    fprintf(file, _("\nThe Function Table (interpreted .pdata section contents)\n"));
    fprintf(file, _("\
 vma:\t\tBegin    Prolog   Function Flags    Exception EH\n\
     \t\tAddress  Length   Length   32b exc  Handler   Data\n"));
}

static void print_size_warning(FILE *file, bfd_size_type size, int expected_multiple)
{
    if ((size % expected_multiple) != 0)
        fprintf(file,
                _("warning, .pdata section size (%ld) is not a multiple of %d\n"),
                (long)size, expected_multiple);
}

static void print_pdata_values(bfd *abfd, FILE *file, bfd_vma offset, 
                               bfd_vma begin_addr, bfd_vma prolog_length,
                               bfd_vma function_length, int flag32bit, int exception_flag)
{
    fputc(' ', file);
    bfd_fprintf_vma(abfd, file, offset);
    fputc('\t', file);
    bfd_fprintf_vma(abfd, file, begin_addr);
    fputc(' ', file);
    bfd_fprintf_vma(abfd, file, prolog_length);
    fputc(' ', file);
    bfd_fprintf_vma(abfd, file, function_length);
    fputc(' ', file);
    fprintf(file, "%2d  %2d   ", flag32bit, exception_flag);
}

static void extract_pdata_fields(bfd_vma other_data, bfd_vma *prolog_length,
                                 bfd_vma *function_length, int *flag32bit, int *exception_flag)
{
    *prolog_length = other_data & PROLOG_LENGTH_MASK;
    *function_length = (other_data & FUNCTION_LENGTH_MASK) >> FUNCTION_LENGTH_SHIFT;
    *flag32bit = (int)((other_data & FLAG32BIT_MASK) >> FLAG32BIT_SHIFT);
    *exception_flag = (int)((other_data & EXCEPTION_FLAG_MASK) >> EXCEPTION_FLAG_SHIFT);
}

static void process_exception_handler(bfd *abfd, FILE *file, bfd_vma begin_addr,
                                     struct sym_cache *cache)
{
    asection *tsection = bfd_get_section_by_name(abfd, ".text");
    
    if (!tsection || !coff_section_data(abfd, tsection) || 
        !pei_section_data(abfd, tsection))
        return;
    
    bfd_vma eh_off = (begin_addr - EH_OFFSET_ADJUSTMENT) - tsection->vma;
    bfd_byte *tdata = (bfd_byte *)bfd_malloc(EH_DATA_SIZE);
    
    if (!tdata)
        return;
    
    if (bfd_get_section_contents(abfd, tsection, tdata, eh_off, EH_DATA_SIZE))
    {
        bfd_vma eh = bfd_get_32(abfd, tdata);
        bfd_vma eh_data = bfd_get_32(abfd, tdata + 4);
        fprintf(file, "%08x  ", (unsigned int)eh);
        fprintf(file, "%08x", (unsigned int)eh_data);
        
        if (eh != 0)
        {
            const char *s = my_symbol_for_address(abfd, eh, cache);
            if (s)
                fprintf(file, " (%s) ", s);
        }
    }
    
    free(tdata);
}

static bool process_pdata_entry(bfd *abfd, FILE *file, bfd_byte *data,
                                bfd_size_type offset, asection *section,
                                struct sym_cache *cache)
{
    bfd_vma begin_addr = GET_PDATA_ENTRY(abfd, data + offset);
    bfd_vma other_data = GET_PDATA_ENTRY(abfd, data + offset + 4);
    
    if (begin_addr == 0 && other_data == 0)
        return false;
    
    bfd_vma prolog_length, function_length;
    int flag32bit, exception_flag;
    extract_pdata_fields(other_data, &prolog_length, &function_length,
                        &flag32bit, &exception_flag);
    
    print_pdata_values(abfd, file, offset + section->vma, begin_addr,
                      prolog_length, function_length, flag32bit, exception_flag);
    
    process_exception_handler(abfd, file, begin_addr, cache);
    
    fprintf(file, "\n");
    return true;
}

bool _bfd_XX_print_ce_compressed_pdata(bfd *abfd, void *vfile)
{
    FILE *file = (FILE *)vfile;
    asection *section = bfd_get_section_by_name(abfd, ".pdata");
    struct sym_cache cache = {0, 0};
    
    if (!validate_pdata_section(abfd, section))
        return true;
    
    bfd_size_type stop = pei_section_data(abfd, section)->virt_size;
    print_size_warning(file, stop, PDATA_ROW_SIZE);
    print_pdata_header(file);
    
    bfd_size_type datasize = section->size;
    if (datasize == 0)
        return true;
    
    bfd_byte *data = NULL;
    if (!bfd_malloc_and_get_section(abfd, section, &data))
    {
        free(data);
        return false;
    }
    
    if (stop > datasize)
        stop = datasize;
    
    for (bfd_size_type i = 0; i < stop; i += PDATA_ROW_SIZE)
    {
        if (i + PDATA_ROW_SIZE > stop)
            break;
        
        if (!process_pdata_entry(abfd, file, data, i, section, &cache))
            break;
    }
    
    free(data);
    cleanup_syms(&cache);
    
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
validate_reloc_section(asection *section)
{
    return section != NULL 
        && section->size > 0 
        && (section->flags & SEC_HAS_CONTENTS) != 0;
}

static bool
load_reloc_data(bfd *abfd, asection *section, bfd_byte **data)
{
    if (!bfd_malloc_and_get_section(abfd, section, data))
    {
        free(*data);
        return false;
    }
    return true;
}

static void
print_reloc_header(FILE *file)
{
    fprintf(file, _("\n\nPE File Base Relocations (interpreted .reloc section contents)\n"));
}

static void
print_virtual_address_info(FILE *file, bfd_vma virtual_address, unsigned long size, unsigned long number)
{
    fprintf(file,
            _("\nVirtual Address: %08lx Chunk size %ld (0x%lx) Number of fixups %ld\n"),
            (unsigned long)virtual_address, size, size, number);
}

static unsigned int
get_reloc_type_index(unsigned short entry)
{
    const int TYPE_SHIFT = 12;
    const unsigned int TYPE_MASK = 0xF000;
    unsigned int t = (entry & TYPE_MASK) >> TYPE_SHIFT;
    unsigned int max_index = sizeof(tbl) / sizeof(tbl[0]);
    
    if (t >= max_index)
        t = max_index - 1;
    
    return t;
}

static void
print_reloc_entry(FILE *file, int j, int off, bfd_vma virtual_address, unsigned int type_index)
{
    fprintf(file,
            _("\treloc %4d offset %4x [%4lx] %s"),
            j, off, (unsigned long)(off + virtual_address), tbl[type_index]);
}

static bfd_byte*
process_highadj_reloc(FILE *file, bfd *abfd, bfd_byte *p, bfd_byte *chunk_end, int *j)
{
    const int ENTRY_SIZE = 2;
    
    if (p + ENTRY_SIZE <= chunk_end)
    {
        fprintf(file, " (%4x)", (unsigned int)bfd_get_16(abfd, p));
        p += ENTRY_SIZE;
        (*j)++;
    }
    return p;
}

static bfd_byte*
process_reloc_entry(FILE *file, bfd *abfd, bfd_byte *p, bfd_byte *chunk_end, 
                    bfd_vma virtual_address, int *j)
{
    const int ENTRY_SIZE = 2;
    const unsigned int OFFSET_MASK = 0x0FFF;
    
    unsigned short entry = bfd_get_16(abfd, p);
    unsigned int type_index = get_reloc_type_index(entry);
    int off = entry & OFFSET_MASK;
    
    print_reloc_entry(file, *j, off, virtual_address, type_index);
    
    p += ENTRY_SIZE;
    (*j)++;
    
    if (type_index == IMAGE_REL_BASED_HIGHADJ)
    {
        p = process_highadj_reloc(file, abfd, p, chunk_end, j);
    }
    
    fprintf(file, "\n");
    return p;
}

static void
process_reloc_chunk(FILE *file, bfd *abfd, bfd_byte *p, bfd_byte *chunk_end, bfd_vma virtual_address)
{
    const int ENTRY_SIZE = 2;
    int j = 0;
    
    while (p + ENTRY_SIZE <= chunk_end)
    {
        p = process_reloc_entry(file, abfd, p, chunk_end, virtual_address, &j);
    }
}

static bool
process_reloc_blocks(FILE *file, bfd *abfd, bfd_byte *data, size_t size)
{
    const int HEADER_SIZE = 8;
    const int VA_OFFSET = 0;
    const int SIZE_OFFSET = 4;
    
    bfd_byte *p = data;
    bfd_byte *end = data + size;
    
    while (p + HEADER_SIZE <= end)
    {
        bfd_vma virtual_address = bfd_get_32(abfd, p + VA_OFFSET);
        unsigned long block_size = bfd_get_32(abfd, p + SIZE_OFFSET);
        
        if (block_size == 0)
            break;
        
        unsigned long number = (block_size - HEADER_SIZE) / 2;
        print_virtual_address_info(file, virtual_address, block_size, number);
        
        p += HEADER_SIZE;
        bfd_byte *chunk_end = p - HEADER_SIZE + block_size;
        if (chunk_end > end)
            chunk_end = end;
        
        process_reloc_chunk(file, abfd, p, chunk_end, virtual_address);
        p = chunk_end;
    }
    
    return true;
}

static bool
pe_print_reloc(bfd *abfd, void *vfile)
{
    FILE *file = (FILE *)vfile;
    bfd_byte *data = NULL;
    asection *section = bfd_get_section_by_name(abfd, ".reloc");
    
    if (!validate_reloc_section(section))
        return true;
    
    print_reloc_header(file);
    
    if (!load_reloc_data(abfd, section, &data))
        return false;
    
    process_reloc_blocks(file, abfd, data, section->size);
    
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

static bool is_data_valid(bfd_byte *data, rsrc_regions *regions, size_t required_size)
{
  return data >= regions->section_start && 
         data + required_size <= regions->section_end;
}

static bfd_byte *get_name_pointer(unsigned long entry, rsrc_regions *regions, bfd_vma rva_bias)
{
  if (HighBitSet(entry))
    return regions->section_start + WithoutHighBit(entry);
  return regions->section_start + entry - rva_bias;
}

static void print_entry_header(FILE *file, bfd_byte *data, rsrc_regions *regions, unsigned int indent)
{
  fprintf(file, _("%03x %*.s Entry: "), (int)(data - regions->section_start), indent, " ");
}

static void print_character(FILE *file, char c)
{
  if (c > 0 && c < 32)
    fprintf(file, "^%c", c + 64);
  else
    fprintf(file, "%.1s", &c);
}

static bfd_byte *print_name_entry(FILE *file, bfd *abfd, unsigned long entry, 
                                   rsrc_regions *regions, bfd_vma rva_bias)
{
  bfd_byte *name = get_name_pointer(entry, regions, rva_bias);
  
  if (!is_data_valid(name, regions, 2))
  {
    fprintf(file, _("<corrupt string offset: %#lx>\n"), entry);
    return regions->section_end + 1;
  }
  
  if (regions->strings_start == NULL)
    regions->strings_start = name;
  
  unsigned int len = bfd_get_16(abfd, name);
  fprintf(file, _("name: [val: %08lx len %d]: "), entry, len);
  
  if (!is_data_valid(name + 2, regions, len * 2))
  {
    fprintf(file, _("<corrupt string length: %#x>\n"), len);
    return regions->section_end + 1;
  }
  
  while (len--)
  {
    name += 2;
    print_character(file, *name);
  }
  
  return NULL;
}

static bfd_byte *print_leaf_entry(FILE *file, bfd *abfd, bfd_byte *leaf, 
                                   unsigned long entry, unsigned int indent,
                                   rsrc_regions *regions, bfd_vma rva_bias)
{
  if (!is_data_valid(leaf, regions, 16))
    return regions->section_end + 1;
  
  unsigned long addr = bfd_get_32(abfd, leaf);
  unsigned long size = bfd_get_32(abfd, leaf + 4);
  int codepage = bfd_get_32(abfd, leaf + 8);
  
  fprintf(file, _("%03x %*.s  Leaf: Addr: %#08lx, Size: %#08lx, Codepage: %d\n"),
          (int)entry, indent, " ", addr, size, codepage);
  
  if (bfd_get_32(abfd, leaf + 12) != 0)
    return regions->section_end + 1;
  
  bfd_byte *resource_data = regions->section_start + (addr - rva_bias);
  
  if (!is_data_valid(resource_data, regions, size))
    return regions->section_end + 1;
  
  if (regions->resource_start == NULL)
    regions->resource_start = resource_data;
  
  return resource_data + size;
}

static bfd_byte *
rsrc_print_resource_entries(FILE *file, bfd *abfd, unsigned int indent,
                            bool is_name, bfd_byte *data,
                            rsrc_regions *regions, bfd_vma rva_bias)
{
  if (!is_data_valid(data, regions, 8))
    return regions->section_end + 1;
  
  print_entry_header(file, data, regions, indent);
  
  unsigned long entry = bfd_get_32(abfd, data);
  
  if (is_name)
  {
    bfd_byte *result = print_name_entry(file, abfd, entry, regions, rva_bias);
    if (result != NULL)
      return result;
  }
  else
  {
    fprintf(file, _("ID: %#08lx"), entry);
  }
  
  entry = bfd_get_32(abfd, data + 4);
  fprintf(file, _(", Value: %#08lx\n"), entry);
  
  if (HighBitSet(entry))
  {
    bfd_byte *dir_data = regions->section_start + WithoutHighBit(entry);
    if (!is_data_valid(dir_data, regions, 0))
      return regions->section_end + 1;
    
    return rsrc_print_resource_directory(file, abfd, indent + 1, dir_data,
                                          regions, rva_bias);
  }
  
  bfd_byte *leaf = regions->section_start + entry;
  return print_leaf_entry(file, abfd, leaf, entry, indent, regions, rva_bias);
}

#define max(a,b) ((a) > (b) ? (a) : (b))
#define min(a,b) ((a) < (b) ? (a) : (b))

static const char* get_directory_type_name(unsigned int indent)
{
  switch (indent)
    {
    case 0: return "Type";
    case 2: return "Name";
    case 4: return "Language";
    default: return NULL;
    }
}

static void print_directory_header(FILE *file, bfd_byte *data, rsrc_regions *regions, unsigned int indent)
{
  fprintf(file, "%03x %*.s ", (int)(data - regions->section_start), indent, " ");
  
  const char* type_name = get_directory_type_name(indent);
  if (type_name)
    fprintf(file, "%s", type_name);
  else
    fprintf(file, _("<unknown directory type: %d>\n"), indent);
}

static void print_directory_table(FILE *file, bfd *abfd, bfd_byte *data, unsigned int num_names, unsigned int num_ids)
{
  fprintf(file, _(" Table: Char: %d, Time: %08lx, Ver: %d/%d, Num Names: %d, IDs: %d\n"),
         (int) bfd_get_32(abfd, data),
         (long) bfd_get_32(abfd, data + 4),
         (int) bfd_get_16(abfd, data + 8),
         (int) bfd_get_16(abfd, data + 10),
         num_names,
         num_ids);
}

static bfd_byte* process_resource_entries(FILE *file, bfd *abfd, unsigned int indent,
                                         bfd_byte *data, rsrc_regions *regions,
                                         bfd_vma rva_bias, unsigned int count,
                                         bool is_named, bfd_byte *highest_data)
{
  while (count--)
    {
      bfd_byte *entry_end = rsrc_print_resource_entries(file, abfd, indent + 1, is_named,
                                                       data, regions, rva_bias);
      data += 8;
      highest_data = max(highest_data, entry_end);
      if (entry_end >= regions->section_end)
        return entry_end;
    }
  return highest_data;
}

static bfd_byte *
rsrc_print_resource_directory(FILE *file,
                            bfd *abfd,
                            unsigned int indent,
                            bfd_byte *data,
                            rsrc_regions *regions,
                            bfd_vma rva_bias)
{
  const unsigned int DIRECTORY_HEADER_SIZE = 16;
  unsigned int num_names, num_ids;
  bfd_byte *highest_data = data;

  if (data + DIRECTORY_HEADER_SIZE >= regions->section_end)
    return regions->section_end + 1;

  print_directory_header(file, data, regions, indent);
  
  if (!get_directory_type_name(indent))
    return regions->section_end + 1;

  num_names = (int) bfd_get_16(abfd, data + 12);
  num_ids = (int) bfd_get_16(abfd, data + 14);
  
  print_directory_table(file, abfd, data, num_names, num_ids);
  data += DIRECTORY_HEADER_SIZE;

  highest_data = process_resource_entries(file, abfd, indent, data, regions, rva_bias,
                                         num_names, true, highest_data);
  if (highest_data >= regions->section_end)
    return highest_data;
  data += num_names * 8;

  highest_data = process_resource_entries(file, abfd, indent, data, regions, rva_bias,
                                         num_ids, false, highest_data);
  if (highest_data >= regions->section_end)
    return highest_data;
  data += num_ids * 8;

  return max(highest_data, data);
}

/* Display the contents of a .rsrc section.  We do not try to
   reproduce the resources, windres does that.  Instead we dump
   the tables in a human readable format.  */

static bool validate_pe_and_section(bfd *abfd, pe_data_type **pe, asection **section)
{
    *pe = pe_data(abfd);
    if (*pe == NULL)
        return false;

    *section = bfd_get_section_by_name(abfd, ".rsrc");
    if (*section == NULL)
        return false;

    if (!((*section)->flags & SEC_HAS_CONTENTS))
        return false;

    if ((*section)->size == 0)
        return false;

    return true;
}

static bool load_section_data(bfd *abfd, asection *section, bfd_byte **data)
{
    if (!bfd_malloc_and_get_section(abfd, section, data))
    {
        free(*data);
        return false;
    }
    return true;
}

static void init_regions(rsrc_regions *regions, bfd_byte *data, bfd_size_type datasize)
{
    regions->section_start = data;
    regions->section_end = data + datasize;
    regions->strings_start = NULL;
    regions->resource_start = NULL;
}

static bfd_byte* align_data(bfd_byte *data, asection *section, bfd_byte *p, bfd_vma *rva_bias)
{
    int align = (1 << section->alignment_power) - 1;
    bfd_byte *aligned = (bfd_byte *)(((ptrdiff_t)(data + align)) & ~align);
    *rva_bias += aligned - p;
    return aligned;
}

#define ALIGNMENT_BOUNDARY_OFFSET 4

static bool is_alignment_boundary_case(bfd_byte *data, bfd_byte *section_end)
{
    return data == (section_end - ALIGNMENT_BOUNDARY_OFFSET);
}

static bool has_non_zero_padding(bfd_byte *data, bfd_byte *section_end)
{
    while (++data < section_end)
        if (*data != 0)
            return true;
    return false;
}

static void handle_extra_data(FILE *file, bfd_byte **data, rsrc_regions *regions)
{
    if (is_alignment_boundary_case(*data, regions->section_end))
    {
        *data = regions->section_end;
        return;
    }

    if (*data < regions->section_end)
    {
        bfd_byte *check_ptr = *data;
        if (has_non_zero_padding(check_ptr, regions->section_end))
            fprintf(file, _("\nWARNING: Extra data in .rsrc section - it will be ignored by Windows:\n"));
        *data = regions->section_end;
    }
}

static void process_resource_directory(FILE *file, bfd *abfd, bfd_byte **data, 
                                      rsrc_regions *regions, bfd_vma *rva_bias, asection *section)
{
    bfd_byte *p = *data;
    *data = rsrc_print_resource_directory(file, abfd, 0, *data, regions, *rva_bias);

    if (*data == regions->section_end + 1)
    {
        fprintf(file, _("Corrupt .rsrc section detected!\n"));
        return;
    }

    *data = align_data(*data, section, p, rva_bias);
    handle_extra_data(file, data, regions);
}

static void print_offsets(FILE *file, rsrc_regions *regions)
{
    if (regions->strings_start != NULL)
        fprintf(file, _(" String table starts at offset: %#03x\n"),
                (int)(regions->strings_start - regions->section_start));
    
    if (regions->resource_start != NULL)
        fprintf(file, _(" Resources start at offset: %#03x\n"),
                (int)(regions->resource_start - regions->section_start));
}

static bool rsrc_print_section(bfd *abfd, void *vfile)
{
    FILE *file = (FILE *)vfile;
    pe_data_type *pe;
    asection *section;
    bfd_byte *data;
    rsrc_regions regions;

    if (!validate_pe_and_section(abfd, &pe, &section))
        return true;

    if (!load_section_data(abfd, section, &data))
        return false;

    bfd_size_type datasize = section->size;
    init_regions(&regions, data, datasize);
    
    bfd_vma rva_bias = section->vma - pe->pe_opthdr.ImageBase;

    fflush(file);
    fprintf(file, "\nThe .rsrc Resource Directory section:\n");

    while (data < regions.section_end)
        process_resource_directory(file, abfd, &data, &regions, &rva_bias, section);

    print_offsets(file, &regions);
    free(regions.section_start);
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

static asection* find_debug_section(bfd *abfd, bfd_vma addr)
{
  asection *section;
  for (section = abfd->sections; section != NULL; section = section->next)
    {
      if ((addr >= section->vma) && (addr < (section->vma + section->size)))
        return section;
    }
  return NULL;
}

static bool validate_debug_section(FILE *file, asection *section, bfd_size_type size)
{
  if (section == NULL)
    {
      fprintf(file, _("\nThere is a debug directory, but the section containing it could not be found\n"));
      return false;
    }
  
  if (!(section->flags & SEC_HAS_CONTENTS))
    {
      fprintf(file, _("\nThere is a debug directory in %s, but that section has no contents\n"), 
              section->name);
      return false;
    }
  
  if (section->size < size)
    {
      fprintf(file, _("\nError: section %s contains the debug data starting address but it is too small\n"), 
              section->name);
      return false;
    }
  
  return true;
}

static const char* get_debug_type_name(unsigned long type)
{
  if (type >= IMAGE_NUMBEROF_DEBUG_TYPES)
    return debug_type_names[0];
  return debug_type_names[type];
}

static void print_codeview_info(bfd *abfd, FILE *file, struct internal_IMAGE_DEBUG_DIRECTORY *idd)
{
  #define SIGNATURE_BUFFER_SIZE (CV_INFO_SIGNATURE_LENGTH * 2 + 1)
  #define PDB_BUFFER_SIZE (256 + 1)
  
  char signature[SIGNATURE_BUFFER_SIZE];
  char buffer[PDB_BUFFER_SIZE] ATTRIBUTE_ALIGNED_ALIGNOF(CODEVIEW_INFO);
  char *pdb;
  CODEVIEW_INFO *cvinfo = (CODEVIEW_INFO *) buffer;
  unsigned int j;
  
  if (!_bfd_XXi_slurp_codeview_record(abfd, (file_ptr) idd->PointerToRawData,
                                       idd->SizeOfData, cvinfo, &pdb))
    return;
  
  for (j = 0; j < cvinfo->SignatureLength; j++)
    sprintf(&signature[j * 2], "%02x", cvinfo->Signature[j] & 0xff);
  
  fprintf(file, _("(format %c%c%c%c signature %s age %ld pdb %s)\n"),
          buffer[0], buffer[1], buffer[2], buffer[3],
          signature, cvinfo->Age, pdb[0] ? pdb : "(none)");
  
  free(pdb);
}

static void print_debug_entry(bfd *abfd, FILE *file, bfd_byte *data, bfd_size_type dataoff, unsigned int index)
{
  struct external_IMAGE_DEBUG_DIRECTORY *ext = 
    &((struct external_IMAGE_DEBUG_DIRECTORY *)(data + dataoff))[index];
  struct internal_IMAGE_DEBUG_DIRECTORY idd;
  
  _bfd_XXi_swap_debugdir_in(abfd, ext, &idd);
  
  fprintf(file, " %2ld  %14s %08lx %08lx %08lx\n",
          idd.Type, get_debug_type_name(idd.Type), idd.SizeOfData,
          idd.AddressOfRawData, idd.PointerToRawData);
  
  if (idd.Type == PE_IMAGE_DEBUG_TYPE_CODEVIEW)
    print_codeview_info(abfd, file, &idd);
}

static bool pe_print_debugdata(bfd *abfd, void *vfile)
{
  FILE *file = (FILE *) vfile;
  pe_data_type *pe = pe_data(abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
  asection *section;
  bfd_byte *data = 0;
  bfd_size_type dataoff;
  unsigned int i;
  
  bfd_vma addr = extra->DataDirectory[PE_DEBUG_DATA].VirtualAddress;
  bfd_size_type size = extra->DataDirectory[PE_DEBUG_DATA].Size;
  
  if (size == 0)
    return true;
  
  addr += extra->ImageBase;
  section = find_debug_section(abfd, addr);
  
  if (!validate_debug_section(file, section, size))
    return section == NULL ? true : false;
  
  fprintf(file, _("\nThere is a debug directory in %s at 0x%lx\n\n"),
          section->name, (unsigned long) addr);
  
  dataoff = addr - section->vma;
  
  if (size > (section->size - dataoff))
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
  
  for (i = 0; i < size / sizeof(struct external_IMAGE_DEBUG_DIRECTORY); i++)
    print_debug_entry(abfd, file, data, dataoff, i);
  
  free(data);
  
  if (size % sizeof(struct external_IMAGE_DEBUG_DIRECTORY) != 0)
    fprintf(file, _("The debug directory size is not a multiple of the debug directory entry size\n"));
  
  return true;
}

static asection *
find_section_containing_address(bfd *abfd, bfd_vma addr)
{
  asection *section;
  for (section = abfd->sections; section != NULL; section = section->next)
    {
      if ((addr >= section->vma) && (addr < (section->vma + section->size)))
        return section;
    }
  return NULL;
}

static bool
is_valid_debug_section(asection *section, bfd_size_type size, bfd_size_type dataoff)
{
  if (section == NULL)
    return false;
  if (!(section->flags & SEC_HAS_CONTENTS))
    return false;
  if (section->size < size)
    return false;
  if (size > (section->size - dataoff))
    return false;
  return true;
}

static bool
has_repro_debug_entry(bfd *abfd, bfd_byte *data, bfd_size_type dataoff, bfd_size_type size)
{
  unsigned int count = size / sizeof(struct external_IMAGE_DEBUG_DIRECTORY);
  unsigned int i;
  
  for (i = 0; i < count; i++)
    {
      struct external_IMAGE_DEBUG_DIRECTORY *ext
        = &((struct external_IMAGE_DEBUG_DIRECTORY *)(data + dataoff))[i];
      struct internal_IMAGE_DEBUG_DIRECTORY idd;

      _bfd_XXi_swap_debugdir_in(abfd, ext, &idd);

      if (idd.Type == PE_IMAGE_DEBUG_TYPE_REPRO)
        return true;
    }
  return false;
}

static bool
pe_is_repro(bfd *abfd)
{
  pe_data_type *pe = pe_data(abfd);
  struct internal_extra_pe_aouthdr *extra = &pe->pe_opthdr;
  asection *section;
  bfd_byte *data = NULL;
  bfd_size_type dataoff;
  bool res = false;

  bfd_vma addr = extra->DataDirectory[PE_DEBUG_DATA].VirtualAddress;
  bfd_size_type size = extra->DataDirectory[PE_DEBUG_DATA].Size;

  if (size == 0)
    return false;

  addr += extra->ImageBase;
  section = find_section_containing_address(abfd, addr);
  
  dataoff = addr - section->vma;
  
  if (!is_valid_debug_section(section, size, dataoff))
    return false;

  if (!bfd_malloc_and_get_section(abfd, section, &data))
    {
      free(data);
      return false;
    }

  res = has_repro_debug_entry(abfd, data, dataoff, size);
  
  free(data);
  return res;
}

/* Print out the program headers.  */

#ifndef IMAGE_NT_OPTIONAL_HDR_MAGIC
#define IMAGE_NT_OPTIONAL_HDR_MAGIC 0x10b
#endif
#ifndef IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#endif
#ifndef IMAGE_NT_OPTIONAL_HDRROM_MAGIC
#define IMAGE_NT_OPTIONAL_HDRROM_MAGIC 0x107
#endif

#define DLL_CHAR_INDENT "\t\t\t\t\t"

static void print_flag_if_set(FILE *file, unsigned int flags, unsigned int flag, const char *description)
{
    if (flags & flag)
        fprintf(file, "\t%s\n", description);
}

static void print_characteristics(FILE *file, unsigned int real_flags)
{
    fprintf(file, _("\nCharacteristics 0x%x\n"), real_flags);
    print_flag_if_set(file, real_flags, IMAGE_FILE_RELOCS_STRIPPED, "relocations stripped");
    print_flag_if_set(file, real_flags, IMAGE_FILE_EXECUTABLE_IMAGE, "executable");
    print_flag_if_set(file, real_flags, IMAGE_FILE_LINE_NUMS_STRIPPED, "line numbers stripped");
    print_flag_if_set(file, real_flags, IMAGE_FILE_LOCAL_SYMS_STRIPPED, "symbols stripped");
    print_flag_if_set(file, real_flags, IMAGE_FILE_LARGE_ADDRESS_AWARE, "large address aware");
    print_flag_if_set(file, real_flags, IMAGE_FILE_BYTES_REVERSED_LO, "little endian");
    print_flag_if_set(file, real_flags, IMAGE_FILE_32BIT_MACHINE, "32 bit words");
    print_flag_if_set(file, real_flags, IMAGE_FILE_DEBUG_STRIPPED, "debugging information removed");
    print_flag_if_set(file, real_flags, IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "copy to swap file if on removable media");
    print_flag_if_set(file, real_flags, IMAGE_FILE_NET_RUN_FROM_SWAP, "copy to swap file if on network media");
    print_flag_if_set(file, real_flags, IMAGE_FILE_SYSTEM, "system file");
    print_flag_if_set(file, real_flags, IMAGE_FILE_DLL, "DLL");
    print_flag_if_set(file, real_flags, IMAGE_FILE_UP_SYSTEM_ONLY, "run only on uniprocessor machine");
    print_flag_if_set(file, real_flags, IMAGE_FILE_BYTES_REVERSED_HI, "big endian");
}

static void print_timestamp(FILE *file, bfd *abfd, pe_data_type *pe)
{
    if (pe_is_repro(abfd))
    {
        fprintf(file, "\nTime/Date\t\t%08lx", pe->coff.timestamp);
        fprintf(file, "\t(This is a reproducible build file hash, not a timestamp)\n");
    }
    else
    {
        time_t t = pe->coff.timestamp;
        fprintf(file, "\nTime/Date\t\t%s", ctime(&t));
    }
}

static const char* get_magic_name(unsigned short magic)
{
    switch (magic)
    {
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

static void print_magic_and_version(FILE *file, struct internal_extra_pe_aouthdr *i)
{
    const char *name = get_magic_name(i->Magic);
    fprintf(file, "Magic\t\t\t%04x", i->Magic);
    if (name)
        fprintf(file, "\t(%s)", name);
    fprintf(file, "\nMajorLinkerVersion\t%d\n", i->MajorLinkerVersion);
    fprintf(file, "MinorLinkerVersion\t%d\n", i->MinorLinkerVersion);
}

static void print_size_fields(FILE *file, bfd *abfd, struct internal_extra_pe_aouthdr *i)
{
    fprintf(file, "SizeOfCode\t\t");
    bfd_fprintf_vma(abfd, file, i->SizeOfCode);
    fprintf(file, "\nSizeOfInitializedData\t");
    bfd_fprintf_vma(abfd, file, i->SizeOfInitializedData);
    fprintf(file, "\nSizeOfUninitializedData\t");
    bfd_fprintf_vma(abfd, file, i->SizeOfUninitializedData);
}

static void print_addresses(FILE *file, bfd *abfd, struct internal_extra_pe_aouthdr *i)
{
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

static void print_alignment_and_version(FILE *file, struct internal_extra_pe_aouthdr *i)
{
    fprintf(file, "\nSectionAlignment\t%08x\n", i->SectionAlignment);
    fprintf(file, "FileAlignment\t\t%08x\n", i->FileAlignment);
    fprintf(file, "MajorOSystemVersion\t%d\n", i->MajorOperatingSystemVersion);
    fprintf(file, "MinorOSystemVersion\t%d\n", i->MinorOperatingSystemVersion);
    fprintf(file, "MajorImageVersion\t%d\n", i->MajorImageVersion);
    fprintf(file, "MinorImageVersion\t%d\n", i->MinorImageVersion);
    fprintf(file, "MajorSubsystemVersion\t%d\n", i->MajorSubsystemVersion);
    fprintf(file, "MinorSubsystemVersion\t%d\n", i->MinorSubsystemVersion);
}

static void print_image_info(FILE *file, struct internal_extra_pe_aouthdr *i)
{
    fprintf(file, "Win32Version\t\t%08x\n", i->Win32Version);
    fprintf(file, "SizeOfImage\t\t%08x\n", i->SizeOfImage);
    fprintf(file, "SizeOfHeaders\t\t%08x\n", i->SizeOfHeaders);
    fprintf(file, "CheckSum\t\t%08x\n", i->CheckSum);
}

static const char* get_subsystem_name(unsigned short subsystem)
{
    switch (subsystem)
    {
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

static void print_subsystem(FILE *file, struct internal_extra_pe_aouthdr *i)
{
    const char *subsystem_name = get_subsystem_name(i->Subsystem);
    fprintf(file, "Subsystem\t\t%08x", i->Subsystem);
    if (subsystem_name)
        fprintf(file, "\t(%s)", subsystem_name);
    fprintf(file, "\n");
}

static void print_dll_char_flag(FILE *file, unsigned short dllch, unsigned short flag, const char *name)
{
    if (dllch & flag)
        fprintf(file, "%s%s\n", DLL_CHAR_INDENT, name);
}

static void print_dll_characteristics(FILE *file, struct internal_extra_pe_aouthdr *i)
{
    fprintf(file, "DllCharacteristics\t%08x\n", i->DllCharacteristics);
    if (i->DllCharacteristics)
    {
        unsigned short dllch = i->DllCharacteristics;
        print_dll_char_flag(file, dllch, IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA, "HIGH_ENTROPY_VA");
        print_dll_char_flag(file, dllch, IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE, "DYNAMIC_BASE");
        print_dll_char_flag(file, dllch, IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY, "FORCE_INTEGRITY");
        print_dll_char_flag(file, dllch, IMAGE_DLL_CHARACTERISTICS_NX_COMPAT, "NX_COMPAT");
        print_dll_char_flag(file, dllch, IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, "NO_ISOLATION");
        print_dll_char_flag(file, dllch, IMAGE_DLLCHARACTERISTICS_NO_SEH, "NO_SEH");
        print_dll_char_flag(file, dllch, IMAGE_DLLCHARACTERISTICS_NO_BIND, "NO_BIND");
        print_dll_char_flag(file, dllch, IMAGE_DLLCHARACTERISTICS_APPCONTAINER, "APPCONTAINER");
        print_dll_char_flag(file, dllch, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, "WDM_DRIVER");
        print_dll_char_flag(file, dllch, IMAGE_DLLCHARACTERISTICS_GUARD_CF, "GUARD_CF");
        print_dll_char_flag(file, dllch, IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, "TERMINAL_SERVICE_AWARE");
    }
}

static void print_stack_heap_info(FILE *file, bfd *abfd, struct internal_extra_pe_aouthdr *i)
{
    fprintf(file, "SizeOfStackReserve\t");
    bfd_fprintf_vma(abfd, file, i->SizeOfStackReserve);
    fprintf(file, "\nSizeOfStackCommit\t");
    bfd_fprintf_vma(abfd, file, i->SizeOfStackCommit);
    fprintf(file, "\nSizeOfHeapReserve\t");
    bfd_fprintf_vma(abfd, file, i->SizeOfHeapReserve);
    fprintf(file, "\nSizeOfHeapCommit\t");
    bfd_fprintf_vma(abfd, file, i->SizeOfHeapCommit);
    fprintf(file, "\nLoaderFlags\t\t%08lx\n", (unsigned long) i->LoaderFlags);
    fprintf(file, "NumberOfRvaAndSizes\t%08lx\n", (unsigned long) i->NumberOfRvaAndSizes);
}

static void print_data_directory(FILE *file, bfd *abfd, struct internal_extra_pe_aouthdr *i)
{
    int j;
    fprintf(file, "\nThe Data Directory\n");
    for (j = 0; j < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; j++)
    {
        fprintf(file, "Entry %1x ", j);
        bfd_fprintf_vma(abfd, file, i->DataDirectory[j].VirtualAddress);
        fprintf(file, " %08lx ", (unsigned long) i->DataDirectory[j].Size);
        fprintf(file, "%s\n", dir_names[j]);
    }
}

static void print_additional_info(bfd *abfd, void *vfile)
{
    pe_print_idata(abfd, vfile);
    pe_print_edata(abfd, vfile);
    if (bfd_coff_have_print_pdata(abfd))
        bfd_coff_print_pdata(abfd, vfile);
    else
        pe_print_pdata(abfd, vfile);
    pe_print_reloc(abfd, vfile);
    pe_print_debugdata(abfd, vfile);
    rsrc_print_section(abfd, vfile);
}

bool
_bfd_XX_print_private_bfd_data_common (bfd * abfd, void * vfile)
{
    FILE *file = (FILE *) vfile;
    pe_data_type *pe = pe_data(abfd);
    struct internal_extra_pe_aouthdr *i = &pe->pe_opthdr;

    print_characteristics(file, pe->real_flags);
    print_timestamp(file, abfd, pe);
    print_magic_and_version(file, i);
    print_size_fields(file, abfd, i);
    print_addresses(file, abfd, i);
    print_alignment_and_version(file, i);
    print_image_info(file, i);
    print_subsystem(file, i);
    print_dll_characteristics(file, i);
    print_stack_heap_info(file, abfd, i);
    print_data_directory(file, abfd, i);
    print_additional_info(abfd, vfile);

    return true;
}

static bool
is_vma_in_section (bfd *abfd ATTRIBUTE_UNUSED, asection *sect, void *obj)
{
  bfd_vma addr = * (bfd_vma *) obj;
  return (addr >= sect->vma) && (addr < (sect->vma + sect->size));
}

static asection *
find_section_by_vma (bfd *abfd, bfd_vma addr)
{
  return bfd_sections_find_if (abfd, is_vma_in_section, (void *) & addr);
}

/* Copy any private info we understand from the input bfd
   to the output bfd.  */

bool
_bfd_XX_bfd_copy_private_bfd_data_common (bfd * ibfd, bfd * obfd)
{
  pe_data_type *ipe, *ope;

  if (!is_coff_format(ibfd, obfd))
    return true;

  ipe = pe_data (ibfd);
  ope = pe_data (obfd);

  copy_pe_data(ibfd, obfd, ipe, ope);
  handle_reloc_section(ibfd, obfd);
  memcpy (ope->dos_message, ipe->dos_message, sizeof (ope->dos_message));

  return update_debug_directory(obfd, ope);
}

static bool
is_coff_format(bfd *ibfd, bfd *obfd)
{
  return ibfd->xvec->flavour == bfd_target_coff_flavour
      && obfd->xvec->flavour == bfd_target_coff_flavour;
}

static void
copy_pe_data(bfd *ibfd, bfd *obfd, pe_data_type *ipe, pe_data_type *ope)
{
  ope->dll = ipe->dll;
  
  if (obfd->xvec != ibfd->xvec)
    ope->pe_opthdr.Subsystem = IMAGE_SUBSYSTEM_UNKNOWN;
}

static void
handle_reloc_section(bfd *ibfd, bfd *obfd)
{
  if (!pe_data(obfd)->has_reloc_section)
    clear_reloc_directory(obfd);

  if (!pe_data(ibfd)->has_reloc_section
      && !(pe_data(ibfd)->real_flags & IMAGE_FILE_RELOCS_STRIPPED))
    pe_data(obfd)->dont_strip_reloc = 1;
}

static void
clear_reloc_directory(bfd *obfd)
{
  pe_data(obfd)->pe_opthdr.DataDirectory[PE_BASE_RELOCATION_TABLE].VirtualAddress = 0;
  pe_data(obfd)->pe_opthdr.DataDirectory[PE_BASE_RELOCATION_TABLE].Size = 0;
}

static bool
update_debug_directory(bfd *obfd, pe_data_type *ope)
{
  bfd_size_type size = ope->pe_opthdr.DataDirectory[PE_DEBUG_DATA].Size;
  
  if (size == 0)
    return true;

  bfd_vma addr = ope->pe_opthdr.DataDirectory[PE_DEBUG_DATA].VirtualAddress
    + ope->pe_opthdr.ImageBase;
  bfd_vma last = addr + size - 1;
  asection *section = find_section_by_vma(obfd, last);

  if (section == NULL)
    return true;

  if (!validate_debug_data_bounds(obfd, ope, section, addr, size))
    return false;

  return process_debug_section(obfd, ope, section, addr, size);
}

static bool
validate_debug_data_bounds(bfd *obfd, pe_data_type *ope, asection *section,
                           bfd_vma addr, bfd_size_type size)
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
process_debug_section(bfd *obfd, pe_data_type *ope, asection *section,
                     bfd_vma addr, bfd_size_type size)
{
  if ((section->flags & SEC_HAS_CONTENTS) == 0)
    return true;

  bfd_byte *data;
  if (!bfd_malloc_and_get_section(obfd, section, &data))
    {
      _bfd_error_handler(_("%pB: failed to read debug data section"), obfd);
      return false;
    }

  bfd_vma dataoff = addr - section->vma;
  update_debug_entries(obfd, ope, data + dataoff, size);

  bool result = bfd_set_section_contents(obfd, section, data, 0, section->size);
  if (!result)
    _bfd_error_handler(_("failed to update file offsets in debug directory"));

  free(data);
  return result;
}

static void
update_debug_entries(bfd *obfd, pe_data_type *ope, bfd_byte *debug_data,
                    bfd_size_type size)
{
  struct external_IMAGE_DEBUG_DIRECTORY *dd =
    (struct external_IMAGE_DEBUG_DIRECTORY *)debug_data;
  unsigned int entry_count = size / sizeof(struct external_IMAGE_DEBUG_DIRECTORY);

  for (unsigned int i = 0; i < entry_count; i++)
    update_single_debug_entry(obfd, ope, &dd[i]);
}

static void
update_single_debug_entry(bfd *obfd, pe_data_type *ope,
                         struct external_IMAGE_DEBUG_DIRECTORY *edd)
{
  struct internal_IMAGE_DEBUG_DIRECTORY idd;
  _bfd_XXi_swap_debugdir_in(obfd, edd, &idd);

  if (idd.AddressOfRawData == 0)
    return;

  bfd_vma idd_vma = idd.AddressOfRawData + ope->pe_opthdr.ImageBase;
  asection *ddsection = find_section_by_vma(obfd, idd_vma);
  
  if (!ddsection)
    return;

  idd.PointerToRawData = ddsection->filepos + idd_vma - ddsection->vma;
  _bfd_XXi_swap_debugdir_out(obfd, &idd, edd);
}

/* Copy private section data.  */

bool
_bfd_XX_bfd_copy_private_section_data (bfd *ibfd,
				       asection *isec,
				       bfd *obfd,
				       asection *osec,
				       struct bfd_link_info *link_info)
{
  if (!should_copy_section_data(ibfd, obfd, link_info))
    return true;

  if (!has_required_section_data(ibfd, isec))
    return true;

  if (!ensure_coff_section_allocated(obfd, osec))
    return false;

  if (!ensure_pei_section_allocated(obfd, osec))
    return false;

  copy_pei_section_properties(ibfd, isec, obfd, osec);

  return true;
}

static bool
should_copy_section_data(bfd *ibfd, bfd *obfd, struct bfd_link_info *link_info)
{
  if (link_info != NULL)
    return false;
  
  if (bfd_get_flavour(ibfd) != bfd_target_coff_flavour)
    return false;
    
  if (bfd_get_flavour(obfd) != bfd_target_coff_flavour)
    return false;
    
  return true;
}

static bool
has_required_section_data(bfd *ibfd, asection *isec)
{
  return coff_section_data(ibfd, isec) != NULL && 
         pei_section_data(ibfd, isec) != NULL;
}

static bool
ensure_coff_section_allocated(bfd *obfd, asection *osec)
{
  if (coff_section_data(obfd, osec) != NULL)
    return true;

  size_t amt = sizeof(struct coff_section_tdata);
  osec->used_by_bfd = bfd_zalloc(obfd, amt);
  
  return osec->used_by_bfd != NULL;
}

static bool
ensure_pei_section_allocated(bfd *obfd, asection *osec)
{
  if (pei_section_data(obfd, osec) != NULL)
    return true;

  size_t amt = sizeof(struct pei_section_tdata);
  coff_section_data(obfd, osec)->tdata = bfd_zalloc(obfd, amt);
  
  return coff_section_data(obfd, osec)->tdata != NULL;
}

static void
copy_pei_section_properties(bfd *ibfd, asection *isec, bfd *obfd, asection *osec)
{
  pei_section_data(obfd, osec)->virt_size = pei_section_data(ibfd, isec)->virt_size;
  pei_section_data(obfd, osec)->pe_flags = pei_section_data(ibfd, isec)->pe_flags;
}

void
_bfd_XX_get_symbol_info (bfd * abfd, asymbol *symbol, symbol_info *ret)
{
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
validate_data_bounds(bfd_byte *data, bfd_byte *datastart, bfd_byte *dataend, size_t required_size)
{
  if (data + required_size >= dataend || data < datastart)
    return dataend + 1;
  return NULL;
}

static bfd_byte *
process_name_entry(bfd *abfd, bfd_byte *datastart, bfd_byte *data, bfd_byte *dataend, bfd_vma rva_bias)
{
  bfd_byte *name;
  unsigned long entry = (long) bfd_get_32 (abfd, data);
  
  if (HighBitSet (entry))
    name = datastart + WithoutHighBit (entry);
  else
    name = datastart + entry - rva_bias;
  
  bfd_byte *error = validate_data_bounds(name, datastart, dataend, 2);
  if (error)
    return error;
  
  unsigned int len = bfd_get_16 (abfd, name);
  if (len == 0 || len > 256)
    return dataend + 1;
  
  return NULL;
}

static bfd_byte *
process_directory_entry(bfd *abfd, bfd_byte *datastart, unsigned long entry, bfd_byte *dataend, bfd_vma rva_bias)
{
  bfd_byte *data = datastart + WithoutHighBit (entry);
  
  if (data <= datastart || data >= dataend)
    return dataend + 1;
  
  return rsrc_count_directory (abfd, datastart, data, dataend, rva_bias);
}

static bfd_byte *
process_data_entry(bfd *abfd, bfd_byte *datastart, unsigned long entry, bfd_byte *dataend, bfd_vma rva_bias)
{
  if (datastart + entry + 16 >= dataend)
    return dataend + 1;
  
  unsigned long addr = (long) bfd_get_32 (abfd, datastart + entry);
  unsigned long size = (long) bfd_get_32 (abfd, datastart + entry + 4);
  
  return datastart + addr - rva_bias + size;
}

static bfd_byte *
rsrc_count_entries (bfd *abfd,
		    bool is_name,
		    bfd_byte *datastart,
		    bfd_byte *data,
		    bfd_byte *dataend,
		    bfd_vma rva_bias)
{
  if (data + 8 >= dataend)
    return dataend + 1;
  
  if (is_name)
    {
      bfd_byte *error = process_name_entry(abfd, datastart, data, dataend, rva_bias);
      if (error)
        return error;
    }
  
  unsigned long entry = (long) bfd_get_32 (abfd, data + 4);
  
  if (HighBitSet (entry))
    return process_directory_entry(abfd, datastart, entry, dataend, rva_bias);
  
  return process_data_entry(abfd, datastart, entry, dataend, rva_bias);
}

static bfd_byte *
rsrc_count_directory (bfd *	     abfd,
		      bfd_byte *     datastart,
		      bfd_byte *     data,
		      bfd_byte *     dataend,
		      bfd_vma	     rva_bias)
{
  #define DIRECTORY_HEADER_SIZE 16
  #define ENTRY_SIZE 8
  #define NUM_ENTRIES_OFFSET 12
  #define NUM_IDS_OFFSET 14

  unsigned int  num_entries, num_ids;
  bfd_byte *    highest_data = data;

  if (data + DIRECTORY_HEADER_SIZE >= dataend)
    return dataend + 1;

  num_entries  = (int) bfd_get_16 (abfd, data + NUM_ENTRIES_OFFSET);
  num_ids      = (int) bfd_get_16 (abfd, data + NUM_IDS_OFFSET);

  num_entries += num_ids;

  data += DIRECTORY_HEADER_SIZE;

  while (num_entries --)
    {
      bfd_byte * entry_end;

      entry_end = rsrc_count_entries (abfd, num_entries >= num_ids,
				      datastart, data, dataend, rva_bias);
      data += ENTRY_SIZE;
      highest_data = max (highest_data, entry_end);
      if (entry_end >= dataend)
	break;
    }

  return max (highest_data, data);
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

static bfd_byte *get_name_address(bfd_byte *datastart, unsigned long val, bfd_vma rva_bias)
{
    if (HighBitSet(val))
        return datastart + WithoutHighBit(val);
    return datastart + val - rva_bias;
}

static bool parse_name_entry(bfd *abfd, rsrc_entry *entry, bfd_byte *address, bfd_byte *dataend)
{
    if (address + 3 > dataend)
        return false;
    
    entry->name_id.name.len = bfd_get_16(abfd, address);
    entry->name_id.name.string = address + 2;
    return true;
}

static bfd_byte *parse_directory_entry(bfd *abfd, rsrc_entry *entry, unsigned long val, 
                                       bfd_byte *datastart, bfd_byte *dataend, bfd_vma rva_bias)
{
    entry->is_dir = true;
    entry->value.directory = bfd_malloc(sizeof(*entry->value.directory));
    if (entry->value.directory == NULL)
        return dataend;
    
    return rsrc_parse_directory(abfd, entry->value.directory,
                               datastart,
                               datastart + WithoutHighBit(val),
                               dataend, rva_bias, entry);
}

static bool validate_leaf_data(bfd_byte *data, bfd_byte *datastart, bfd_byte *dataend)
{
    return data >= datastart && data + 12 <= dataend;
}

static bfd_byte *parse_leaf_entry(bfd *abfd, rsrc_entry *entry, unsigned long val,
                                  bfd_byte *datastart, bfd_byte *dataend, bfd_vma rva_bias)
{
    entry->is_dir = false;
    entry->value.leaf = bfd_malloc(sizeof(*entry->value.leaf));
    if (entry->value.leaf == NULL)
        return dataend;
    
    bfd_byte *data = datastart + val;
    if (!validate_leaf_data(data, datastart, dataend))
        return dataend;
    
    unsigned long addr = bfd_get_32(abfd, data);
    unsigned long size = bfd_get_32(abfd, data + 4);
    entry->value.leaf->size = size;
    entry->value.leaf->codepage = bfd_get_32(abfd, data + 8);
    
    if (size > dataend - datastart - (addr - rva_bias))
        return dataend;
    
    entry->value.leaf->data = bfd_malloc(size);
    if (entry->value.leaf->data == NULL)
        return dataend;
    
    memcpy(entry->value.leaf->data, datastart + addr - rva_bias, size);
    return datastart + (addr - rva_bias) + size;
}

static bfd_byte *rsrc_parse_entry(bfd *abfd,
                                  bool is_name,
                                  rsrc_entry *entry,
                                  bfd_byte *datastart,
                                  bfd_byte *data,
                                  bfd_byte *dataend,
                                  bfd_vma rva_bias,
                                  rsrc_directory *parent)
{
    unsigned long val = bfd_get_32(abfd, data);
    
    entry->parent = parent;
    entry->is_name = is_name;
    
    if (is_name)
    {
        bfd_byte *address = get_name_address(datastart, val, rva_bias);
        if (!parse_name_entry(abfd, entry, address, dataend))
            return dataend;
    }
    else
    {
        entry->name_id.id = val;
    }
    
    val = bfd_get_32(abfd, data + 4);
    
    if (HighBitSet(val))
        return parse_directory_entry(abfd, entry, val, datastart, dataend, rva_bias);
    
    return parse_leaf_entry(abfd, entry, val, datastart, dataend, rva_bias);
}

static bfd_byte *
allocate_entry(rsrc_entry **entry)
{
  *entry = bfd_malloc(sizeof(**entry));
  return *entry;
}

static bfd_byte *
process_single_entry(bfd *abfd,
                    bool is_name,
                    rsrc_entry *entry,
                    bfd_byte *datastart,
                    bfd_byte *data,
                    bfd_byte *dataend,
                    bfd_vma rva_bias,
                    rsrc_directory *parent,
                    bfd_byte *highest_data)
{
  bfd_byte *entry_end = rsrc_parse_entry(abfd, is_name, entry, datastart,
                                         data, dataend, rva_bias, parent);
  return max(entry_end, highest_data);
}

static rsrc_entry *
create_next_entry(rsrc_entry *current, unsigned int remaining)
{
  if (remaining == 0) {
    current->next_entry = NULL;
    return current;
  }
  
  current->next_entry = bfd_malloc(sizeof(*current));
  return current->next_entry;
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
  unsigned int i;
  rsrc_entry *entry;

  if (chain->num_entries == 0) {
    chain->first_entry = chain->last_entry = NULL;
    return highest_data;
  }

  if (!allocate_entry(&entry))
    return dataend;

  chain->first_entry = entry;

  for (i = chain->num_entries; i--;) {
    bfd_byte *entry_end = process_single_entry(abfd, is_name, entry, 
                                               datastart, data, dataend,
                                               rva_bias, parent, highest_data);
    data += 8;
    highest_data = entry_end;
    
    if (entry_end > dataend)
      return dataend;

    entry = create_next_entry(entry, i);
    if (!entry && i > 0)
      return dataend;
  }

  chain->last_entry = entry;
  return highest_data;
}

static bfd_byte *
read_directory_header(bfd *abfd, rsrc_directory *table, bfd_byte *data)
{
  table->characteristics = bfd_get_32(abfd, data);
  table->time = bfd_get_32(abfd, data + 4);
  table->major = bfd_get_16(abfd, data + 8);
  table->minor = bfd_get_16(abfd, data + 10);
  table->names.num_entries = bfd_get_16(abfd, data + 12);
  table->ids.num_entries = bfd_get_16(abfd, data + 14);
  return data + 16;
}

static bfd_byte *
parse_entry_section(bfd *abfd, rsrc_entries *entries, bool is_named,
                   bfd_byte *highest_data, bfd_byte *datastart,
                   bfd_byte *data, bfd_byte *dataend, bfd_vma rva_bias,
                   rsrc_directory *table)
{
  #define ENTRY_SIZE 8
  
  bfd_byte *new_highest = rsrc_parse_entries(abfd, entries, is_named,
                                             highest_data, datastart, data,
                                             dataend, rva_bias, table);
  return new_highest;
}

static bfd_byte *
rsrc_parse_directory(bfd *abfd, rsrc_directory *table, bfd_byte *datastart,
                    bfd_byte *data, bfd_byte *dataend, bfd_vma rva_bias,
                    rsrc_entry *entry)
{
  #define ENTRY_SIZE 8
  
  if (table == NULL)
    return dataend;

  bfd_byte *highest_data = data;
  table->entry = entry;

  data = read_directory_header(abfd, table, data);

  highest_data = parse_entry_section(abfd, &table->names, true, data,
                                     datastart, data, dataend, rva_bias, table);
  data += table->names.num_entries * ENTRY_SIZE;

  highest_data = parse_entry_section(abfd, &table->ids, false, highest_data,
                                     datastart, data, dataend, rva_bias, table);
  data += table->ids.num_entries * ENTRY_SIZE;

  return max(highest_data, data);
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
  const size_t LENGTH_FIELD_SIZE = 2;
  const size_t CHAR_SIZE = 2;
  
  bfd_put_16 (data->abfd, string->len, data->next_string);
  memcpy (data->next_string + LENGTH_FIELD_SIZE, string->string, string->len * CHAR_SIZE);
  data->next_string += (string->len + 1) * CHAR_SIZE;
}

static inline unsigned int rsrc_compute_rva(rsrc_write_data *data, bfd_byte *addr)
{
    return (addr - data->datastart) + data->rva_bias;
}

static void write_leaf_header(rsrc_write_data *data, rsrc_leaf *leaf, bfd_vma rva) {
    bfd_put_32(data->abfd, rva, data->next_leaf);
    bfd_put_32(data->abfd, leaf->size, data->next_leaf + 4);
    bfd_put_32(data->abfd, leaf->codepage, data->next_leaf + 8);
    bfd_put_32(data->abfd, 0, data->next_leaf + 12);
}

static void copy_leaf_data(rsrc_write_data *data, rsrc_leaf *leaf) {
    memcpy(data->next_data, leaf->data, leaf->size);
}

static unsigned int align_to_8_bytes(unsigned int size) {
    #define ALIGNMENT_MASK 7
    return (size + ALIGNMENT_MASK) & ~ALIGNMENT_MASK;
}

static void rsrc_write_leaf(rsrc_write_data *data, rsrc_leaf *leaf) {
    #define LEAF_HEADER_SIZE 16
    
    bfd_vma rva = rsrc_compute_rva(data, data->next_data);
    write_leaf_header(data, leaf, rva);
    data->next_leaf += LEAF_HEADER_SIZE;
    
    copy_leaf_data(data, leaf);
    data->next_data += align_to_8_bytes(leaf->size);
}

static void rsrc_write_directory (rsrc_write_data *, rsrc_directory *);

static void write_entry_name(rsrc_write_data *data, bfd_byte *where, rsrc_entry *entry)
{
    if (entry->is_name)
    {
        bfd_put_32(data->abfd,
                   SetHighBit(data->next_string - data->datastart),
                   where);
        rsrc_write_string(data, &entry->name_id.name);
    }
    else
    {
        bfd_put_32(data->abfd, entry->name_id.id, where);
    }
}

static void write_entry_value(rsrc_write_data *data, bfd_byte *where, rsrc_entry *entry)
{
    if (entry->is_dir)
    {
        bfd_put_32(data->abfd,
                   SetHighBit(data->next_table - data->datastart),
                   where + 4);
        rsrc_write_directory(data, entry->value.directory);
    }
    else
    {
        bfd_put_32(data->abfd, data->next_leaf - data->datastart, where + 4);
        rsrc_write_leaf(data, entry->value.leaf);
    }
}

static void rsrc_write_entry(rsrc_write_data *data,
                             bfd_byte *where,
                             rsrc_entry *entry)
{
    write_entry_name(data, where, entry);
    write_entry_value(data, where, entry);
}

static void
rsrc_compute_region_sizes (rsrc_directory * dir)
{
  if (dir == NULL)
    return;

  sizeof_tables_and_entries += 16;

  process_entry_list(dir->names.first_entry, 1);
  process_entry_list(dir->ids.first_entry, 0);
}

static void
process_entry_list(struct rsrc_entry * entry, int process_names)
{
  while (entry != NULL)
  {
    process_single_entry(entry, process_names);
    entry = entry->next_entry;
  }
}

static void
process_single_entry(struct rsrc_entry * entry, int process_names)
{
  sizeof_tables_and_entries += 8;

  if (process_names)
    sizeof_strings += (entry->name_id.name.len + 1) * 2;

  if (entry->is_dir)
    rsrc_compute_region_sizes(entry->value.directory);
  else
    sizeof_leaves += 16;
}

static void
write_directory_header(rsrc_write_data *data, rsrc_directory *dir)
{
  bfd_put_32(data->abfd, dir->characteristics, data->next_table);
  bfd_put_32(data->abfd, 0, data->next_table + 4);
  bfd_put_16(data->abfd, dir->major, data->next_table + 8);
  bfd_put_16(data->abfd, dir->minor, data->next_table + 10);
  bfd_put_16(data->abfd, dir->names.num_entries, data->next_table + 12);
  bfd_put_16(data->abfd, dir->ids.num_entries, data->next_table + 14);
}

static void
write_entry_list(rsrc_write_data *data, bfd_byte **next_entry, 
                 rsrc_entry *first_entry, unsigned int num_entries,
                 int expected_is_name)
{
  rsrc_entry *entry = first_entry;
  unsigned int i;
  
  for (i = num_entries; i > 0 && entry != NULL; i--)
  {
    BFD_ASSERT(entry->is_name == expected_is_name);
    rsrc_write_entry(data, *next_entry, entry);
    *next_entry += 8;
    entry = entry->next_entry;
  }
  
  BFD_ASSERT(i == 0);
  BFD_ASSERT(entry == NULL);
}

static void
rsrc_write_directory(rsrc_write_data *data, rsrc_directory *dir)
{
  #define HEADER_SIZE 16
  #define ENTRY_SIZE 8
  
  bfd_byte *next_entry;
  bfd_byte *nt;
  
  write_directory_header(data, dir);
  
  next_entry = data->next_table + HEADER_SIZE;
  data->next_table = next_entry + (dir->names.num_entries * ENTRY_SIZE)
    + (dir->ids.num_entries * ENTRY_SIZE);
  nt = data->next_table;
  
  write_entry_list(data, &next_entry, dir->names.first_entry, 
                   dir->names.num_entries, 1);
  write_entry_list(data, &next_entry, dir->ids.first_entry,
                   dir->ids.num_entries, 0);
  
  BFD_ASSERT(nt == next_entry);
}

#if ! defined __CYGWIN__ && ! defined __MINGW32__
/* Return the length (number of units) of the first character in S,
   putting its 'ucs4_t' representation in *PUC.  */

static const unsigned short HIGH_SURROGATE_MIN = 0xd800;
static const unsigned short HIGH_SURROGATE_MAX = 0xdc00;
static const unsigned short LOW_SURROGATE_MIN = 0xdc00;
static const unsigned short LOW_SURROGATE_MAX = 0xe000;
static const unsigned int SURROGATE_BASE = 0x10000;
static const unsigned int SURROGATE_SHIFT = 10;
static const wint_t REPLACEMENT_CHAR = 0xfffd;

static int is_single_unit(unsigned short c)
{
    return c < HIGH_SURROGATE_MIN || c >= LOW_SURROGATE_MAX;
}

static int is_high_surrogate(unsigned short c)
{
    return c >= HIGH_SURROGATE_MIN && c < HIGH_SURROGATE_MAX;
}

static int is_low_surrogate(unsigned short c)
{
    return c >= LOW_SURROGATE_MIN && c < LOW_SURROGATE_MAX;
}

static wint_t combine_surrogates(unsigned short high, unsigned short low)
{
    return SURROGATE_BASE + ((high - HIGH_SURROGATE_MIN) << SURROGATE_SHIFT) + (low - LOW_SURROGATE_MIN);
}

static unsigned int process_surrogate_pair(wint_t *puc, const unsigned short *s, unsigned int n)
{
    if (n < 2)
    {
        *puc = REPLACEMENT_CHAR;
        return n;
    }
    
    if (is_low_surrogate(s[1]))
    {
        *puc = combine_surrogates(s[0], s[1]);
        return 2;
    }
    
    *puc = REPLACEMENT_CHAR;
    return 1;
}

static unsigned int u16_mbtouc(wint_t *puc, const unsigned short *s, unsigned int n)
{
    unsigned short c = *s;
    
    if (is_single_unit(c))
    {
        *puc = c;
        return 1;
    }
    
    if (is_high_surrogate(c))
    {
        return process_surrogate_pair(puc, s, n);
    }
    
    *puc = REPLACEMENT_CHAR;
    return 1;
}
#endif /* not Cygwin/Mingw */

/* Perform a comparison of two entries.  */
static signed int compare_ids(rsrc_entry *a, rsrc_entry *b)
{
    return a->name_id.id - b->name_id.id;
}

static signed int compare_wchar_strings(const wchar_t *astring, const wchar_t *bstring, unsigned int min_len)
{
#ifdef __CYGWIN__
    return wcsncasecmp(astring, bstring, min_len);
#elif defined __MINGW32__
    return wcsnicmp(astring, bstring, min_len);
#else
    return 0;
#endif
}

static signed int compare_utf16_char(const bfd_byte *astring, const bfd_byte *bstring)
{
    wint_t awc;
    wint_t bwc;
    
    unsigned int Alen = u16_mbtouc(&awc, (const unsigned short *)astring, 2);
    unsigned int Blen = u16_mbtouc(&bwc, (const unsigned short *)bstring, 2);
    
    if (Alen != Blen)
        return Alen - Blen;
    
    awc = towlower(awc);
    bwc = towlower(bwc);
    
    return awc - bwc;
}

static signed int compare_utf16_strings(bfd_byte *astring, bfd_byte *bstring, unsigned int min_len)
{
    signed int res = 0;
    unsigned int i;
    
    for (i = min_len; i--; astring += 2, bstring += 2)
    {
        res = compare_utf16_char(astring, bstring);
        if (res)
            break;
    }
    
    return res;
}

static signed int compare_unicode_strings(bfd_byte *astring, unsigned int alen, bfd_byte *bstring, unsigned int blen)
{
    unsigned int min_len = min(alen, blen);
    signed int res;
    
#if defined __CYGWIN__ || defined __MINGW32__
    res = compare_wchar_strings((const wchar_t *)astring, (const wchar_t *)bstring, min_len);
#else
    res = compare_utf16_strings(astring, bstring, min_len);
#endif
    
    if (res == 0)
        res = alen - blen;
    
    return res;
}

static signed int rsrc_cmp(bool is_name, rsrc_entry *a, rsrc_entry *b)
{
    if (!is_name)
        return compare_ids(a, b);
    
    return compare_unicode_strings(a->name_id.name.string, a->name_id.name.len,
                                   b->name_id.name.string, b->name_id.name.len);
}

static void
rsrc_print_name (char * buffer, rsrc_string string)
{
  unsigned int  i;
  bfd_byte *    name = string.string;

  for (i = string.len; i--; name += 2)
    {
      size_t buffer_len = strlen(buffer);
      sprintf(buffer + buffer_len, "%.1s", name);
    }
}

static const char *get_resource_type_name(unsigned int id) {
    switch (id) {
        case 1: return " (CURSOR)";
        case 2: return " (BITMAP)";
        case 3: return " (ICON)";
        case 4: return " (MENU)";
        case 5: return " (DIALOG)";
        case 6: return " (STRING)";
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
        default: return "";
    }
}

static void append_name_or_id(char *buffer, bool is_name, rsrc_id name_id) {
    if (is_name) {
        rsrc_print_name(buffer + strlen(buffer), name_id.name);
    } else {
        sprintf(buffer + strlen(buffer), "%x", name_id.id);
    }
}

static bool append_resource_type(char *buffer, rsrc_directory *dir) {
    #define STRING_RESOURCE_ID 6
    
    if (dir == NULL || dir->entry == NULL || dir->entry->parent == NULL || 
        dir->entry->parent->entry == NULL) {
        return false;
    }
    
    strcpy(buffer, "type: ");
    rsrc_entry *parent_entry = dir->entry->parent->entry;
    append_name_or_id(buffer, parent_entry->is_name, parent_entry->name_id);
    
    if (!parent_entry->is_name) {
        unsigned int id = parent_entry->name_id.id;
        strcat(buffer, get_resource_type_name(id));
        if (id == STRING_RESOURCE_ID) {
            return true;
        }
    }
    
    return false;
}

static void append_resource_name(char *buffer, rsrc_directory *dir, bool is_string) {
    #define STRING_ID_SHIFT 4
    
    if (dir == NULL || dir->entry == NULL) {
        return;
    }
    
    strcat(buffer, " name: ");
    append_name_or_id(buffer, dir->entry->is_name, dir->entry->name_id);
    
    if (!dir->entry->is_name && is_string) {
        unsigned int id = dir->entry->name_id.id;
        sprintf(buffer + strlen(buffer), " (resource id range: %d - %d)",
                (id - 1) << STRING_ID_SHIFT, (id << STRING_ID_SHIFT) - 1);
    }
}

static void append_language(char *buffer, rsrc_entry *entry) {
    if (entry == NULL) {
        return;
    }
    
    strcat(buffer, " lang: ");
    append_name_or_id(buffer, entry->is_name, entry->name_id);
}

static const char *rsrc_resource_name(rsrc_entry *entry, rsrc_directory *dir, char *buffer) {
    buffer[0] = 0;
    
    bool is_string = append_resource_type(buffer, dir);
    append_resource_name(buffer, dir, is_string);
    append_language(buffer, entry);
    
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

static unsigned int get_string_length(const bfd_byte *string)
{
    return string[0] + (string[1] << 8);
}

static unsigned int calculate_string_size(unsigned int len)
{
    return (len + 1) * 2;
}

static bool strings_are_equal(const bfd_byte *str1, const bfd_byte *str2, unsigned int len)
{
    return memcmp(str1 + 2, str2 + 2, len * 2) == 0;
}

static void report_duplicate_string_error(rsrc_entry *a, unsigned int index)
{
    if (a->parent != NULL && a->parent->entry != NULL && !a->parent->entry->is_name)
    {
        _bfd_error_handler(_(".rsrc merge failure: duplicate string resource: %d"),
                          ((a->parent->entry->name_id.id - 1) << 4) + index);
    }
}

static unsigned int check_string_conflicts(const bfd_byte *astring, const bfd_byte *bstring, 
                                           unsigned int *copy_needed, unsigned int *conflict_index)
{
    #define MAX_STRINGS 16
    unsigned int i;
    
    for (i = 0; i < MAX_STRINGS; i++)
    {
        unsigned int alen = get_string_length(astring);
        unsigned int blen = get_string_length(bstring);
        
        if (alen == 0)
        {
            *copy_needed += blen * 2;
        }
        else if (blen != 0)
        {
            if (alen != blen || !strings_are_equal(astring, bstring, alen))
            {
                *conflict_index = i;
                return false;
            }
        }
        
        astring += calculate_string_size(alen);
        bstring += calculate_string_size(blen);
    }
    
    return true;
}

static void copy_string_data(bfd_byte *dest, const bfd_byte *source, unsigned int len)
{
    memcpy(dest, source, calculate_string_size(len));
}

static bfd_byte* merge_single_string(bfd_byte *nstring, const bfd_byte *astring, 
                                     const bfd_byte *bstring, unsigned int alen, unsigned int blen)
{
    if (alen != 0)
    {
        copy_string_data(nstring, astring, alen);
        nstring += calculate_string_size(alen);
    }
    else if (blen != 0)
    {
        copy_string_data(nstring, bstring, blen);
        nstring += calculate_string_size(blen);
    }
    else
    {
        *nstring++ = 0;
        *nstring++ = 0;
    }
    
    return nstring;
}

static bfd_byte* merge_all_strings(bfd_byte *new_data, const bfd_byte *astring, const bfd_byte *bstring)
{
    #define MAX_STRINGS 16
    bfd_byte *nstring = new_data;
    unsigned int i;
    
    for (i = 0; i < MAX_STRINGS; i++)
    {
        unsigned int alen = get_string_length(astring);
        unsigned int blen = get_string_length(bstring);
        
        nstring = merge_single_string(nstring, astring, bstring, alen, blen);
        
        astring += calculate_string_size(alen);
        bstring += calculate_string_size(blen);
    }
    
    return nstring;
}

static bool
rsrc_merge_string_entries (rsrc_entry * a ATTRIBUTE_UNUSED,
                          rsrc_entry * b ATTRIBUTE_UNUSED)
{
    unsigned int copy_needed = 0;
    unsigned int conflict_index = 0;
    bfd_byte *astring;
    bfd_byte *bstring;
    bfd_byte *new_data;
    bfd_byte *nstring;
    
    BFD_ASSERT(!a->is_dir);
    astring = a->value.leaf->data;
    
    BFD_ASSERT(!b->is_dir);
    bstring = b->value.leaf->data;
    
    if (!check_string_conflicts(astring, bstring, &copy_needed, &conflict_index))
    {
        report_duplicate_string_error(a, conflict_index);
        return false;
    }
    
    if (copy_needed == 0)
        return true;
    
    new_data = bfd_malloc(a->value.leaf->size + copy_needed);
    if (new_data == NULL)
        return false;
    
    nstring = merge_all_strings(new_data, a->value.leaf->data, b->value.leaf->data);
    
    BFD_ASSERT(nstring - new_data == (signed)(a->value.leaf->size + copy_needed));
    
    free(a->value.leaf->data);
    a->value.leaf->data = new_data;
    a->value.leaf->size += copy_needed;
    
    return true;
}

static void rsrc_merge (rsrc_entry *, rsrc_entry *);

/* Sort the entries in given part of the directory.
   We use an old fashioned bubble sort because we are dealing
   with lists and we want to handle matches specially.  */

static bool is_default_manifest(rsrc_entry *entry, rsrc_directory *dir)
{
    return !entry->is_name
           && entry->name_id.id == 1
           && dir != NULL
           && dir->entry != NULL
           && !dir->entry->is_name
           && dir->entry->name_id.id == 0x18;
}

static bool is_zero_lang_manifest(rsrc_directory *directory)
{
    return directory->names.num_entries == 0
           && directory->ids.num_entries == 1
           && !directory->ids.first_entry->is_name
           && directory->ids.first_entry->name_id.id == 0;
}

static bool is_default_manifest_leaf(rsrc_entry *entry, rsrc_directory *dir)
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

static bool is_string_resource(rsrc_directory *dir)
{
    #define RT_STRING 0x6
    
    return dir != NULL
           && dir->entry != NULL
           && dir->entry->parent != NULL
           && dir->entry->parent->entry != NULL
           && !dir->entry->parent->entry->is_name
           && dir->entry->parent->entry->name_id.id == RT_STRING;
}

static void swap_entries(rsrc_entry **points_to_entry, rsrc_entry *entry, rsrc_entry *next)
{
    entry->next_entry = next->next_entry;
    next->next_entry = entry;
    *points_to_entry = next;
}

static void unhook_entry(rsrc_entry *entry, rsrc_entry *next, rsrc_dir_chain *chain)
{
    entry->next_entry = next->next_entry;
    chain->num_entries--;
}

static rsrc_entry* handle_manifest_merge(rsrc_entry **points_to_entry, rsrc_entry *entry, 
                                         rsrc_entry *next, rsrc_dir_chain *chain, 
                                         bool *swapped, rsrc_directory *dir)
{
    if (!is_default_manifest(entry, dir)) {
        rsrc_merge(entry, next);
        return next;
    }

    if (is_zero_lang_manifest(next->value.directory)) {
        unhook_entry(entry, next, chain);
        return next->next_entry;
    }
    
    if (is_zero_lang_manifest(entry->value.directory)) {
        swap_entries(points_to_entry, entry, next);
        *swapped = true;
        unhook_entry(entry, next, chain);
        return entry->next_entry;
    }
    
    _bfd_error_handler(_(".rsrc merge failure: multiple non-default manifests"));
    bfd_set_error(bfd_error_file_truncated);
    return NULL;
}

static rsrc_entry* handle_duplicate_leaves(rsrc_entry *entry, rsrc_entry *next, 
                                          rsrc_dir_chain *chain, rsrc_directory *dir)
{
    if (is_default_manifest_leaf(entry, dir)) {
        unhook_entry(entry, next, chain);
        return next->next_entry;
    }
    
    if (is_string_resource(dir)) {
        if (!rsrc_merge_string_entries(entry, next)) {
            bfd_set_error(bfd_error_file_truncated);
            return NULL;
        }
        unhook_entry(entry, next, chain);
        return next->next_entry;
    }
    
    if (dir == NULL || dir->entry == NULL || 
        dir->entry->parent == NULL || dir->entry->parent->entry == NULL) {
        _bfd_error_handler(_(".rsrc merge failure: duplicate leaf"));
    } else {
        char buff[256];
        _bfd_error_handler(_(".rsrc merge failure: duplicate leaf: %s"),
                          rsrc_resource_name(entry, dir, buff));
    }
    bfd_set_error(bfd_error_file_truncated);
    return NULL;
}

static rsrc_entry* handle_equal_comparison(rsrc_entry **points_to_entry, rsrc_entry *entry,
                                          rsrc_entry *next, rsrc_dir_chain *chain,
                                          bool *swapped, rsrc_directory *dir)
{
    if (entry->is_dir && next->is_dir) {
        return handle_manifest_merge(points_to_entry, entry, next, chain, swapped, dir);
    }
    
    if (entry->is_dir != next->is_dir) {
        _bfd_error_handler(_(".rsrc merge failure: a directory matches a leaf"));
        bfd_set_error(bfd_error_file_truncated);
        return NULL;
    }
    
    return handle_duplicate_leaves(entry, next, chain, dir);
}

static rsrc_entry* process_entry_pair(rsrc_entry **points_to_entry, rsrc_entry *entry,
                                     rsrc_entry *next, rsrc_dir_chain *chain,
                                     bool *swapped, bool is_name, rsrc_directory *dir)
{
    signed int cmp = rsrc_cmp(is_name, entry, next);
    
    if (cmp > 0) {
        swap_entries(points_to_entry, entry, next);
        *swapped = true;
        return entry->next_entry;
    }
    
    if (cmp == 0) {
        rsrc_entry *result = handle_equal_comparison(points_to_entry, entry, next, chain, swapped, dir);
        if (!result) {
            return NULL;
        }
        if (chain->num_entries < 2) {
            return NULL;
        }
        return result;
    }
    
    return next->next_entry;
}

static bool bubble_sort_pass(rsrc_dir_chain *chain, bool is_name, rsrc_directory *dir)
{
    bool swapped = false;
    rsrc_entry **points_to_entry = &chain->first_entry;
    rsrc_entry *entry = *points_to_entry;
    rsrc_entry *next = entry->next_entry;
    
    while (next) {
        signed int cmp = rsrc_cmp(is_name, entry, next);
        
        if (cmp > 0) {
            swap_entries(points_to_entry, entry, next);
            points_to_entry = &next->next_entry;
            next = entry->next_entry;
            swapped = true;
        } else if (cmp == 0) {
            rsrc_entry *new_next = handle_equal_comparison(points_to_entry, entry, next, 
                                                          chain, &swapped, dir);
            if (!new_next) {
                return false;
            }
            if (chain->num_entries < 2) {
                return false;
            }
            next = new_next;
        } else {
            points_to_entry = &entry->next_entry;
            entry = next;
            next = next->next_entry;
        }
    }
    
    chain->last_entry = entry;
    return swapped;
}

static void rsrc_sort_entries(rsrc_dir_chain *chain, bool is_name, rsrc_directory *dir)
{
    if (chain->num_entries < 2) {
        return;
    }
    
    bool swapped;
    do {
        swapped = bubble_sort_pass(chain, is_name, dir);
    } while (swapped);
}

/* Attach B's chain onto A.  */
static void
rsrc_attach_chain (rsrc_dir_chain * achain, rsrc_dir_chain * bchain)
{
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
  bchain->first_entry = bchain->last_entry = NULL;
}

static void
rsrc_merge (struct rsrc_entry * a, struct rsrc_entry * b)
{
  rsrc_directory * adir;
  rsrc_directory * bdir;

  BFD_ASSERT (a->is_dir);
  BFD_ASSERT (b->is_dir);

  adir = a->value.directory;
  bdir = b->value.directory;

  if (!rsrc_validate_directories(adir, bdir))
    return;

  rsrc_merge_chains(adir, bdir);
  rsrc_sort_directory_entries(adir);
}

static bool
rsrc_validate_directories (rsrc_directory * adir, rsrc_directory * bdir)
{
  if (adir->characteristics != bdir->characteristics)
    {
      _bfd_error_handler (_(".rsrc merge failure: dirs with differing characteristics"));
      bfd_set_error (bfd_error_file_truncated);
      return false;
    }

  if (adir->major != bdir->major || adir->minor != bdir->minor)
    {
      _bfd_error_handler (_(".rsrc merge failure: differing directory versions"));
      bfd_set_error (bfd_error_file_truncated);
      return false;
    }

  return true;
}

static void
rsrc_merge_chains (rsrc_directory * adir, rsrc_directory * bdir)
{
  rsrc_attach_chain (& adir->names, & bdir->names);
  rsrc_attach_chain (& adir->ids, & bdir->ids);
}

static void
rsrc_sort_directory_entries (rsrc_directory * adir)
{
  rsrc_sort_entries (& adir->names, true, adir);
  rsrc_sort_entries (& adir->ids, false, adir);
}

/* Check the .rsrc section.  If it contains multiple concatenated
   resources then we must merge them properly.  Otherwise Windows
   will ignore all but the first set.  */

static void initialize_new_table(rsrc_directory *new_table) {
    new_table->names.num_entries = 0;
    new_table->ids.num_entries = 0;
}

static asection* get_rsrc_section(bfd *abfd, bfd_size_type *size) {
    asection *sec = bfd_get_section_by_name(abfd, ".rsrc");
    if (sec == NULL || (*size = sec->rawsize) == 0)
        return NULL;
    return sec;
}

static bfd_vma calculate_rva_bias(asection *sec, pe_data_type *pe) {
    return sec->vma - pe->pe_opthdr.ImageBase;
}

static int count_input_rsrc_sections(struct coff_final_link_info *pfinfo, 
                                     ptrdiff_t **rsrc_sizes,
                                     unsigned int *max_num_input_rsrc) {
    unsigned int num_input_rsrc = 0;
    bfd *input;
    
    *max_num_input_rsrc = 4;
    *rsrc_sizes = bfd_malloc(*max_num_input_rsrc * sizeof(**rsrc_sizes));
    if (*rsrc_sizes == NULL)
        return -1;
    
    for (input = pfinfo->info->input_bfds; input != NULL; input = input->link.next) {
        asection *rsrc_sec = bfd_get_section_by_name(input, ".rsrc");
        
        if (rsrc_sec != NULL && !discarded_section(rsrc_sec)) {
            if (num_input_rsrc == *max_num_input_rsrc) {
                *max_num_input_rsrc += 10;
                *rsrc_sizes = bfd_realloc(*rsrc_sizes, 
                                         *max_num_input_rsrc * sizeof(**rsrc_sizes));
                if (*rsrc_sizes == NULL)
                    return -1;
            }
            BFD_ASSERT(rsrc_sec->size > 0);
            (*rsrc_sizes)[num_input_rsrc++] = rsrc_sec->size;
        }
    }
    return num_input_rsrc;
}

static bfd_bool validate_resource_set(bfd *abfd, bfd_byte *data, bfd_byte *p,
                                      bfd_byte *dataend, ptrdiff_t expected_size,
                                      bfd_vma rva_bias) {
    bfd_byte *new_data = rsrc_count_directory(abfd, data, data, dataend, rva_bias);
    
    if (new_data > dataend) {
        _bfd_error_handler(_("%pB: .rsrc merge failure: corrupt .rsrc section"), abfd);
        bfd_set_error(bfd_error_file_truncated);
        return FALSE;
    }
    
    if ((new_data - p) > expected_size) {
        _bfd_error_handler(_("%pB: .rsrc merge failure: unexpected .rsrc size"), abfd);
        bfd_set_error(bfd_error_file_truncated);
        return FALSE;
    }
    return TRUE;
}

static unsigned int count_resource_sets(bfd *abfd, bfd_byte *data, 
                                       bfd_size_type size, ptrdiff_t *rsrc_sizes,
                                       bfd_vma initial_rva_bias) {
    unsigned int num_resource_sets = 0;
    bfd_byte *dataend = data + size;
    bfd_vma rva_bias = initial_rva_bias;
    
    while (data < dataend) {
        bfd_byte *p = data;
        
        if (!validate_resource_set(abfd, data, p, dataend, 
                                   rsrc_sizes[num_resource_sets], rva_bias))
            return 0;
        
        data = p + rsrc_sizes[num_resource_sets];
        rva_bias += data - p;
        ++num_resource_sets;
    }
    return num_resource_sets;
}

static rsrc_directory* build_type_tables(bfd *abfd, bfd_byte *datastart,
                                        bfd_byte *dataend, ptrdiff_t *rsrc_sizes,
                                        unsigned int num_resource_sets,
                                        bfd_vma initial_rva_bias) {
    rsrc_directory *type_tables = bfd_malloc(num_resource_sets * sizeof(*type_tables));
    if (type_tables == NULL)
        return NULL;
    
    bfd_byte *data = datastart;
    bfd_vma rva_bias = initial_rva_bias;
    unsigned int indx = 0;
    
    while (data < dataend) {
        bfd_byte *p = data;
        rsrc_parse_directory(abfd, type_tables + indx, data, data,
                           dataend, rva_bias, NULL);
        data = p + rsrc_sizes[indx];
        rva_bias += data - p;
        ++indx;
    }
    BFD_ASSERT(indx == num_resource_sets);
    return type_tables;
}

static void copy_table_metadata(rsrc_directory *new_table, rsrc_directory *type_tables) {
    new_table->characteristics = type_tables[0].characteristics;
    new_table->time = type_tables[0].time;
    new_table->major = type_tables[0].major;
    new_table->minor = type_tables[0].minor;
}

static void merge_table_chains(rsrc_directory *new_table, rsrc_directory *type_tables,
                               unsigned int num_resource_sets) {
    new_table->names.first_entry = NULL;
    new_table->names.last_entry = NULL;
    
    for (unsigned int indx = 0; indx < num_resource_sets; indx++)
        rsrc_attach_chain(&new_table->names, &type_tables[indx].names);
    
    rsrc_sort_entries(&new_table->names, true, new_table);
    
    new_table->ids.first_entry = NULL;
    new_table->ids.last_entry = NULL;
    
    for (unsigned int indx = 0; indx < num_resource_sets; indx++)
        rsrc_attach_chain(&new_table->ids, &type_tables[indx].ids);
    
    rsrc_sort_entries(&new_table->ids, false, new_table);
}

#define STRING_ALIGNMENT 7

static void setup_write_data(rsrc_write_data *write_data, bfd *abfd,
                            bfd_byte *new_data, asection *sec,
                            pe_data_type *pe) {
    write_data->abfd = abfd;
    write_data->datastart = new_data;
    write_data->next_table = new_data;
    write_data->next_leaf = new_data + sizeof_tables_and_entries;
    write_data->next_string = write_data->next_leaf + sizeof_leaves;
    write_data->next_data = write_data->next_string + sizeof_strings;
    write_data->rva_bias = sec->vma - pe->pe_opthdr.ImageBase;
}

static void rsrc_process_section(bfd *abfd, struct coff_final_link_info *pfinfo) {
    rsrc_directory new_table;
    bfd_size_type size;
    asection *sec;
    pe_data_type *pe;
    bfd_vma rva_bias;
    bfd_byte *datastart = NULL;
    bfd_byte *dataend;
    bfd_byte *new_data;
    unsigned int num_resource_sets;
    rsrc_directory *type_tables = NULL;
    rsrc_write_data write_data;
    unsigned int num_input_rsrc;
    unsigned int max_num_input_rsrc;
    ptrdiff_t *rsrc_sizes = NULL;
    
    initialize_new_table(&new_table);
    
    sec = get_rsrc_section(abfd, &size);
    if (sec == NULL)
        return;
    
    pe = pe_data(abfd);
    if (pe == NULL)
        return;
    
    rva_bias = calculate_rva_bias(sec, pe);
    
    if (!bfd_malloc_and_get_section(abfd, sec, &datastart))
        goto end;
    
    num_input_rsrc = count_input_rsrc_sections(pfinfo, &rsrc_sizes, &max_num_input_rsrc);
    if (num_input_rsrc == -1)
        goto end;
    
    if (num_input_rsrc < 2)
        goto end;
    
    dataend = datastart + size;
    num_resource_sets = count_resource_sets(abfd, datastart, size, rsrc_sizes, rva_bias);
    if (num_resource_sets == 0)
        goto end;
    
    BFD_ASSERT(num_resource_sets == num_input_rsrc);
    
    type_tables = build_type_tables(abfd, datastart, dataend, rsrc_sizes,
                                   num_resource_sets, rva_bias);
    if (type_tables == NULL)
        goto end;
    
    copy_table_metadata(&new_table, type_tables);
    merge_table_chains(&new_table, type_tables, num_resource_sets);
    
    sizeof_leaves = sizeof_strings = sizeof_tables_and_entries = 0;
    rsrc_compute_region_sizes(&new_table);
    sizeof_strings = (sizeof_strings + STRING_ALIGNMENT) & ~STRING_ALIGNMENT;
    
    new_data = bfd_zalloc(abfd, size);
    if (new_data == NULL)
        goto end;
    
    setup_write_data(&write_data, abfd, new_data, sec, pe);
    rsrc_write_directory(&write_data, &new_table);
    
    bfd_set_section_contents(pfinfo->output_bfd, sec, new_data, 0, size);
    sec->size = sec->rawsize = size;
    
end:
    free(datastart);
    free(rsrc_sizes);
}

/* Handle the .idata section and other things that need symbol table
   access.  */

static bool is_hash_defined(struct coff_link_hash_entry *h1)
{
    return h1 != NULL &&
           (h1->root.type == bfd_link_hash_defined ||
            h1->root.type == bfd_link_hash_defweak) &&
           h1->root.u.def.section != NULL &&
           h1->root.u.def.section->output_section != NULL;
}

static bfd_vma get_virtual_address(struct coff_link_hash_entry *h1)
{
    return h1->root.u.def.value +
           h1->root.u.def.section->output_section->vma +
           h1->root.u.def.section->output_offset;
}

static bool process_idata_section(bfd *abfd, struct bfd_link_info *info, 
                                  const char *section_name, int directory_index,
                                  bool set_size)
{
    struct coff_link_hash_entry *h1 = coff_link_hash_lookup(
        coff_hash_table(info), section_name, false, false, true);
    
    if (!is_hash_defined(h1))
    {
        _bfd_error_handler(
            _("%pB: unable to fill in DataDirectory[%d]: %s is missing"),
            abfd, directory_index, section_name);
        return false;
    }
    
    if (set_size)
    {
        pe_data(abfd)->pe_opthdr.DataDirectory[directory_index].Size =
            get_virtual_address(h1) - 
            pe_data(abfd)->pe_opthdr.DataDirectory[directory_index].VirtualAddress;
    }
    else
    {
        pe_data(abfd)->pe_opthdr.DataDirectory[directory_index].VirtualAddress =
            get_virtual_address(h1);
    }
    
    return true;
}

static bool process_import_table(bfd *abfd, struct bfd_link_info *info)
{
    struct coff_link_hash_entry *h1 = coff_link_hash_lookup(
        coff_hash_table(info), ".idata$2", false, false, true);
    
    if (h1 == NULL)
        return true;
    
    bool result = true;
    
    if (!is_hash_defined(h1))
    {
        _bfd_error_handler(
            _("%pB: unable to fill in DataDirectory[%d]: %s is missing"),
            abfd, PE_IMPORT_TABLE, ".idata$2");
        result = false;
    }
    else
    {
        pe_data(abfd)->pe_opthdr.DataDirectory[PE_IMPORT_TABLE].VirtualAddress =
            get_virtual_address(h1);
    }
    
    if (!process_idata_section(abfd, info, ".idata$4", PE_IMPORT_TABLE, true))
        result = false;
    
    if (!process_idata_section(abfd, info, ".idata$5", PE_IMPORT_ADDRESS_TABLE, false))
        result = false;
    
    if (!process_idata_section(abfd, info, ".idata$6", PE_IMPORT_ADDRESS_TABLE, true))
        result = false;
    
    return result;
}

static bool process_iat_symbols(bfd *abfd, struct bfd_link_info *info)
{
    struct coff_link_hash_entry *h_start = coff_link_hash_lookup(
        coff_hash_table(info), "__IAT_start__", false, false, true);
    
    if (!is_hash_defined(h_start))
        return true;
    
    bfd_vma iat_va = get_virtual_address(h_start);
    
    struct coff_link_hash_entry *h_end = coff_link_hash_lookup(
        coff_hash_table(info), "__IAT_end__", false, false, true);
    
    if (!is_hash_defined(h_end))
    {
        _bfd_error_handler(
            _("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
            abfd, PE_IMPORT_ADDRESS_TABLE, "__IAT_end__");
        return false;
    }
    
    pe_data(abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].Size =
        get_virtual_address(h_end) - iat_va;
    
    if (pe_data(abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].Size != 0)
    {
        pe_data(abfd)->pe_opthdr.DataDirectory[PE_IMPORT_ADDRESS_TABLE].VirtualAddress =
            iat_va - pe_data(abfd)->pe_opthdr.ImageBase;
    }
    
    return true;
}

static bool process_delay_import(bfd *abfd, struct bfd_link_info *info)
{
    struct coff_link_hash_entry *h_start = coff_link_hash_lookup(
        coff_hash_table(info), "__DELAY_IMPORT_DIRECTORY_start__", 
        false, false, true);
    
    if (!is_hash_defined(h_start))
        return true;
    
    bfd_vma delay_va = get_virtual_address(h_start);
    
    struct coff_link_hash_entry *h_end = coff_link_hash_lookup(
        coff_hash_table(info), "__DELAY_IMPORT_DIRECTORY_end__", 
        false, false, true);
    
    if (!is_hash_defined(h_end))
    {
        _bfd_error_handler(
            _("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
            abfd, PE_DELAY_IMPORT_DESCRIPTOR, "__DELAY_IMPORT_DIRECTORY_end__");
        return false;
    }
    
    pe_data(abfd)->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR].Size =
        get_virtual_address(h_end) - delay_va;
    
    if (pe_data(abfd)->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR].Size != 0)
    {
        pe_data(abfd)->pe_opthdr.DataDirectory[PE_DELAY_IMPORT_DESCRIPTOR].VirtualAddress =
            delay_va - pe_data(abfd)->pe_opthdr.ImageBase;
    }
    
    return true;
}

static void build_symbol_name(char *name, bfd *abfd, const char *suffix)
{
    name[0] = bfd_get_symbol_leading_char(abfd);
    strcpy(name + !!name[0], suffix);
}

static bool process_tls_table(bfd *abfd, struct bfd_link_info *info)
{
    char name[20];
    build_symbol_name(name, abfd, "_tls_used");
    
    struct coff_link_hash_entry *h1 = coff_link_hash_lookup(
        coff_hash_table(info), name, false, false, true);
    
    if (h1 == NULL)
        return true;
    
    if (!is_hash_defined(h1))
    {
        _bfd_error_handler(
            _("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
            abfd, PE_TLS_TABLE, name);
        return false;
    }
    
    pe_data(abfd)->pe_opthdr.DataDirectory[PE_TLS_TABLE].VirtualAddress =
        get_virtual_address(h1) - pe_data(abfd)->pe_opthdr.ImageBase;
    
#if !defined(COFF_WITH_pep) && !defined(COFF_WITH_pex64) && !defined(COFF_WITH_peAArch64) && !defined(COFF_WITH_peLoongArch64) && !defined(COFF_WITH_peRiscV64)
    #define TLS_TABLE_SIZE 0x18
#else
    #define TLS_TABLE_SIZE 0x28
#endif
    
    pe_data(abfd)->pe_opthdr.DataDirectory[PE_TLS_TABLE].Size = TLS_TABLE_SIZE;
    return true;
}

static bool is_xp_compatible(bfd *abfd)
{
    return bfd_get_arch(abfd) == bfd_arch_i386 &&
           ((bfd_get_mach(abfd) & ~bfd_mach_i386_intel_syntax) == bfd_mach_i386_i386) &&
           ((pe_data(abfd)->pe_opthdr.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) ||
            (pe_data(abfd)->pe_opthdr.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI)) &&
           (pe_data(abfd)->pe_opthdr.MajorSubsystemVersion * 256 +
            pe_data(abfd)->pe_opthdr.MinorSubsystemVersion <= 0x0501);
}

static bool process_load_config_table(bfd *abfd, struct bfd_link_info *info)
{
    char name[20];
    char data[4];
    
    build_symbol_name(name, abfd, "_load_config_used");
    
    struct coff_link_hash_entry *h1 = coff_link_hash_lookup(
        coff_hash_table(info), name, false, false, true);
    
    if (h1 == NULL)
        return true;
    
    if (!is_hash_defined(h1))
    {
        _bfd_error_handler(
            _("%pB: unable to fill in DataDirectory[%d]: %s not defined correctly"),
            abfd, PE_LOAD_CONFIG_TABLE, name);
        return false;
    }
    
    pe_data(abfd)->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].VirtualAddress =
        get_virtual_address(h1) - pe_data(abfd)->pe_opthdr.ImageBase;
    
    if (pe_data(abfd)->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].VirtualAddress &
        (bfd_arch_bits_per_address(abfd) / bfd_arch_bits_per_byte(abfd) - 1))
    {
        _bfd_error_handler(
            _("%pB: unable to fill in DataDirectory[%d]: %s not properly aligned"),
            abfd, PE_LOAD_CONFIG_TABLE, name);
        return false;
    }
    
    if (!bfd_get_section_contents(abfd,
            h1->root.u.def.section->output_section, data,
            h1->root.u.def.section->output_offset + h1->root.u.def.value, 4))
    {
        _bfd_error_handler(
            _("%pB: unable to fill in DataDirectory[%d]: size can't be read from %s"),
            abfd, PE_LOAD_CONFIG_TABLE, name);
        return false;
    }
    
    uint32_t size = bfd_get_32(abfd, data);
    
    #define XP_COMPAT_SIZE 64
    pe_data(abfd)->pe_opthdr.DataDirectory[PE_LOAD_CONFIG_TABLE].Size =
        is_xp_compatible(abfd) ? XP_COMPAT_SIZE : size;
    
    if (size > h1->root.u.def.section->size - h1->root.u.def.value)
    {
        _bfd_error_handler(
            _("%pB: unable to fill in DataDirectory[%d]: size too large for the containing section"),
            abfd, PE_LOAD_CONFIG_TABLE);
        return false;
    }
    
    return true;
}

#if !defined(COFF_WITH_pep) && (defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined(COFF_WITH_peRiscV64))
static bool process_pdata_section(bfd *abfd, struct coff_final_link_info *pfinfo)
{
    asection *sec = bfd_get_section_by_name(abfd, ".pdata");
    
    if (!sec)
        return true;
    
    bfd_size_type x = sec->rawsize;
    bfd_byte *tmp_data;
    
    if (!bfd_malloc_and_get_section(abfd, sec, &tmp_data))
        return false;
    
    #define PDATA_ENTRY_SIZE 12
    qsort(tmp_data, (size_t)(x / PDATA_ENTRY_SIZE), PDATA_ENTRY_SIZE, sort_x64_pdata);
    bfd_set_section_contents(pfinfo->output_bfd, sec, tmp_data, 0, x);
    free(tmp_data);
    
    return true;
}
#endif

bool _bfd_XXi_final_link_postscript(bfd *abfd, struct coff_final_link_info *pfinfo)
{
    struct bfd_link_info *info = pfinfo->info;
    bool result = true;
    
    struct coff_link_hash_entry *h1 = coff_link_hash_lookup(
        coff_hash_table(info), ".idata$2", false, false, true);
    
    if (h1 != NULL)
    {
        if (!process_import_table(abfd, info))
            result = false;
    }
    else
    {
        if (!process_iat_symbols(abfd, info))
            result = false;
    }
    
    if (!process_delay_import(abfd, info))
        result = false;
    
    if (!process_tls_table(abfd, info))
        result = false;
    
    if (!process_load_config_table(abfd, info))
        result = false;
    
#if !defined(COFF_WITH_pep) && (defined(COFF_WITH_pex64) || defined(COFF_WITH_peAArch64) || defined(COFF_WITH_peLoongArch64) || defined(COFF_WITH_peRiscV64))
    if (!process_pdata_section(abfd, pfinfo))
        result = false;
#endif
    
    rsrc_process_section(abfd, pfinfo);
    
    return result;
}
