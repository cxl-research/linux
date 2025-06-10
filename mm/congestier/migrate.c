// SPDX-License-Identifier: GPL-2.0

/*
 * Congestier Migrate Functionality
 *
 * Copyright (c) 2025 Alan Nair
 */

#include <linux/congestier.h>
#include <linux/rmap.h>

#include "../internal.h"

#ifdef CONFIG_CONGESTIER_TRANSACTIONAL_MIGRATE

static bool rwc_mkclean_pte(struct folio *folio,
		struct vm_area_struct *vma, unsigned long addr, void *arg)
{
	DEFINE_FOLIO_VMA_WALK(pvmw, folio, vma, addr, 0);
	while (page_vma_mapped_walk(&pvmw)) {
		addr = pvmw.address;
		if (pvmw.pte) {
			ptep_test_and_clear_dirty(vma->vm_mm, addr, pvmw.pte);
		} else {
			/* UNEXPECTED: pmd-mapped page ? */
			WARN_ON_ONCE(true);
		}
	}
	return true;
}

struct remap_args {
	struct folio *new_folio;
	bool mapped_new_folio;
};

static bool rwc_remap_pte(struct folio *folio,
		struct vm_area_struct *vma, unsigned long addr, void *arg)
{
	struct page *page, *subpage;
	struct remap_args *remap_args = (struct remap_args *)arg;
	struct folio *new_folio = remap_args->new_folio;
	unsigned long pfn;
	pte_t oldpte, newpte;
	DEFINE_FOLIO_VMA_WALK(pvmw, folio, vma, addr, 0);

	while (page_vma_mapped_walk(&pvmw)) {
		addr = pvmw.address;
		if (!pvmw.pte)
			return false;

		pfn = pte_pfn(ptep_get(pvmw.pte));
		subpage = folio_page(folio, pfn - folio_pfn(folio));

		/* NUKE the old mapping */
		oldpte = ptep_clear_flush(vma, addr, pvmw.pte);

		new_folio = new_folio - folio->index + linear_page_index(vma, addr);
		if (pte_dirty(oldpte)) {
			/* Remap the old page back */
			remap_args->mapped_new_folio = false;
			page = folio_page(folio, 0);
			newpte = pte_mkold(
				mk_pte(page, READ_ONCE(vma->vm_page_prot)));
			if (pte_write(oldpte))
				newpte = maybe_mkwrite(newpte, vma);
			else
				newpte = pte_wrprotect(newpte);
		} else {
			/* Create mapping for new page */
			remap_args->mapped_new_folio = true;
			folio_put(folio);
			folio_get(new_folio);
			page = folio_page(new_folio, 0);
			newpte = pte_mkold(mk_pte(page, READ_ONCE(vma->vm_page_prot)));
			if (pte_write(oldpte)) 
				newpte = pte_mkwrite(newpte, vma);
			else
				newpte = pte_wrprotect(newpte);
		}

		set_pte_at(vma->vm_mm, addr, pvmw.pte, newpte);

		if (remap_args->mapped_new_folio) {
			folio_add_anon_rmap_pte(new_folio, page, vma, addr,
						RMAP_NONE);
			folio_remove_rmap_pte(folio, subpage, vma);
		}

		update_mmu_cache(vma, addr, pvmw.pte);
	}
	return true;
}

static int copy_and_remap_folio(struct folio *src, struct folio *dst)
{
	int rc = -ENOMEM;
	unsigned long srcflags;
	struct address_space *mapping;
	struct rmap_walk_control rwc_mkclean = {
		.rmap_one = rwc_mkclean_pte,
		.anon_lock = folio_lock_anon_vma_read,
	};
	struct remap_args remap_args = {
		.new_folio = dst,
		.mapped_new_folio = false,
	};
	struct rmap_walk_control rwc_remap = {
		.rmap_one = rwc_remap_pte,
		.arg = &remap_args,
		.done = folio_is_not_mapped,
		.anon_lock = folio_lock_anon_vma_read,
	};

	if (!folio_trylock(src))
		return -EAGAIN;

	mapping = folio_mapping(src);
	if (!folio_trylock(dst))
		goto out;

	srcflags = READ_ONCE(src->flags);
	rmap_walk(src, &rwc_mkclean);
	folio_copy(dst, src);

	rc = folio_migrate_mapping(mapping, dst, src, 1);
	if (rc) {
		WRITE_ONCE(src->flags, srcflags);
		rc = -EAGAIN;
		goto out2;
	}

	folio_migrate_flags(dst, src);
	rmap_walk(src, &rwc_remap);

	if (remap_args.mapped_new_folio)
		rc = MIGRATEPAGE_SUCCESS;
	else
		rc = MIGRATEPAGE_UNMAP;

out2:
	folio_unlock(dst);
out:
	folio_unlock(src);
	return rc;
}

static int unmap_and_move_folio(struct folio *folio, new_folio_t getfolio,
		free_folio_t putfolio, unsigned long private)
{
	struct folio *newfolio = NULL;
	int rc = MIGRATEPAGE_SUCCESS;

	if (folio_mapcount(folio) != 1 || !folio_test_anon(folio))
		return -EAGAIN;

	newfolio = getfolio(folio, private);
	if (!newfolio)
		return -ENOMEM;

	rc = copy_and_remap_folio(folio, newfolio);

	if (rc != -EAGAIN) {
		/* If not trying again, we dont need folio anymore */
		list_del(&folio->lru);
		folio_putback_lru(folio);
	}

	if (rc != MIGRATEPAGE_SUCCESS) {
		if (putfolio)
			putfolio(newfolio, private);
		else
			folio_put(newfolio);
	} else {
		folio_add_lru(newfolio);
	}

	return rc;
}

int congestier_migrate_pages(struct list_head *folios,
		new_folio_t new_folio, free_folio_t free_folio,
		unsigned long private, enum migrate_mode mode,
		int reason, unsigned int *nr_migrated)
{
	struct folio *pos, *next;
	int retry = 1, nr_failed = 0, rc;

	(*nr_migrated) = 0;

	for (int pass = 0; pass < 3 && retry; pass++) {
		retry = 0;
		list_for_each_entry_safe(pos, next, folios, lru) {
			rc = unmap_and_move_folio(pos, new_folio, free_folio, private);
			switch (rc) {
			case MIGRATEPAGE_SUCCESS:
				(*nr_migrated)++;
				break;
			case -EAGAIN:
				retry++;
				break;
			case -ENOMEM:
				nr_failed++;
				goto out;
			default:
				nr_failed++;
				break;
			}
		}
	}
	nr_failed += retry;
	rc = nr_failed;
out:
	return rc;
}

#endif /* CONFIG_CONGESTIER_TRANSACTIONAL_MIGRATE */

#ifdef CONFIG_CONGESTIER_SHADOW_PAGING
#endif /* CONFIG_CONGESTIER_SHADOW_PAGING */