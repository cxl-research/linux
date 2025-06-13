// SPDX-License-Identifier: GPL-2.0

/*
 * Congestier Migrate Functionality
 *
 * Copyright (c) 2025 Alan Nair
 */

#include <linux/congestier.h>
#include <linux/rmap.h>

#include <asm/tlbflush.h>

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
	struct folio *dst;
	int ret;
};

static bool remap_folio(struct folio *folio, struct vm_area_struct *vma,
		  unsigned long address, void *arg)
{
	struct mm_struct *mm = vma->vm_mm;
	struct remap_args *remap_args = (struct remap_args *)arg;
	struct folio *dstfolio = remap_args->dst;
	struct page *page, *newpage;
	DEFINE_FOLIO_VMA_WALK(pvmw, folio, vma, address, 0);
	unsigned long pfn;
	pte_t oldpte, newpte;
	bool ret = true;

	remap_args->ret = -EAGAIN;
	while (page_vma_mapped_walk(&pvmw)) {
		if (!pvmw.pte) {
			printk("UNEXPECTED: pmd-mapped page\n");
			break;
		}

		address = pvmw.address;
		oldpte = ptep_get(pvmw.pte);
		pfn = pte_pfn(oldpte);
		page = folio_page(folio, 0);
		newpage = folio_page(dstfolio, 0);

		newpte = pte_mkold(mk_pte(newpage, READ_ONCE(vma->vm_page_prot)));
		if (pte_write(oldpte)) {
			newpte = pte_mkwrite(newpte, vma);
		} else {
			newpte = pte_wrprotect(newpte);
		}

		oldpte = ptep_get(pvmw.pte);
		if (pte_dirty(oldpte)) {
			/* Keep the old page. Discard new. */
			remap_args->ret = MIGRATEPAGE_UNMAP;
		} else {
			if (arch_tlbbatch_should_defer(mm)) {
				oldpte = ptep_get_and_clear(mm, address, pvmw.pte);
				set_tlb_ubc_flush_pending(mm, oldpte, address);
			} else {
				oldpte = ptep_clear_flush(vma, address, pvmw.pte);
			}

			set_pte_at(vma->vm_mm, address, pvmw.pte, newpte);
			folio_remove_rmap_pte(folio, page, vma);
			folio_add_anon_rmap_pte(dstfolio, newpage, vma, address, RMAP_NONE);

			folio_put(folio); /* refcnt should become 1 */
			list_del(&folio->lru);
			// folio_get(dstfolio); /* refcnt should become 2 */
			dstfolio->index = folio->index;
			dstfolio->mapping = folio->mapping;
			if (folio_test_swapbacked(folio))
				__folio_set_swapbacked(dstfolio);
			folio_migrate_flags(dstfolio, folio);
			folio_add_lru(dstfolio);
			remap_args->ret = MIGRATEPAGE_SUCCESS;
		}
	}
	return ret;
}

static int copy_and_remap_folio(struct folio *src, new_folio_t get_new_folio,
													free_folio_t put_new_folio, unsigned long private)
{
	int rc = -EAGAIN;
	struct folio *dst;
	struct remap_args remap_args;
	struct anon_vma *anon_vma = NULL;
	struct rmap_walk_control rwc_mkclean = {
		.rmap_one = rwc_mkclean_pte,
		.anon_lock = folio_lock_anon_vma_read,
	};
	struct rmap_walk_control rwc_remap_flush = {
		.rmap_one = remap_folio,
		.arg = &remap_args,
		.anon_lock = folio_lock_anon_vma_read,
		.done = folio_is_not_mapped,
	};

	dst = get_new_folio(src, private);
	if (!dst)
		return -ENOMEM;
	dst->private = NULL;
	remap_args.dst = dst;

	rmap_walk(src, &rwc_mkclean);
	folio_copy(dst, src);

	if (!folio_trylock(src))
		return -EAGAIN;

	if (!folio_trylock(dst))
		goto unlock;

	anon_vma = folio_get_anon_vma(src);

	/* src->mapcnt should be 0 after this */
	// printk(KERN_INFO "carf: %p %p refs=(%d %d) maps=(%d %d) nid=(%d %d)\n",
	// 			src, dst, folio_ref_count(src), folio_ref_count(dst),
	// 			folio_mapcount(src), folio_mapcount(dst),
	// 			folio_nid(src), folio_nid(dst));
	rmap_walk(src, &rwc_remap_flush);
	if (remap_args.ret == MIGRATEPAGE_SUCCESS)
		rc = MIGRATEPAGE_SUCCESS;
	// printk(KERN_INFO "carf: %p %p refs=(%d %d) maps=(%d %d) nid=(%d %d) ret=%d\n",
	// 			src, dst, folio_ref_count(src), folio_ref_count(dst),
	// 			folio_mapcount(src), folio_mapcount(dst),
	// 			folio_nid(src), folio_nid(dst), remap_args.ret);
	// printk(KERN_INFO "-----\n");

	if (folio_mapped(src)) {
		/* restore folios to correct lists */
		if (put_new_folio)
			put_new_folio(dst, private);
		else
			folio_put(dst);
	}

	put_anon_vma(anon_vma);
	folio_unlock(dst);
unlock:
	folio_unlock(src);
	return rc;
}

struct congestier_migrate_stats {
	int nr_succeeded;
	int nr_failed;
};

static int __congestier_migrate_pages(struct list_head *from,
		new_folio_t get_new_folio, free_folio_t put_new_folio,
		unsigned long private, struct congestier_migrate_stats *stats)
{
	int retry = 1, nr_pass = 3;
	int nr_failed = 0, nr_retry_pages = 0;
	int rc, pass, nr_pages;
	bool large, anon, mapped_once, ksm;
	struct folio *folio, *folio2;

	for (pass = 0; pass < nr_pass && retry; pass++) {
		retry = 0;
		nr_retry_pages = 0;

		list_for_each_entry_safe(folio, folio2, from, lru) {
			nr_pages = folio_nr_pages(folio);
			large = folio_test_large(folio);
			anon = folio_test_anon(folio);
			mapped_once = (folio_mapcount(folio) == 1);
			ksm = folio_test_ksm(folio);

			if (nr_pages > 1 || large || !anon || !mapped_once || ksm) {
				printk(KERN_INFO "Unexpected Page Type %d %d %d %d %d\n",
					nr_pages, large, anon, mapped_once, ksm);
				nr_failed += nr_pages;
				continue;
			}

			rc = copy_and_remap_folio(folio, get_new_folio, put_new_folio, private);

			switch(rc) {
			case MIGRATEPAGE_SUCCESS:
				stats->nr_succeeded += nr_pages;
				break;
			case -EAGAIN:
				retry++;
				nr_retry_pages += nr_pages;
				break;
			default:
				nr_failed++;
				stats->nr_failed += nr_pages;
				break;
			}
		}
	}
	nr_failed += retry;
	stats->nr_failed += nr_retry_pages;
	return nr_failed;
}

int congestier_migrate_pages(struct list_head *folios,
		new_folio_t get_new_folio, free_folio_t put_new_folio,
		unsigned long private, enum migrate_mode mode,
		int reason, unsigned int *nr_success)
{
	int rc;
	struct congestier_migrate_stats stats = { 0 };

	if (mode != MIGRATE_ASYNC || reason != MR_CONGESTIER)
		return -EINVAL;

	rc = __congestier_migrate_pages(folios, get_new_folio,
												put_new_folio, private, &stats);

	*nr_success = stats.nr_succeeded;
	return rc;
}

#endif /* CONFIG_CONGESTIER_TRANSACTIONAL_MIGRATE */