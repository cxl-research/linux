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
	int mapped_new, mapped_old;
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

		pr_info("remap_folio: %lx (%d,%d) -> (%d,%d)\n",
			address, folio_mapcount(folio), folio_ref_count(folio),
			folio_mapcount(dstfolio), folio_ref_count(dstfolio));

		newpte = pte_mkold(mk_pte(newpage, READ_ONCE(vma->vm_page_prot)));
		if (pte_write(oldpte)) {
			newpte = pte_mkwrite(newpte, vma);
		} else {
			newpte = pte_wrprotect(newpte);
		}

		oldpte = ptep_get(pvmw.pte);
		if (pte_dirty(oldpte)) {
			/* Keep the old page. Discard new. */
			remap_args->mapped_old++;
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

			dstfolio->index = folio->index;
			dstfolio->mapping = folio->mapping;
			if (folio_test_swapbacked(folio))
				__folio_set_swapbacked(dstfolio);
			folio_migrate_flags(dstfolio, folio);
			folio_add_lru(dstfolio);
			remap_args->mapped_new++;
		}
	}
	pr_info("RET SUCCESSFULLY\n");
	return ret;
}

static int copy_and_remap_folio(struct folio *src, new_folio_t get_new_folio,
													free_folio_t put_new_folio, unsigned long private)
{
	int rc = -EAGAIN, mapcnt = folio_mapcount(src);
	struct folio *dst;
	struct remap_args remap_args = { 0 };
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

	rmap_walk(src, &rwc_remap_flush);
	if (remap_args.mapped_new == mapcnt) {
		rc = MIGRATEPAGE_SUCCESS;
		pr_info("HERRRE222 %lx %d (%d,%d)->(%d,%d)!!\n", 
			(unsigned long)src,	rc, 
			folio_ref_count(src), folio_mapcount(src),
			folio_ref_count(dst), folio_mapcount(dst));
		list_del(&src->lru);
		// if (folio_ref_count(src))
		// 	folio_put(src);
		pr_info("HERRRE332!!\n");
	} else {
		/* restore folios to correct lists */
		pr_info("XGDCJHCKF!!\n");
		if (put_new_folio)
			put_new_folio(dst, private);
		else
			folio_put(dst);
	}

	if (anon_vma)
		put_anon_vma(anon_vma);
	folio_unlock(dst);
unlock:
	folio_unlock(src);
	return rc;
}

struct congestier_migrate_stats {
	int nr_succeeded, copy_remap_succeeded;
	int nr_failed;
};

static int __congestier_migrate_pages(struct list_head *from,
		new_folio_t get_new_folio, free_folio_t put_new_folio,
		unsigned long private, struct congestier_migrate_stats *stats)
{
	int retry = 1, nr_pass = 1;
	int nr_failed = 0, nr_retry_pages = 0;
	int rc, pass, nr_pages;
	bool large, anon, mapped_once, ksm, do_copy_remap = false;
	struct folio *folio, *folio2;
	LIST_HEAD(temp_folios);
	LIST_HEAD(failed_folios);

	for (pass = 0; pass < nr_pass && retry; pass++) {
		retry = 0;
		nr_retry_pages = 0;

		list_for_each_entry_safe(folio, folio2, from, lru) {
			nr_pages = folio_nr_pages(folio);
			large = folio_test_large(folio);
			anon = folio_test_anon(folio);
			mapped_once = (folio_mapcount(folio) == 1);
			ksm = folio_test_ksm(folio);

			// if (nr_pages > 1 || large || !anon || !mapped_once || ksm) {
			if (ksm) {
				printk(KERN_INFO "Unexpected Page Type flags=%lx maps=%d refs=%d anon=%d movable=%lx\n",
														folio->flags, folio_mapcount(folio), folio_ref_count(folio), anon,
														((unsigned long)folio->mapping & PAGE_MAPPING_FLAGS));
				nr_failed += nr_pages;
				continue;
			}

			if (anon) {
				rc = copy_and_remap_folio(folio, get_new_folio, put_new_folio, private);
				do_copy_remap = true;
			} else {
				list_move_tail(&folio->lru, &temp_folios);
				rc = migrate_pages(&temp_folios, get_new_folio, put_new_folio,
						private, MIGRATE_ASYNC, MR_CONGESTIER, &stats->nr_succeeded);
				if (!list_empty(&temp_folios))
					list_splice_init(&temp_folios, &failed_folios);
				do_copy_remap = false;
			}

			switch(rc) {
			case MIGRATEPAGE_SUCCESS:
				stats->nr_succeeded += nr_pages;
				if (do_copy_remap)
					stats->copy_remap_succeeded += nr_pages;
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
		if (!list_empty(&failed_folios))
			list_splice_tail_init(&failed_folios, from);
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