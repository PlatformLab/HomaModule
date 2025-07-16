// SPDX-License-Identifier: BSD-2-Clause

/* This file implements a special-purpose queuing discipline for Homa.
 * This queuing discipline serves the following purposes:
 * - It paces output traffic so that queues do not build up in the NIC
 *   (they build up here instead).
 * - It implements the SRPT policy for Homa traffic (highest priority goes
 *   to the message with the fewest bytes remaining to transmit).
 * - It manages TCP traffic as well as Homa traffic, so that TCP doesn't
 *   result in long NIC queues.
 * - When queues do build up, it balances output traffic between Homa and TCP.
 */

#include "homa_impl.h"
#include "homa_pacer.h"
#include "homa_qdisc.h"
#include "timetrace.h"

#include <linux/ethtool.h>
#include <net/pkt_sched.h>

static struct Qdisc_ops homa_qdisc_ops __read_mostly = {
        .id = "homa",
        .priv_size = sizeof(struct homa_qdisc),
        .enqueue = homa_qdisc_enqueue,
        .dequeue = qdisc_dequeue_head,
        .peek = qdisc_peek_head,
        .init = homa_qdisc_init,
        .reset = qdisc_reset_queue,
        .destroy = homa_qdisc_destroy,
        .owner = THIS_MODULE,
};

/**
 * homa_qdisc_register() - Invoked when the Homa module is loaded; makes
 * the homa qdisk known to Linux.
 * Return:  0 for success or a negative errno if an error occurred.
 */
int homa_qdisc_register(void)
{
        return register_qdisc(&homa_qdisc_ops);
}

/**
 * homa_qdisc_unregister() - Invoked when the Homa module is about to be
 * unloaded: deletes all information related to the homa qdisc.
 */
void homa_qdisc_unregister(void)
{
        unregister_qdisc(&homa_qdisc_ops);
}

/**
 * homa_qdisc_init() - Initialize a new instance of this queuing discipline.
 * @sch:      Qdisc to initialize.
 * @opt:      Options for this qdisc; not currently used.
 * @extack:   For reporting detailed information relating to errors; not used.
 * Return:    0 for success, otherwise a negative errno.
 */
int homa_qdisc_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
        struct homa_qdisc *q = qdisc_priv(sch);
        struct homa_qdisc_dev *qdev;
        struct homa_net *hnet;
        bool found = false;

        hnet = homa_net_from_net(dev_net(sch->dev_queue->dev));
	spin_lock_bh(&hnet->qdisc_devs_lock);
        list_for_each_entry(qdev, &hnet->qdisc_devs, links) {
                if (qdev->dev == sch->dev_queue->dev) {
                        found = true;
                        break;
                }
        }
        if (!found) {
                qdev = homa_qdisc_qdev_new(hnet, sch->dev_queue->dev);
                if (IS_ERR(qdev)) {
	                spin_unlock_bh(&hnet->qdisc_devs_lock);
                        return PTR_ERR(qdev);
                }
        } else {
                qdev->num_qdiscs++;
        }
	spin_unlock_bh(&hnet->qdisc_devs_lock);

        q->qdev = qdev;
        skb_queue_head_init(&q->queue);

	sch->limit = 10*1024;
        return 0;
}

/**
 * homa_qdisc_qdev_new() - Allocate and initialize a new homa_qdisc_dev.
 * @hnet:     Network namespace for the homa_qdisc_dev.
 * @dev:      NIC that the homa_qdisc_dev will manage.
 * Return     A pointer to the new homa_qdisc_dev, or a PTR_ERR errno.
 */
struct homa_qdisc_dev *homa_qdisc_qdev_new(struct homa_net *hnet,
                                           struct net_device *dev)
        __must_hold(hnet->qdisc_devs_lock)
{
        struct homa_qdisc_dev *qdev;

        qdev = kzalloc(sizeof(*qdev), GFP_ATOMIC);
        if (!qdev)
                return ERR_PTR(-ENOMEM);
        qdev->dev = dev;
        qdev->hnet = hnet;
        qdev->num_qdiscs = 1;
        homa_qdisc_update_sysctl(qdev);
        INIT_LIST_HEAD(&qdev->links);
        skb_queue_head_init(&qdev->homa_deferred);
        skb_queue_head_init(&qdev->tcp_deferred);
	init_waitqueue_head(&qdev->pacer_sleep);
	spin_lock_init(&qdev->pacer_mutex);

	qdev->pacer_kthread = kthread_run(homa_qdisc_pacer_main, qdev,
					  "homa_qdisc_pacer");
	if (IS_ERR(qdev->pacer_kthread)) {
		int error = PTR_ERR(qdev->pacer_kthread);

		pr_err("couldn't create homa qdisc pacer thread: error %d\n",
                       error);
                kfree(qdev);
		return ERR_PTR(error);
	}
        list_add(&qdev->links, &hnet->qdisc_devs);
        return qdev;
}

/**
 * homa_qdisc_destroy() - This function is invoked to perform final cleanup
 * before a qdisc is deleted.
 * @sch:      Qdisc that is being deleted.
 */
void homa_qdisc_destroy(struct Qdisc *sch)
{
        struct homa_qdisc *q = qdisc_priv(sch);
        struct homa_qdisc_dev *qdev = q->qdev;

	spin_lock_bh(&qdev->hnet->qdisc_devs_lock);
        qdev->num_qdiscs--;
        if (qdev->num_qdiscs == 0)
                homa_qdisc_qdev_destroy(qdev);
	spin_unlock_bh(&qdev->hnet->qdisc_devs_lock);
}

/**
 * homa_qdisc_qdev_destroy() - Cleanup and release memory for a homa_qdisc_dev.
 * @qdev:       Object to destroy; its memory will be freed.
 */
void homa_qdisc_qdev_destroy(struct homa_qdisc_dev *qdev)
        __must_hold(qde)
{
	kthread_stop(qdev->pacer_kthread);
	qdev->pacer_kthread = NULL;

        __list_del_entry(&qdev->links);
        homa_qdisc_srpt_free(&qdev->homa_deferred);
        skb_queue_purge(&qdev->tcp_deferred);
        kfree(qdev);
}

/**
 * homa_qdisc_enqueue() - Add a packet to the queue for this qdisc.
 * @skb:      Packet to enqueue.
 * @sch:      Qdisc on which to enqueue @skb.
 * @to_free:  Used when dropping packets.
 */
int homa_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			      struct sk_buff **to_free)
{
        struct homa_qdisc *q = qdisc_priv(sch);
        struct homa_qdisc_dev *qdev = q->qdev;
        struct homa *homa = qdev->hnet->homa;
        int pkt_len;

        if (skb == q->qdev->pacer_skb) {
                q->qdev->pacer_skb = NULL;
                goto enqueue;
        }

        /* The packet length computed by Linux didn't include overheads
         * such as inter-frame gap; add that in here.
         */
        pkt_len = qdisc_skb_cb(skb)->pkt_len + HOMA_ETH_FRAME_OVERHEAD;
        if (pkt_len < homa->pacer->throttle_min_bytes) {
                homa_qdisc_update_link_idle(q->qdev, pkt_len, -1);
                goto enqueue;
        }

        if (!is_homa_pkt(skb)) {
                homa_qdisc_update_link_idle(q->qdev, pkt_len, -1);
                goto enqueue;
        }

        if (homa_qdisc_update_link_idle(q->qdev, pkt_len,
                                        homa->pacer->max_nic_queue_cycles))
                goto enqueue;

        /* This packet needs to be deferred until the NIC queue has
         * been drained a bit.
         */
        homa_qdisc_srpt_enqueue(&qdev->homa_deferred, skb);
	wake_up(&qdev->pacer_sleep);

enqueue:
	if (likely(sch->q.qlen < READ_ONCE(sch->limit)))
		return qdisc_enqueue_tail(skb, sch);
	return qdisc_drop(skb, sch, to_free);
}

/**
 * homa_qdisc_srpt_enqueue() - Add a Homa packet to an skb queue in SRPT
 * priority order.
 * @list:    List on which to enqueue packet (usually &qdev->homa_deferred).
 * @skb:     Packet to enqueue.
 */
void homa_qdisc_srpt_enqueue(struct sk_buff_head *list, struct sk_buff *skb)
{
        struct homa_skb_info *info = homa_get_skb_info(skb);
        struct sk_buff *other;
	unsigned long flags;

        /* Tricky point: only one packet from an RPC may appear in
         * qdev->homa_deferred at once (the earliest one in the message).
         * If later packets from the same message were also in the queue,
         * they would have higher priorities and would get transmitted
         * first, which we don't want. So, if more than one packet from
         * a message is waiting, only the first appears in qdev->homa_deferred;
         * the others are queued up using links in the homa_skb_info of
         * the first packet.
         *
         * This also means that we must scan the list starting at the
         * low-priority end, so we'll notice if there is an earlier
         * (lower priority) packet for the same RPC already in the list.
         */

        info->next_sibling = NULL;
        info->last_sibling = NULL;
	spin_lock_irqsave(&list->lock, flags);
        if (skb_queue_empty(list)) {
                __skb_queue_head(list, skb);
                goto done;
        }
        skb_queue_reverse_walk(list, other) {
                struct homa_skb_info *other_info = homa_get_skb_info(other);

                if (other_info->rpc == info->rpc) {
                        if (!other_info->last_sibling)
                                other_info->next_sibling = skb;
                        else
                                homa_get_skb_info(other_info->last_sibling)->
                                                next_sibling = skb;
                        other_info->last_sibling = skb;
                        break;
                }

                if (other_info->bytes_left <= info->bytes_left) {
                        __skb_queue_after(list, other, skb);
                        break;
                }

                if (skb_queue_is_first(list, other)) {
                        __skb_queue_head(list, skb);
                        break;
                }
        }

done:
	spin_unlock_irqrestore(&list->lock, flags);
}

/**
 * homa_qdisc_srpt_dequeue() - Remove the frontmost packet from a list that
 * is managed with SRPT priority.
 * @list:    List from which to remove packet.
 * Return:   The frontmost packet from the list, or NULL if the list was empty.
 */
struct sk_buff *homa_qdisc_srpt_dequeue(struct sk_buff_head *list)
{
        struct homa_skb_info *sibling_info;
        struct sk_buff *skb, *sibling;
        struct homa_skb_info *info;
	unsigned long flags;

        /* The only tricky element about this function is that skb may
         * have a sibling list. If so, we need to enqueue the next
         * sibling.
         */
	spin_lock_irqsave(&list->lock, flags);
        if (skb_queue_empty(list)) {
	        spin_unlock_irqrestore(&list->lock, flags);
                return NULL;
        }
        skb = list->next;
        __skb_unlink(skb, list);
        info = homa_get_skb_info(skb);
        if (info->next_sibling) {
                /* This is a "compound" packet, containing multiple
                 * packets from the same RPC. Put the next packet
                 * back on the list at the front (it should have even
                 * higher priority than skb, since it is later in the
                 * message).
                 */
                sibling = info->next_sibling;
                sibling_info = homa_get_skb_info(sibling);
                sibling_info->last_sibling = info->last_sibling;
                __skb_queue_head(list, sibling);
        }

	spin_unlock_irqrestore(&list->lock, flags);
        return skb;
}

/**
 * homa_qdisc_srpt_free() - Free all of the packets on @list,
 * including siblings that are nested inside packets on the list.
 * @list:   List containing packets to free, which is managed using
 *          by homa_qdisc_srpt_enqueue and homa_qdisc_srpt_dequeue;
 *          it will be empty on return.
 */
void homa_qdisc_srpt_free(struct sk_buff_head *list)
{
        struct sk_buff *skb;

        while (1) {
                skb = homa_qdisc_srpt_dequeue(list);
                if (!skb)
                        break;
                kfree_skb(skb);
        }
}

/**
 * homa_qdisc_update_link_idle() - This function is invoked before transmitting
 * a packet. If the current NIC queue length is no more than @max_queue_cycles
 * then it updates @qdev->link_idle_time to include @bytes; otherwise it does
 * nothing.
 * @qdev:              Information about the device.
 * @bytes:             Size of a packet that is about to be transmitted;
 *                     includes all headers out through the Ethernet header,
 *                     but not additional overhead such as CRC and gap
 *                     between packets.
 * @max_queue_cycles:  If it will take longer than this amount of time for
 *                     previously queued bytes to be transmitted, then don't
 *                     update @qdev->link_idle_time. A negative value means
 *                     any length queue is OK.
 * Return:             Nonzero if @qdev->link_idle_time was updated, false
 *                     if the queue was too long.
 */
int homa_qdisc_update_link_idle(struct homa_qdisc_dev *qdev, int bytes,
                                int max_queue_cycles)
{
	u64 idle, new_idle, clock, cycles_for_packet;

	cycles_for_packet = qdev->cycles_per_mibyte;
	cycles_for_packet = (cycles_for_packet *
                             (bytes + HOMA_ETH_FRAME_OVERHEAD)) >> 20;

        /* The following loop may be executed multiple times if there
         * are conflicting udpates to qdev->link_idle_time.
         */
	while (1) {
		clock = homa_clock();
		idle = atomic64_read(&qdev->link_idle_time);
		if (idle < clock) {
			new_idle = clock + cycles_for_packet;
		} else {
                        if (max_queue_cycles >= 0 && (idle - clock) >
                                                     max_queue_cycles)
                                return 0;
			new_idle = idle + cycles_for_packet;
                }

		if (atomic64_cmpxchg_relaxed(&qdev->link_idle_time, idle,
					     new_idle) == idle)
			break;
                INC_METRIC(idle_time_conflicts, 1);
	}
	return 1;
}

/**
 * homa_qdisc_pacer_main() - Top-level function for a device-specific
 * thread that is responsible for transmitting deferred packets on that
 * device.
 * @device:  Pointer to a struct homa_qdisc_dev.
 * Return:   Always 0.
 */
int homa_qdisc_pacer_main(void *device)
{
	struct homa_qdisc_dev *qdev = device;
        int status;
        u64 start;

	while (1) {
		if (kthread_should_stop())
			break;
                start = homa_clock();
		homa_qdisc_pacer(qdev);
		INC_METRIC(pacer_cycles, homa_clock() - start);

		if (!skb_queue_empty(&qdev->homa_deferred) ||
                    !skb_queue_empty(&qdev->tcp_deferred)) {
			/* There are more packets to transmit (the NIC queue
                         * must be full); call the pacer again, but first
			 * give other threads a chance to run (otherwise
			 * low-level packet processing such as softirq could
			 * starve).
			 */
			schedule();
			continue;
		}

		tt_record("homa_qdisc pacer sleeping");
		status = wait_event_interruptible(qdev->pacer_sleep,
			kthread_should_stop() ||
                        !skb_queue_empty(&qdev->homa_deferred) ||
                        !skb_queue_empty(&qdev->tcp_deferred));
		tt_record1("homa_qdisc pacer woke up with status %d", status);
		if (status != 0 && status != -ERESTARTSYS)
			break;
	}
	return 0;
}

/**
 * homa_qdisc_pacer() - Transmit a few packets from the homa_deferred and
 * tcp_deferred lists while keeping NIC queue short. There may still be
 * deferred packets when this function returns.
 *
 * Note: this function may be invoked from places other than
 * homa_qdisc_pacer_main. The reason for this is that (as of 10/2019)
 * Linux's thread scheduler is unpredictable and could neglect the thread
 * for long periods of time (e.g., because it is assigned to the same
 * CPU as a busy interrupt handler). This can result in poor utilization
 * of the network link. So, this method gets invoked from other places as
 * well, to increase the likelihood that we keep the link busy. Those other
 * invocations are not guaranteed to happen, so the pacer thread provides a
 * backstop.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_qdisc_pacer(struct homa_qdisc_dev *qdev)
{
	int i;

	/* Make sure only one instance of this function executes at a
	 * time.
	 */
	if (!spin_trylock_bh(&qdev->pacer_mutex))
		return;

	/* Each iteration through the following loop sends one packet. We
	 * limit the number of passes through this loop in order to cap the
	 * time spent in one call to this function (see note in
	 * homa_qdisc_pacer_main about interfering with softirq handlers).
	 */
	for (i = 0; i < 5; i++) {
                struct sk_buff *skb;
		u64 idle_time, now;

		/* If the NIC queue is too long, wait until it gets shorter. */
		now = homa_clock();
		idle_time = atomic64_read(&qdev->link_idle_time);
		while ((now + qdev->hnet->homa->pacer->max_nic_queue_cycles) <
                       idle_time) {
			/* If we've xmitted at least one packet then
			 * return (this helps with testing and also
			 * allows homa_qdisc_pacer_main to yield the core).
			 */
			if (i != 0)
				goto done;
			now = homa_clock();
		}

		/* Note: when we get here, it's possible that the NIC queue is
		 * still too long because other threads have queued packets,
		 * but we transmit anyway so the pacer thread doesn't starve.
		 */
                skb = homa_qdisc_srpt_dequeue(&qdev->homa_deferred);
                if (!skb)
                        break;
                homa_qdisc_update_link_idle(qdev, qdisc_skb_cb(skb)->pkt_len,
                                            -1);

                /* Resubmit the packet. Concentrate all of the (long)
                 * resubmitted packets on device queue 0, in order
                 * to reduce contention between them and short packets
                 * on other queues.
                 */
                qdev->pacer_skb = skb;
                homa_qdisc_resubmit_skb(skb, qdev->dev, 0);
                qdev->pacer_skb = NULL;
	}
done:
	spin_unlock_bh(&qdev->pacer_mutex);
}

/**
 * homa_qdisc_resubmit_skb() - This function is called by the pacer to
 * restart the transmission of an skb that was deferred because of NIC
 * queue length. The packet may be dropped under various error conditions.
 * @skb:     Packet to resubmit.
 * @dev:     Network device to which the packet should be resubmitted.
 * @queue:   Index of desired tx queue on @dev.
 * Return:   Zero for success, otherwise a negative errno.
 */
void homa_qdisc_resubmit_skb(struct sk_buff *skb, struct net_device *dev,
                            int queue)
{
        /* The code of this function was extracted from __dev_xmit_skb
         * (with RCU lock/unlock from __dev_queue_xmit). Ideally this
         * module would simply invoke __dev_xmit_skb, but it isn't
         * globally available.
         */
	struct sk_buff *to_free = NULL;
        struct netdev_queue *txq;
	spinlock_t *root_lock;
        struct Qdisc *q;
	bool contended;

	rcu_read_lock_bh();
        txq = netdev_get_tx_queue(dev, 0);
	q = rcu_dereference_bh(txq->qdisc);
        root_lock = qdisc_lock(q);

	contended = qdisc_is_running(q) || IS_ENABLED(CONFIG_PREEMPT_RT);
	if (unlikely(contended))
		spin_lock(&q->busylock);

	spin_lock(root_lock);
	if (unlikely(test_bit(__QDISC_STATE_DEACTIVATED, &q->state))) {
		__qdisc_drop(skb, &to_free);
	} else {
		WRITE_ONCE(q->owner, smp_processor_id());
                q->enqueue(skb, q, &to_free);
		WRITE_ONCE(q->owner, -1);
		if (qdisc_run_begin(q)) {
			if (unlikely(contended)) {
				spin_unlock(&q->busylock);
				contended = false;
			}
			// __qdisc_run(q);
			qdisc_run_end(q);
		}
	}
	spin_unlock(root_lock);
	if (unlikely(to_free))
		kfree_skb_list_reason(to_free,
				      tcf_get_drop_reason(to_free));
	if (unlikely(contended))
		spin_unlock(&q->busylock);
	rcu_read_unlock_bh();
}

/**
 * homa_qdisc_update_sysctl() - Recompute information in a homa_qdisc_dev
 * that depends on sysctl parameters.
 * @homa:    Used to fetch current sysctl parameter values.
 * @qdev:    Update information here that depends on sysctl values.
 */
void homa_qdisc_update_sysctl(struct homa_qdisc_dev *qdev)
{
        struct ethtool_link_ksettings ksettings;
        struct homa *homa = qdev->hnet->homa;
        const struct ethtool_ops *ops;
	u64 tmp;

        qdev->link_mbps = homa->link_mbps;
        ops = qdev->dev->ethtool_ops;
        if (ops && ops->get_link_ksettings) {
                if (ops->get_link_ksettings(qdev->dev, &ksettings) == 0)
                        qdev->link_mbps = ksettings.base.speed;
        }

        /* Underestimate link bandwidth (overestimate time) by 1%.
         *
         *                                 cycles/sec
         * cycles/mibyte =    (101/100) * -------------
         *                                 mibytes/sec
         *
         *                        101 * homa_clock_khz() * 1000
         *               =    ---------------------------------------
         *                     100 * link_mbps * (1<<20 / 1000000) / 8
         *
         *                     8 * 1010 * homa_clock_khz()      1<<20
         *               =    ----------------------------- * ---------
         *                              link_mbps              1000000
         */
	tmp = 8ULL * 1010;
        tmp *= homa_clock_khz();
        do_div(tmp, qdev->link_mbps);
        tmp <<= 20;
        do_div(tmp, 1000000);
        qdev->cycles_per_mibyte = tmp;
}

/**
 * homa_qdisc_update_all_sysctl() - Invoked whenever a sysctl value is changed;
 * updates all qdisc structures to reflect new values.
 * @homa:    Overall data about the Homa protocol implementation.
 */
void homa_qdisc_update_all_sysctl(struct homa_net *hnet)
{
        struct homa_qdisc_dev *qdev;

	spin_lock_bh(&hnet->qdisc_devs_lock);
        list_for_each_entry(qdev, &hnet->qdisc_devs, links)
                homa_qdisc_update_sysctl(qdev);
	spin_unlock_bh(&hnet->qdisc_devs_lock);
}
