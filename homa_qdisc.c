// SPDX-License-Identifier: BSD-2-Clause or GPL-2.0+

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
 * homa_qdisc_qdev_get() - Find the homa_qdisc_dev to use for a particular
 * net_device and increment its reference count. Create a new one if there
 * isn't an existing one to use.
 * @hnet:     Network namespace for the homa_qdisc_dev.
 * @dev:      NIC that the homa_qdisc_dev will manage.
 * Return:     A pointer to the new homa_qdisc_dev, or a PTR_ERR errno.
 */
struct homa_qdisc_dev *homa_qdisc_qdev_get(struct homa_net *hnet,
					   struct net_device *dev)
{
	struct homa_qdisc_dev *qdev;

	mutex_lock(&hnet->qdisc_devs_mutex);
	list_for_each_entry(qdev, &hnet->qdisc_devs, links) {
		if (qdev->dev == dev) {
			qdev->refs++;
			goto done;
		}
	}

	qdev = kzalloc(sizeof(*qdev), GFP_ATOMIC);
	if (!qdev) {
		qdev = ERR_PTR(-ENOMEM);
		goto done;
	}
	qdev->dev = dev;
	qdev->hnet = hnet;
	qdev->refs = 1;
	qdev->pacer_qix = -1;
	qdev->redirect_qix = -1;
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
		qdev = ERR_PTR(error);
		goto done;
	}
	list_add(&qdev->links, &hnet->qdisc_devs);

done:
	mutex_unlock(&hnet->qdisc_devs_mutex);
	return qdev;
}

/**
 * homa_qdisc_qdev_put() - Decrement the reference count for a homa_qdisc_qdev
 * and free it if the count becomes zero.
 * @qdev:       Object to unreference.
 */
void homa_qdisc_qdev_put(struct homa_qdisc_dev *qdev)
{
	struct homa_net *hnet = qdev->hnet;

	mutex_lock(&hnet->qdisc_devs_mutex);
	qdev->refs--;
	if (qdev->refs == 0) {
		kthread_stop(qdev->pacer_kthread);
		qdev->pacer_kthread = NULL;

		__list_del_entry(&qdev->links);
		homa_qdisc_free_homa(qdev);
		skb_queue_purge(&qdev->tcp_deferred);
		kfree(qdev);
	}
	mutex_unlock(&hnet->qdisc_devs_mutex);
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
	int i;

	hnet = homa_net(dev_net(sch->dev_queue->dev));
	qdev = homa_qdisc_qdev_get(hnet, sch->dev_queue->dev);
	if (IS_ERR(qdev))
		return PTR_ERR(qdev);

	q->qdev = qdev;
	q->ix = -1;
	for (i = 0; i < qdev->dev->num_tx_queues; i++) {
		if (netdev_get_tx_queue(qdev->dev, i) == sch->dev_queue) {
			q->ix = i;
			break;
		}
	}

	sch->limit = 10 * 1024;
	return 0;
}

/**
 * homa_qdisc_destroy() - This function is invoked to perform final cleanup
 * before a qdisc is deleted.
 * @qdisc:      Qdisc that is being deleted.
 */
void homa_qdisc_destroy(struct Qdisc *qdisc)
{
	struct homa_qdisc *q = qdisc_priv(qdisc);

	qdisc_reset_queue(qdisc);
	homa_qdisc_qdev_put(q->qdev);
}

/**
 * homa_qdisc_set_qixs() - Recompute the @pacer_qix and @redirect_qix
 * fields in @qdev. Upon return, both fields will be valid unless there
 * are no Homa qdiscs associated with qdev's net_device.
 * @qdev:    Identifies net_device containing qnetdev_queues to choose
 *           between.
 */
void homa_qdisc_set_qixs(struct homa_qdisc_dev *qdev)
{
	int i, pacer_qix, redirect_qix;
	struct netdev_queue *txq;
	struct Qdisc *qdisc;

	/* Note: it's safe for multiple instances of this function to
	 * execute concurrently so no synchronization is needed (other
	 * than using RCU to protect against deletion of the underlying
	 * data structures).
	 */

	pacer_qix = -1;
	redirect_qix = -1;
	rcu_read_lock();
	for (i = 0; i < qdev->dev->num_tx_queues; i++) {
		txq = netdev_get_tx_queue(qdev->dev, i);
		qdisc = rcu_dereference_bh(txq->qdisc);
		if (!qdisc || qdisc->ops != &homa_qdisc_ops)
			continue;
		if (pacer_qix == -1) {
			pacer_qix = i;
			redirect_qix = i;
		} else {
			redirect_qix = i;
			break;
		}
	}
	qdev->pacer_qix = pacer_qix;
	qdev->redirect_qix = redirect_qix;
	rcu_read_unlock();
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
	struct homa_data_hdr *h;
	int pkt_len;
	int result;
	int offset;

	pkt_len = qdisc_skb_cb(skb)->pkt_len;
	if (!is_homa_pkt(skb)) {
		homa_qdisc_update_link_idle(qdev, pkt_len, -1);
		goto enqueue;
	}

	/* For Homa packets, transmit control packets and short messages
	 * immediately, bypassing the pacer mechanism completely. We do
	 * this because (a) we don't want to delay control packets, (b) the
	 * pacer's single thread doesn't have enough throughput to handle
	 * all the short packets (whereas processing here happens concurrently
	 * on multiple cores), and (c) there is no way to generate enough
	 * short packets to cause NIC queue buildup, so bypassing the pacer
	 * won't impact the SRPT mechanism significantly.
	 *
	 * Note: it's very important to use message length, not packet
	 * length when deciding whether to bypass the pacer. If packet
	 * length were used, then the short packet at the end of a long
	 * message might be transmitted when all the earlier packets in the
	 * message have been deferred, and the deferred packets might not be
	 * transmitted for a long time due to SRPT. In the meantime, the
	 * receiver will have reserved incoming for those packets. These
	 * reservations can pile up to the point where the receiver can't
	 * issue any grants, even though the "incoming" data isn't going to
	 * be transmitted anytime soon.
	 */

	h = (struct homa_data_hdr *)skb_transport_header(skb);
	offset = ntohl(h->seg.offset);
	if (offset == -1)
		offset = ntohl(h->common.sequence);
	if (h->common.type != DATA || ntohl(h->message_length) <
			homa->pacer->throttle_min_bytes) {
		homa_qdisc_update_link_idle(qdev, pkt_len, -1);
		goto enqueue;
	}

	if (skb_queue_empty(&qdev->homa_deferred) &&
	    homa_qdisc_update_link_idle(qdev, pkt_len,
					homa->pacer->max_nic_queue_cycles))
		goto enqueue;

	/* This packet needs to be deferred until the NIC queue has
	 * been drained a bit.
	 */
	tt_record4("homa_qdisc_enqueue deferring homa data packet for id %d, offset %d, bytes_left %d on qid %d",
		   be64_to_cpu(h->common.sender_id), offset,
		   homa_get_skb_info(skb)->bytes_left, qdev->pacer_qix);
	homa_qdisc_defer_homa(qdev, skb);
	return NET_XMIT_SUCCESS;

enqueue:
	if (is_homa_pkt(skb)) {
		if (h->common.type == DATA) {
			h = (struct homa_data_hdr *)skb_transport_header(skb);
			tt_record4("homa_qdisc_enqueue queuing homa data packet for id %d, offset %d, bytes_left %d on qid %d",
				be64_to_cpu(h->common.sender_id), offset,
				homa_get_skb_info(skb)->bytes_left, q->ix);
		}
	} else {
		tt_record2("homa_qdisc_enqueue queuing non-homa packet, qix %d, pacer_qix %d",
			   q->ix, qdev->pacer_qix);
	}
	if (q->ix != qdev->pacer_qix) {
		if (unlikely(sch->q.qlen >= READ_ONCE(sch->limit)))
			return qdisc_drop(skb, sch, to_free);
		result = qdisc_enqueue_tail(skb, sch);
	} else {
		/* homa_enqueue_special is going to lock a different qdisc,
		 * so in order to avoid deadlocks we have to release the
		 * lock for this qdisc.
		 */
		spin_unlock(qdisc_lock(sch));
		result = homa_qdisc_redirect_skb(skb, qdev, false);
		spin_lock(qdisc_lock(sch));
	}
	return result;
}

/**
 * homa_qdisc_defer_homa() - Add a Homa packet to the deferred list for
 * a qdev.
 * @qdev:    Network device for which the packet should be enqueued.
 * @skb:     Packet to enqueue.
 */
void homa_qdisc_defer_homa(struct homa_qdisc_dev *qdev, struct sk_buff *skb)
{
	struct homa_skb_info *info = homa_get_skb_info(skb);
	u64 now = homa_clock();
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
	spin_lock_irqsave(&qdev->homa_deferred.lock, flags);
	if (skb_queue_empty(&qdev->homa_deferred)) {
		__skb_queue_head(&qdev->homa_deferred, skb);
		wake_up(&qdev->pacer_sleep);
		goto done;
	}
	INC_METRIC(throttled_cycles, now - qdev->last_defer);
	skb_queue_reverse_walk(&qdev->homa_deferred, other) {
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
			__skb_queue_after(&qdev->homa_deferred, other, skb);
			break;
		}

		if (skb_queue_is_first(&qdev->homa_deferred, other)) {
			__skb_queue_head(&qdev->homa_deferred, skb);
			break;
		}
	}

done:
	qdev->last_defer = now;
	spin_unlock_irqrestore(&qdev->homa_deferred.lock, flags);
}

/**
 * homa_qdisc_dequeue_homa() - Remove the frontmost packet from the list
 * of deferred Homa packets for a qdev.
 * @qdev:    The homa_deferred element is the list from which a packet
 *           will be dequeued.
 * Return:   The frontmost packet from the list, or NULL if the list was empty.
 */
struct sk_buff *homa_qdisc_dequeue_homa(struct homa_qdisc_dev *qdev)
{
	struct homa_skb_info *sibling_info;
	struct sk_buff *skb, *sibling;
	struct homa_skb_info *info;
	unsigned long flags;

	/* The only tricky element about this function is that skb may
	 * have a sibling list. If so, we need to enqueue the next
	 * sibling.
	 */
	spin_lock_irqsave(&qdev->homa_deferred.lock, flags);
	if (skb_queue_empty(&qdev->homa_deferred)) {
		spin_unlock_irqrestore(&qdev->homa_deferred.lock, flags);
		return NULL;
	}
	skb = qdev->homa_deferred.next;
	__skb_unlink(skb, &qdev->homa_deferred);
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
		__skb_queue_head(&qdev->homa_deferred, sibling);
	}

	if (skb_queue_empty(&qdev->homa_deferred))
		INC_METRIC(throttled_cycles, homa_clock() - qdev->last_defer);
	spin_unlock_irqrestore(&qdev->homa_deferred.lock, flags);
	return skb;
}

/**
 * homa_qdisc_free_homa() - Free all of the Homa packets that have been
 * deferred for @qdev.
 * @qdev:   Object whose @homa_deferred list should be emptied.
 */
void homa_qdisc_free_homa(struct homa_qdisc_dev *qdev)
{
	struct sk_buff *skb;

	while (1) {
		skb = homa_qdisc_dequeue_homa(qdev);
		if (!skb)
			break;
		kfree_skb_reason(skb, SKB_DROP_REASON_QUEUE_PURGE);
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
	 * are conflicting updates to qdev->link_idle_time.
	 */
	while (1) {
		clock = homa_clock();
		idle = atomic64_read(&qdev->link_idle_time);
		if (idle < clock) {
			if (qdev->pacer_wake_time) {
				u64 lost = (qdev->pacer_wake_time > idle)
						? clock - qdev->pacer_wake_time
						: clock - idle;
				INC_METRIC(pacer_lost_cycles, lost);
				tt_record1("homa_qdisc pacer lost %d cycles", lost);
			}
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
	if (!skb_queue_empty(&qdev->homa_deferred))
		INC_METRIC(pacer_bytes, bytes);
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
		qdev->pacer_wake_time = start;
		homa_qdisc_pacer(qdev);
		qdev->pacer_wake_time = 0;
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
 * @qdev:    The device on which to transmit.
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
		struct homa_data_hdr *h;
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
			cpu_relax();
			now = homa_clock();
		}

		/* Note: when we get here, it's possible that the NIC queue is
		 * still too long because other threads have queued packets,
		 * but we transmit anyway so the pacer thread doesn't starve.
		 */
		skb = homa_qdisc_dequeue_homa(qdev);
		if (!skb)
			break;

		homa_qdisc_update_link_idle(qdev, qdisc_skb_cb(skb)->pkt_len,
					    -1);
		h = (struct homa_data_hdr *)skb_transport_header(skb);
		tt_record4("homa_qdisc_pacer queuing homa data packet for id %d, offset %d, bytes_left %d on qid %d",
			   be64_to_cpu(h->common.sender_id),
			   ntohl(h->seg.offset),
			   homa_get_skb_info(skb)->bytes_left, qdev->pacer_qix);
		homa_qdisc_redirect_skb(skb, qdev, true);
	}
done:
	spin_unlock_bh(&qdev->pacer_mutex);
}

/**
 * homa_qdisc_redirect_skb() - Enqueue a packet on a different queue from
 * the one it was originally passed to and wakeup that queue for
 * transmission. This is used to transmit all pacer packets via a single
 * queue and to redirect other packets originally sent to that queue to
 * another queue.
 * @skb:     Packet to resubmit.
 * @qdev:    Homa data about the network device on which the packet should
 *           be resubmitted.
 * @pacer:   True means queue the packet on qdev->pacer_qix, false means
 *           qdev->redirect_qix.
 * Return:   Standard enqueue return code (usually NET_XMIT_SUCCESS).
 */
int homa_qdisc_redirect_skb(struct sk_buff *skb,
			    struct homa_qdisc_dev *qdev, bool pacer)
{
	struct netdev_queue *txq;
	struct Qdisc *qdisc;
	int result;
	int qix;
	int i;

	rcu_read_lock();

	/* Must make sure that the queue index is still valid (refers
	 * to a Homa qdisc).
	 */
	for (i = 0; ; i++) {
		qix = pacer ? qdev->pacer_qix : qdev->redirect_qix;
		if (qix >= 0 && qix < qdev->dev->num_tx_queues) {
			txq = netdev_get_tx_queue(qdev->dev, qix);
			qdisc = rcu_dereference_bh(txq->qdisc);
			if (qdisc->ops == &homa_qdisc_ops)
				break;
		}
		if (i > 0) {
			/* Couldn't find a Homa qdisc to use; drop the skb.
			 * Shouldn't ever happen?
			 */
			kfree_skb_reason(skb, SKB_DROP_REASON_QDISC_DROP);
			result = NET_XMIT_DROP;
			goto done;
		}
		homa_qdisc_set_qixs(qdev);
	}

	skb_set_queue_mapping(skb, qix);
	spin_lock_bh(qdisc_lock(qdisc));
	result = qdisc_enqueue_tail(skb, qdisc);
	spin_unlock_bh(qdisc_lock(qdisc));
	netif_schedule_queue(txq);

done:
	rcu_read_unlock();
	return result;
}

/**
 * homa_qdisc_update_sysctl() - Recompute information in a homa_qdisc_dev
 * that depends on sysctl parameters.
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
 * @hnet:    Homa's information about a network namespace: changes will apply
 *           to qdiscs in this namespace.
 */
void homa_qdisc_update_all_sysctl(struct homa_net *hnet)
{
	struct homa_qdisc_dev *qdev;

	mutex_lock(&hnet->qdisc_devs_mutex);
	list_for_each_entry(qdev, &hnet->qdisc_devs, links)
		homa_qdisc_update_sysctl(qdev);
	mutex_unlock(&hnet->qdisc_devs_mutex);
}
