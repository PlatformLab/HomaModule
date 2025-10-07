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
#include "homa_rpc.h"
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
 * the homa qdisc known to Linux.
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
 * homa_rcu_kfree() - Call kfree on a block of memory when it is safe to
 * do so from an RCU standpoint. If possible, the freeing is done
 * asynchronously.
 * @object:     Eventually invoke kfree on this.
 */
void homa_rcu_kfree(void *object)
{
	struct homa_rcu_kfreer *freer;

	freer = kmalloc(sizeof *freer, GFP_KERNEL);
	if (!freer) {
		/* Can't allocate memory needed for asynchronous freeing,
		 * so free synchronously.
		 */
		UNIT_LOG("; ", "homa_rcu_kfree kmalloc failed");
		synchronize_rcu();
		kfree(object);
	} else {
		freer->object = object;
		call_rcu(&freer->rcu_head, homa_rcu_kfree_callback);
	}
}

/**
 * homa_rcu_kfree_callback() - This function is invoked by the RCU subsystem
 * when it safe to free an object previously passed to homa_rcu_kfree.
 * @head:     Points to the rcu_head member of a struct homa_rcu_kfreer.
 */
void homa_rcu_kfree_callback(struct rcu_head *head)
{
	struct homa_rcu_kfreer *freer;

	freer = container_of(head, struct homa_rcu_kfreer, rcu_head);
	kfree(freer->object);
	kfree(freer);
}

/**
 * homa_qdisc_alloc_devs() - Allocate and initialize a new homa_qdisc_qdevs
 * object.
 * Return:   The new object, or an ERR_PTR if an error occurred.
 */
struct homa_qdisc_qdevs *homa_qdisc_qdevs_alloc(void)
{
	struct homa_qdisc_qdevs *qdevs;

	qdevs = kzalloc(sizeof(*qdevs), GFP_KERNEL);
	if (!qdevs)
		return ERR_PTR(-ENOMEM);

	mutex_init(&qdevs->mutex);
	INIT_LIST_HEAD(&qdevs->qdevs);
	return qdevs;
}

/**
 * homa_qdisc_qdevs_free() - Invoked when a struct homa is being freed;
 * releases information related to all the assoiciated homa_qdiscs.
 * @qdevs:    Information about homa_qdisc_devs associated with a
 *            particular struct homa.
 */
void homa_qdisc_qdevs_free(struct homa_qdisc_qdevs *qdevs)
{
	struct homa_qdisc_dev *qdev;
	int stranded = 0;

	/* At this point this object no-one else besides us should
	 * ever access this object again, but lock it just to be safe.
	 */
	mutex_lock(&qdevs->mutex);
	while (1) {
		qdev = list_first_or_null_rcu(&qdevs->qdevs,
					      struct homa_qdisc_dev, links);
		if (!qdev)
			break;

		/* This code should never execute (all the qdevs should
		 * already have been deleted). We can't safely free the
		 * stranded qdevs, but at least stop their pacer threads to
		 * reduce the likelihood of dereferencing dangling pointers.
		 */
		stranded++;
		list_del_rcu(&qdev->links);
		INIT_LIST_HEAD(&qdev->links);
		kthread_stop(qdev->pacer_kthread);
		qdev->pacer_kthread = NULL;
	}

	if (stranded != 0)
		pr_err("homa_qdisc_devs_free found %d live qdevs (should have been none)\n",
		       stranded);
	mutex_unlock(&qdevs->mutex);
	homa_rcu_kfree(qdevs);
}

/**
 * homa_qdisc_qdev_get() - Find the homa_qdisc_dev to use for a particular
 * net_device and increment its reference count. Create a new one if there
 * isn't an existing one to use. Do this in an RCU-safe fashion.
 * @dev:      NIC that the homa_qdisc_dev will manage.
 * Return:    A pointer to the new homa_qdisc_dev, or a PTR_ERR errno.
 */
struct homa_qdisc_dev *homa_qdisc_qdev_get(struct net_device *dev)
{
	struct homa_qdisc_qdevs *qdevs;
	struct homa_qdisc_dev *qdev;
	struct homa_net *hnet;

	rcu_read_lock();
	hnet = homa_net(dev_net(dev));
	qdevs = hnet->homa->qdevs;
	list_for_each_entry_rcu(qdev, &qdevs->qdevs, links) {
		if (qdev->dev == dev && refcount_inc_not_zero(&qdev->refs)) {
			rcu_read_unlock();
			return qdev;
		}
	}
	rcu_read_unlock();

	/* Must allocate a new homa_qdisc_dev (but must check again,
	 * after acquiring the mutex, in case someone else already
	 * created it).
	 */
	mutex_lock(&qdevs->mutex);
	list_for_each_entry_rcu(qdev, &qdevs->qdevs, links) {
		if (qdev->dev == dev && refcount_inc_not_zero(&qdev->refs)) {
			UNIT_LOG("; ", "race in homa_qdisc_qdev_get");
			goto done;
		}
	}

	qdev = kzalloc(sizeof(*qdev), GFP_KERNEL);
	if (!qdev) {
		qdev = ERR_PTR(-ENOMEM);
		goto done;
	}
	qdev->dev = dev;
	qdev->hnet = hnet;
	refcount_set(&qdev->refs, 1);
	qdev->pacer_qix = -1;
	qdev->redirect_qix = -1;
	homa_qdisc_update_sysctl(qdev);
	INIT_LIST_HEAD(&qdev->links);
	qdev->deferred_rpcs = RB_ROOT_CACHED;
	skb_queue_head_init(&qdev->tcp_deferred);
	spin_lock_init(&qdev->defer_lock);
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
	list_add_rcu(&qdev->links, &qdevs->qdevs);

done:
	mutex_unlock(&qdevs->mutex);
	return qdev;
}

/**
 * homa_qdisc_qdev_put() - Decrement the reference count for a homa_qdisc_qdev
 * and free it if the count becomes zero.
 * @qdev:       Object to unreference.
 */
void homa_qdisc_qdev_put(struct homa_qdisc_dev *qdev)
{
	struct homa_qdisc_qdevs *qdevs;

	if (!refcount_dec_and_test(&qdev->refs))
		return;

	/* Make this homa_qdisc_dev inaccessible, then schedule an RCU-safe
	 * free. Think carefully before you modify this code, to ensure that
	 * concurrent RCU scans of qdevs->qdevs are safe.
	 */
	qdevs = qdev->hnet->homa->qdevs;
	mutex_lock(&qdevs->mutex);
	list_del_rcu(&qdev->links);
	kthread_stop(qdev->pacer_kthread);
	qdev->pacer_kthread = NULL;
	call_rcu(&qdev->rcu_head, homa_qdisc_dev_callback);
	mutex_unlock(&qdevs->mutex);
}

/**
 * homa_qdisc_dev_callback() - Invoked by the RCU subsystem when it is
 * safe to finish deleting a homa_qdisc_dev.
 * @head:    Pointer to the rcu_head field in a homa_qdisc_qdev.
 */
void homa_qdisc_dev_callback(struct rcu_head *head)
{
	struct homa_qdisc_dev *qdev;

	qdev = container_of(head, struct homa_qdisc_dev, rcu_head);
	homa_qdisc_free_homa(qdev);
	skb_queue_purge(&qdev->tcp_deferred);
	kfree(qdev);
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
	int i;

	qdev = homa_qdisc_qdev_get(sch->dev_queue->dev);
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

	if (!homa_qdisc_any_deferred(qdev) &&
	    homa_qdisc_update_link_idle(qdev, pkt_len,
					homa->pacer->max_nic_queue_cycles))
		goto enqueue;

	/* This packet needs to be deferred until the NIC queue has
	 * been drained a bit.
	 */
	tt_record3("homa_qdisc_enqueue deferring homa data packet for id %d, offset %d on qid %d",
		   be64_to_cpu(h->common.sender_id), offset, qdev->pacer_qix);
	homa_qdisc_defer_homa(qdev, skb);
	return NET_XMIT_SUCCESS;

enqueue:
	if (is_homa_pkt(skb)) {
		if (h->common.type == DATA) {
			h = (struct homa_data_hdr *)skb_transport_header(skb);
			tt_record3("homa_qdisc_enqueue queuing homa data packet for id %d, offset %d on qid %d",
				be64_to_cpu(h->common.sender_id), offset,
				q->ix);
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
	struct homa_rpc *rpc = info->rpc;
	u64 now = homa_clock();
	unsigned long flags;

	spin_lock_irqsave(&qdev->defer_lock, flags);
	__skb_queue_tail(&rpc->qrpc.packets, skb);
	if (skb_queue_len(&rpc->qrpc.packets) == 1) {
		int bytes_left;

		bytes_left = rpc->msgout.length - info->offset;
		if (bytes_left < rpc->qrpc.tx_left)
			rpc->qrpc.tx_left = bytes_left;
		homa_qdisc_insert_rb(qdev, rpc);
	}
	if (qdev->last_defer)
		INC_METRIC(nic_backlog_cycles, now - qdev->last_defer);
	else
		wake_up(&qdev->pacer_sleep);
	qdev->last_defer = now;
	spin_unlock_irqrestore(&qdev->defer_lock, flags);
}

/**
 * homa_qdisc_insert_rb() - Insert an RPC into the deferred_rpcs red-black
 * tree.
 * @qdev:    Network device for the RPC.
 * @rpc:     RPC to insert.
 */
void homa_qdisc_insert_rb(struct homa_qdisc_dev *qdev, struct homa_rpc *rpc)
{
	struct rb_node **new = &(qdev->deferred_rpcs.rb_root.rb_node);
	struct rb_node *parent = NULL;
	struct homa_rpc *rpc2;
	bool leftmost = true;

	while (*new) {
		parent = *new;
		rpc2 = container_of(*new, struct homa_rpc, qrpc.rb_node);
		if (homa_qdisc_precedes(rpc, rpc2)) {
			new = &((*new)->rb_left);
		} else {
			new = &((*new)->rb_right);
			leftmost = false;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&rpc->qrpc.rb_node, parent, new);
	rb_insert_color_cached(&rpc->qrpc.rb_node, &qdev->deferred_rpcs,
			       leftmost);
}

/**
 * homa_qdisc_dequeue_homa() - Return the highest-priority deferred Homa packet
 * and dequeue it from the structures that manage deferred packets.
 * @qdev:    Info about deferred packets is stored here.
 * Return:   The next packet to transmit, or NULL if there are no deferred
 *           Homa packets.
 */
struct sk_buff *homa_qdisc_dequeue_homa(struct homa_qdisc_dev *qdev)
{
	struct homa_rpc_qdisc *qrpc;
	struct homa_skb_info *info;
	struct homa_rpc *rpc;
	struct rb_node *node;
	struct sk_buff *skb;
	unsigned long flags;
	int bytes_left;

	spin_lock_irqsave(&qdev->defer_lock, flags);
	node = rb_first_cached(&qdev->deferred_rpcs);
	if (!node) {
		spin_unlock_irqrestore(&qdev->defer_lock, flags);
		return NULL;
	}
	qrpc = container_of(node, struct homa_rpc_qdisc, rb_node);
	skb = skb_dequeue(&qrpc->packets);
	if (skb_queue_len(&qrpc->packets) == 0)
		rb_erase_cached(node, &qdev->deferred_rpcs);

	/* Update qrpc->bytes_left. This can change the priority of the RPC
	 * in qdev->deferred_rpcs, but the RPC was already the highest-
	 * priority one and its priority only gets higher, so its position
	 * in the rbtree won't change (thus we don't need to remove and
	 * reinsert it).
	 */
	rpc = container_of(qrpc, struct homa_rpc, qrpc);
	info = homa_get_skb_info(skb);
	bytes_left = rpc->msgout.length - (info->offset + info->data_bytes);
	if (bytes_left < qrpc->tx_left)
		qrpc->tx_left = bytes_left;

	if (!homa_qdisc_any_deferred(qdev)) {
		INC_METRIC(nic_backlog_cycles, homa_clock() - qdev->last_defer);
		qdev->last_defer = 0;
	}
	spin_unlock_irqrestore(&qdev->defer_lock, flags);
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
		homa_qdisc_pacer(qdev, false);
		INC_METRIC(pacer_cycles, homa_clock() - start);

		if (homa_qdisc_any_deferred(qdev)) {
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
			kthread_should_stop() || homa_qdisc_any_deferred(qdev));
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
 * @help:    True means this function was invoked from homa_qdisc_pacer_check
 *           rather than homa_qdisc_pacer_main (indicating that the pacer
 *           thread wasn't keeping up and needs help).
 */
void homa_qdisc_pacer(struct homa_qdisc_dev *qdev, bool help)
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
		 * but we transmit anyway (don't want this thread to get
		 * starved by others).
		 */
		UNIT_HOOK("pacer_xmit");
		skb = homa_qdisc_dequeue_homa(qdev);
		if (!skb)
			break;

		INC_METRIC(pacer_packets, 1);
		INC_METRIC(pacer_bytes, qdisc_skb_cb(skb)->pkt_len);
		if (help)
			INC_METRIC(pacer_help_bytes,
				   qdisc_skb_cb(skb)->pkt_len);
		homa_qdisc_update_link_idle(qdev, qdisc_skb_cb(skb)->pkt_len,
					    -1);
		h = (struct homa_data_hdr *)skb_transport_header(skb);
		tt_record3("homa_qdisc_pacer queuing homa data packet for id %d, offset %d on qid %d",
			   be64_to_cpu(h->common.sender_id),
			   ntohl(h->seg.offset), qdev->pacer_qix);
		homa_qdisc_redirect_skb(skb, qdev, true);
		INC_METRIC(pacer_xmit_cycles, homa_clock() - now);
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
 * homa_qdisc_pacer_check() - Check whether any of the homa_qdisc pacer
 * threads associated with @homa have fallen behind (e.g. because they
 * got descheduled by Linux). If so, call the pacer directly to transmit
 * deferred packets.
 * @homa:       Overall information about the Homa transport; used to find
 *              homa_qdisc_devs to check.
 */
void homa_qdisc_pacer_check(struct homa *homa) {
	struct homa_qdisc_dev *qdev;
	u64 now = homa_clock();
	int max_cycles;

	max_cycles = homa->pacer->max_nic_queue_cycles;
	rcu_read_lock();
	list_for_each_entry_rcu(qdev, &homa->qdevs->qdevs, links) {
		if (!homa_qdisc_any_deferred(qdev))
			continue;

		/* The ">> 1" means that we only help out if the NIC queue has
		 * dropped below half of its maximum allowed capacity. This
		 * gives the pacer thread the first shot at queuting new
		 * packets.
		 */
		if (now + (max_cycles >> 1) <
		    atomic64_read(&qdev->link_idle_time))
			continue;
		tt_record("homa_qdisc_pacer_check calling homa_qdisc_pacer");
		homa_qdisc_pacer(qdev, true);
	}
	rcu_read_unlock();
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

	rcu_read_lock();
	list_for_each_entry_rcu(qdev, &hnet->homa->qdevs->qdevs, links) {
		if (qdev->hnet != hnet)
			continue;
		homa_qdisc_update_sysctl(qdev);
	}
	rcu_read_unlock();
}
