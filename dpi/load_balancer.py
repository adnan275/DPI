import queue
import threading
from typing import List, Optional

from .types import FiveTuple, PacketJob


class LoadBalancer:
    def __init__(self, lb_id: int, fp_queues: List[queue.Queue], fp_start_id: int):
        self._lb_id = lb_id
        self._fp_start_id = fp_start_id
        self._num_fps = len(fp_queues)
        self._input_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._fp_queues = fp_queues
        self._per_fp_counts = [0] * len(fp_queues)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._packets_received = 0
        self._packets_dispatched = 0

    def start(self):
        if self._running:
            return
        self._running = True
        t = threading.Thread(target=self._run, daemon=True)
        self._thread = t
        t.start()
        end_fp = self._fp_start_id + self._num_fps - 1
        print(f"[LB{self._lb_id}] Started (serving FP{self._fp_start_id}-FP{end_fp})")

    def stop(self):
        if not self._running:
            return
        self._running = False
        self._input_queue.put(None)
        t = self._thread
        if t is not None and t.is_alive():
            t.join()
        print(f"[LB{self._lb_id}] Stopped")

    def get_input_queue(self) -> queue.Queue:
        return self._input_queue

    def _run(self):
        while self._running:
            try:
                job = self._input_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            if job is None:
                break

            self._packets_received += 1
            fp_index = self._select_fp(job.tuple)
            try:
                self._fp_queues[fp_index].put_nowait(job)
            except queue.Full:
                pass
            self._packets_dispatched += 1
            self._per_fp_counts[fp_index] += 1

    def _select_fp(self, tuple_: FiveTuple) -> int:
        return hash(tuple_) % self._num_fps

    def get_stats(self) -> dict:
        return {
            "packets_received": self._packets_received,
            "packets_dispatched": self._packets_dispatched,
            "per_fp_packets": list(self._per_fp_counts),
        }


class LBManager:
    def __init__(self, num_lbs: int, fps_per_lb: int, fp_queues: List[queue.Queue]):
        self._fps_per_lb = fps_per_lb
        self._lbs: List[LoadBalancer] = []

        for lb_id in range(num_lbs):
            fp_start = lb_id * fps_per_lb
            lb_fp_queues = fp_queues[fp_start: fp_start + fps_per_lb]
            self._lbs.append(LoadBalancer(lb_id, lb_fp_queues, fp_start))

        print(f"[LBManager] Created {num_lbs} load balancers, {fps_per_lb} FPs each")

    def start_all(self):
        for lb in self._lbs:
            lb.start()

    def stop_all(self):
        for lb in self._lbs:
            lb.stop()

    def get_lb_for_packet(self, tuple_: FiveTuple) -> LoadBalancer:
        lb_index = hash(tuple_) % len(self._lbs)
        return self._lbs[lb_index]

    def get_aggregated_stats(self) -> dict:
        total_received = sum(lb.get_stats()["packets_received"] for lb in self._lbs)
        total_dispatched = sum(lb.get_stats()["packets_dispatched"] for lb in self._lbs)
        return {"total_received": total_received, "total_dispatched": total_dispatched}
