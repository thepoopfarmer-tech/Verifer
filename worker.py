import threading
import time

import db
import verifier_core as vc

SLEEP_WHEN_IDLE = 2.0
SLEEP_BETWEEN_SCANS = 0.5


class Worker:
    def __init__(self, sender, helo_domain, timeout=10):
        self.sender = sender
        self.helo_domain = helo_domain
        self.timeout = timeout
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            did_work = self._tick()
            time.sleep(SLEEP_WHEN_IDLE if not did_work else SLEEP_BETWEEN_SCANS)

    def _tick(self):
        count_today, cap_today = db.daily_status()
        if count_today >= cap_today:
            return False  # warm-up cap reached for today; wait for the next day

        domains = db.all_pending_domains()
        if not domains:
            return False

        # Group pending domains by their pacing lane, process at most one
        # ready group per tick so lanes interleave instead of one hogging.
        groups = {}
        for d in domains:
            groups.setdefault(vc.provider_group(d), []).append(d)

        for group_name, group_domains in groups.items():
            if not db.group_ready(group_name):
                continue
            job = db.next_pending_for_group(group_name, group_domains)
            if not job:
                continue
            self._process(job, group_name)
            return True

        return False

    def _process(self, job, group_name):
        db.mark_in_progress(job["id"])
        status, detail, confidence, catchall_found = vc.verify(
            job["email"], self.sender, self.helo_domain, self.timeout,
            db.mx_cache_get, db.mx_cache_set, db.catchall_cache_get,
        )
        if catchall_found is not None:
            db.catchall_cache_set(job["domain"], catchall_found)

        db.finish_job(job["id"], status, detail, confidence)
        db.daily_increment()

        is_trouble = status in (vc.TEMPORARY, vc.BLOCKED)
        db.record_outcome(group_name, is_trouble)
