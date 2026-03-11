#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define SCX_OPS(name, args...)           \
    SEC("struct_ops/"#name)              \
    BPF_PROG(name, ##args)

#define SCX_OPS_SLEEPABLE(name, args...) \
    SEC("struct_ops.s/"#name)            \
    BPF_PROG(name, ##args)

/* ── Tunables ── */
#define DEM_MAX_TASKS        4096
#define DEM_MAX_VOTES        8
#define DEM_STARVE_NS        (20ULL * 1000000ULL)
#define DEM_SLICE_NS         (5ULL  * 1000000ULL)
#define DEM_SLICE_RT_NS      (2ULL  * 1000000ULL)
#define DEM_RT_PRIO_THRESH   100

#define DEM_VOTE_BOOST_NS    500000ULL
#define DEM_MAX_BOOST_NS     (5ULL * 1000000ULL)

#define DEM_VOTE_BOOST_GM_NS 1000000ULL
#define DEM_MAX_BOOST_GM_NS  (10ULL * 1000000ULL)

#define DEM_PENALTY_NS       1000000ULL
#define DEM_IRRELEVANCE_CAP  32
#define DEM_RECOVERY_PER_WIN 4

/* ── Reinforcement learning tunables ── */
#define DEM_LEARN_CYCLES_BASE  2   /* v24: base learning window (first convergence) */
#define DEM_LEARN_CYCLES_MAX   16  /* v24: cap — never learn more than 16 cycles */
#define DEM_PREF_SLOTS       16
#define DEM_REINFORCE_POS    3
#define DEM_REINFORCE_NEG    1
#define DEM_RECONVERGE_RUNS  128  /* v24: safety ceiling — drift detection handles normal case */
#define DEM_DRIFT_THRESHOLD_SHIFT  1  /* v24: re-elect when metric_ema > converged_metric + (converged_metric >> 1) = 50% worse */

/* v21: minimum runs before a dying thread merges prefs into commstate */
#define DEM_COMMSTATE_MERGE_MIN_RUNS  2  /* v21: was 8 — let even 2-run threads leave a trace */

/* v21: flush live task prefs into commstate every N runs (not just on death) */
#define DEM_FLUSH_INTERVAL_RUNS      16  /* v21: was 64 — 4× more frequent flushes */

/* v20: boost stats map indices */
#define DEM_BOOST_STAT_BOOSTED       0   /* enqueues with vote score > 0 */
#define DEM_BOOST_STAT_UNBOOSTED     1   /* enqueues with no votes */
#define DEM_BOOST_STAT_RT            2   /* RT-lane enqueues */
#define DEM_BOOST_STAT_SIZE          3

/* slots merged per flush — limited to keep BPF verifier happy */
#define DEM_MERGE_SLOTS              2

/* v25b: Institutions sample RL every Nth enqueue to avoid per-enqueue overhead.
 * With 100K+ runs typical, sampling at 1/8 still gives 12K+ learning observations. */
#define DEM_INST_RL_SAMPLE_MASK      0x7  /* learn every 8th enqueue (runs & mask == 0) */

/* ── Institution detection ── */
#define DEM_INSTITUTION_BURST_NS  (5ULL * 1000000ULL)
#define DEM_INSTITUTION_MIN_RUNS  2    /* v24: was 4 — detect even sooner for p50 latency */

/* ── Vote accumulator ── */
#define DEM_VOTE_ACCUM_SIZE  8192
#define DEM_VOTE_ACCUM_MASK  (DEM_VOTE_ACCUM_SIZE - 1)

/* ── Snapshot tunables (v17) ── */
/* v21: Take a snapshot every 5 seconds (was 10s) for finer-grained analysis */
#define DEM_SNAPSHOT_INTERVAL_NS  (5ULL * 1000000000ULL)
/* Max snapshot entries: 60 samples × 512 tasks per sample (v21: doubled from 30) */
#define DEM_SNAPSHOT_MAX_ENTRIES  (60 * 512)

#define DEM_DSQ_RT           0ULL
#define DEM_DSQ_DEMOCRATIC   1ULL
#define DEM_DSQ_FALLBACK     2ULL
#define DEM_SCHED_FIFO       1
#define DEM_SCHED_RR         2

#ifndef BPF_LOCAL_STORAGE_GET_F_CREATE
#define BPF_LOCAL_STORAGE_GET_F_CREATE (1ULL << 0)
#endif

/* errno constants — not available via <errno.h> in BPF target builds */
#ifndef ENOMEM
#define ENOMEM  12
#endif
#ifndef EINVAL
#define EINVAL  22
#endif
#ifndef ENOENT
#define ENOENT   2
#endif

/* ── Per-task state (unchanged from v16) ── */
struct dem_tstate {
    __u64 enqueue_ts;
    __u64 last_run_ts;
    __u32 irrelevance;
    __u32 runs;
    __u32 starvation_rescues;
    __u32 tgid;
    __u64 prev_metric;
    __u8  converged;           /* 0 = learning, 1 = frozen */
    __u8  institution;         /* 1 = short-burst task, bypasses elections */
    __u8  _pad[2];
    __u32 convergence_count;   /* v24: how many times this task has converged */
    __u32 converged_at_run;    /* v23: run count when last converged, for re-election */
    __u64 converged_metric;    /* v24: metric snapshot at convergence — drift baseline */
    __u64 metric_ema;          /* v24: running EMA of metric, updated even when converged */
    __u32 last_snapped_sample_id; /* v17c: sample_id of last snapshot written */
    __u64 avg_burst_ns;
    __u32 votes_fired;      /* v19: cumulative votes cast, never reset */
    __u32 waker_pid;        /* v25: PID of last waker, set in select_cpu */
    __u32 pref_pid[DEM_PREF_SLOTS];
    __s32 pref_score[DEM_PREF_SLOTS];
};

struct dem_vprefs {
    __u32 preferred[DEM_MAX_VOTES];
    __u32 n_preferred;
};

struct dem_winner {
    __u32 pid;
    __u32 _pad;
    __u64 burst_ns;
};

struct dem_warmstart {
    __u8  institution;
    __u8  _pad[7];
    __u64 avg_burst_ns;
    char  comm[16];
};

/* ── v17: Snapshot entry ──
 * One entry per (sample_id, task). Key encodes both so userspace can
 * separate samples cleanly. Value captures the full preference table
 * plus metadata needed to reconstruct the timeline.
 */
struct dem_snap_key {
    __u32 sample_id;   /* which 10s window (0, 1, 2, ...) */
    __u32 pid;
};

struct dem_snap_val {
    __u32 pid;
    __u32 tgid;
    __u32 runs;
    __u8  converged;
    __u8  institution;
    __u8  _pad[2];
    __u64 avg_burst_ns;
    __u64 snapshot_ts_ns;  /* ktime when snapshot was taken */
    char  comm[16];
    /* Full inline preference table */
    __u32 pref_pid[DEM_PREF_SLOTS];
    __s32 pref_score[DEM_PREF_SLOTS];
    /* Aggregate: total positive votes cast this sample window */
    __u32 votes_cast;
    /* Aggregate: total votes received (read from accum at snapshot time) */
    __u32 votes_received;
    /* v19: cumulative votes fired by this task since it was created.
     * Unlike votes_received (which reads the drainable accumulator),
     * this counter is only incremented and never reset, giving dem_analyze
     * a true picture of vote activity across snapshot windows. */
    __u32 votes_fired;
};

/* ── v17: Snapshot sequence counter + last snapshot time ── */
struct dem_snap_seq {
    __u32 sample_id;     /* increments each snapshot interval */
    __u32 _pad;
    __u64 last_snap_ts;  /* ktime of last snapshot */
};

/* ── v18: Shared preference archetype state ── */
struct dem_commstate {
    __u16 merge_count;
    __u16 _pad[3];
    __u32 pref_pid[DEM_PREF_SLOTS];
    __s32 pref_score[DEM_PREF_SLOTS];
};

/* ── Maps ── */

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct dem_tstate);
} dem_task_storage SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, DEM_MAX_TASKS);
    __type(key,   __u32);
    __type(value, struct dem_vprefs);
} dem_vote_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct dem_winner);
} dem_winner_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, DEM_VOTE_ACCUM_SIZE);
    __type(key,   __u32);
    __type(value, __u32);
} dem_vote_accum SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key,   __u32);
    __type(value, struct dem_warmstart);
} dem_warmstart_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u32);
} dem_gamemode SEC(".maps");

/* v17: Snapshot map — keyed by {sample_id, pid} struct */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, DEM_SNAPSHOT_MAX_ENTRIES);
    __type(key,   struct dem_snap_key);
    __type(value, struct dem_snap_val);
} dem_snapshot_map SEC(".maps");

/* v17: Snapshot sequence state */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct dem_snap_seq);
} dem_snap_seq_map SEC(".maps");

/* v18: Shared archetype state map */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,   __u64);
    __type(value, struct dem_commstate);
} dem_commstate_map SEC(".maps");

/* v20: Boost instrumentation counters — index 0=boosted, 1=unboosted */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, DEM_BOOST_STAT_SIZE);
    __type(key,   __u32);
    __type(value, __u64);
} dem_boost_stats SEC(".maps");

/* ── Helpers ── */

static __always_inline struct dem_tstate *dem_get(struct task_struct *p)
{
    return bpf_task_storage_get(&dem_task_storage, p, 0, 0);
}

static __always_inline bool dem_is_rt(struct task_struct *p)
{
    unsigned int pol = BPF_CORE_READ(p, policy);
    int prio         = BPF_CORE_READ(p, static_prio);
    return pol == DEM_SCHED_FIFO || pol == DEM_SCHED_RR ||
           prio < DEM_RT_PRIO_THRESH;
}

static __always_inline __u32 dem_comm_hash(const char *c)
{
    __u32 h = 5381;
    for (int i = 0; i < 16; i++) {
        if (c[i] == 0) break;
        h = ((h << 5) + h) + (unsigned char)c[i];
    }
    return h;
}

static __always_inline bool dem_gamemode_on(void)
{
    __u32 zero = 0;
    __u32 *gm = bpf_map_lookup_elem(&dem_gamemode, &zero);
    return gm && *gm;
}

/* v17: Write a snapshot entry for this task.
 * Called from stopping() when the snapshot interval has elapsed.
 * snapshot_ts, sample_id, votes_received are passed in by caller
 * since they've already been computed.
 */
static __always_inline void dem_write_snapshot(
    struct task_struct *p,
    struct dem_tstate *ts,
    __u32 sample_id,
    __u64 snapshot_ts,
    __u32 votes_received)
{
    __u32 pid = BPF_CORE_READ(p, pid);

    struct dem_snap_key sk = {
        .sample_id = sample_id,
        .pid       = pid,
    };

    struct dem_snap_val sv = {};
    sv.pid            = pid;
    sv.tgid           = ts->tgid;
    sv.runs           = ts->runs;
    sv.converged      = ts->converged;
    sv.institution    = ts->institution;
    sv.avg_burst_ns   = ts->avg_burst_ns;
    sv.snapshot_ts_ns = snapshot_ts;
    sv.votes_received = votes_received;
    sv.votes_fired    = ts->votes_fired;

    bpf_core_read(sv.comm, sizeof(sv.comm), &p->comm);

    /* Copy preference table */
    for (int i = 0; i < DEM_PREF_SLOTS; i++) {
        sv.pref_pid[i]   = ts->pref_pid[i];
        sv.pref_score[i] = ts->pref_score[i];
    }

    /* votes_cast: count how many non-zero positive scores exist
     * (proxy for how actively this task is voting) */
    __u32 vc = 0;
    for (int i = 0; i < DEM_PREF_SLOTS; i++) {
        if (ts->pref_score[i] > 0)
            vc++;
    }
    sv.votes_cast = vc;

    bpf_map_update_elem(&dem_snapshot_map, &sk, &sv, BPF_ANY);
}

/* ── v20: Shared commstate merge helper ──
 * Merges this task's top learned preferences into the shared archetype map.
 * Called from both stopping() (periodic flush) and exit_task() (on death).
 * Safe to call multiple times — uses moving average so repeated merges
 * converge rather than amplify noise.
 */
static __always_inline void dem_merge_to_commstate(struct task_struct *p,
                                                    struct dem_tstate *ts)
{
    char comm[16] = {};
    bpf_core_read(comm, sizeof(comm), &p->comm);
    __u32 chash = dem_comm_hash(comm);
    __u64 ckey  = (__u64)chash;

    struct dem_commstate *cs = bpf_map_lookup_elem(&dem_commstate_map, &ckey);
    if (cs) {
        __u32 mc = cs->merge_count;
        if (mc > 64) mc = 64;

        #pragma unroll
        for (int i = 0; i < DEM_MERGE_SLOTS; i++) {
            __u32 t_pid   = ts->pref_pid[i];
            __s32 t_score = ts->pref_score[i];
            if (t_pid == 0 || t_score <= 0) continue;

            int target_slot = -1;
            int empty_slot  = -1;
            int min_slot    = -1;
            __s32 min_score = 0x7FFFFFFF;

            #pragma unroll
            for (int j = 0; j < DEM_PREF_SLOTS; j++) {
                if (cs->pref_pid[j] == t_pid) { target_slot = j; break; }
                if (cs->pref_pid[j] == 0 && empty_slot == -1) empty_slot = j;
                if (cs->pref_score[j] < min_score) {
                    min_score = cs->pref_score[j];
                    min_slot  = j;
                }
            }

            if (target_slot >= 0)
                cs->pref_score[target_slot] =
                    ((cs->pref_score[target_slot] * mc) + t_score) / (mc + 1);
            else if (empty_slot >= 0) {
                cs->pref_pid[empty_slot]   = t_pid;
                cs->pref_score[empty_slot] = t_score;
            } else if (min_slot >= 0 && t_score > cs->pref_score[min_slot]) {
                cs->pref_pid[min_slot]   = t_pid;
                cs->pref_score[min_slot] = t_score;
            }
        }
        if (cs->merge_count < 65535) cs->merge_count++;
    } else {
        struct dem_commstate new_cs = {};
        new_cs.merge_count = 1;
        for (int i = 0; i < DEM_PREF_SLOTS; i++) {
            new_cs.pref_pid[i]   = ts->pref_pid[i];
            new_cs.pref_score[i] = ts->pref_score[i];
        }
        bpf_map_update_elem(&dem_commstate_map, &ckey, &new_cs, BPF_ANY);
    }
}

/* ── Ops ── */

int SCX_OPS_SLEEPABLE(democratic_init)
{
    int e;
    e = scx_bpf_create_dsq(DEM_DSQ_RT,         -1); if (e) return e;
    e = scx_bpf_create_dsq(DEM_DSQ_DEMOCRATIC, -1); if (e) return e;
    e = scx_bpf_create_dsq(DEM_DSQ_FALLBACK,   -1); if (e) return e;
    bpf_printk("democratic v25: universal suffrage + waker identity\n");
    return 0;
}

int SCX_OPS_SLEEPABLE(democratic_init_task,
                      struct task_struct *p,
                      struct scx_init_task_args *args)
{
    __u64 now = bpf_ktime_get_ns();

    struct dem_tstate *ts = bpf_task_storage_get(&dem_task_storage, p, 0,
                                                  BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ts) return -ENOMEM;

    ts->enqueue_ts  = now;
    ts->last_run_ts = now;
    ts->tgid        = BPF_CORE_READ(p, tgid);

    char comm[16] = {};
    bpf_core_read(comm, sizeof(comm), &p->comm);
    __u32 chash = dem_comm_hash(comm);
    struct dem_warmstart *ws = bpf_map_lookup_elem(&dem_warmstart_map, &chash);
    if (ws) {
        ts->institution  = ws->institution;
        ts->avg_burst_ns = ws->avg_burst_ns;
    }

    /* ── v18: Inherit shared preferences from comm state ── */
    __u64 ckey = (__u64)chash;
    struct dem_commstate *cs = bpf_map_lookup_elem(&dem_commstate_map, &ckey);
    if (cs) {
        __u8 has_prefs = 0;
        for (int i = 0; i < DEM_PREF_SLOTS; i++) {
            ts->pref_pid[i]   = cs->pref_pid[i];
            ts->pref_score[i] = cs->pref_score[i];
            if (cs->pref_score[i] > 0)
                has_prefs = 1;
        }
        /* v21: only auto-converge if inherited prefs actually contain
         * non-zero positive scores. Prevents freezing on empty commstate
         * entries that have high merge counts but no real preference data. */
        if (cs->merge_count >= 4 && has_prefs) {
            ts->converged = 1;
        }
    }

    return 0;
}

/* ── v25: select_cpu — idle CPU fast-path + waker identity ──
 * select_cpu() runs in the WAKER's context. bpf_get_current_task() returns
 * the waker, not the wakee (p). We store the waker PID in the wakee's
 * tstate so enqueue() can cast a vote for it — giving every task,
 * including institutions, a democratic voice.
 */
int SCX_OPS(democratic_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    bool is_idle = false;
    s32 cpu;

    /* v25: Record waker identity before anything else */
    struct dem_tstate *ts = dem_get(p);
    if (ts) {
        struct task_struct *waker = (struct task_struct *)bpf_get_current_task();
        __u32 wpid = BPF_CORE_READ(waker, pid);
        __u32 my_pid = BPF_CORE_READ(p, pid);
        if (wpid != 0 && wpid != my_pid) {
            ts->waker_pid = wpid;

            /* v25c: Waker voting moved here from enqueue().
             * Since select_cpu() now always inserts to SCX_DSQ_LOCAL,
             * woken tasks bypass enqueue() entirely, so the vote must
             * fire here while we still have the waker context. */
            __u32 vidx = wpid & DEM_VOTE_ACCUM_MASK;
            __u32 *va = bpf_map_lookup_elem(&dem_vote_accum, &vidx);
            if (va)
                __sync_fetch_and_add(va, 1);
            __sync_fetch_and_add(&ts->votes_fired, 1);
        }
    }

    cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

    {
        /* v25c: Always dispatch woken tasks directly to SCX_DSQ_LOCAL.
         *
         * Previously, only idle CPUs got direct local dispatch; busy CPUs
         * received just a SCX_KICK_PREEMPT.  The task then entered enqueue(),
         * landed in the global DEM_DSQ_FALLBACK, waited for the kicked CPU's
         * dispatch() callback to pull it via scx_bpf_dsq_move_to_local().
         * That 3-hop path added ~1.7ms latency (our schbench p50 = 1714µs).
         *
         * For busy CPUs, we only kick-preempt when the woken task has been
         * sleeping long enough to suggest it's latency-sensitive (e.g.
         * schbench workers waiting for messages).  Tasks that cycle rapidly
         * with near-zero sleep (e.g. hackbench send/recv) skip the kick
         * to avoid thousands of forced preemptions per second that destroy
         * throughput.  200µs threshold: hackbench cycles in <50µs,
         * schbench workers sleep for 1-5ms between messages. */
        __u64 slice = DEM_SLICE_NS;
        if (ts && ts->institution)
            slice = DEM_SLICE_RT_NS;

        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, 0);

        if (!is_idle && ts) {
            __u64 sleep_ns = bpf_ktime_get_ns() - ts->last_run_ts;
            if (sleep_ns > 200000ULL)  /* 200µs */
                scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
        }
    }

    return cpu;
}

int SCX_OPS(democratic_enqueue, struct task_struct *p, u64 enq_flags)
{
    __u32 pid = BPF_CORE_READ(p, pid);
    __u64 now = bpf_ktime_get_ns();
    struct dem_tstate *ts = dem_get(p);

    if (dem_is_rt(p)) {
        __u32 bs_idx = DEM_BOOST_STAT_RT;
        __u64 *bs = bpf_map_lookup_elem(&dem_boost_stats, &bs_idx);
        if (bs) __sync_fetch_and_add(bs, 1);
        scx_bpf_dsq_insert(p, DEM_DSQ_RT, DEM_SLICE_RT_NS, enq_flags);
        return 0;
    }

    if (!ts) {
        scx_bpf_dsq_insert(p, DEM_DSQ_FALLBACK, DEM_SLICE_NS, enq_flags);
        return 0;
    }

    /* ── v25b: Institution fast-path with sampled learning ──
     * 7 out of 8 enqueues: institutions dispatch immediately (same as v24).
     * Every 8th enqueue: institutions fall through to RL learning + voting
     * below, then dispatch at the institution routing block.
     * This preserves v24-level throughput while still letting institutions
     * build preference tables for commstate persistence. */
    if (ts->institution && (ts->runs & DEM_INST_RL_SAMPLE_MASK) != 0) {
        scx_bpf_dsq_insert(p, DEM_DSQ_FALLBACK, DEM_SLICE_RT_NS, enq_flags);
        return 0;
    }

    /* ── v25c: Waker voting moved to select_cpu() ──
     * Since woken tasks now bypass enqueue (direct local dispatch in
     * select_cpu), waker voting fires there.  This block is kept as a
     * fallback for any edge case where a wakeup enters enqueue. */
    if ((enq_flags & 1ULL) && ts->waker_pid != 0 && ts->waker_pid != pid) {
        __u32 vote_idx = ts->waker_pid & DEM_VOTE_ACCUM_MASK;
        __u32 *va = bpf_map_lookup_elem(&dem_vote_accum, &vote_idx);
        if (va)
            __sync_fetch_and_add(va, 1);
        __sync_fetch_and_add(&ts->votes_fired, 1);
    }

    /* ── v25: Early vote drain — before any routing decision ──
     * Drain this task's received votes NOW so institutions can benefit too.
     * Previously the drain sat after institution routing, meaning 99% of
     * desktop tasks (institutions) never consumed their votes. */
    __u32 vote_idx = pid & DEM_VOTE_ACCUM_MASK;
    __u32 *accum = bpf_map_lookup_elem(&dem_vote_accum, &vote_idx);
    __u32 score = 0;
    if (accum && *accum > 0) {
        score = __sync_lock_test_and_set(accum, 0);
    }

    /* ── v25: Boost stats — track vote influence for all tasks ── */
    if (score > 0) {
        __u32 bs_idx = DEM_BOOST_STAT_BOOSTED;
        __u64 *bs = bpf_map_lookup_elem(&dem_boost_stats, &bs_idx);
        if (bs) __sync_fetch_and_add(bs, 1);
    } else {
        __u32 bs_idx = DEM_BOOST_STAT_UNBOOSTED;
        __u64 *bs = bpf_map_lookup_elem(&dem_boost_stats, &bs_idx);
        if (bs) __sync_fetch_and_add(bs, 1);
    }

    /* ── v25b: RL learning — ALL tasks including institutions ──
     * Moved before institution routing so institutions participate in RL.
     * Previously institutions exited before this, so pref tables were
     * permanently empty on desktop workloads (99% institutions).
     * v25b: Institutions sample every 8th enqueue to avoid per-enqueue overhead. */
    bool rl_sample = !ts->institution ||
                     (ts->runs & DEM_INST_RL_SAMPLE_MASK) == 0;
    if (!ts->converged && rl_sample) {
        __u32 zero = 0;
        struct dem_winner *w = bpf_map_lookup_elem(&dem_winner_map, &zero);

        if (w && w->pid != 0 && w->pid != pid) {
            __u64 my_wait = now - ts->last_run_ts;
            __u64 metric = (my_wait + w->burst_ns) / 2;

            if (ts->prev_metric > 0) {
                __u32 winner_pid = w->pid;
                __s32 delta = 0;

                if (metric < ts->prev_metric)
                    delta = DEM_REINFORCE_POS;
                else if (metric > ts->prev_metric)
                    delta = -DEM_REINFORCE_NEG;

                if (delta != 0) {
                    __u32 found_slot = DEM_PREF_SLOTS;
                    __u32 min_slot = 0;
                    __u32 min_abs = 0x7FFFFFFF;

                    for (__u32 i = 0; i < DEM_PREF_SLOTS; i++) {
                        if (ts->pref_pid[i] == winner_pid &&
                            (ts->pref_score[i] != 0 || ts->pref_pid[i] != 0)) {
                            found_slot = i;
                            break;
                        }
                        __s32 s = ts->pref_score[i];
                        __u32 abs_s = s < 0 ? (__u32)(-s) : (__u32)s;
                        if (abs_s < min_abs ||
                            (abs_s == min_abs && ts->pref_pid[i] == 0)) {
                            min_abs = abs_s;
                            min_slot = i;
                        }
                    }

                    if (found_slot < DEM_PREF_SLOTS) {
                        ts->pref_score[found_slot] += delta;
                    } else {
                        ts->pref_pid[min_slot] = winner_pid;
                        ts->pref_score[min_slot] = delta;
                    }
                }
            }

            ts->prev_metric = metric;
        }

        /* v24: Adaptive convergence — learning window grows with experience. */
        __u32 learn_window = DEM_LEARN_CYCLES_BASE;
        if (ts->convergence_count > 0) {
            __u32 shift = ts->convergence_count;
            if (shift > 3) shift = 3;
            learn_window = DEM_LEARN_CYCLES_BASE << shift;
            if (learn_window > DEM_LEARN_CYCLES_MAX)
                learn_window = DEM_LEARN_CYCLES_MAX;
        }

        if ((ts->runs - ts->converged_at_run) >= learn_window &&
            !ts->converged) {
            ts->converged = 1;
            ts->converged_at_run = ts->runs;
            ts->convergence_count++;
            ts->converged_metric = ts->prev_metric;
            ts->metric_ema = ts->prev_metric;
            dem_merge_to_commstate(p, ts);
        }
    }

    /* ── v24: Metric observation for converged tasks ── */
    if (ts->converged && rl_sample) {
        __u32 zero = 0;
        struct dem_winner *w = bpf_map_lookup_elem(&dem_winner_map, &zero);

        if (w && w->pid != 0 && w->pid != pid) {
            __u64 my_wait = now - ts->last_run_ts;
            __u64 metric = (my_wait + w->burst_ns) / 2;

            if (ts->metric_ema == 0)
                ts->metric_ema = metric;
            else
                ts->metric_ema = ts->metric_ema
                    - (ts->metric_ema >> 2) + (metric >> 2);
        }
    }

    /* ── v24: Drift-triggered re-elections ── */
    if (ts->converged && rl_sample) {
        bool drift = false;

        if (ts->converged_metric > 0 && ts->metric_ema > 0) {
            __u64 threshold = ts->converged_metric +
                              (ts->converged_metric >> DEM_DRIFT_THRESHOLD_SHIFT);
            if (ts->metric_ema > threshold)
                drift = true;
        }

        bool ceiling = (ts->runs - ts->converged_at_run) >= DEM_RECONVERGE_RUNS;

        if (drift || ceiling) {
            ts->converged = 0;
            ts->prev_metric = 0;
            ts->converged_at_run = ts->runs;
        }
    }

    /* ── v25b: Institution routing — AFTER RL learning ──
     * Institutions participate in RL, convergence, and drift detection,
     * but still route to FALLBACK for low-latency dispatch.
     * Popular institutions (vote score > 0) get a shorter 1ms slice. */
    if (ts->institution) {
        __u64 inst_slice = DEM_SLICE_RT_NS;         /* default 2ms */
        if (score > 0)
            inst_slice = (1ULL * 1000000ULL);        /* 1ms for popular */
        scx_bpf_dsq_insert(p, DEM_DSQ_FALLBACK, inst_slice, enq_flags);
        return 0;
    }

    /* ── v24: Institution fast-path for warmstarted tasks ── */
    if (!ts->institution && ts->avg_burst_ns > 0 &&
        ts->avg_burst_ns < DEM_INSTITUTION_BURST_NS &&
        ts->runs < DEM_INSTITUTION_MIN_RUNS) {
        __u64 inst_slice = DEM_SLICE_RT_NS;
        if (score > 0)
            inst_slice = (1ULL * 1000000ULL);
        scx_bpf_dsq_insert(p, DEM_DSQ_FALLBACK, inst_slice, enq_flags);
        return 0;
    }

    /* ── Starvation rescue (after RL) ── */
    if ((now - ts->last_run_ts) > DEM_STARVE_NS) {
        __sync_fetch_and_add(&ts->starvation_rescues, 1);
        scx_bpf_dsq_insert(p, DEM_DSQ_FALLBACK, DEM_SLICE_NS, enq_flags);
        return 0;
    }

    /* ── Vtime computation — score already drained in early block ── */
    __u64 vtime = now;
    bool gamemode = dem_gamemode_on();

    if (score > 0) {
        __u64 boost_per = gamemode ? DEM_VOTE_BOOST_GM_NS : DEM_VOTE_BOOST_NS;
        __u64 max_boost = gamemode ? DEM_MAX_BOOST_GM_NS : DEM_MAX_BOOST_NS;
        __u64 boost = (__u64)score * boost_per;
        if (boost > max_boost)
            boost = max_boost;
        vtime = (boost < now) ? (now - boost) : 0;

        if (ts->irrelevance >= DEM_RECOVERY_PER_WIN)
            ts->irrelevance -= DEM_RECOVERY_PER_WIN;
        else
            ts->irrelevance = 0;

    } else {
        if (ts->irrelevance < DEM_IRRELEVANCE_CAP)
            ts->irrelevance++;

        __u64 penalty = (__u64)ts->irrelevance * DEM_PENALTY_NS;
        vtime = now + penalty;

        if (ts->avg_burst_ns > 0) {
            __u64 burst_nudge = ts->avg_burst_ns >> 10;
            vtime += burst_nudge;
        }
    }

    scx_bpf_dsq_insert_vtime(p, DEM_DSQ_DEMOCRATIC,
                              DEM_SLICE_NS, vtime, enq_flags);
    return 0;
}

int SCX_OPS(democratic_dispatch, s32 cpu, struct task_struct *prev)
{
    if (scx_bpf_dsq_move_to_local(DEM_DSQ_RT))
        return 0;

    /* v22: always serve DEMOCRATIC first, then FALLBACK.
     * The old adaptive queue-depth logic (dem_q >= fb_q) starved
     * DEMOCRATIC under asymmetric load — e.g. hackbench flooding
     * FALLBACK with 640 starvation-rescued tasks caused a runnable
     * task stall (38s) on a claude process sitting in DEMOCRATIC.
     * DEMOCRATIC holds voted/RL-routed tasks; they deserve priority.
     * FALLBACK drains when DEMOCRATIC is empty (the common case). */
    if (scx_bpf_dsq_move_to_local(DEM_DSQ_DEMOCRATIC))
        return 0;
    scx_bpf_dsq_move_to_local(DEM_DSQ_FALLBACK);
    return 0;
}

int SCX_OPS(democratic_running, struct task_struct *p)
{
    __u64 now = bpf_ktime_get_ns();
    struct dem_tstate *ts = dem_get(p);
    if (!ts) return 0;

    ts->last_run_ts = now;
    __sync_fetch_and_add(&ts->runs, 1);

    /* ── v17c: Advance snapshot window ──
     * running() fires frequently on every task dispatch — reliable
     * way to detect elapsed intervals without depending on stopping().
     * We only update the global seq counter here; each task tracks
     * its own last_snapped_sample_id and compares in stopping().
     */
    {
        __u32 zero = 0;
        struct dem_snap_seq *seq = bpf_map_lookup_elem(&dem_snap_seq_map, &zero);
        if (seq) {
            if (seq->last_snap_ts == 0) {
                seq->last_snap_ts = now;
                seq->sample_id    = 0;
            } else if ((now - seq->last_snap_ts) >= DEM_SNAPSHOT_INTERVAL_NS) {
                seq->sample_id++;
                seq->last_snap_ts = now;
            }
        }
    }

    return 0;
}

int SCX_OPS(democratic_stopping, struct task_struct *p, bool runnable)
{
    __u32 pid = BPF_CORE_READ(p, pid);
    __u64 now = bpf_ktime_get_ns();
    struct dem_tstate *ts = dem_get(p);

    if (!ts) return 0;

    /* ── Step 1: Record last winner ── */
    {
        __u32 zero = 0;
        struct dem_winner *w = bpf_map_lookup_elem(&dem_winner_map, &zero);
        __u64 burst = now - ts->last_run_ts;
        if (w) {
            w->pid      = pid;
            w->burst_ns = burst;
        }

        if (ts->avg_burst_ns == 0)
            ts->avg_burst_ns = burst;
        else
            ts->avg_burst_ns = ts->avg_burst_ns
                - (ts->avg_burst_ns >> 2) + (burst >> 2);

        if (!ts->institution && ts->runs >= DEM_INSTITUTION_MIN_RUNS &&
            ts->avg_burst_ns < DEM_INSTITUTION_BURST_NS) {
            ts->institution = 1;

            char comm[16] = {};
            bpf_core_read(comm, sizeof(comm), &p->comm);
            __u32 chash = dem_comm_hash(comm);
            struct dem_warmstart ws = {};
            ws.institution = 1;
            ws.avg_burst_ns = ts->avg_burst_ns;
            __builtin_memcpy(ws.comm, comm, 16);
            bpf_map_update_elem(&dem_warmstart_map, &chash, &ws, BPF_ANY);
        }

    }

    /* ── v17c: Snapshot write ──
     * Compare this task's last_snapped_sample_id against the global
     * sample_id. If they differ, this task hasn't written a snapshot
     * for the current window yet — do it now and update the marker.
     * Moved ABOVE institution early-return so ALL tasks (including
     * institutions) get periodic snapshots for dem_analyze visibility.
     */
    {
        __u32 zero2 = 0;
        struct dem_snap_seq *seq = bpf_map_lookup_elem(&dem_snap_seq_map, &zero2);
        if (seq && seq->last_snap_ts != 0 &&
            ts->last_snapped_sample_id != seq->sample_id + 1) {
            __u32 vote_idx = pid & DEM_VOTE_ACCUM_MASK;
            __u32 *va = bpf_map_lookup_elem(&dem_vote_accum, &vote_idx);
            __u32 votes_recv = va ? *va : 0;

            dem_write_snapshot(p, ts, seq->sample_id, now, votes_recv);
            ts->last_snapped_sample_id = seq->sample_id + 1;
        }
    }

    /* v25b: Institution sampled learning in stopping() —
     * 7 out of 8: institutions return after snapshot write (fast path).
     * Every 8th: fall through to commstate flush + pref-table voting. */
    if (ts->institution && (ts->runs & DEM_INST_RL_SAMPLE_MASK) != 0)
        return 0;

    /* ── Step 1b: v20 periodic commstate flush ──
     * Long-lived tasks never hit exit_task, so they'd never contribute
     * learned prefs to shared state. Flush every DEM_FLUSH_INTERVAL_RUNS
     * so commstate warms up while tasks are alive.
     */
    if (!ts->converged && ts->runs > 0 &&
        (ts->runs % DEM_FLUSH_INTERVAL_RUNS) == 0) {
        dem_merge_to_commstate(p, ts);
    }

    /* ── Step 2: Cast votes from inline preference table ── */
    {
        __s32 best_score = 0;
        __u32 best_pid = 0;

        for (__u32 i = 0; i < DEM_PREF_SLOTS; i++) {
            if (ts->pref_score[i] > best_score) {
                best_score = ts->pref_score[i];
                best_pid   = ts->pref_pid[i];
            }
        }

        if (best_pid != 0) {
            __u32 vote_idx = best_pid & DEM_VOTE_ACCUM_MASK;
            __u32 *va = bpf_map_lookup_elem(&dem_vote_accum, &vote_idx);
            if (va)
                __sync_fetch_and_add(va, (__u32)best_score);
            /* v19: track cumulative vote activity */
            __sync_fetch_and_add(&ts->votes_fired, 1);
            return 0;
        }
    }

    /* ── Step 3: Fallback to static vote map ── */
    struct dem_vprefs *vp = bpf_map_lookup_elem(&dem_vote_map, &pid);
    if (!vp) return 0;

    __u32 n = vp->n_preferred < DEM_MAX_VOTES ? vp->n_preferred : DEM_MAX_VOTES;
    for (__u32 i = 0; i < DEM_MAX_VOTES; i++) {
        if (i >= n) break;
        __u32 vpid = vp->preferred[i];
        __u32 vote_idx = vpid & DEM_VOTE_ACCUM_MASK;
        __u32 *va = bpf_map_lookup_elem(&dem_vote_accum, &vote_idx);
        if (va)
            __sync_fetch_and_add(va, DEM_MAX_VOTES - i);
    }
    /* v19: count fallback votes too */
    if (n > 0)
        __sync_fetch_and_add(&ts->votes_fired, 1);
    return 0;
}

int SCX_OPS(democratic_exit_task, struct task_struct *p,
            struct scx_exit_task_args *args)
{
    __u32 pid = BPF_CORE_READ(p, pid);
    struct dem_tstate *ts = dem_get(p);

    /* ── v18/v20: Merge learned preferences into shared comm state ── */
    if (ts && (ts->converged || ts->runs > DEM_COMMSTATE_MERGE_MIN_RUNS)) {
        dem_merge_to_commstate(p, ts);
    }

    bpf_map_delete_elem(&dem_vote_map, &pid);
    __u32 vote_idx = pid & DEM_VOTE_ACCUM_MASK;
    __u32 zero_val = 0;
    bpf_map_update_elem(&dem_vote_accum, &vote_idx, &zero_val, BPF_ANY);
    bpf_task_storage_delete(&dem_task_storage, p);

    return 0;
}

int SCX_OPS(democratic_exit, struct scx_exit_info *ei)
{
    bpf_printk("democratic v25: unloading\n");
    scx_bpf_destroy_dsq(DEM_DSQ_RT);
    scx_bpf_destroy_dsq(DEM_DSQ_DEMOCRATIC);
    scx_bpf_destroy_dsq(DEM_DSQ_FALLBACK);
    return 0;
}

SEC(".struct_ops")
struct sched_ext_ops democratic_ops = {
    .init        = (void *)democratic_init,
    .init_task   = (void *)democratic_init_task,
    .select_cpu  = (void *)democratic_select_cpu,
    .enqueue     = (void *)democratic_enqueue,
    .dispatch    = (void *)democratic_dispatch,
    .running     = (void *)democratic_running,
    .stopping    = (void *)democratic_stopping,
    .exit_task   = (void *)democratic_exit_task,
    .exit        = (void *)democratic_exit,
    .timeout_ms  = 30000,
    .name        = "democratic",
};
