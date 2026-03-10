/* dem_analyze.c — Democratic Scheduler Preference Drift Analyzer v2
 *
 * Improvements over v1:
 *   - Periodic map draining (every 30s) prevents snapshot map overflow
 *   - Three-epoch comparison (early/mid/late 2-minute windows)
 *   - Preference table Jaccard similarity tracking between windows
 *   - Burst-time × vote correlation ("celebrity staleness" detection)
 *
 * Attaches to a running democratic v17 scheduler via pinned maps,
 * waits for the specified duration (default 6 minutes), periodically
 * draining the snapshot map, then produces:
 *
 *   1. dem_raw_dump.jsonl  — one JSON line per snapshot entry
 *   2. dem_graph_data.csv  — per-task per-window aggregated data
 *   3. dem_analysis.txt    — human-readable analysis with epoch comparison
 *
 * Usage:
 *   sudo ./dem_analyze [duration_seconds]
 *
 * duration_seconds defaults to 360 (6 minutes).
 * The tool is passive — it does NOT load or unload the scheduler.
 *
 * Build:
 *   gcc -O2 -o dem_analyze dem_analyze.c -lbpf -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <math.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Pin paths — must match democratic_loader.c exactly */
#define DEM_PIN_SNAPSHOT  "/sys/fs/bpf/dem_snapshot_map"
#define DEM_PIN_SEQ       "/sys/fs/bpf/dem_snap_seq_map"
#define DEM_PIN_COMMSTATE "/sys/fs/bpf/dem_commstate_map"  /* v19 */
#define DEM_PIN_BOOSTSTATS "/sys/fs/bpf/dem_boost_stats"   /* v20 */

/* Must match democratic.bpf.c v17 exactly */
#define DEM_PREF_SLOTS       16
#define DEM_MAX_VOTES        8
#define DEM_SNAPSHOT_MAX_ENTRIES (30 * 512)  /* v19: was 30*256, doubled to reduce eviction */

/* Timing */
#define DEFAULT_DURATION_S   360
#define SNAPSHOT_INTERVAL_S  10
#define DRAIN_INTERVAL_S     30
#define N_EPOCHS             3

/* Output paths */
#define OUT_RAW    "dem_raw_dump.jsonl"
#define OUT_CSV    "dem_graph_data.csv"
#define OUT_TEXT   "dem_analysis.txt"

struct dem_snap_key {
    uint32_t sample_id;
    uint32_t pid;
};

struct dem_snap_val {
    uint32_t pid;
    uint32_t tgid;
    uint32_t runs;
    uint8_t  converged;
    uint8_t  institution;
    uint8_t  _pad[2];
    uint64_t avg_burst_ns;
    uint64_t snapshot_ts_ns;
    char     comm[16];
    uint32_t pref_pid[DEM_PREF_SLOTS];
    int32_t  pref_score[DEM_PREF_SLOTS];
    uint32_t votes_cast;
    uint32_t votes_received;
    uint32_t votes_fired;   /* v19: cumulative, never drained — true vote activity */
};

/* In-memory store — sized for 6 min of periodic draining */
#define MAX_SNAP_RECORDS 16384

struct snap_record {
    uint32_t sample_id;
    struct dem_snap_val val;
};

static struct snap_record records[MAX_SNAP_RECORDS];
static int n_records = 0;

static volatile int running = 1;
static void sig_handler(int sig) {
    (void)sig;
    running = 0;
}

/* ── Progress bar with epoch indicator ── */
static void print_progress(int elapsed, int total)
{
    int pct = (elapsed * 100) / total;
    int bars = pct / 5;
    int epoch = (elapsed * N_EPOCHS) / total + 1;
    if (epoch > N_EPOCHS) epoch = N_EPOCHS;
    printf("\r  [");
    for (int i = 0; i < 20; i++)
        printf("%s", i < bars ? "█" : "░");
    printf("] %3d%% (%ds/%ds) Epoch %d/%d  ", pct, elapsed, total, epoch, N_EPOCHS);
    fflush(stdout);
}

/* ── Drain snapshots: read all entries and clear the map ── */
static int drain_snapshots(int snap_map_fd)
{
    struct dem_snap_key key, next_key;
    struct dem_snap_val val;
    int collected = 0;

    /* Collect keys for deletion after iteration */
    static struct dem_snap_key del_keys[DEM_SNAPSHOT_MAX_ENTRIES];
    int n_del = 0;

    int err = bpf_map_get_next_key(snap_map_fd, NULL, &key);
    while (err == 0 && n_records < MAX_SNAP_RECORDS) {
        if (bpf_map_lookup_elem(snap_map_fd, &key, &val) == 0) {
            records[n_records].sample_id = key.sample_id;
            records[n_records].val = val;
            n_records++;
            collected++;
            if (n_del < DEM_SNAPSHOT_MAX_ENTRIES)
                del_keys[n_del++] = key;
        }
        err = bpf_map_get_next_key(snap_map_fd, &key, &next_key);
        key = next_key;
    }

    /* Delete drained entries to free map space */
    for (int i = 0; i < n_del; i++)
        bpf_map_delete_elem(snap_map_fd, &del_keys[i]);

    return collected;
}

/* ── Write raw JSON dump ── */
static void write_raw_dump(void)
{
    FILE *f = fopen(OUT_RAW, "w");
    if (!f) { perror("  open " OUT_RAW); return; }

    for (int i = 0; i < n_records; i++) {
        struct snap_record *r = &records[i];
        struct dem_snap_val *v = &r->val;

        char comm[17];
        strncpy(comm, v->comm, 16);
        comm[16] = '\0';
        for (int c = 0; c < 16; c++)
            if (comm[c] == '"') comm[c] = '\'';

        fprintf(f,
            "{\"sample_id\":%u,\"pid\":%u,\"tgid\":%u,\"comm\":\"%s\","
            "\"runs\":%u,\"converged\":%u,\"institution\":%u,"
            "\"avg_burst_ns\":%llu,\"snapshot_ts_ns\":%llu,"
            "\"votes_cast\":%u,\"votes_received\":%u,\"votes_fired\":%u,"
            "\"pref_table\":[",
            r->sample_id, v->pid, v->tgid, comm,
            v->runs, (unsigned)v->converged, (unsigned)v->institution,
            (unsigned long long)v->avg_burst_ns,
            (unsigned long long)v->snapshot_ts_ns,
            v->votes_cast, v->votes_received, v->votes_fired);

        for (int s = 0; s < DEM_PREF_SLOTS; s++) {
            fprintf(f, "{\"pref_pid\":%u,\"pref_score\":%d}%s",
                    v->pref_pid[s], v->pref_score[s],
                    s < DEM_PREF_SLOTS - 1 ? "," : "");
        }

        fprintf(f, "]}\n");
    }

    fclose(f);
    printf("  Raw dump: %d records → %s\n", n_records, OUT_RAW);
}

/* ── Write CSV (v2: adds epoch column) ── */
static void write_graph_csv(int duration_s)
{
    FILE *f = fopen(OUT_CSV, "w");
    if (!f) { perror("  open " OUT_CSV); return; }

    fprintf(f, "sample_id,time_s,epoch,pid,comm,tgid,runs,converged,institution,"
               "avg_burst_us,votes_received,votes_cast,votes_fired,"
               "top_pref_pid,top_pref_score,total_positive_score,"
               "total_negative_score,n_known_peers\n");

    int epoch_windows = (duration_s / N_EPOCHS) / SNAPSHOT_INTERVAL_S;

    for (int i = 0; i < n_records; i++) {
        struct snap_record *r = &records[i];
        struct dem_snap_val *v = &r->val;
        char comm[17];
        strncpy(comm, v->comm, 16);
        comm[16] = '\0';

        int32_t  top_score = 0;
        uint32_t top_pid = 0;
        int64_t  total_pos = 0;
        int64_t  total_neg = 0;
        int      n_peers = 0;

        for (int s = 0; s < DEM_PREF_SLOTS; s++) {
            if (v->pref_pid[s] == 0) continue;
            n_peers++;
            if (v->pref_score[s] > top_score) {
                top_score = v->pref_score[s];
                top_pid = v->pref_pid[s];
            }
            if (v->pref_score[s] > 0) total_pos += v->pref_score[s];
            else                       total_neg += v->pref_score[s];
        }

        uint32_t time_s = r->sample_id * SNAPSHOT_INTERVAL_S;
        int epoch = (epoch_windows > 0) ?
                    ((int)r->sample_id / epoch_windows) + 1 : 1;
        if (epoch > N_EPOCHS) epoch = N_EPOCHS;

        fprintf(f,
            "%u,%u,%d,%u,\"%s\",%u,%u,%u,%u,%llu,%u,%u,%u,%u,%d,%lld,%lld,%d\n",
            r->sample_id, time_s, epoch,
            v->pid, comm, v->tgid,
            v->runs, (unsigned)v->converged, (unsigned)v->institution,
            (unsigned long long)(v->avg_burst_ns / 1000),
            v->votes_received, v->votes_cast, v->votes_fired,
            top_pid, top_score,
            (long long)total_pos, (long long)total_neg,
            n_peers);
    }

    fclose(f);
    printf("  Graph CSV: %s\n", OUT_CSV);
}

/* ── Preference table Jaccard similarity ── */
static double pref_jaccard(struct dem_snap_val *a, struct dem_snap_val *b)
{
    int intersection = 0, union_count = 0;

    for (int i = 0; i < DEM_PREF_SLOTS; i++) {
        if (a->pref_pid[i] == 0) continue;
        union_count++;
        for (int j = 0; j < DEM_PREF_SLOTS; j++) {
            if (b->pref_pid[j] == a->pref_pid[i]) {
                intersection++;
                break;
            }
        }
    }

    for (int i = 0; i < DEM_PREF_SLOTS; i++) {
        if (b->pref_pid[i] == 0) continue;
        int found = 0;
        for (int j = 0; j < DEM_PREF_SLOTS; j++) {
            if (a->pref_pid[j] == b->pref_pid[i]) { found = 1; break; }
        }
        if (!found) union_count++;
    }

    if (union_count == 0) return 1.0;
    return (double)intersection / (double)union_count;
}

/* ── Find a task's record for a given sample_id ── */
static struct dem_snap_val *find_record(uint32_t pid, uint32_t sample_id)
{
    for (int i = 0; i < n_records; i++) {
        if (records[i].val.pid == pid && records[i].sample_id == sample_id)
            return &records[i].val;
    }
    return NULL;
}

/* ── Get top preference from a snapshot value ── */
static void get_top_pref(struct dem_snap_val *v, uint32_t *out_pid, int32_t *out_score)
{
    *out_pid = 0;
    *out_score = 0;
    for (int s = 0; s < DEM_PREF_SLOTS; s++) {
        if (v->pref_score[s] > *out_score) {
            *out_score = v->pref_score[s];
            *out_pid   = v->pref_pid[s];
        }
    }
}

/* ── Write human-readable analysis v2 ── */
static void write_analysis(int duration_s)
{
    FILE *f = fopen(OUT_TEXT, "w");
    if (!f) { perror("  open " OUT_TEXT); return; }

    uint32_t max_sample = 0;
    for (int i = 0; i < n_records; i++)
        if (records[i].sample_id > max_sample)
            max_sample = records[i].sample_id;

    /* Collect distinct PIDs */
    uint32_t pids[512];
    char     comms[512][17];
    int n_pids = 0;

    for (int i = 0; i < n_records; i++) {
        uint32_t pid = records[i].val.pid;
        int found = 0;
        for (int j = 0; j < n_pids; j++)
            if (pids[j] == pid) { found = 1; break; }
        if (!found && n_pids < 512) {
            pids[n_pids] = pid;
            strncpy(comms[n_pids], records[i].val.comm, 16);
            comms[n_pids][16] = '\0';
            n_pids++;
        }
    }

    int epoch_windows = (duration_s / N_EPOCHS) / SNAPSHOT_INTERVAL_S;
    int epoch_s = duration_s / N_EPOCHS;

    /* ═══ Header ═══ */
    fprintf(f, "═══════════════════════════════════════════════════════════\n");
    fprintf(f, "  Democratic Scheduler — Preference Drift Analysis v2\n");
    fprintf(f, "  Duration: %ds | Snapshot interval: %ds | Windows: %u\n",
            duration_s, SNAPSHOT_INTERVAL_S, max_sample + 1);
    fprintf(f, "  Epochs: %d × %ds | Drain interval: %ds\n",
            N_EPOCHS, epoch_s, DRAIN_INTERVAL_S);
    fprintf(f, "  Total records: %d | Distinct tasks: %d\n",
            n_records, n_pids);
    fprintf(f, "═══════════════════════════════════════════════════════════\n\n");

    /* ═══ Section 1: Per-task timeline with Jaccard ═══ */
    fprintf(f, "══ SECTION 1: Per-Task Timeline & Preference Stability ══\n\n");

    for (int pi = 0; pi < n_pids; pi++) {
        uint32_t pid = pids[pi];
        int is_inst = 1;
        for (int i = 0; i < n_records; i++)
            if (records[i].val.pid == pid && !records[i].val.institution)
                { is_inst = 0; break; }

        fprintf(f, "── Task: %s (PID %u)%s ──\n", comms[pi], pid,
                is_inst ? " [INSTITUTION]" : "");

        struct dem_snap_val *prev_val = NULL;
        uint32_t prev_top_pid = 0;
        int32_t  prev_top_score = 0;
        int drift_events = 0, convergence_seen = 0, first = 1;

        for (uint32_t sid = 0; sid <= max_sample; sid++) {
            struct dem_snap_val *v = find_record(pid, sid);
            if (!v) continue;

            uint32_t top_pid; int32_t top_score;
            get_top_pref(v, &top_pid, &top_score);

            int64_t total_pos = 0, total_neg = 0;
            for (int s = 0; s < DEM_PREF_SLOTS; s++) {
                if (v->pref_score[s] > 0) total_pos += v->pref_score[s];
                else                       total_neg += v->pref_score[s];
            }

            uint32_t time_s = sid * SNAPSHOT_INTERVAL_S;
            int epoch = (epoch_windows > 0) ? (sid / epoch_windows) + 1 : 1;
            if (epoch > N_EPOCHS) epoch = N_EPOCHS;

            double jaccard = -1.0;
            if (prev_val) jaccard = pref_jaccard(prev_val, v);

            fprintf(f,
                "  t=%3us [E%d] runs=%-6u conv=%u inst=%u "
                "burst=%5llums votes=%-4u fired=%-4u "
                "top→PID%-6u sc=%-4d pos=%-5lld neg=%-5lld",
                time_s, epoch, v->runs,
                (unsigned)v->converged, (unsigned)v->institution,
                (unsigned long long)(v->avg_burst_ns / 1000000),
                v->votes_received, v->votes_fired, top_pid, top_score,
                (long long)total_pos, (long long)total_neg);
            if (jaccard >= 0.0) fprintf(f, " J=%.2f", jaccard);
            fprintf(f, "\n");

            if (!first) {
                if (top_pid != prev_top_pid && prev_top_pid != 0) {
                    fprintf(f, "  *** DRIFT at t=%us: top PID %u→%u (sc %d→%d)\n",
                            time_s, prev_top_pid, top_pid,
                            prev_top_score, top_score);
                    drift_events++;
                }
                if (jaccard >= 0.0 && jaccard < 0.5)
                    fprintf(f, "  *** TABLE CHURN at t=%us: J=%.2f (>50%% peers changed)\n",
                            time_s, jaccard);
            }

            if (v->converged && !convergence_seen) {
                fprintf(f, "  >>> CONVERGED at t=%us (%u runs)\n", time_s, v->runs);
                convergence_seen = 1;
            }

            prev_top_pid = top_pid;
            prev_top_score = top_score;
            prev_val = v;
            first = 0;
        }
        fprintf(f, "  Summary: %d drift(s)%s\n\n", drift_events,
                convergence_seen ? ", frozen after convergence" : ", still learning");
    }

    /* ═══ Section 2: Three-Epoch Comparison ═══ */
    fprintf(f, "══ SECTION 2: Three-Epoch Comparison ══\n");
    fprintf(f, "  E1: 0-%ds | E2: %d-%ds | E3: %d-%ds\n\n",
            epoch_s, epoch_s, 2*epoch_s, 2*epoch_s, 3*epoch_s);

    for (int pi = 0; pi < n_pids; pi++) {
        uint32_t pid = pids[pi];
        int is_inst = 1;
        for (int i = 0; i < n_records; i++)
            if (records[i].val.pid == pid && !records[i].val.institution)
                { is_inst = 0; break; }
        if (is_inst) continue;

        fprintf(f, "── %s (PID %u) ──\n", comms[pi], pid);
        fprintf(f, "  %-6s %10s %10s %10s %8s %8s\n",
                "Epoch", "AvgVotes", "AvgBurst", "TopPref", "TopSc", "Jaccard");

        for (int e = 0; e < N_EPOCHS; e++) {
            uint32_t e_start = e * epoch_windows;
            uint32_t e_end   = (e + 1) * epoch_windows - 1;
            if (e_end > max_sample) e_end = max_sample;

            double sum_v = 0, sum_b = 0, sum_j = 0;
            int cnt = 0, n_j = 0;
            uint32_t last_top_pid = 0;
            int32_t  last_top_score = 0;
            struct dem_snap_val *eprev = NULL;

            for (uint32_t sid = e_start; sid <= e_end; sid++) {
                struct dem_snap_val *v = find_record(pid, sid);
                if (!v) continue;
                sum_v += v->votes_received;
                sum_b += (double)v->avg_burst_ns / 1000000.0;
                cnt++;
                get_top_pref(v, &last_top_pid, &last_top_score);
                if (eprev) { sum_j += pref_jaccard(eprev, v); n_j++; }
                eprev = v;
            }

            if (cnt > 0)
                fprintf(f, "  E%-5d %10.1f %8.1fms %10u %8d %8.2f\n",
                        e+1, sum_v/cnt, sum_b/cnt, last_top_pid,
                        last_top_score, n_j > 0 ? sum_j/n_j : 1.0);
            else
                fprintf(f, "  E%-5d %10s %10s %10s %8s %8s\n",
                        e+1, "-", "-", "-", "-", "-");
        }
        fprintf(f, "\n");
    }

    /* ═══ Section 3: Celebrity Staleness Detection ═══ */
    fprintf(f, "══ SECTION 3: Celebrity Staleness Detection ══\n");
    fprintf(f, "  (Burst changed >20%% but voters held — preferences may be stale)\n\n");
    int n_celebrity = 0;

    for (int pi = 0; pi < n_pids; pi++) {
        uint32_t tgt = pids[pi];
        double b1 = 0, b3 = 0; int c1 = 0, c3 = 0;

        for (int i = 0; i < n_records; i++) {
            if (records[i].val.pid != tgt) continue;
            int ep = (epoch_windows > 0) ? (records[i].sample_id / epoch_windows) : 0;
            double b = (double)records[i].val.avg_burst_ns / 1000000.0;
            if (ep == 0)             { b1 += b; c1++; }
            else if (ep == N_EPOCHS-1) { b3 += b; c3++; }
        }
        if (c1 == 0 || c3 == 0) continue;
        b1 /= c1; b3 /= c3;

        int v1 = 0, v3 = 0;
        for (int qi = 0; qi < n_pids; qi++) {
            if (pids[qi] == tgt) continue;
            for (int i = 0; i < n_records; i++) {
                if (records[i].val.pid != pids[qi]) continue;
                int ep = (epoch_windows > 0) ? (records[i].sample_id / epoch_windows) : 0;
                uint32_t tp; int32_t ts;
                get_top_pref(&records[i].val, &tp, &ts);
                if (ep == 0 && tp == tgt)             { v1++; break; }
            }
            for (int i = 0; i < n_records; i++) {
                if (records[i].val.pid != pids[qi]) continue;
                int ep = (epoch_windows > 0) ? (records[i].sample_id / epoch_windows) : 0;
                uint32_t tp; int32_t ts;
                get_top_pref(&records[i].val, &tp, &ts);
                if (ep == N_EPOCHS-1 && tp == tgt) { v3++; break; }
            }
        }

        double pct = (b1 > 0.001) ? (b3 - b1) / b1 * 100.0 : 0.0;
        if ((pct > 20.0 || pct < -20.0) && (v1 > 0 || v3 > 0)) {
            fprintf(f, "  %s (PID %u):\n", comms[pi], tgt);
            fprintf(f, "    Burst: %.1fms → %.1fms (%+.0f%%)\n", b1, b3, pct);
            fprintf(f, "    Voters: %d → %d\n", v1, v3);
            if (v3 >= v1 && pct > 20.0)
                fprintf(f, "    ⚠ STALE: burst grew but voters held\n");
            else if (v3 < v1)
                fprintf(f, "    ✓ Voters adapted (dropped %d→%d)\n", v1, v3);
            fprintf(f, "\n");
            n_celebrity++;
        }
    }
    if (n_celebrity == 0)
        fprintf(f, "  (No celebrity staleness detected)\n\n");

    /* ═══ Section 4: Vote Popularity by Epoch ═══ */
    fprintf(f, "══ SECTION 4: Vote Popularity by Epoch ══\n\n");

    for (int e = 0; e < N_EPOCHS; e++) {
        uint32_t e_start = e * epoch_windows;
        uint32_t e_end   = (e + 1) * epoch_windows - 1;
        if (e_end > max_sample) e_end = max_sample;

        fprintf(f, "  Epoch %d (t=%u-%us):\n", e+1,
                e_start * SNAPSHOT_INTERVAL_S,
                (e_end + 1) * SNAPSHOT_INTERVAL_S);

        uint32_t ap[128] = {0}; double av[128] = {0};
        char ac[128][17]; int acnt[128] = {0}; int na = 0;

        for (int i = 0; i < n_records; i++) {
            if (records[i].sample_id < e_start || records[i].sample_id > e_end)
                continue;
            if (records[i].val.institution) continue;
            uint32_t p = records[i].val.pid;
            int idx = -1;
            for (int k = 0; k < na; k++)
                if (ap[k] == p) { idx = k; break; }
            if (idx < 0 && na < 128) {
                idx = na++;
                ap[idx] = p;
                strncpy(ac[idx], records[i].val.comm, 16);
                ac[idx][16] = '\0';
            }
            if (idx >= 0) {
                av[idx] += records[i].val.votes_received;
                acnt[idx]++;
            }
        }

        /* Sort descending by total votes */
        for (int a = 0; a < na - 1; a++)
            for (int b = a + 1; b < na; b++)
                if (av[b] > av[a]) {
                    uint32_t tp=ap[a]; ap[a]=ap[b]; ap[b]=tp;
                    double tv=av[a]; av[a]=av[b]; av[b]=tv;
                    int tc=acnt[a]; acnt[a]=acnt[b]; acnt[b]=tc;
                    char tt[17]; memcpy(tt,ac[a],17); memcpy(ac[a],ac[b],17); memcpy(ac[b],tt,17);
                }

        int show = na < 10 ? na : 10;
        for (int k = 0; k < show; k++)
            fprintf(f, "    #%d  %s(%u) total=%.0f avg=%.1f/win\n",
                    k+1, ac[k], ap[k], av[k],
                    acnt[k] > 0 ? av[k]/acnt[k] : 0.0);
        fprintf(f, "\n");
    }

    fprintf(f, "═══════════════════════════════════════════════════════════\n");
    fprintf(f, "  End of analysis v2.\n");
    fprintf(f, "═══════════════════════════════════════════════════════════\n");

    fclose(f);
    printf("  Analysis:  %s\n", OUT_TEXT);
}

/* ── v19: Commstate map dump ──
 * Reads dem_commstate_map directly from bpffs — this is the actual learned
 * state, not the sampled snapshot. Shows what the RL has truly accumulated.
 */

#define DEM_COMMSTATE_OUT "dem_commstate_dump.txt"

/* Must match BPF-side dem_commstate exactly */
struct dem_commstate_a {
    uint16_t merge_count;
    uint16_t _pad[3];
    uint32_t pref_pid[DEM_PREF_SLOTS];
    int32_t  pref_score[DEM_PREF_SLOTS];
};

static void dump_commstate(int cs_fd)
{
    if (cs_fd < 0) {
        printf("  [commstate] map not available — skipping\n");
        return;
    }

    FILE *f = fopen(DEM_COMMSTATE_OUT, "w");
    if (!f) { perror("open dem_commstate_dump.txt"); return; }

    fprintf(f, "═══════════════════════════════════════════════════════════\n");
    fprintf(f, "  Democratic Scheduler v19 — Commstate (Live RL State)\n");
    fprintf(f, "  Source: %s (direct map read, not sampled)\n", DEM_PIN_COMMSTATE);
    fprintf(f, "═══════════════════════════════════════════════════════════\n\n");

    uint64_t key, next_key;
    int err = bpf_map_get_next_key(cs_fd, NULL, &key);

    int total = 0, active = 0, converged = 0;

    /* First pass: count */
    uint64_t keys[8192];
    int nkeys = 0;
    while (err == 0 && nkeys < 8192) {
        keys[nkeys++] = key;
        err = bpf_map_get_next_key(cs_fd, &key, &next_key);
        key = next_key;
    }
    total = nkeys;

    fprintf(f, "  Total archetypes in commstate: %d\n\n", total);

    if (total == 0) {
        fprintf(f, "  (empty — no tasks have merged preferences yet)\n");
        fprintf(f, "  This is normal on first run or with very short-lived processes.\n\n");
        fclose(f);
        printf("  [commstate] 0 archetypes — RL hasn't accumulated yet\n");
        return;
    }

    /* Sort and print by merge_count descending */
    /* Simple selection for up to 8192 entries */
    struct {
        uint64_t key;
        struct dem_commstate_a cs;
    } entries[8192];

    int n_valid = 0;
    for (int i = 0; i < nkeys; i++) {
        struct dem_commstate_a cs;
        if (bpf_map_lookup_elem(cs_fd, &keys[i], &cs) == 0 && cs.merge_count > 0) {
            entries[n_valid].key = keys[i];
            entries[n_valid].cs  = cs;
            n_valid++;
            if (cs.merge_count >= 16) converged++;
            /* count active pref slots */
            for (int s = 0; s < DEM_PREF_SLOTS; s++)
                if (cs.pref_pid[s] != 0) { active++; break; }
        }
    }

    /* Sort by merge_count descending (bubble, good enough for <8192) */
    for (int i = 0; i < n_valid - 1; i++)
        for (int j = 0; j < n_valid - i - 1; j++)
            if (entries[j].cs.merge_count < entries[j+1].cs.merge_count) {
                typeof(entries[0]) tmp = entries[j];
                entries[j] = entries[j+1];
                entries[j+1] = tmp;
            }

    fprintf(f, "  Valid archetypes   : %d\n", n_valid);
    fprintf(f, "  With pref data     : %d\n", active);
    fprintf(f, "  Mature (≥16 merges): %d  (these auto-converge new threads)\n\n", converged);

    fprintf(f, "══ Top archetypes by merge count ══\n\n");

    int show = n_valid < 50 ? n_valid : 50;
    for (int i = 0; i < show; i++) {
        uint64_t k   = entries[i].key;
        struct dem_commstate_a *cs = &entries[i].cs;
        uint32_t tgid  = (uint32_t)(k >> 32);
        uint32_t chash = (uint32_t)(k & 0xFFFFFFFF);

        /* Find best preference slot */
        int32_t  best_score = 0;
        uint32_t best_pid   = 0;
        int      n_prefs    = 0;
        int64_t  total_pos  = 0;

        for (int s = 0; s < DEM_PREF_SLOTS; s++) {
            if (cs->pref_pid[s] == 0) continue;
            n_prefs++;
            if (cs->pref_score[s] > best_score) {
                best_score = cs->pref_score[s];
                best_pid   = cs->pref_pid[s];
            }
            if (cs->pref_score[s] > 0) total_pos += cs->pref_score[s];
        }

        char mature = cs->merge_count >= 16 ? '*' : ' ';
        fprintf(f, "  %c tgid=%-8u chash=0x%08x  merges=%-5u  peers=%-2d  "
                   "top→pid%-8u sc=%-4d  pos_total=%lld\n",
                mature, tgid, chash, cs->merge_count,
                n_prefs, best_pid, best_score, (long long)total_pos);

        /* Show all preference slots for mature archetypes */
        if (cs->merge_count >= 8 && n_prefs > 0) {
            for (int s = 0; s < DEM_PREF_SLOTS; s++) {
                if (cs->pref_pid[s] == 0) continue;
                fprintf(f, "      slot[%2d]: pid=%-8u score=%d\n",
                        s, cs->pref_pid[s], cs->pref_score[s]);
            }
        }
    }

    fprintf(f, "\n  (* = mature, merge_count ≥ 16, new threads of this type "
               "auto-converge)\n");
    fprintf(f, "\n═══════════════════════════════════════════════════════════\n");
    fprintf(f, "  End of commstate dump.\n");
    fprintf(f, "═══════════════════════════════════════════════════════════\n");

    fclose(f);
    printf("  [commstate] %d archetypes (%d mature, %d with pref data) → %s\n",
           n_valid, converged, active, DEM_COMMSTATE_OUT);
}

/* ── v20: Boost stats report ──
 * Reads dem_boost_stats counters directly from BPF map and prints
 * a one-line summary of what % of scheduling decisions are vote-influenced.
 */
static void report_boost_stats(int bs_fd)
{
    if (bs_fd < 0) {
        printf("  [boost]    map not available — upgrade to v20 loader\n");
        return;
    }

    uint32_t idx0 = 0, idx1 = 1;
    uint64_t boosted = 0, unboosted = 0;

    bpf_map_lookup_elem(bs_fd, &idx0, &boosted);
    bpf_map_lookup_elem(bs_fd, &idx1, &unboosted);

    uint64_t total = boosted + unboosted;
    double pct = total > 0 ? (double)boosted / (double)total * 100.0 : 0.0;

    printf("  [boost]    boosted=%llu  unboosted=%llu  total=%llu  "
           "vote-influenced: %.2f%%\n",
           (unsigned long long)boosted,
           (unsigned long long)unboosted,
           (unsigned long long)total,
           pct);

    if (pct < 1.0)
        printf("             ↳ <1%% vote influence — RL not yet warm\n");
    else if (pct < 5.0)
        printf("             ↳ low influence — commstate warming up\n");
    else if (pct < 20.0)
        printf("             ↳ moderate influence — RL contributing\n");
    else
        printf("             ↳ strong influence — RL fully active\n");
}

/* ── Main ── */
int main(int argc, char **argv)
{
    int duration_s = DEFAULT_DURATION_S;
    if (argc >= 2) {
        int v = atoi(argv[1]);
        if (v > 0) duration_s = v;
    }

    int epoch_s = duration_s / N_EPOCHS;

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    printf("\n");
    printf("══════════════════════════════════════════════════════\n");
    printf("  Democratic Scheduler — Preference Drift Analyzer v2\n");
    printf("  Duration   : %ds (%d epochs × %ds)\n",
           duration_s, N_EPOCHS, epoch_s);
    printf("  Drain every: %ds | Snapshot interval: %ds\n",
           DRAIN_INTERVAL_S, SNAPSHOT_INTERVAL_S);
    printf("  Outputs    : %s  %s  %s\n", OUT_RAW, OUT_CSV, OUT_TEXT);
    printf("══════════════════════════════════════════════════════\n\n");

    /* ── Open pinned maps ── */
    printf("  Attaching to live scheduler maps...\n");

    int snap_map_fd = bpf_obj_get(DEM_PIN_SNAPSHOT);
    if (snap_map_fd < 0) {
        fprintf(stderr, "  ERROR: could not open %s: %s\n",
                DEM_PIN_SNAPSHOT, strerror(errno));
        fprintf(stderr, "  Make sure:\n");
        fprintf(stderr, "    1. democratic_loader v8 is running\n");
        fprintf(stderr, "    2. The v17 BPF object was loaded\n");
        fprintf(stderr, "    3. /sys/fs/bpf is mounted\n");
        return 1;
    }

    int seq_map_fd = bpf_obj_get(DEM_PIN_SEQ);
    if (seq_map_fd < 0)
        fprintf(stderr, "  Warning: could not open %s: %s\n",
                DEM_PIN_SEQ, strerror(errno));

    /* v19: open commstate map (optional — graceful if missing) */
    int cs_map_fd = bpf_obj_get(DEM_PIN_COMMSTATE);
    if (cs_map_fd < 0)
        printf("  Note: commstate map not available (%s) — upgrade loader to v19\n",
               DEM_PIN_COMMSTATE);

    /* v20: open boost stats map (optional) */
    int bs_map_fd = bpf_obj_get(DEM_PIN_BOOSTSTATS);
    if (bs_map_fd < 0)
        printf("  Note: boost stats map not available (%s) — upgrade loader to v20\n",
               DEM_PIN_BOOSTSTATS);

    printf("  Map FDs: snapshot=%d seq=%d commstate=%d booststats=%d\n",
           snap_map_fd, seq_map_fd, cs_map_fd, bs_map_fd);
    printf("  Running for %ds. Do your thing...\n\n", duration_s);

    /* v20: baseline boost stats at start */
    printf("  Boost stats (baseline):\n");
    report_boost_stats(bs_map_fd);
    printf("\n");

    /* ── Main loop: periodic drain ── */
    time_t start = time(NULL);
    time_t last_drain = start;
    int total_drained = 0;

    while (running) {
        int elapsed = (int)(time(NULL) - start);
        if (elapsed >= duration_s) break;

        print_progress(elapsed, duration_s);

        if ((time(NULL) - last_drain) >= DRAIN_INTERVAL_S) {
            int d = drain_snapshots(snap_map_fd);
            if (d > 0) {
                total_drained += d;
                printf("\n  [drain] +%d entries (total: %d)\n", d, total_drained);
            }
            last_drain = time(NULL);
        }

        sleep(1);
    }

    /* Final drain */
    printf("\n\n  Time's up. Final drain...\n");
    int final_d = drain_snapshots(snap_map_fd);
    total_drained += final_d;
    printf("  Final: +%d | Total: %d records across %d tasks\n",
           final_d, n_records,
           n_records > 0 ? (int)(records[n_records-1].sample_id + 1) : 0);

    if (n_records == 0) {
        printf("  No snapshots — check that the scheduler is v17\n");
        printf("  and has been running long enough.\n");
        close(snap_map_fd);
        if (seq_map_fd >= 0) close(seq_map_fd);
        return 1;
    }

    /* ── Write outputs ── */
    printf("\n  Writing outputs...\n");
    write_raw_dump();
    write_graph_csv(duration_s);
    write_analysis(duration_s);
    dump_commstate(cs_map_fd);

    /* v20: final boost stats */
    printf("\n  Boost stats (final):\n");
    report_boost_stats(bs_map_fd);

    printf("\n══════════════════════════════════════════════════════\n");
    printf("  Done. Outputs:\n");
    printf("    %s  — raw data for analysis\n", OUT_RAW);
    printf("    %s  — graph data (use dem_plot.py)\n", OUT_CSV);
    printf("    %s  — human-readable drift analysis\n", OUT_TEXT);
    printf("    %s  — live RL state (v19)\n", DEM_COMMSTATE_OUT);
    printf("══════════════════════════════════════════════════════\n\n");

    close(snap_map_fd);
    if (seq_map_fd >= 0) close(seq_map_fd);
    if (cs_map_fd  >= 0) close(cs_map_fd);
    if (bs_map_fd  >= 0) close(bs_map_fd);
    return 0;
}
