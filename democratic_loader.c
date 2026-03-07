/* democratic_loader.c — v18
 * Loads the democratic v18 scheduler BPF object and optionally seeds the
 * static vote map as a bootstrap hint. Reinforcement learning in the BPF
 * program builds per-task preferences; institutions bypass elections entirely.
 *
 * New in v18:
 *   - Compatible with v18 BPF (shared preference state via dem_commstate_map).
 *   - Automatically saves and loads shared preferences to/from disk at
 *     /tmp/democratic_commstate to preserve memory across reboots/restarts.
 *
 * New in v8:
 *   - Compatible with v17 BPF (snapshot map for preference drift analysis).
 *   - Pins dem_snapshot_map and dem_snap_seq_map to /sys/fs/bpf/ after load.
 *
 * Usage:
 *   sudo ./democratic_loader democratic.bpf.o [workload_pid] [--gamemode]
 *
 * If no PID given, watches for game_* threads system-wide.
 * Send SIGUSR1 to toggle gamemode at runtime.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Pin paths for snapshot maps — shared with dem_analyze */
#define DEM_PIN_SNAPSHOT  "/sys/fs/bpf/dem_snapshot_map"
#define DEM_PIN_SEQ       "/sys/fs/bpf/dem_snap_seq_map"

/* Must match democratic.bpf.c exactly */
#define DEM_MAX_VOTES   8
#define DEM_PREF_SLOTS  16
#define DEM_WARMSTATE_PATH "/tmp/democratic_warmstate"
#define DEM_COMMSTATE_PATH "/tmp/democratic_commstate"

struct dem_vprefs {
    __u32 preferred[DEM_MAX_VOTES];
    __u32 n_preferred;
};

struct dem_warmstart {
    __u8  institution;
    __u8  _pad[7];
    __u64 avg_burst_ns;
    char  comm[16];
};

/* Must match BPF-side dem_commstate exactly (v18) */
struct dem_commstate {
    __u16 merge_count;
    __u16 _pad[3];
    __u32 pref_pid[DEM_PREF_SLOTS];
    __s32 pref_score[DEM_PREF_SLOTS];
};

/* Known thread voting relationships for the game workload.
 * Physics -> votes for GameLogic (it produces data GL needs)
 * GameLogic -> votes for Renderer (it produces data RE needs)
 * Renderer -> votes for Physics (pipeline cycle, RE done = start next frame)
 * Audio -> votes for Physics (audio needs a new frame to mix)
 * AssetStream -> votes for Physics (background, yields to pipeline)
 *
 * Thread names must match what workload.py sets via prctl().
 */
#define N_KNOWN_THREADS 5
static const char *THREAD_NAMES[N_KNOWN_THREADS] = {
    "game_physics",
    "game_logic",
    "game_renderer",
    "game_audio",
    "game_assets",
};

/* votes_for[i] = list of indices into THREAD_NAMES that thread i votes for */
static const int VOTES_FOR[N_KNOWN_THREADS][DEM_MAX_VOTES] = {
    /* game_physics   -> votes for game_logic, game_renderer */
    {1, 2, -1},
    /* game_logic     -> votes for game_renderer, game_physics */
    {2, 0, -1},
    /* game_renderer  -> votes for game_physics, game_logic */
    {0, 1, -1},
    /* game_audio     -> votes for game_physics (needs fresh frame data) */
    {0, -1},
    /* game_assets    -> votes for game_physics (low priority, yields to pipeline) */
    {0, -1},
};

static volatile int running = 1;
static int gamemode_map_fd = -1;

static void sig_handler(int sig) {
    printf("\n  Caught signal %d — unloading...\n", sig);
    running = 0;
}

static void gamemode_toggle(int sig) {
    (void)sig;
    if (gamemode_map_fd < 0) return;
    __u32 zero = 0;
    __u32 current = 0;
    bpf_map_lookup_elem(gamemode_map_fd, &zero, &current);
    current = current ? 0 : 1;
    bpf_map_update_elem(gamemode_map_fd, &zero, &current, BPF_ANY);
    printf("\n  GAMEMODE: %s\n", current ? "ON" : "OFF");
}

/* djb2 hash — must match BPF-side dem_comm_hash() exactly */
static __u32 dem_comm_hash(const char *c)
{
    __u32 h = 5381;
    for (int i = 0; i < 16 && c[i]; i++) {
        h = ((h << 5) + h) + (unsigned char)c[i];
    }
    return h;
}

/* Save institution data from warmstart_map for next load.
 * v7: BPF maintains warmstart_map with comm names, so we just iterate it
 * directly. No more /proc lookups or dem_task_map dependency.
 */
static void save_warmstate(int warmstart_map_fd)
{
    FILE *f = fopen(DEM_WARMSTATE_PATH, "w");
    if (!f) {
        printf("  Warning: could not save warm state to %s\n",
               DEM_WARMSTATE_PATH);
        return;
    }

    __u32 key;
    int count = 0;

    int err = bpf_map_get_next_key(warmstart_map_fd, NULL, &key);
    while (err == 0) {
        struct dem_warmstart ws;
        if (bpf_map_lookup_elem(warmstart_map_fd, &key, &ws) == 0) {
            if (ws.institution && ws.comm[0] != '\0') {
                /* Numbers first, comm last — comm may have spaces */
                fprintf(f, "%u %llu %s\n",
                        (unsigned)ws.institution,
                        (unsigned long long)ws.avg_burst_ns,
                        ws.comm);
                count++;
            }
        }
        __u32 prev_key = key;
        err = bpf_map_get_next_key(warmstart_map_fd, &prev_key, &key);
    }

    fclose(f);
    printf("  Saved warm state: %d institution entries to %s\n",
           count, DEM_WARMSTATE_PATH);
}

/* Load warm state from previous run and populate warmstart map */
static int load_warmstate(int warmstart_map_fd)
{
    FILE *f = fopen(DEM_WARMSTATE_PATH, "r");
    if (!f) {
        printf("  No warm state file found (cold start)\n");
        return 0;
    }

    char line[256];
    int count = 0;

    /* Format: "inst avg_burst comm_name\n" — comm is last (may have spaces) */
    while (fgets(line, sizeof(line), f)) {
        unsigned int inst = 0;
        unsigned long long avg_burst = 0;
        int n = 0;

        if (sscanf(line, "%u %llu %n", &inst, &avg_burst, &n) >= 2 && n > 0) {
            char *comm = line + n;
            comm[strcspn(comm, "\n")] = 0;
            if (strlen(comm) == 0) continue;

            __u32 chash = dem_comm_hash(comm);
            struct dem_warmstart ws = {};
            ws.institution = inst ? 1 : 0;
            ws.avg_burst_ns = avg_burst;
            strncpy(ws.comm, comm, 15);
            ws.comm[15] = '\0';

            if (bpf_map_update_elem(warmstart_map_fd, &chash, &ws, BPF_ANY) == 0)
                count++;
        }
    }

    fclose(f);
    printf("  Loaded warm state: %d entries from %s\n",
           count, DEM_WARMSTATE_PATH);
    return count;
}

/* ── v18: Save and load shared preference archetypes ── */
static void save_commstate(int commstate_map_fd)
{
    if (commstate_map_fd < 0) return;

    FILE *f = fopen(DEM_COMMSTATE_PATH, "w");
    if (!f) {
        printf("  Warning: could not save comm state to %s\n", DEM_COMMSTATE_PATH);
        return;
    }

    __u64 key;
    int count = 0;

    int err = bpf_map_get_next_key(commstate_map_fd, NULL, &key);
    while (err == 0) {
        struct dem_commstate cs;
        if (bpf_map_lookup_elem(commstate_map_fd, &key, &cs) == 0 && cs.merge_count > 0) {
            fprintf(f, "%llu %u", (unsigned long long)key, (unsigned)cs.merge_count);
            for (int i = 0; i < DEM_PREF_SLOTS; i++) {
                fprintf(f, " %u %d", cs.pref_pid[i], cs.pref_score[i]);
            }
            fprintf(f, "\n");
            count++;
        }
        __u64 prev_key = key;
        err = bpf_map_get_next_key(commstate_map_fd, &prev_key, &key);
    }

    fclose(f);
    printf("  Saved comm state: %d archetype entries to %s\n",
           count, DEM_COMMSTATE_PATH);
}

static int load_commstate(int commstate_map_fd)
{
    if (commstate_map_fd < 0) return 0;

    FILE *f = fopen(DEM_COMMSTATE_PATH, "r");
    if (!f) {
        printf("  No comm state file found (first v18 run)\n");
        return 0;
    }

    char line[4096];
    int count = 0;

    while (fgets(line, sizeof(line), f)) {
        __u64 key = 0;
        unsigned int mc = 0;
        int n = 0;
        int offset = 0;

        if (sscanf(line, "%llu %u %n", &key, &mc, &n) >= 2) {
            offset += n;
            struct dem_commstate cs = {};
            cs.merge_count = mc;
            
            for (int i = 0; i < DEM_PREF_SLOTS; i++) {
                unsigned int pid = 0;
                int score = 0;
                int tn = 0;
                if (sscanf(line + offset, "%u %d %n", &pid, &score, &tn) >= 2) {
                    cs.pref_pid[i] = pid;
                    cs.pref_score[i] = score;
                    offset += tn;
                }
            }

            if (bpf_map_update_elem(commstate_map_fd, &key, &cs, BPF_ANY) == 0)
                count++;
        }
    }

    fclose(f);
    printf("  Loaded comm state: %d archetype entries from %s\n",
           count, DEM_COMMSTATE_PATH);
    return count;
}

/* Find TID of a thread by name under a given PID's task directory.
 * If watch_pid == 0, searches all of /proc.
 * Returns TID or 0 if not found.
 */
static __u32 find_tid_by_name(const char *thread_name, int watch_pid)
{
    char path[256];
    char comm[64];
    DIR *dir;
    struct dirent *ent;
    __u32 found_tid = 0;

    /* If we have a specific PID, only look in its task dir */
    if (watch_pid > 0) {
        snprintf(path, sizeof(path), "/proc/%d/task", watch_pid);
        dir = opendir(path);
        if (!dir) return 0;

        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            int tid = atoi(ent->d_name);
            if (tid <= 0) continue;

            snprintf(path, sizeof(path), "/proc/%d/task/%d/comm",
                     watch_pid, tid);
            FILE *f = fopen(path, "r");
            if (!f) continue;
            if (fgets(comm, sizeof(comm), f)) {
                comm[strcspn(comm, "\n")] = 0;
                if (strcmp(comm, thread_name) == 0) {
                    found_tid = (__u32)tid;
                }
            }
            fclose(f);
            if (found_tid) break;
        }
        closedir(dir);
        return found_tid;
    }

    /* No PID given — scan all of /proc */
    dir = opendir("/proc");
    if (!dir) return 0;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        int pid = atoi(ent->d_name);
        if (pid <= 0) continue;

        snprintf(path, sizeof(path), "/proc/%d/task", pid);
        DIR *tdir = opendir(path);
        if (!tdir) continue;

        struct dirent *tent;
        while ((tent = readdir(tdir)) != NULL) {
            if (tent->d_name[0] == '.') continue;
            int tid = atoi(tent->d_name);
            if (tid <= 0) continue;

            snprintf(path, sizeof(path), "/proc/%d/task/%d/comm", pid, tid);
            FILE *f = fopen(path, "r");
            if (!f) continue;
            if (fgets(comm, sizeof(comm), f)) {
                comm[strcspn(comm, "\n")] = 0;
                if (strcmp(comm, thread_name) == 0)
                    found_tid = (__u32)tid;
            }
            fclose(f);
            if (found_tid) break;
        }
        closedir(tdir);
        if (found_tid) break;
    }
    closedir(dir);
    return found_tid;
}

/* Register votes for all known threads into the BPF map.
 * Returns number of threads successfully registered.
 */
static int register_votes(int vote_map_fd, int watch_pid)
{
    /* Step 1: resolve all thread names to TIDs */
    __u32 tids[N_KNOWN_THREADS] = {0};
    int found = 0;

    for (int i = 0; i < N_KNOWN_THREADS; i++) {
        tids[i] = find_tid_by_name(THREAD_NAMES[i], watch_pid);
        if (tids[i]) found++;
    }

    if (found == 0) return 0;

    /* Step 2: for each found thread, write its vote preferences */
    int registered = 0;
    for (int i = 0; i < N_KNOWN_THREADS; i++) {
        if (!tids[i]) continue;

        struct dem_vprefs vp = {0};
        for (int j = 0; j < DEM_MAX_VOTES; j++) {
            int vote_idx = VOTES_FOR[i][j];
            if (vote_idx < 0) break;          /* -1 = end of list */
            if (!tids[vote_idx]) continue;    /* that thread not found yet */
            vp.preferred[vp.n_preferred++] = tids[vote_idx];
        }

        if (vp.n_preferred == 0) continue;

        if (bpf_map_update_elem(vote_map_fd, &tids[i], &vp, BPF_ANY) == 0)
            registered++;
    }

    return registered;
}

int main(int argc, char **argv)
{
    const char *bpf_obj_path = "democratic.bpf.o";
    int watch_pid = 0;
    int gamemode = 0;

    /* Parse args: positional (bpf_obj, pid) + flags (--gamemode / -g) */
    int pos = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--gamemode") == 0 || strcmp(argv[i], "-g") == 0) {
            gamemode = 1;
        } else {
            pos++;
            if (pos == 1) bpf_obj_path = argv[i];
            else if (pos == 2) watch_pid = atoi(argv[i]);
        }
    }

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGUSR1, gamemode_toggle);

    printf("\n");
    printf("══════════════════════════════════════════════════════\n");
    printf("  Democratic CPU Scheduler — BPF Loader v18\n");
    printf("  (v18: shared preference memory across reboots)\n");
    printf("══════════════════════════════════════════════════════\n");
    printf("  BPF object : %s\n", bpf_obj_path);
    if (watch_pid)
        printf("  Watching   : PID %d\n", watch_pid);
    else
        printf("  Watching   : system-wide (game_* threads)\n");
    if (gamemode)
        printf("  Gamemode   : ENABLED at startup\n");
    printf("  SIGUSR1    : toggle gamemode at runtime\n");

    /* ── Load BPF object ── */
    struct bpf_object *obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "  Failed to open %s: %s\n",
                bpf_obj_path, strerror(errno));
        return 1;
    }

    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "  Failed to load BPF object: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }
    printf("  BPF object loaded\n");

    /* ── Get map FDs ── */
    int vote_map_fd = bpf_object__find_map_fd_by_name(obj, "dem_vote_map");
    if (vote_map_fd < 0) {
        fprintf(stderr, "  Could not find dem_vote_map\n");
        bpf_object__close(obj);
        return 1;
    }

    int warmstart_map_fd = bpf_object__find_map_fd_by_name(obj,
                                                            "dem_warmstart_map");
    if (warmstart_map_fd < 0) {
        printf("  Warning: dem_warmstart_map not found (no warm start)\n");
    }

    gamemode_map_fd = bpf_object__find_map_fd_by_name(obj, "dem_gamemode");
    if (gamemode_map_fd < 0) {
        printf("  Warning: dem_gamemode map not found\n");
    }

    int commstate_map_fd = bpf_object__find_map_fd_by_name(obj, "dem_commstate_map");
    if (commstate_map_fd < 0) {
        printf("  Warning: dem_commstate_map not found (no shared preferences)\n");
    }

    printf("  Map fds: vote=%d warmstart=%d gamemode=%d commstate=%d\n",
           vote_map_fd, warmstart_map_fd, gamemode_map_fd, commstate_map_fd);

    /* ── Pin snapshot maps for dem_analyze to share ──
     * Ensures /sys/fs/bpf exists, removes any stale pins, then pins
     * dem_snapshot_map and dem_snap_seq_map so dem_analyze can open
     * the live map instances via bpf_obj_get().
     */
    {
        struct stat st;
        if (stat("/sys/fs/bpf", &st) != 0) {
            printf("  Warning: /sys/fs/bpf not found — snapshot pinning skipped\n");
            printf("  (mount bpffs: mount -t bpf bpf /sys/fs/bpf)\n");
        } else {
            unlink(DEM_PIN_SNAPSHOT);
            unlink(DEM_PIN_SEQ);

            struct bpf_map *snap_map = bpf_object__find_map_by_name(obj,
                                                                     "dem_snapshot_map");
            struct bpf_map *seq_map  = bpf_object__find_map_by_name(obj,
                                                                     "dem_snap_seq_map");

            int pin_ok = 1;
            if (snap_map) {
                if (bpf_map__pin(snap_map, DEM_PIN_SNAPSHOT) == 0)
                    printf("  Pinned dem_snapshot_map  → %s\n", DEM_PIN_SNAPSHOT);
                else {
                    printf("  Warning: could not pin dem_snapshot_map: %s\n",
                           strerror(errno));
                    pin_ok = 0;
                }
            } else {
                printf("  Warning: dem_snapshot_map not found (is this v17?)\n");
                pin_ok = 0;
            }

            if (seq_map) {
                if (bpf_map__pin(seq_map, DEM_PIN_SEQ) == 0)
                    printf("  Pinned dem_snap_seq_map  → %s\n", DEM_PIN_SEQ);
                else {
                    printf("  Warning: could not pin dem_snap_seq_map: %s\n",
                           strerror(errno));
                    pin_ok = 0;
                }
            } else {
                printf("  Warning: dem_snap_seq_map not found (is this v17?)\n");
                pin_ok = 0;
            }

            if (pin_ok)
                printf("  dem_analyze can now attach to live snapshot maps.\n");
        }
    }

    /* ── Load warm start data before attaching ── */
    if (warmstart_map_fd >= 0) {
        load_warmstate(warmstart_map_fd);
    }
    if (commstate_map_fd >= 0) {
        load_commstate(commstate_map_fd);
    }

    /* ── Set gamemode if requested ── */
    if (gamemode && gamemode_map_fd >= 0) {
        __u32 zero = 0;
        __u32 one = 1;
        bpf_map_update_elem(gamemode_map_fd, &zero, &one, BPF_ANY);
    }

    /* ── Attach scheduler ── */
    struct bpf_map *ops_map = bpf_object__find_map_by_name(obj, "democratic_ops");
    if (!ops_map) {
        fprintf(stderr, "  Could not find democratic_ops\n");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_link *link = bpf_map__attach_struct_ops(ops_map);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "  Failed to attach sched_ext: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    printf("  Democratic scheduler v18 ACTIVE%s\n",
           gamemode ? " [GAMEMODE]" : "");
    printf("  Press Ctrl+C to stop and revert to BORE\n");
    printf("══════════════════════════════════════════════════════\n\n");

    /* ── Main loop: register votes, poll state ── */
    int last_registered = 0;

    while (running) {
        /* Re-register votes every second (handles new workload launches) */
        int reg = register_votes(vote_map_fd, watch_pid);

        if (reg != last_registered) {
            printf("  Bootstrap vote registrations: %d/%d threads wired up\n",
                   reg, N_KNOWN_THREADS);
            if (reg > 0)
                printf("  (reinforcement learning will build preferences over ~128 runs)\n");

            /* Print exactly which TIDs are voting for what */
            if (reg > 0) {
                printf("  ┌─────────────────────────────────────────┐\n");
                for (int i = 0; i < N_KNOWN_THREADS; i++) {
                    __u32 tid = find_tid_by_name(THREAD_NAMES[i], watch_pid);
                    if (!tid) continue;
                    printf("  │ %-14s (TID %5u) votes for: ",
                           THREAD_NAMES[i], tid);
                    for (int j = 0; j < DEM_MAX_VOTES; j++) {
                        int vi = VOTES_FOR[i][j];
                        if (vi < 0) break;
                        __u32 vtid = find_tid_by_name(THREAD_NAMES[vi], watch_pid);
                        if (vtid)
                            printf("%s(%u) ", THREAD_NAMES[vi], vtid);
                    }
                    printf("\n");
                }
                printf("  └─────────────────────────────────────────┘\n");
            }
            last_registered = reg;
        }

        /* Check scheduler is still alive */
        FILE *f = fopen("/sys/kernel/sched_ext/state", "r");
        if (f) {
            char state[64] = {0};
            fgets(state, sizeof(state), f);
            fclose(f);
            state[strcspn(state, "\n")] = 0;
            if (strcmp(state, "enabled") != 0) {
                printf("  sched_ext state: %s — scheduler died\n", state);
                break;
            }
        }

        sleep(1);
    }

    /* ── Cleanup: save warm state BEFORE detach ──
     * v16: warmstart_map is maintained by BPF (written in stopping when
     * institutions are detected), so we iterate it directly.
     * v18: commstate_map stores shared preference state.
     * These maps are NOT emptied by bpf_link__destroy, but we save before
     * detach for consistency.
     */
    if (warmstart_map_fd >= 0) {
        save_warmstate(warmstart_map_fd);
    }
    if (commstate_map_fd >= 0) {
        save_commstate(commstate_map_fd);
    }

    /* ── Unpin snapshot maps ── */
    unlink(DEM_PIN_SNAPSHOT);
    unlink(DEM_PIN_SEQ);

    bpf_link__destroy(link);
    bpf_object__close(obj);
    printf("\n  Democratic scheduler v18 unloaded. Reverted to BORE.\n\n");
    return 0;
}