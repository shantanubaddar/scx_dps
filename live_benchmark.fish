#!/usr/bin/env fish
# live_benchmark.fish — Benchmark the CURRENTLY RUNNING scheduler, then compare with BORE.
#
# This script does NOT reload Democratic. It benchmarks whatever is active right now,
# giving you "hours-warmed" results if Democratic has been running for a while.
#
# Phase 1: Benchmark current scheduler (assumed to be warmed-up Democratic)
# Phase 2: Unload, benchmark BORE
#
# Usage: sudo ./live_benchmark.fish

set SCRIPT_DIR (dirname (status filename))
set LOADER "$SCRIPT_DIR/democratic_loader"
set BPF_OBJ "$SCRIPT_DIR/democratic.bpf.o"
set RESULTS /tmp/live_benchmark
set NCPU (nproc)

# ── Preflight ──

if test (id -u) -ne 0
    echo "  This script must be run as root (sudo)."
    exit 1
end

for tool in schbench cyclictest hackbench
    if not which $tool >/dev/null 2>&1
        echo "  $tool not found."
        exit 1
    end
end

rm -rf $RESULTS
mkdir -p $RESULTS

# ── Helpers ──

function start_cpu_load
    stress-ng --cpu 1 --timeout 1 2>/dev/null
    if test $status -eq 0
        echo "    Using stress-ng ($NCPU cores)..."
        stress-ng --cpu $NCPU --timeout 300 &
        set -g LOAD_PIDS $last_pid
        set -g LOAD_TYPE "stress-ng"
    else
        echo "    Using yes burners ($NCPU cores)..."
        set -g LOAD_PIDS
        for i in (seq $NCPU)
            yes > /dev/null 2>&1 &
            set -a LOAD_PIDS $last_pid
        end
        set -g LOAD_TYPE "yes"
    end
    sleep 2
end

function stop_cpu_load
    for pid in $LOAD_PIDS
        kill $pid 2>/dev/null
        wait $pid 2>/dev/null
    end
    echo "    Stopped ($LOAD_TYPE)"
end

function run_all_benchmarks --argument-names prefix label
    echo "    schbench (120s, wakeup latency)..."
    schbench -m 2 -t 4 -r 120 2>&1 | tee $RESULTS/{$prefix}_schbench.txt
    echo ""

    echo "    hackbench x3 (throughput)..."
    for i in 1 2 3
        echo "      hackbench run $i/3..."
        hackbench -g 4 -l 5000 -p 2>&1 | tee -a $RESULTS/{$prefix}_hackbench.txt
    end
    echo ""

    echo "    cyclictest (60s, periodic latency)..."
    cyclictest -t 4 -p 80 -i 1000 -D 60 --mlockall -q 2>&1 | tee $RESULTS/{$prefix}_cyclictest.txt
    echo ""
end

# ── Detect current scheduler ──

echo ""
echo "================================================================"
echo "  Live Scheduler Benchmark"
echo "  schbench 120s | hackbench x3 | cyclictest 60s"
echo "  CPU cores: $NCPU"
echo "================================================================"
echo ""

set current_sched "BORE"
if test -f /sys/kernel/sched_ext/state
    set state (cat /sys/kernel/sched_ext/state)
    if test "$state" = "enabled"
        set current_sched "Democratic"
        echo "  Detected: Democratic scheduler is ACTIVE (sched_ext enabled)"
        echo "  Benchmarking the live, warmed-up instance."
    else
        echo "  Detected: sched_ext is $state — running on BORE"
    end
else
    echo "  Detected: No sched_ext — running on BORE"
end

echo ""

# ── Phase 1: Current scheduler — Clean ──

echo "━━━━ [1/4] $current_sched (live) — Clean ━━━━"
echo ""
run_all_benchmarks {$current_sched}_live_clean "$current_sched live clean"
sleep 2

# ── Phase 2: Current scheduler — Under load ──

echo "━━━━ [2/4] $current_sched (live) — Under Load ━━━━"
echo ""
start_cpu_load
run_all_benchmarks {$current_sched}_live_load "$current_sched live load"
stop_cpu_load
sleep 2

# ── Unload if Democratic, switch to BORE ──

if test "$current_sched" = "Democratic"
    echo "━━━━ Switching to BORE... ━━━━"
    echo ""

    # Find and kill the loader process
    set loader_pids (pgrep -f democratic_loader)
    if test (count $loader_pids) -gt 0
        for pid in $loader_pids
            kill $pid 2>/dev/null
        end
        sleep 3
        echo "  Democratic unloaded."
    else
        echo "  WARNING: Could not find loader process."
        echo "  Manually unload Democratic before continuing."
        echo "  Press Enter when ready..."
        read
    end

    # Verify unloaded
    if test -f /sys/kernel/sched_ext/state
        set state (cat /sys/kernel/sched_ext/state)
        if test "$state" = "enabled"
            echo "  ERROR: sched_ext still enabled. Aborting BORE phase."
            echo "  Results for $current_sched saved to: $RESULTS/"
            exit 1
        end
    end

    echo "  Now running on BORE."
    echo ""

    # ── Phase 3: BORE — Clean ──

    echo "━━━━ [3/4] BORE — Clean ━━━━"
    echo ""
    run_all_benchmarks BORE_clean "BORE clean"
    sleep 2

    # ── Phase 4: BORE — Under load ──

    echo "━━━━ [4/4] BORE — Under Load ━━━━"
    echo ""
    start_cpu_load
    run_all_benchmarks BORE_load "BORE load"
    stop_cpu_load

    echo ""
    echo "  Reloading Democratic (so you can keep using it)..."
    $LOADER $BPF_OBJ &
    set RELOAD_PID $last_pid
    sleep 3
    if test -f /sys/kernel/sched_ext/state
        set state (cat /sys/kernel/sched_ext/state)
        if test "$state" = "enabled"
            echo "  Democratic reloaded and active."
        else
            echo "  WARNING: Democratic may not have loaded correctly."
        end
    end
end

# ── Results Summary ──

echo ""
echo "================================================================"
echo "  LIVE BENCHMARK RESULTS"
echo "================================================================"
echo ""

echo "──── SCHBENCH (wakeup latency, last snapshot — lower is better) ────"
echo ""

for scenario in {$current_sched}_live_clean {$current_sched}_live_load BORE_clean BORE_load
    set file $RESULTS/{$scenario}_schbench.txt
    if test -f $file
        echo "  $scenario:"
        set sections (string split "Wakeup Latencies" < $file)
        set last_section $sections[-1]
        for pct in "50.0th" "90.0th" "99.0th" "99.9th"
            echo "$last_section" | grep "$pct" | tail -1 | sed 's/^/    /'
        end
        grep "average rps" $file | tail -1 | sed 's/^/    /'
        echo ""
    end
end

echo "──── HACKBENCH (time, 3 runs — lower is better) ────"
echo ""

for scenario in {$current_sched}_live_clean {$current_sched}_live_load BORE_clean BORE_load
    set file $RESULTS/{$scenario}_hackbench.txt
    if test -f $file
        echo "  $scenario:"
        grep -i 'Time:' $file | sed 's/^/    /'
        echo ""
    end
end

echo "──── CYCLICTEST (60s, periodic latency — lower is better) ────"
echo ""

for scenario in {$current_sched}_live_clean {$current_sched}_live_load BORE_clean BORE_load
    set file $RESULTS/{$scenario}_cyclictest.txt
    if test -f $file
        echo "  $scenario:"
        grep -E '^T:' $file | sed 's/^/    /'
        echo ""
    end
end

echo "================================================================"
echo "  Results saved to: $RESULTS/"
echo "================================================================"
echo ""
