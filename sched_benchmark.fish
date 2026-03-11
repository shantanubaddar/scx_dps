#!/usr/bin/env fish
# sched_benchmark.fish — Comprehensive scheduler comparison benchmark
#
# Tests Democratic (DPS) against all available sched_ext schedulers + BORE baseline.
# Outputs structured CSV data for plotting.
#
# Usage: sudo ./sched_benchmark.fish [--schedulers "bore,democratic,scx_lavd,..."]
#                                    [--runs N]  (default: 3)
#                                    [--outdir DIR] (default: /tmp/sched_benchmark)
#
# Benchmarks run per scheduler:
#   - hackbench:  g2, g4, g8, g16 (IPC throughput)
#   - sysbench:   cpu, memory (raw throughput)
#   - schbench:   wakeup latency (120s)
#   - cyclictest: periodic RT latency (60s)

set SCRIPT_DIR (dirname (status filename))
set LOADER "$SCRIPT_DIR/democratic_loader"
set BPF_OBJ "$SCRIPT_DIR/democratic.bpf.o"
set NCPU (nproc)

# ── Defaults ──
set RUNS 3
set OUTDIR /tmp/sched_benchmark
set SCHED_LIST bore democratic scx_bpfland scx_lavd scx_flash scx_rusty scx_bore

# ── Parse args ──
set i 1
while test $i -le (count $argv)
    switch $argv[$i]
        case --schedulers
            set i (math $i + 1)
            set SCHED_LIST (string split "," $argv[$i])
        case --runs
            set i (math $i + 1)
            set RUNS $argv[$i]
        case --outdir
            set i (math $i + 1)
            set OUTDIR $argv[$i]
    end
    set i (math $i + 1)
end

# ── Preflight ──
if test (id -u) -ne 0
    echo "  ERROR: Must run as root (sudo)."
    exit 1
end

for tool in schbench cyclictest hackbench sysbench
    if not which $tool >/dev/null 2>&1
        echo "  ERROR: $tool not found. Install it first."
        exit 1
    end
end

rm -rf $OUTDIR
mkdir -p $OUTDIR/raw

# ── CSV headers ──
set RESULTS_CSV $OUTDIR/results.csv
echo "scheduler,benchmark,metric,run,value" > $RESULTS_CSV

# ── Helper: append a result row ──
function record --argument-names sched bench metric run_n val
    echo "$sched,$bench,$metric,$run_n,$val" >> $RESULTS_CSV
end

# ── Helper: stop any running sched_ext scheduler ──
function stop_scx
    # Kill known scx schedulers and our loader
    # NOTE: use pkill -x (exact process name match), NOT pkill -f (full cmdline match),
    # because -f would match this script's own arguments and kill us.
    for proc in democratic_loader scx_bpfland scx_lavd scx_flash scx_rusty scx_bore scx_rustland scx_layered scx_chaos scx_cosmos scx_p2dq scx_tickless scx_beerland
        pkill -x $proc 2>/dev/null
    end
    sleep 2

    # Verify sched_ext is off
    if test -f /sys/kernel/sched_ext/state
        set state (cat /sys/kernel/sched_ext/state)
        if test "$state" = "enabled"
            echo "    WARNING: sched_ext still enabled after stop attempt"
            sleep 3
            for proc in democratic_loader scx_bpfland scx_lavd scx_flash scx_rusty scx_bore
                pkill -9 -x $proc 2>/dev/null
            end
            sleep 2
        end
    end
end

# ── Helper: start a scheduler, return 0 on success ──
function start_scheduler --argument-names sched
    switch $sched
        case bore
            # BORE is the default when no sched_ext is loaded — nothing to start
            stop_scx
            echo "    Running on BORE (default kernel scheduler)"
            return 0
        case democratic
            $LOADER $BPF_OBJ &
            set -g SCHED_PID $last_pid
        case 'scx_*'
            # Start the scx scheduler in background
            $sched &
            set -g SCHED_PID $last_pid
        case '*'
            echo "    ERROR: Unknown scheduler: $sched"
            return 1
    end

    sleep 3

    if test -f /sys/kernel/sched_ext/state
        set state (cat /sys/kernel/sched_ext/state)
        if test "$state" = "enabled"
            echo "    $sched is ACTIVE"
            return 0
        end
    end

    echo "    ERROR: $sched failed to activate"
    return 1
end

# ── Helper: stop current scheduler ──
function stop_scheduler --argument-names sched
    if test "$sched" = "bore"
        return 0
    end
    if set -q SCHED_PID
        kill $SCHED_PID 2>/dev/null
        wait $SCHED_PID 2>/dev/null
    end
    sleep 2
end

# ── Benchmark functions ──

function run_hackbench --argument-names sched groups run_n
    set tasks (math "$groups * 40")
    set raw_file $OUTDIR/raw/{$sched}_hackbench_g{$groups}_run{$run_n}.txt
    hackbench -g $groups -l 5000 -s 100 2>&1 | tee $raw_file
    set time_val (grep -i 'Time:' $raw_file | awk '{print $2}')
    if test -n "$time_val"
        record $sched "hackbench_g$groups" "time_s" $run_n $time_val
    end
end

function run_sysbench_cpu --argument-names sched run_n
    set raw_file $OUTDIR/raw/{$sched}_sysbench_cpu_run{$run_n}.txt
    sysbench cpu --threads=$NCPU --time=30 run 2>&1 | tee $raw_file
    set eps (grep 'events per second' $raw_file | awk '{print $NF}')
    set lat_avg (grep 'avg:' $raw_file | head -1 | awk '{print $NF}')
    set lat_p95 (grep '95th percentile:' $raw_file | awk '{print $NF}')
    if test -n "$eps"
        record $sched "sysbench_cpu" "events_per_sec" $run_n $eps
    end
    if test -n "$lat_avg"
        record $sched "sysbench_cpu" "latency_avg_ms" $run_n $lat_avg
    end
    if test -n "$lat_p95"
        record $sched "sysbench_cpu" "latency_p95_ms" $run_n $lat_p95
    end
end

function run_sysbench_mem --argument-names sched run_n
    set raw_file $OUTDIR/raw/{$sched}_sysbench_mem_run{$run_n}.txt
    sysbench memory --threads=$NCPU --time=30 run 2>&1 | tee $raw_file
    set mbs (grep 'MiB/sec' $raw_file | grep -oP '[\d.]+(?= MiB/sec)')
    if test -n "$mbs"
        record $sched "sysbench_mem" "throughput_mib_s" $run_n $mbs
    end
end

function run_schbench --argument-names sched run_n
    set raw_file $OUTDIR/raw/{$sched}_schbench_run{$run_n}.txt
    schbench -m 2 -t $NCPU -r 120 2>&1 | tee $raw_file

    # Extract final snapshot (last occurrence of each percentile)
    # NOTE: schbench marks one line with a leading "* " which shifts awk fields.
    # Use grep -oP to extract just the number after "NN.Nth: " reliably.
    for pct_label in "50.0th" "90.0th" "99.0th" "99.9th"
        set val (grep "Wakeup" -A 5 $raw_file | grep "$pct_label" | tail -1 | grep -oP "$pct_label:\s+\K\d+")
        if test -n "$val"
            set metric_name (string replace "." "p" $pct_label | string replace "th" "")
            record $sched "schbench" "wakeup_$metric_name" $run_n $val
        end
    end
    set rps (grep 'average rps' $raw_file | tail -1 | awk '{print $NF}')
    if test -n "$rps"
        record $sched "schbench" "avg_rps" $run_n $rps
    end
end

function run_cyclictest --argument-names sched run_n
    set raw_file $OUTDIR/raw/{$sched}_cyclictest_run{$run_n}.txt
    cyclictest -t $NCPU -p 80 -i 1000 -D 60 --mlockall -q 2>&1 | tee $raw_file

    # Parse each thread line: T: N (...) ... Min: X Act: Y Avg: Z Max: W
    set thread_n 0
    for line in (grep '^T:' $raw_file)
        set avg_val (echo $line | grep -oP 'Avg:\s+\K\d+')
        set max_val (echo $line | grep -oP 'Max:\s+\K\d+')
        if test -n "$avg_val"
            record $sched "cyclictest" "avg_us_t$thread_n" $run_n $avg_val
        end
        if test -n "$max_val"
            record $sched "cyclictest" "max_us_t$thread_n" $run_n $max_val
        end
        set thread_n (math $thread_n + 1)
    end
end

# ── Main ──

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Comprehensive Scheduler Benchmark"
echo "  Schedulers: $SCHED_LIST"
echo "  Runs per benchmark: $RUNS"
echo "  CPU cores: $NCPU"
echo "  Output: $OUTDIR/"
echo "═══════════════════════════════════════════════════════════════"
echo ""

set total_scheds (count $SCHED_LIST)
set sched_n 0

for sched in $SCHED_LIST
    set sched_n (math $sched_n + 1)
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  [$sched_n/$total_scheds] $sched"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    if not start_scheduler $sched
        echo "    SKIPPING $sched (failed to start)"
        continue
    end

    sleep 2

    # ── hackbench ──
    for groups in 2 4 8 16
        echo "  ── hackbench -g$groups ($RUNS runs) ──"
        for run_n in (seq $RUNS)
            echo "    run $run_n/$RUNS..."
            run_hackbench $sched $groups $run_n
        end
    end

    # ── sysbench cpu ──
    echo "  ── sysbench cpu ($RUNS runs x 30s) ──"
    for run_n in (seq $RUNS)
        echo "    run $run_n/$RUNS..."
        run_sysbench_cpu $sched $run_n
    end

    # ── sysbench memory ──
    echo "  ── sysbench memory ($RUNS runs x 30s) ──"
    for run_n in (seq $RUNS)
        echo "    run $run_n/$RUNS..."
        run_sysbench_mem $sched $run_n
    end

    # ── schbench ──
    echo "  ── schbench (120s wakeup latency, $RUNS runs) ──"
    for run_n in (seq $RUNS)
        echo "    run $run_n/$RUNS..."
        run_schbench $sched $run_n
    end

    # ── cyclictest ──
    echo "  ── cyclictest (60s RT latency, $RUNS runs) ──"
    for run_n in (seq $RUNS)
        echo "    run $run_n/$RUNS..."
        run_cyclictest $sched $run_n
    end

    stop_scheduler $sched
    echo ""
    echo "  $sched complete."
    sleep 3
end

# ── Summary ──
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ALL BENCHMARKS COMPLETE"
echo "  Results CSV:  $RESULTS_CSV"
echo "  Raw outputs:  $OUTDIR/raw/"
echo ""
echo "  Schedulers tested: $SCHED_LIST"
echo "  Runs per benchmark: $RUNS"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  To plot: python3 $SCRIPT_DIR/plot_benchmarks.py $RESULTS_CSV"
echo ""
