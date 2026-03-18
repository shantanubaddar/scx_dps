# scx_dps
A scheduler written under the kernel framework sched-ext that works on the basis of processes voting for each other in order to decide who gets the CPU-slice - Democratic Process Scheduler (DPS)



<img width="1398" height="743" alt="1_schbench_percentiles" src="https://github.com/user-attachments/assets/7f0ab40c-54f5-4013-90c0-82161af91448" />
<img width="1270" height="712" alt="2_hackbench_scaling" src="https://github.com/user-attachments/assets/bff2257a-f176-433c-9557-ea3ba3deae83" />
<img width="1293" height="628" alt="3_cyclictest_max" src="https://github.com/user-attachments/assets/460b816b-cce0-4040-ae03-dece53a7757e" />

<img width="1784" height="688" alt="4_sysbench" src="https://github.com/user-attachments/assets/8d71eb1f-d03c-4c60-8c01-e36b64437515" />
<img width="1072" height="979" alt="5_radar_summary" src="https://github.com/user-attachments/assets/0399e06e-d28b-4fd4-b991-86d962136fc8" />


---

## Requirements

- Linux kernel with `CONFIG_SCHED_EXT=y` (6.12+)
- `clang` (for BPF compilation)
- `gcc` and `libbpf-dev` (for the userspace loader)
- `bpftool`

On Arch/CachyOS:
```sh
sudo pacman -S clang gcc libbpf bpf
```

On Debian/Ubuntu:
```sh
sudo apt install clang gcc libbpf-dev linux-tools-common bpftool
```

Check everything is in order:
```sh
make check
```

---

## Build

Generate `vmlinux.h` from your running kernel (required once, and after any kernel update):
```sh
make fetch-headers
```

Then build the BPF object and loader:
```sh
make
```

---

## Load / Unload

Load DPS (replaces the current scheduler immediately):
```sh
sudo make load
```

Or manually:
```sh
sudo bpftool struct_ops register democratic.bpf.o /sys/fs/bpf/democratic
```

Verify it's running:
```sh
cat /sys/kernel/sched_ext/state
# should print: enabled
```

Unload and revert to the default scheduler (BORE/CFS):
```sh
sudo make unload
```

The scheduler can be swapped in and out at runtime — no reboot needed.

---

## Benchmarking

DPS uses a reinforcement learning pipeline that builds task preference tables over time. Cold-start performance (immediately after loading) is lower than warm performance after a few minutes of workload. For fair benchmarking, let it run for a couple of minutes before taking measurements.

The benchmark scripts used in development are included:

```sh
# Full live comparison vs BORE (runs both schedulers, outputs to /tmp/live_benchmark/)
sudo fish live_benchmark.fish

# Broader multi-scheduler comparison
sudo fish sched_benchmark.fish
```

---

## Notes on hybrid CPUs (P/E-core, e.g. Intel 12th gen+)

DPS uses `scx_bpf_select_cpu_dfl` for CPU selection, which respects the kernel's topology and should handle P/E-core systems without issues. The institution detection heuristic (burst duration < 5ms) may classify tasks differently on E-cores due to their lower IPC, but this does not affect stability.
