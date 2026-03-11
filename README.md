# scx_dps
A scheduler written under the kernel framework sched-ext that works on the basis of processes voting for each other in order to decide who gets the CPU-slice - Democratic Process Scheduler (DPS)



<img width="1485" height="883" alt="hackbench_throughput" src="https://github.com/user-attachments/assets/05d51710-b8ef-44a5-ba78-ae65b30c9dbc" />
<img width="1485" height="883" alt="sysbench_cpu" src="https://github.com/user-attachments/assets/a6261179-7bc4-46aa-a421-34462482ce62" />
<img width="1485" height="883" alt="schbench_latency" src="https://github.com/user-attachments/assets/ad4eff0e-d666-4533-8efe-d1d5fc1c9a13" />
<img width="1485" height="883" alt="sysbench_memory" src="https://github.com/user-attachments/assets/5769c474-b7de-407d-804f-2664c1f00214" />
<img width="1485" height="883" alt="schbench_rps" src="https://github.com/user-attachments/assets/b0e13c1a-2a21-4bd1-9c71-18515251377e" />
<img width="2085" height="885" alt="cyclictest_latency" src="https://github.com/user-attachments/assets/820354d6-5dcf-4ca4-984f-186fc34630d2" />
<img width="2574" height="1183" alt="summary_table" src="https://github.com/user-attachments/assets/3ec0c7a9-d52c-4830-8d30-fda635bfdf8d" />


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
