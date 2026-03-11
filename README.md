# scx_dps
A scheduler written under the kernel framework sched-ext that works on the basis of processes voting for each other in order to decide who gets the CPU-slice - Democratic Process Scheduler (DPS)

<img width="1750" height="739" alt="1_hackbench" src="https://github.com/user-attachments/assets/ef586b9f-501a-444d-a611-6ec4e5aa7b4b" />

<img width="1749" height="790" alt="2_cyclictest" src="https://github.com/user-attachments/assets/46cf723c-6209-4c7f-9290-7f6621da708a" />

<img width="1749" height="788" alt="3_schbench_wakeup_percentiles" src="https://github.com/user-attachments/assets/65eef311-eeef-4c02-ae07-f4b8eea005ea" />

<img width="1750" height="788" alt="4_schbench_request_latency" src="https://github.com/user-attachments/assets/ef14bd37-3ca2-401a-ab80-e60084e487ee" />

<img width="1750" height="737" alt="5_schbench_rps" src="https://github.com/user-attachments/assets/9fb01465-7e40-425c-8339-91e61a1eae74" />

<img width="2390" height="786" alt="6_schbench_wakeup_evolution_load" src="https://github.com/user-attachments/assets/a63a8278-e38e-40a8-b096-9100fe1bbc76" />

<img width="2390" height="786" alt="7_schbench_wakeup_evolution_clean" src="https://github.com/user-attachments/assets/a07ac414-f02d-414f-bdab-3b06b78d7252" />

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
