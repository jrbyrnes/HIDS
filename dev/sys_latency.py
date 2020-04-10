from time import sleep, strftime
from bcc import BPF
from bcc.utils import printb
from bcc.syscall import syscall_name, syscalls


b = BPF(text = """
struct data_t {
	u64 count;
	u64 total_ns;
};

BPF_HASH(start, u32, u64);
BPF_HASH(data, u32, struct data_t);

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
	u32 syscall_id = args->id;
	u64 t = bpf_ktime_get_ns();
	start.update(&syscall_id, &t);
	return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
	u32 syscall_id = args->id;
	struct data_t *val, zero = {};
	u64 *start_ns = start.lookup(&syscall_id);
	if (!start_ns)
		return 0;
	val = data.lookup_or_try_init(&syscall_id, &zero);
	if (val) {
		val->count++;	
		val->total_ns += bpf_ktime_get_ns() - *start_ns;
	}
	return 0;
}
""")


agg_colname = "SYSCALL"
time_colname = "TIME (us)"

def agg_colval(key):
	return syscall_name(key.value)

def print_latency_stats():
	data = b["data"]
	print("[%s]" % strftime("%H:%M:%S"))
	print("%-22s %8s" % (agg_colname, "COUNT"))
	for k, v in sorted(data.items(), key=lambda kv: -kv[1].total_ns):
		if k.value == 0xFFFFFFFF:
			continue
		printb(b"%-22s %8d %16.3f" % (agg_colval(k), v.count, v.total_ns / 1e3))
	print("")
	data.clear()



while 1:
	try:
		print_latency_stats()
		print("Sleeping 5")
		sleep(5)
	except KeyboardInterrupt:
		print("Detaching")
		exit()


