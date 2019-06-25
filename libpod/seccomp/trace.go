package genSeccomp

import (
	"C"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/containers/libpod/libpod"
	"github.com/docker/docker/api/types"
	bpf "github.com/iovisor/gobpf/bcc"
	sec "github.com/seccomp/libseccomp-golang"
)

type event struct {
	Pid uint32
	Id  uint32
	// Inum    uint
	Command [16]byte
}

type calls map[string]int

var necesarry = []string{
	"capget",
	"capset",
	"chdir",
	"fchown",
	"futex",
	"getdents64",
	"getpid",
	"getppid",
	"lstat",
	"openat",
	"prctl",
	"setgid",
	"setgroups",
	"setuid",
	"stat",
}

func (c calls) init() {

	for _, s := range necesarry {
		c[s]++
	}
}

// Start tracing the syscalls
func Start(ctr *libpod.Container, fileName string, done <-chan bool) {
	syscalls := make(calls, 303)

	pid, err := ctr.PID()
	if err != nil {
		fmt.Println("an error")
	}
	for pid == 0 {
		pid, _ = ctr.PID()
	}
	source := `
#include <linux/bpf.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/ns_common.h>
#include <linux/sched.h>
#include <linux/tracepoint.h>

BPF_HASH(parent_namespace, u64,unsigned int);
BPF_PERF_OUTPUT(events);

struct data_t {
u32 pid;
u32 id;
char comm[16];
};

int enter_trace(struct tracepoint__raw_syscalls__sys_enter *args){
struct data_t data = {};
u64 key = 0;
unsigned int zero = 0;
struct task_struct *task;

data.pid = bpf_get_current_pid_tgid();
data.id = (int)args->id;
bpf_get_current_comm(&data.comm, sizeof(data.comm));

task = (struct task_struct *)bpf_get_current_task();
struct nsproxy* ns = task->nsproxy;
unsigned int inum = ns->pid_ns_for_children->ns.inum;


if (data.pid == PARENT_PID){
	parent_namespace.update(&key, &inum);
} 
unsigned int* parent_inum = parent_namespace.lookup_or_init(&key, &zero);

if (*parent_inum != inum){
	return 0;
}

events.perf_submit(args, &data, sizeof(data));	
return 0;
}
`
	src := strings.Replace(source, "PARENT_PID", strconv.Itoa(pid), -1)
	m := bpf.NewModule(src, []string{})
	defer m.Close()

	tracepoint, err := m.LoadTracepoint("enter_trace")
	if err != nil {
		fmt.Println(err)
	}

	if err := m.AttachTracepoint("raw_syscalls:sys_enter", tracepoint); err != nil {
		fmt.Println("unable to load tracepoint")
	}

	table := bpf.NewTable(m.TableId("events"), m)
	channel := make(chan []byte)
	perfMap, err := bpf.InitPerfMap(table, channel)
	if err != nil {
		fmt.Println("unable to init perf map")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var e event
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e)
			if err != nil {
				fmt.Printf("failed to decode received data '%s': %s\n", data, err)
				continue
			}
			// comm := (*C.char)(unsafe.Pointer(&e.Command))
			// fmt.Printf("Pid : %d, Syscall_ID : %d, , Command : %q", e.Pid, e.Id, C.GoString(comm))
			name := getName(e.Id)
			syscalls[name]++
		}
	}()
	perfMap.Start()
	<-done
	perfMap.Stop()

	generateProfile(syscalls, fileName)

}

func getName(id uint32) string {
	name, _ := sec.ScmpSyscall(id).GetName()
	return name
}

func generateProfile(c calls, fileName string) {
	s := types.Seccomp{}
	var names []string
	for s, t := range c {
		if t > 0 {
			names = append(names, s)
		}
	}
	s.DefaultAction = types.ActErrno

	s.Syscalls = []*types.Syscall{
		&types.Syscall{
			Action: types.ActAllow,
			Names:  names,
			Args:   []*types.Arg{},
		},
	}
	sJSON, _ := json.Marshal(s)

	err := ioutil.WriteFile(fileName, sJSON, 0644)
	if err != nil {
		panic(err)
	}
}
