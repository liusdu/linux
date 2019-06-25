{
	"superfluous subtype",
	.insns = {
		BPF_MOV32_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.errstr = "",
	.result = REJECT,
	.has_prog_subtype = true,
},
