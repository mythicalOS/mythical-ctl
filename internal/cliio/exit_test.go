package cliio

import "testing"

// PORTED: tests/unit/exit.bats: "the four codes are exactly §7.3's" -> TestExitContractValues
// (The remaining exit.bats tests exercise mi_ex_worst, the batch worst-wins aggregate — they
// are inventoried by the verbs wave, which ports that aggregation.)
func TestExitContractValues(t *testing.T) {
	if ExitOK != 0 || ExitFail != 1 || ExitUsage != 2 || ExitNotLaunched != 3 {
		t.Fatalf("exit contract drifted: OK=%d Fail=%d Usage=%d NotLaunched=%d",
			ExitOK, ExitFail, ExitUsage, ExitNotLaunched)
	}
}
