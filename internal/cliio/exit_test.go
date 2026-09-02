package cliio

import "testing"

// PORTED: tests/unit/exit.bats: "the four codes are exactly §7.3's" -> TestExitContractValues
// (The remaining seven exit.bats rows exercise mi_ex_worst and mi_ex_name, the batch worst-wins
// aggregate and its vocabulary. Those became verbs.Worst and verbs.ExitName, and their PORTED
// lines are in internal/verbs/verbs_test.go beside the tests. Two files each deferring the claim
// to the other is how nothing claims a row, and only a machine reading BOTH files can see it.)
func TestExitContractValues(t *testing.T) {
	if ExitOK != 0 || ExitFail != 1 || ExitUsage != 2 || ExitNotLaunched != 3 {
		t.Fatalf("exit contract drifted: OK=%d Fail=%d Usage=%d NotLaunched=%d",
			ExitOK, ExitFail, ExitUsage, ExitNotLaunched)
	}
}
