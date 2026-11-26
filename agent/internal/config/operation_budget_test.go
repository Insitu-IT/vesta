package config

import "testing"

func TestOperationBudgetEnvironmentIsStrict(t *testing.T) {
	for _, value := range []string{"NaN", "Inf", "0", "-1", "101", "", "wrong"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("OPERATION_TIME_COEFFICIENT", value)
			if loadOperationBudget().Valid() {
				t.Fatal("invalid coefficient silently defaulted")
			}
		})
	}
	t.Setenv("OPERATION_TIME_COEFFICIENT", "4.5")
	p := loadOperationBudget()
	if !p.Valid() || p.TimeCoefficient != 4.5 {
		t.Fatal("valid configured coefficient lost")
	}
}

func TestSourceHealthProbeConfiguration(t *testing.T) {
	valid := `[{"namespace":"ns","vm_name":"database","url":"http://service.ns/health"}]`
	if p, err := ParseSourceHealthProbes(valid); err != nil || len(p) != 1 {
		t.Fatal(p, err)
	}
	for _, raw := range []string{
		`null`, `[{"namespace":"ns","vm_name":"vm","url":"http://user:secret@host/"}]`,
		`[{"namespace":"ns","vm_name":"vm","url":"http://host/?token=secret"}]`,
		`[{"namespace":"ns","vm_name":"vm","url":"file:///etc/key"}]`,
		`[{"namespace":"ns","vm_name":"vm","url":"http://host/","headers":{}}]`,
	} {
		if _, err := ParseSourceHealthProbes(raw); err == nil {
			t.Fatal("unsafe probe configuration accepted")
		}
	}
}
