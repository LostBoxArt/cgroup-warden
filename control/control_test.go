package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateUnit(t *testing.T) {
	valid := []string{
		"user-0.slice",
		"user-1000.slice",
		"user-123456.slice",
	}
	for _, unit := range valid {
		if err := validateUnit(unit); err != nil {
			t.Errorf("validateUnit(%q) = %v, want nil", unit, err)
		}
	}

	invalid := []string{
		"",
		"-.slice",
		"user.slice",
		"system.slice",
		"init.scope",
		"sshd.service",
		"user-1000.scope",
		"user-abc.slice",
		"../system.slice/sshd.service",
		"user-1000.slice/../../system.slice",
		"user-1000.slice/",
		"user-1000.slice ",
		"user-1000.slice\n",
	}
	for _, unit := range invalid {
		if err := validateUnit(unit); err == nil {
			t.Errorf("validateUnit(%q) = nil, want error", unit)
		}
	}
}

func TestControlHandlerRejectsNonUserUnits(t *testing.T) {
	handler := ControlHandler("/user.slice", 1000, 0)

	for _, unit := range []string{
		"",
		"system.slice",
		"init.scope",
		"sshd.service",
		"user.slice",
		"../system.slice/sshd.service",
	} {
		body, err := json.Marshal(controlRequest{
			Unit: unit,
			Property: controlProperty{
				Name: "CPUQuotaPerSecUSec",
				// Non-numeric: if the unit check regresses, transform() still
				// rejects the request before systemd is contacted.
				Value: "x",
			},
		})
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/control", bytes.NewReader(body))
		rec := httptest.NewRecorder()

		handler(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("unit %q: status = %d, want %d", unit, rec.Code, http.StatusBadRequest)
		}

		var response controlResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Errorf("unit %q: response is not JSON: %v", unit, err)
			continue
		}
		want := ""
		if validationErr := validateUnit(unit); validationErr != nil {
			want = validationErr.Error()
		}
		if response.Error != want {
			t.Errorf("unit %q: error = %q, want %q", unit, response.Error, want)
		}
	}
}

func TestControlHandlerRejectsBelowMinUID(t *testing.T) {
	handler := ControlHandler("/user.slice", 1000, 0)
	body, err := json.Marshal(controlRequest{
		Unit: "user-0.slice",
		Property: controlProperty{
			Name:  "CPUQuotaPerSecUSec",
			Value: "x",
		},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/control", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var response controlResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if !strings.Contains(response.Error, "below the configured minimum") {
		t.Errorf("error = %q, want a minimum-uid error", response.Error)
	}
}

func TestControlHandlerRejectsDisallowedProperty(t *testing.T) {
	handler := ControlHandler("/user.slice", 1000, 0)
	body, err := json.Marshal(controlRequest{
		Unit: "user-1000.slice",
		Property: controlProperty{
			Name:  "MemoryHigh",
			Value: 1,
		},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/control", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var response controlResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if !strings.Contains(response.Error, "property is not allowed") {
		t.Errorf("error = %q, want a property-allowlist error", response.Error)
	}
}


func TestControlHandlerRejectsAboveMaxUID(t *testing.T) {
	handler := ControlHandler("/user.slice", 1000, 2000)
	body, err := json.Marshal(controlRequest{
		Unit: "user-2001.slice",
		Property: controlProperty{
			Name:  "CPUQuotaPerSecUSec",
			Value: -1,
		},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/control", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var response controlResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if !strings.Contains(response.Error, "above the configured maximum") {
		t.Errorf("error = %q, want a maximum-uid error", response.Error)
	}
}
