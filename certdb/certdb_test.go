package certdb

import "testing"

type fullRowsOnlyAccessor struct {
	Accessor
	records []CertificateRecord
}

func (a fullRowsOnlyAccessor) GetRevokedAndUnexpiredCertificates() ([]CertificateRecord, error) {
	return a.records, nil
}

func TestGetRevokedAndUnexpiredCertificatesForCRLFallsBack(t *testing.T) {
	want := []CertificateRecord{{Serial: "1", PEM: "full row"}}
	got, err := GetRevokedAndUnexpiredCertificatesForCRL(fullRowsOnlyAccessor{records: want})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].PEM != "full row" {
		t.Errorf("want fallback to GetRevokedAndUnexpiredCertificates, got %+v", got)
	}
}
