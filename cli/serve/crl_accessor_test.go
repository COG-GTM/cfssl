package serve

import (
	"testing"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	certsql "github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
)

func TestCRLAccessorSelectsColumns(t *testing.T) {
	db := testdb.SQLiteDB("../../certdb/testdb/certstore_development.db")
	if _, err := db.Exec("DELETE FROM certificates"); err != nil {
		t.Fatal(err)
	}
	full := certsql.NewAccessor(db)
	if err := full.InsertCertificate(certdb.CertificateRecord{
		Serial: "1",
		AKI:    "aki",
		Expiry: time.Now().Add(time.Hour),
		PEM:    "pem",
		Status: "good",
	}); err != nil {
		t.Fatal(err)
	}
	if err := full.RevokeCertificate("1", "aki", 1); err != nil {
		t.Fatal(err)
	}

	want, err := full.GetRevokedAndUnexpiredCertificates()
	if err != nil {
		t.Fatal(err)
	}
	got, err := crlAccessor{full}.GetRevokedAndUnexpiredCertificates()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(want) != 1 || got[0].Serial != want[0].Serial ||
		!got[0].RevokedAt.Equal(want[0].RevokedAt) || got[0].PEM != "" {
		t.Errorf("want serial and revoked_at of %+v, got %+v", want, got)
	}
}
