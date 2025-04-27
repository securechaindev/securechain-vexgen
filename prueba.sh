CVE=CVE-2024-3092

cd osv.dev/vulnfeeds

mkdir -p /tmp/nvd /tmp/nvd2osv

(cd test_data && ./download_specific_cves $CVE)
mv test_data/nvdcve-2.0/${CVE}.json /tmp/nvd

go run cmd/nvd-cve-osv/main.go \
    --cpe_repos "/tmp/cpe_product_to_repo.json" \
    --nvd_json "/tmp/nvd/${CVE}.json" \
    --out_dir "/tmp/nvd2osv"

cat /tmp/nvd2osv/*/*/${CVE}.json