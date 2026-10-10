#!/bin/sh
# Full end-to-end regression against the test VM. Summary: dist/e2e/summary.txt
cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1 MSYS2_ENV_CONV_EXCL=QA_PAGES
mkdir -p dist/e2e
: > dist/e2e/summary.txt
run() { # name, command...
	n=$1; shift
	"$@" > "dist/e2e/$n.log" 2>&1
	echo "$n: $(grep -E '[0-9]+/[0-9]+ (checks )?passed' "dist/e2e/$n.log" | tail -1) $(grep -c '^FAIL' "dist/e2e/$n.log") FAIL" >> dist/e2e/summary.txt
}
run p3_gateway node scripts/e2e/e2e_p3_gateway.cjs
node scripts/remote/vm.cjs exec "setsid setpriv --reuid=nobody --regid=nogroup --clear-groups /usr/local/sbin/ngm-testkit https-echo -listen 127.0.0.1:9401 -name S >/dev/null 2>&1 < /dev/null & sleep 1" >/dev/null 2>&1
run p8_routing node scripts/e2e/e2e_p8_routing.cjs
run p5_dns_acme node scripts/e2e/e2e_p5.cjs dns,acme,renew
run p5_site node scripts/e2e/e2e_p5_site.cjs
run p6_logs node scripts/e2e/e2e_p6.cjs logs
run p6b_ops node scripts/e2e/e2e_p6b.cjs
node scripts/e2e/cleanup_p6.cjs >/dev/null 2>&1
run p4_reliability node scripts/e2e/e2e_p4.cjs monitor,firewall,deadman,backup,vault,crash,drift
run p7_lifecycle node scripts/e2e/e2e_p7.cjs repair,nginx,uninstall,cli
run p8_security node scripts/e2e/e2e_p8_sec.cjs
run p8_origin node scripts/e2e/e2e_p8_origin.cjs
run p8_disk node scripts/e2e/e2e_p8_disk.cjs
run p9_decoy node scripts/e2e/e2e_p9_decoy.cjs
run p10_features node scripts/e2e/e2e_p10_features.cjs
run ui_qa node scripts/e2e/ui_qa.cjs
run panel_public node scripts/ops/publish_panel.cjs
echo DONE >> dist/e2e/summary.txt
