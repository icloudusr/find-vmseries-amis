#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
find_pa_instances.py
List VM-Series (Palo Alto Networks) supported EC2 instance types per AMI in a Region/AZ.
Supports x86_64 and ARM64 (BYOL + PAYG), with optional strict Marketplace validation via DryRun.
"""

import argparse, boto3, botocore, json, re, sys, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# -----------------------------
# Marketplace product codes
# -----------------------------
PAN_PRODUCT_CODES = {
    # x86_64
    "byol":     "6njl1pau431dv1qxipg63mvah",
    "bundle1":  "e9yfvyj3uag5uo5j2hjikv74n",
    "bundle2":  "hd44w1chf26uv4p52cdynb2o",
    # ARM64
    "arm-byol": "70xbkm08ivye46l4gfa6c85v7",
    "arm-payg": "3qxryq2rjnyddvecce0pvhf2j",
}

# -----------------------------
# Allowlist of known-good families for VM-Series (x86 + ARM)
# (Use --only-pan-families to apply this; otherwise just a reference.)
# -----------------------------
PAN_FAMILY_ALLOWLIST = {
    # x86
    "c5","c5d","c5n","c6i","c6id","c6in","c7i","c7i-flex","c7a",
    "m5","m5d","m5n","m5dn","m5zn","m6i","m6id","m6in","m6idn","m7i","m7i-flex","m7a",
    "r5","r5d","r5n","r5dn","r6i","r6id","r6in","r6idn","r7i","r7iz","r7a",
    "i4i","z1d",
    # ARM
    "c6g","c6gd","c6gn","c7g","c7gd","c7gn",
    "m6g","m6gd","m7g","m7gd",
    "r6g","r6gd","r7g","r7gd",
}

# -----------------------------
# Misc
# -----------------------------
VERSION_RE = re.compile(r"PA-VM(?:ARM)?-AWS[-_]?(\d+\.\d+(?:\.\w+)?)", re.IGNORECASE)
SPIN = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

ERROR_HELP = {
    "UnsupportedOperation": "AMI listing says this instance type/region/OS isn't supported by the Marketplace product.",
    "OptInRequired": "Account is not subscribed to the Marketplace product.",
    "UnauthorizedOperation": "IAM/SCP deny for ec2:RunInstances (even DryRun).",
    "RequestLimitExceeded": "API throttling. Increase --throttle-retries or reduce --workers.",
    "Throttling": "API throttling. Increase --throttle-retries or reduce --workers.",
    "ThrottlingException": "API throttling. Increase --throttle-retries or reduce --workers.",
    "RequestThrottled": "API throttling. Increase --throttle-retries or reduce --workers.",
    "VcpuLimitExceeded": "vCPU quota prevents launching this size.",
    "InsufficientInstanceCapacity": "Capacity not currently available in this AZ/size.",
}

# -----------------------------
# Args
# -----------------------------
def parse_args():
    p = argparse.ArgumentParser(description="List VM-Series supported EC2 instance types per AMI in a Region/AZ.")
    p.add_argument("--region", required=True)
    p.add_argument("--az", required=True, help="AZ name (us-east-1a) or AZ ID (use1-az5)")

    # Product selection
    p.add_argument("--product", choices=list(PAN_PRODUCT_CODES.keys()), default="byol",
                   help="Shortcut for known PAN products (x86/ARM).")
    p.add_argument("--product-code", default="", help="Override Marketplace product code (skips --product).")
    p.add_argument("--version-filter", default="", help="Substring to match in AMI name, e.g. 11.1.6")
    p.add_argument("--arch", choices=["x86_64","arm64"],
                   help="Force architecture filter used during technical screening; defaults to AMI arch.")

    # Type filters
    p.add_argument("--min-vcpu", type=int, default=2)
    p.add_argument("--include-accelerators", action="store_true",
                   help="Include GPU/FPGA/Inferentia/Trainium families.")
    p.add_argument("--include-burstable", action="store_true", help="Include t* burstable families.")
    p.add_argument("--include-legacy", action="store_true", help="Include older families (c3/c4/m3/m4/r3/r4...).")
    p.add_argument("--families", default="", help="Comma list of families to include (e.g. c6i,m6i).")
    p.add_argument("--only-pan-families", action="store_true",
                   help="Restrict to the curated PAN_FAMILY_ALLOWLIST.")

    # Strict Marketplace validation (DryRun)
    p.add_argument("--strict-marketplace", action="store_true",
                   help="DryRun each type to confirm Marketplace support.")
    p.add_argument("--http-tokens", choices=["required","optional"], default=None,
                   help="Pass MetadataOptions.HttpTokens during DryRun launch.")
    p.add_argument("--subnet-id", default="",
                   help="Subnet to use for DryRun. If omitted, auto-pick one in the target AZ.")
    p.add_argument("--workers", type=int, default=16, help="Concurrency for DryRun attempts.")
    p.add_argument("--throttle-retries", type=int, default=3,
                   help="Retries per type on RequestLimitExceeded/Throttling.")
    p.add_argument("--progress", action="store_true", help="Show spinner/progress")
    p.add_argument("--debug", action="store_true", help="Verbose stderr logs")

    # Output
    p.add_argument("--show-rejected", action="store_true",
                   help="Print rejected instance types per AMI (UnsupportedOperation by default).")
    p.add_argument("--show-rejected-all-codes", action="store_true",
                   help="With --show-rejected, include all rejection codes (not only UnsupportedOperation).")
    p.add_argument("--rejected-limit", type=int, default=50,
                   help="Max rejected types to list per AMI/code group (0 = unlimited).")
    p.add_argument("--max-amis", type=int, default=200, help="Ceiling on AMIs processed (newest first).")
    p.add_argument("--format", choices=["json","pretty","table","markdown","csv"], default="table")
    return p.parse_args()

def log(msg, debug=False):
    if debug:
        sys.stderr.write(msg + "\n"); sys.stderr.flush()

def spinner(label, stop_event):
    i = 0
    while not stop_event.is_set():
        sys.stderr.write(f"\r{SPIN[i%len(SPIN)]} {label} "); sys.stderr.flush()
        time.sleep(0.1); i += 1
    sys.stderr.write("\r")

def ec2(region):
    from botocore.config import Config
    cfg = Config(retries={"max_attempts": 10, "mode": "adaptive"}, read_timeout=20, connect_timeout=5)
    return boto3.client("ec2", region_name=region, config=cfg)

def resolve_az(ec2c, region, az_input):
    # If they passed an AZ name (e.g., us-east-1a), use that; if an AZ ID (use1-az5), use location-type id.
    if re.match(r"^[a-z]{2}-[a-z]+-\d[a-z]$", az_input):  # name
        return ("availability-zone", az_input)
    if "-az" in az_input:  # id
        return ("availability-zone-id", az_input)
    # Fallback: try to match either
    resp = ec2c.describe_availability_zones(
        AllAvailabilityZones=False,
        Filters=[{"Name":"region-name","Values":[region]}]
    )
    for az in resp.get("AvailabilityZones", []):
        if az_input in (az.get("ZoneName"), az.get("ZoneId")):
            return ("availability-zone-id", az["ZoneId"]) if az_input == az.get("ZoneId") else ("availability-zone", az["ZoneName"])
    raise ValueError(f"AZ not found in {region}: {az_input}")

def list_amis(ec2c, product_code, version_filter, debug=False):
    # Match both x86 and ARM naming: PA-VM-AWS* and PA-VMARM-AWS*
    name_filter = f"PA-VM*-AWS*{version_filter}*" if version_filter else "PA-VM*-AWS*"
    resp = ec2c.describe_images(
        Owners=["aws-marketplace"],
        Filters=[
            {"Name":"product-code","Values":[product_code]},
            {"Name":"name","Values":[name_filter]},
            {"Name":"virtualization-type","Values":["hvm"]}
        ],
    )
    imgs = sorted(resp.get("Images", []), key=lambda i: i.get("CreationDate",""), reverse=True)
    log(f"Found {len(imgs)} AMIs for product {product_code}", debug)
    return imgs

def list_offered_types(ec2c, loc_type, loc_value, debug=False):
    paginator = ec2c.get_paginator("describe_instance_type_offerings")
    types = set()
    for page in paginator.paginate(LocationType=loc_type, Filters=[{"Name":"location","Values":[loc_value]}]):
        for off in page.get("InstanceTypeOfferings", []):
            t = off.get("InstanceType")
            if t: types.add(t)
    log(f"AZ {loc_value} offers {len(types)} instance types (pre-filter).", debug)
    return types

def family(itype): return itype.split(".", 1)[0]
def size(itype): return itype.split(".", 1)[1]

def looks_legacy(fam):
    return fam.startswith(("c3","c4","m3","m4","r3","r4","i2","i3","h1","d2"))

def extract_version(name):
    m = VERSION_RE.search(name or "")
    return m.group(1) if m else (name or "unknown")

def technical_filter(ec2c, candidate_types, ami, *, min_vcpu, include_accelerators, include_burstable,
                     include_legacy, restrict_families, forced_arch=None):
    """
    Sift instance types using describe_instance_types only (no RunInstances).
    """
    if not candidate_types: return set()
    arch_needed = forced_arch or ami.get("Architecture","x86_64")
    ena_needed = ami.get("EnaSupport", True)

    keep, batch = set(), list(candidate_types)
    for i in range(0, len(batch), 100):
        resp = ec2c.describe_instance_types(InstanceTypes=batch[i:i+100])
        for it in resp.get("InstanceTypes", []):
            t = it.get("InstanceType",""); fam = family(t)
            if ".metal" in t or fam.startswith(("mac","a1")):  # no bare metal or mac/a1
                continue
            if not include_burstable and fam.startswith("t"):
                continue
            if not include_legacy and looks_legacy(fam):
                continue
            if restrict_families and fam not in restrict_families:
                continue
            if it.get("VCpuInfo",{}).get("DefaultVCpus",0) < min_vcpu:
                continue
            if arch_needed not in set(it.get("ProcessorInfo",{}).get("SupportedArchitectures", [])):
                continue
            if ena_needed and it.get("NetworkInfo",{}).get("EnaSupport","unsupported") not in ("supported","required"):
                continue
            has_gpu = bool(it.get("GpuInfo"))
            has_fpga = bool(it.get("FpgaInfo"))
            has_inf = bool(it.get("InferenceAcceleratorInfo"))
            is_train = t.startswith("trn")
            if not include_accelerators and (has_gpu or has_fpga or has_inf or is_train):
                continue
            keep.add(t)
    return keep

def any_subnet_in_location(ec2c, loc_type, loc_value):
    flt = [{"Name":"state","Values":["available"]}]
    flt.append({"Name":"availability-zone","Values":[loc_value]} if loc_type=="availability-zone"
               else {"Name":"availability-zone-id","Values":[loc_value]})
    resp = ec2c.describe_subnets(Filters=flt)
    subs = resp.get("Subnets", [])
    return subs[0] if subs else None

def default_sg(ec2c, vpc_id):
    try:
        r = ec2c.describe_security_groups(Filters=[{"Name":"group-name","Values":["default"]},{"Name":"vpc-id","Values":[vpc_id]}])
        return r.get("SecurityGroups",[{}])[0].get("GroupId")
    except botocore.exceptions.ClientError:
        return None

def strict_validate(ec2c, ami_id, types, subnet, *, http_tokens=None, workers=16,
                    throttle_retries=3, progress=False, debug=False):
    """
    Return (supported_set, diag_counts_dict, rejected_by_type) using DryRun run_instances.
    """
    vpc_id, subnet_id, sg_id = subnet["VpcId"], subnet["SubnetId"], default_sg(ec2c, subnet["VpcId"])
    diag_counts = defaultdict(int)
    supported = set()
    rejected_by_type = {}

    throttle_codes = {"RequestLimitExceeded","Throttling","ThrottlingException","RequestThrottled"}

    def try_one(t):
        params = {"ImageId": ami_id, "InstanceType": t, "MinCount":1, "MaxCount":1, "SubnetId":subnet_id, "DryRun":True}
        if sg_id: params["SecurityGroupIds"] = [sg_id]
        if http_tokens:
            params["MetadataOptions"] = {"HttpTokens": http_tokens}
        attempt, delay = 0, 0.6
        while True:
            try:
                ec2c.run_instances(**params)  # Should raise DryRunOperation if allowed & technically valid
                return (t, "UnexpectedSuccess")
            except botocore.exceptions.ClientError as e:
                code = e.response.get("Error",{}).get("Code","") or "OtherError"
                if code == "DryRunOperation":
                    return (t, "SUPPORTED")
                if code in throttle_codes and attempt < throttle_retries:
                    time.sleep(delay); attempt += 1; delay = min(delay*1.8, 6.0); continue
                return (t, code)

    stop = threading.Event()
    if progress:
        th = threading.Thread(target=spinner, args=("Validating instance types via DryRun…", stop), daemon=True)
        th.start()

    futures = []
    max_workers = max(1, min(workers, len(types)))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for t in sorted(types):
            futures.append(ex.submit(try_one, t))
        done = 0
        for f in as_completed(futures):
            t, code = f.result()
            if code == "SUPPORTED":
                supported.add(t)
            else:
                diag_counts[code] += 1
                rejected_by_type[t] = code
            done += 1
            if progress and done % 10 == 0:
                sys.stderr.write(f"\r✓ Validated {done}/{len(types)} types…"); sys.stderr.flush()

    if progress:
        stop.set(); time.sleep(0.05); sys.stderr.write("\n")

    log(f"Strict results: {len(supported)} supported / {len(types)} tested; diag={dict(diag_counts)}", debug)
    return supported, dict(diag_counts), rejected_by_type

def fam_sizes(sorted_types):
    g = defaultdict(list)
    for it in sorted(sorted_types):
        f,s = it.split(".",1)
        g[f].append(s)
    return g

def render_table(rows, *, show_rejected=False, show_all_codes=False, rejected_limit=50):
    header = f"{'PAN-OS':10}  {'AMI ID':20}  {'Created':18}  {'Count':5}  {'AMI Name':32}  Families→sizes"
    out = [header, "-"*len(header)]
    for r in rows:
        left = f"{r['version']:10}  {r['ami_id']:20}  {r['created'][:18]:18}  {r['count']:5}  {r['ami_name'][:32]:32}  "
        fams = ", ".join(f"{f}:{'/'.join(s)}" for f,s in sorted(r["families"].items()))
        # Lightweight wrap for the families column
        width = 120; line = ""; lines=[]
        for w in fams.split():
            if len(line)+1+len(w) > width: lines.append(line); line=w
            else: line = w if not line else line+" "+w
        if line: lines.append(line)
        for i,seg in enumerate(lines):
            out.append(left+seg if i==0 else " "*len(left)+seg)

        if show_rejected and r.get("rejected_by_code"):
            for code, types in sorted(r["rejected_by_code"].items()):
                if (not show_all_codes) and code != "UnsupportedOperation":
                    continue
                limit = len(types) if rejected_limit == 0 else min(rejected_limit, len(types))
                listed = ", ".join(sorted(types)[:limit])
                extra = "" if limit == len(types) else f" …(+{len(types)-limit} more)"
                help_txt = ERROR_HELP.get(code, "")
                out.append(" " * 10 + f"Rejected ({code}){':' if help_txt else ''} {help_txt}".rstrip())
                out.append(" " * 12 + f"{listed}{extra}")
    return "\n".join(out)

def render_markdown(rows, *, show_rejected=False, show_all_codes=False, rejected_limit=50):
    out = ["| PAN-OS | AMI ID | Created | #Types | AMI Name | Families → sizes |",
           "|:------:|:------|:--------|------:|:--------|:------------------|"]
    for r in rows:
        fams = ", ".join(f"{f}:{'/'.join(s)}" for f,s in sorted(r["families"].items()))
        out.append(f"| {r['version']} | `{r['ami_id']}` | {r['created'][:19]} | {r['count']} | `{r['ami_name']}` | {fams} |")
        if show_rejected and r.get("rejected_by_code"):
            blocks = []
            for code, types in sorted(r["rejected_by_code"].items()):
                if (not show_all_codes) and code != "UnsupportedOperation":
                    continue
                limit = len(types) if rejected_limit == 0 else min(rejected_limit, len(types))
                listed = ", ".join(sorted(types)[:limit])
                extra = "" if limit == len(types) else f" …(+{len(types)-limit} more)"
                help_txt = ERROR_HELP.get(code, "")
                blocks.append(f"**Rejected ({code})**{' – ' + help_txt if help_txt else ''}<br/>{listed}{extra}")
            if blocks:
                out.append(f"|  |  |  |  |  | " + "<br/>".join(blocks) + " |")
    return "\n".join(out)

def render_csv(rows):
    import csv, io
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["panos_version","ami_id","creation_date","#types","ami_name","families"])
    for r in rows:
        fams = ", ".join(f"{f}:{'/'.join(s)}" for f,s in sorted(r["families"].items()))
        w.writerow([r["version"], r["ami_id"], r["created"], r["count"], r["ami_name"], fams])
    return buf.getvalue()

def main():
    args = parse_args()
    ec2c = ec2(args.region)
    loc_type, loc_value = resolve_az(ec2c, args.region, args.az)

    offered = list_offered_types(ec2c, loc_type, loc_value, debug=args.debug)
    if not offered:
        sys.stderr.write("ERROR: No instance types are offered in that AZ for your account.\n"); sys.exit(2)

    # Build family restriction
    restrict = None
    if args.families:
        restrict = {f.strip() for f in args.families.split(",") if f.strip()}
    elif args.only_pan_families:
        restrict = set(PAN_FAMILY_ALLOWLIST)

    # Resolve product code
    product_code = args.product_code or PAN_PRODUCT_CODES.get(args.product)
    if not product_code:
        sys.stderr.write("ERROR: No product code resolved. Use --product or --product-code.\n"); sys.exit(3)

    imgs = list_amis(ec2c, product_code, args.version_filter, debug=args.debug)
    if args.max_amis and len(imgs) > args.max_amis:
        imgs = imgs[:args.max_amis]
    if not imgs:
        sys.stderr.write("ERROR: No AMIs found for that product in this account/region. Are you subscribed to the Marketplace product?\n")
        # still print a header-only table/json to be consistent
        if args.format in ("json","pretty"): print(json.dumps({"ami_count":0,"results":[]}, indent=2 if args.format=="pretty" else None))
        else: print(render_table([]))
        sys.exit(3)

    # Strict validation pre-reqs
    subnet, strict_ok = None, False
    if args.strict_marketplace:
        if args.subnet_id:
            try:
                r = ec2c.describe_subnets(SubnetIds=[args.subnet_id])
                subs = r.get("Subnets", [])
                if subs:
                    subnet = subs[0]; strict_ok = True
            except botocore.exceptions.ClientError as e:
                sys.stderr.write(f"WARN: Could not use --subnet-id ({e}); attempting auto-discovery in target AZ.\n")
        if not strict_ok:
            try:
                subnet = any_subnet_in_location(ec2c, loc_type, loc_value)
                if subnet: strict_ok = True
                else: sys.stderr.write("WARN: No subnet found in target AZ; skipping strict validation, using technical list.\n")
            except botocore.exceptions.ClientError as e:
                sys.stderr.write(f"WARN: Could not list subnets ({e}); skipping strict validation.\n")

    rows = []
    for ami in imgs:
        ami_id = ami["ImageId"]; name = ami.get("Name",""); created = ami.get("CreationDate","")
        version = extract_version(name)

        pre = technical_filter(ec2c, offered, ami,
                               min_vcpu=args.min_vcpu,
                               include_accelerators=args.include_accelerators,
                               include_burstable=args.include_burstable,
                               include_legacy=args.include_legacy,
                               restrict_families=restrict,
                               forced_arch=args.arch)

        post = set(pre)
        diag = {}
        rejected_by_type = {}
        if strict_ok and pre:
            post, diag, rejected_by_type = strict_validate(
                ec2c, ami_id, pre, subnet,
                http_tokens=args.http_tokens, workers=args.workers,
                throttle_retries=args.throttle_retries,
                progress=args.progress, debug=args.debug
            )
            # If everything failed only due to subscription/permissions, fall back loudly
            if not post and diag and all(k in ("OptInRequired","UnauthorizedOperation") for k in diag.keys()):
                sys.stderr.write(
                    "WARN: Strict validation failed for all types (likely not subscribed to the Marketplace product "
                    "or missing ec2:RunInstances permission). Falling back to technical list.\n"
                )
                post = pre  # fallback

        rej_by_code = defaultdict(list)
        for t, code in rejected_by_type.items():
            rej_by_code[code].append(t)

        row = {
            "version": version,
            "ami_id": ami_id,
            "created": created,
            "count": len(post),
            "ami_name": name,
            "families": fam_sizes(sorted(post)),
            "diagnostics": diag,
            "rejected_by_type": rejected_by_type,
            "rejected_by_code": dict(rej_by_code),
        }
        log(f"[{version} {ami_id}] pre={len(pre)} strict_supported={len(post)} diag={diag}", args.debug)
        rows.append(row)

    if args.format in ("json","pretty"):
        out = {
            "region": args.region, "location_type": loc_type, "location_value": loc_value,
            "product": args.product, "product_code": product_code, "ami_count": len(rows),
            "results": [{
                "panos_version": r["version"], "ami_id": r["ami_id"], "creation_date": r["created"],
                "count": r["count"], "ami_name": r["ami_name"],
                "by_family": r["families"], "diagnostics": r["diagnostics"],
                "rejected_by_type": r["rejected_by_type"], "rejected_by_code": r["rejected_by_code"],
            } for r in rows]
        }
        print(json.dumps(out, indent=2 if args.format=="pretty" else None))
    elif args.format == "markdown":
        print(render_markdown(rows,
                              show_rejected=args.show_rejected,
                              show_all_codes=args.show_rejected_all_codes,
                              rejected_limit=args.rejected_limit))
    elif args.format == "csv":
        print(render_csv(rows))
    else:
        print(render_table(rows,
                           show_rejected=args.show_rejected,
                           show_all_codes=args.show_rejected_all_codes,
                           rejected_limit=args.rejected_limit))

if __name__ == "__main__":
    try:
        main()
    except botocore.exceptions.ClientError as e:
        sys.stderr.write(json.dumps({"error": str(e)}) + "\n"); sys.exit(1)
    except Exception as e:
        sys.stderr.write(json.dumps({"error": str(e)}) + "\n"); sys.exit(1)