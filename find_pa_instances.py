#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
find_pa_instances.py
List VM-Series (Palo Alto Networks) supported EC2 instance types per AMI in a Region/AZ.
Simplified version focusing on essential functionality.
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
# Core families for VM-Series
# -----------------------------
CORE_VM_FAMILIES = {
    # x86 - most commonly used
    "c5", "c5n", "c6i", "c6in", "c7i",
    "m5", "m5n", "m6i", "m6in", "m7i", 
    "r5", "r5n", "r6i", "r6in", "r7i",
    # ARM
    "c6g", "c7g", "m6g", "m7g", "r6g", "r7g",
}

VERSION_RE = re.compile(r"PA-VM(?:ARM)?-AWS[-_]?(\d+\.\d+(?:\.\w+)?)", re.IGNORECASE)

def parse_args():
    p = argparse.ArgumentParser(description="List VM-Series supported EC2 instance types per AMI in a Region/AZ.")
    p.add_argument("--region", required=True, help="AWS region")
    p.add_argument("--az", required=True, help="AZ name (us-east-1a) or AZ ID (use1-az5)")

    # Product selection
    p.add_argument("--product", choices=list(PAN_PRODUCT_CODES.keys()), default="byol",
                   help="VM-Series license type")
    p.add_argument("--version-filter", default="", help="PAN-OS version filter (e.g. 11.2)")

    # Validation options
    p.add_argument("--validate", action="store_true",
                   help="Validate instance types via DryRun (slower but accurate)")
    p.add_argument("--subnet-id", default="",
                   help="Subnet to use for validation. Auto-detected if not provided.")

    # Output options
    p.add_argument("--format", choices=["json", "table"], default="table",
                   help="Output format")
    p.add_argument("--show-rejected", action="store_true",
                   help="Show rejected instance types")

    return p.parse_args()

def ec2(region):
    from botocore.config import Config
    cfg = Config(retries={"max_attempts": 10, "mode": "adaptive"})
    return boto3.client("ec2", region_name=region, config=cfg)

def resolve_az(ec2c, region, az_input):
    """Validate AZ exists in the specified region"""
    try:
        resp = ec2c.describe_availability_zones(
            AllAvailabilityZones=False,
            Filters=[{"Name":"region-name","Values":[region]}]
        )
        available_azs = resp.get("AvailabilityZones", [])
        
        # Check if input matches any available AZ name or ID
        for az in available_azs:
            if az_input in (az.get("ZoneName"), az.get("ZoneId")):
                if az_input == az.get("ZoneId"):
                    return ("availability-zone-id", az["ZoneId"])
                else:
                    return ("availability-zone", az["ZoneName"])
        
        # If no match found, show available options
        az_names = [az.get("ZoneName") for az in available_azs]
        az_ids = [az.get("ZoneId") for az in available_azs]
        
        raise ValueError(f"AZ '{az_input}' not found in region {region}. "
                        f"Available AZs: {', '.join(az_names)} "
                        f"or IDs: {', '.join(az_ids)}")
        
    except botocore.exceptions.ClientError as e:
        raise ValueError(f"Could not validate AZ in region {region}: {e}")

def list_amis(ec2c, product_code, version_filter):
    name_filter = f"PA-VM*-AWS*{version_filter}*" if version_filter else "PA-VM*-AWS*"
    resp = ec2c.describe_images(
        Owners=["679593333241"],  # Palo Alto Networks account
        Filters=[
            {"Name":"product-code","Values":[product_code]},
            {"Name":"name","Values":[name_filter]},
            {"Name":"virtualization-type","Values":["hvm"]},
            {"Name":"state","Values":["available"]}
        ],
    )
    imgs = sorted(resp.get("Images", []), key=lambda i: i.get("CreationDate",""), reverse=True)
    return imgs

def list_offered_types(ec2c, loc_type, loc_value):
    paginator = ec2c.get_paginator("describe_instance_type_offerings")
    types = set()
    for page in paginator.paginate(LocationType=loc_type, Filters=[{"Name":"location","Values":[loc_value]}]):
        for off in page.get("InstanceTypeOfferings", []):
            t = off.get("InstanceType")
            if t: types.add(t)
    return types

def extract_version(name):
    m = VERSION_RE.search(name or "")
    return m.group(1) if m else "unknown"

def extract_product_code(ami):
    """Extract product code from AMI"""
    product_codes = ami.get("ProductCodes", [])
    if product_codes:
        return product_codes[0].get("ProductCodeId", "unknown")  # Changed from ProductCode to ProductCodeId
    return "unknown"

def technical_filter(ec2c, candidate_types, ami):
    """Filter instance types using describe_instance_types"""
    if not candidate_types:
        return set()
    
    arch_needed = ami.get("Architecture", "x86_64")
    ena_needed = ami.get("EnaSupport", True)
    
    # ARM instances often have different vCPU minimums
    min_vcpus = 1 if arch_needed == "arm64" else 2

    keep = set()
    batch = list(candidate_types)
    for i in range(0, len(batch), 100):
        resp = ec2c.describe_instance_types(InstanceTypes=batch[i:i+100])
        for it in resp.get("InstanceTypes", []):
            t = it.get("InstanceType", "")
            family_name = t.split(".", 1)[0]
            
            # Skip metal instances and unsupported families
            if ".metal" in t or family_name.startswith(("mac", "a1")):
                continue
            
            # Focus on core VM-Series families (ARM and x86)
            if family_name not in CORE_VM_FAMILIES:
                continue
                
            # Adjusted vCPU requirements
            if it.get("VCpuInfo", {}).get("DefaultVCpus", 0) < min_vcpus:
                continue
                
            # Check architecture compatibility
            supported_archs = set(it.get("ProcessorInfo", {}).get("SupportedArchitectures", []))
            if arch_needed not in supported_archs:
                continue
                
            if ena_needed and it.get("NetworkInfo", {}).get("EnaSupport", "unsupported") not in ("supported", "required"):
                continue
                
            keep.add(t)
    return keep

def find_subnet_in_az(ec2c, loc_type, loc_value):
    """Find a subnet in the specified AZ for validation"""
    flt = [{"Name":"state","Values":["available"]}]
    flt.append({"Name":"availability-zone","Values":[loc_value]} if loc_type=="availability-zone"
               else {"Name":"availability-zone-id","Values":[loc_value]})
    resp = ec2c.describe_subnets(Filters=flt)
    subs = resp.get("Subnets", [])
    return subs[0] if subs else None

def validate_instances(ec2c, ami_id, types, subnet):
    """Validate instance types using DryRun"""
    vpc_id, subnet_id = subnet["VpcId"], subnet["SubnetId"]
    
    # Get default security group
    try:
        sg_resp = ec2c.describe_security_groups(
            Filters=[{"Name":"group-name","Values":["default"]},{"Name":"vpc-id","Values":[vpc_id]}]
        )
        sg_id = sg_resp.get("SecurityGroups", [{}])[0].get("GroupId")
    except:
        sg_id = None

    supported = set()
    rejected = {}

    for instance_type in types:
        params = {
            "ImageId": ami_id, 
            "InstanceType": instance_type, 
            "MinCount": 1, 
            "MaxCount": 1, 
            "SubnetId": subnet_id, 
            "DryRun": True
        }
        if sg_id:
            params["SecurityGroupIds"] = [sg_id]

        try:
            ec2c.run_instances(**params)
            supported.add(instance_type)  # Should not reach here
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "DryRunOperation":
                supported.add(instance_type)
            else:
                rejected[instance_type] = code

    return supported, rejected

def format_families(types):
    """Group instance types by family"""
    families = defaultdict(list)
    for t in sorted(types):
        family_name, size = t.split(".", 1)
        families[family_name].append(size)
    return {f: sorted(sizes) for f, sizes in families.items()}

def render_table(results):
    """Render results as a table with supported instances"""
    header = f"{'PAN-OS':<12} {'AMI ID':<21} {'Product Code':<32} {'#Types':<7} {'Supported Instances'}"
    lines = [header, "-" * len(header)]
    
    for result in results:
        # Show first line with summary
        families_str = ", ".join(f"{f}:{'/'.join(s)}" for f, s in result["families"].items())
        line = f"{result['version']:<12} {result['ami_id']:<21} {result['product_code']:<32} {result['count']:<7} {families_str}"
        lines.append(line)
        
        # Show individual supported instances
        if result.get("supported_instances"):
            instances_str = ", ".join(sorted(result["supported_instances"]))
            lines.append(f"{'':>73} Types: {instances_str}")
        
        # Show rejected instances if requested
        if result.get("rejected") and len(result["rejected"]) > 0:
            rejected_str = ", ".join(f"{k}({v})" for k, v in list(result["rejected"].items())[:10])
            lines.append(f"{'':>73} Rejected: {rejected_str}")
    
    return "\n".join(lines)

def render_json(results):
    """Render results as JSON"""
    return json.dumps({
        "results": [{
            "panos_version": r["version"],
            "ami_id": r["ami_id"], 
            "product_code": r["product_code"],
            "supported_count": r["count"],
            "families": r["families"],
            "rejected": r.get("rejected", {})
        } for r in results]
    }, indent=2)

def main():
    args = parse_args()
    ec2c = ec2(args.region)
    
    try:
        loc_type, loc_value = resolve_az(ec2c, args.region, args.az)
    except ValueError as e:
        sys.stderr.write(f"ERROR: {e}\n")
        sys.exit(1)

    # Get available instance types in AZ
    offered = list_offered_types(ec2c, loc_type, loc_value)
    if not offered:
        sys.stderr.write("ERROR: No instance types offered in that AZ\n")
        sys.exit(2)

    # Get product code
    product_code = PAN_PRODUCT_CODES.get(args.product)
    if not product_code:
        sys.stderr.write("ERROR: Invalid product type\n")
        sys.exit(3)

    # Find AMIs
    amis = list_amis(ec2c, product_code, args.version_filter)
    if not amis:
        sys.stderr.write("ERROR: No AMIs found. Check product subscription.\n")
        sys.exit(3)

    # Setup validation if requested
    subnet = None
    if args.validate:
        if args.subnet_id:
            try:
                resp = ec2c.describe_subnets(SubnetIds=[args.subnet_id])
                subnet = resp.get("Subnets", [{}])[0]
            except:
                sys.stderr.write("WARN: Invalid subnet ID, attempting auto-discovery\n")
        
        if not subnet:
            subnet = find_subnet_in_az(ec2c, loc_type, loc_value)
            if not subnet:
                sys.stderr.write("WARN: No subnet found for validation, using technical filtering only\n")

    # Process each AMI
    results = []
    for ami in amis:
        ami_id = ami["ImageId"]
        version = extract_version(ami.get("Name", ""))
        product_code = extract_product_code(ami)

        # Technical filtering
        candidates = technical_filter(ec2c, offered, ami)
        
        supported = candidates
        rejected = {}
        
        # Validation if enabled and subnet available
        if args.validate and subnet and candidates:
            supported, rejected = validate_instances(ec2c, ami_id, candidates, subnet)

        result = {
            "version": version,
            "ami_id": ami_id,
            "product_code": product_code,
            "count": len(supported),
            "families": format_families(supported),
            "supported_instances": supported  # ADD THIS LINE

        }
        
        if args.show_rejected and rejected:
            result["rejected"] = rejected
            
        results.append(result)

    # Output results
    if args.format == "json":
        print(render_json(results))
    else:
        print(render_table(results))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"ERROR: {e}\n")
        sys.exit(1)