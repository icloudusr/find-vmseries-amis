#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
find_pa_instances.py
List VM-Series (Palo Alto Networks) supported EC2 instance types per AMI in a Region/AZ.
Enhanced version with better filtering and output formatting.
"""

import argparse
import boto3
import botocore
import json
import re
import sys
import threading
import time
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
    "c5", "c5n", "c5d", "c5a",
    "c6i", "c6in", "c6id", "c6a",
    "c7i", "c7a",
    "m5", "m5n", "m5d", "m5a",
    "m6i", "m6in", "m6id", "m6a",
    "m7i", "m7a",
    "r5", "r5n", "r5d", "r5a",
    "r6i", "r6in", "r6id", "r6a",
    "r7i", "r7a",
    # ARM
    "c6g", "c6gd", "c6gn",
    "c7g", "c7gd", "c7gn",
    "c8g",
    "m6g", "m6gd",
    "m7g", "m7gd",
    "m8g",
    "r6g", "r6gd",
    "r7g", "r7gd",
    "r8g",
    "t4g",
}

VERSION_RE = re.compile(r"PA-VM(?:ARM)?-AWS[-_]?(\d+\.\d+(?:\.\w+)?)", re.IGNORECASE)

def spinner(stop_event, message="Processing"):
    """Progress spinner animation"""
    if not sys.stderr.isatty():
        return
    chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    i = 0
    while not stop_event.is_set():
        sys.stderr.write(f'\r{message} {chars[i % len(chars)]} ')
        sys.stderr.flush()
        i += 1
        time.sleep(0.1)
    sys.stderr.write('\r' + ' ' * (len(message) + 3) + '\r')
    sys.stderr.flush()

def parse_args():
    p = argparse.ArgumentParser(description="List VM-Series supported EC2 instance types per AMI in a Region/AZ.")
    
    # Required arguments
    p.add_argument("--region", required=True, help="AWS region (e.g., us-east-1)")
    p.add_argument("--az", required=True, help="AZ name (us-east-1a) or AZ ID (use1-az5)")
    
    # Product selection
    p.add_argument("--product", choices=list(PAN_PRODUCT_CODES.keys()), default="byol",
                   help="VM-Series license type (default: byol)")
    p.add_argument("--version-filter", default="", help="PAN-OS version filter (e.g. 11.2)")
    
    # Instance filtering
    p.add_argument("--families", default="",
                   help="Comma-separated list of instance families (e.g., c5,m5,r5)")
    p.add_argument("--min-vcpus", type=int, default=0,
                   help="Minimum number of vCPUs (default: 0)")
    p.add_argument("--max-vcpus", type=int, default=999,
                   help="Maximum number of vCPUs (default: 999)")
    p.add_argument("--max-amis", type=int, default=10,
                   help="Maximum number of AMIs to process (default: 10)")
    
    # Validation options
    p.add_argument("--validate", action="store_true",
                   help="Validate instance types via DryRun (slower but accurate)")
    p.add_argument("--subnet-id", default="",
                   help="Subnet to use for validation. Auto-detected if not provided.")
    
    # Output options
    p.add_argument("--format", choices=["json", "table"], default="table",
                   help="Output format (default: table)")
    p.add_argument("--show-rejected", action="store_true",
                   help="Show rejected instance types")
    p.add_argument("--progress", action="store_true",
                   help="Show progress spinner")
    p.add_argument("--debug", action="store_true",
                   help="Enable debug output")
    
    args = p.parse_args()
    
    # Input validation
    if args.min_vcpus < 0:
        p.error("--min-vcpus must be >= 0")
    if args.max_vcpus < args.min_vcpus:
        p.error("--max-vcpus must be >= --min-vcpus")
    if args.max_amis < 1:
        p.error("--max-amis must be >= 1")
    
    return args

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
        return product_codes[0].get("ProductCodeId", "unknown")
    return "unknown"

def technical_filter(ec2c, candidate_types, ami, args):
    """Filter instance types using describe_instance_types"""
    if not candidate_types:
        return set()
    
    arch_needed = ami.get("Architecture", "x86_64")
    ena_needed = ami.get("EnaSupport", True)
    
    # Parse requested families
    requested_families = set()
    if args.families:
        requested_families = set(f.strip() for f in args.families.split(','))
    
    if args.debug:
        sys.stderr.write(f"DEBUG: Filtering {len(candidate_types)} candidates for {arch_needed} architecture\n")
        if requested_families:
            sys.stderr.write(f"DEBUG: Requested families: {requested_families}\n")
    
    keep = set()
    batch = list(candidate_types)
    
    for i in range(0, len(batch), 100):
        resp = ec2c.describe_instance_types(InstanceTypes=batch[i:i+100])
        for it in resp.get("InstanceTypes", []):
            t = it.get("InstanceType", "")
            family_name = t.split(".", 1)[0]
            
            # Skip metal instances
            if ".metal" in t:
                continue
            
            # Skip unsupported instance families
            if family_name.startswith(("mac", "a1", "x1", "x2", "z1", "p2", "p3", "p4", "p5", "g3", "g4", "g5", "f1", "inf1", "inf2", "trn1", "dl1")):
                continue
            
            # Apply family filter if specified
            if requested_families and family_name not in requested_families:
                continue
            
            # Focus on core VM-Series families if no specific families requested
            if not requested_families and family_name not in CORE_VM_FAMILIES:
                continue
            
            # Check vCPU requirements
            vcpus = it.get("VCpuInfo", {}).get("DefaultVCpus", 0)
            if vcpus < args.min_vcpus or vcpus > args.max_vcpus:
                continue
            
            # Check architecture compatibility
            supported_archs = set(it.get("ProcessorInfo", {}).get("SupportedArchitectures", []))
            if arch_needed not in supported_archs:
                continue
            
            # Check ENA support
            if ena_needed and it.get("NetworkInfo", {}).get("EnaSupport", "unsupported") not in ("supported", "required"):
                continue
            
            keep.add(t)
    
    if args.debug:
        sys.stderr.write(f"DEBUG: Technical filter kept {len(keep)} instance types\n")
    
    return keep

def find_subnet_in_az(ec2c, loc_type, loc_value):
    """Find a subnet in the specified AZ for validation"""
    flt = [{"Name":"state","Values":["available"]}]
    flt.append({"Name":"availability-zone","Values":[loc_value]} if loc_type=="availability-zone"
               else {"Name":"availability-zone-id","Values":[loc_value]})
    resp = ec2c.describe_subnets(Filters=flt)
    subs = resp.get("Subnets", [])
    return subs[0] if subs else None

def validate_instances(ec2c, ami_id, types, subnet, args):
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
    
    if args.debug:
        sys.stderr.write(f"DEBUG: Validation complete: {len(supported)} supported, {len(rejected)} rejected\n")
    
    return supported, rejected

def format_families(types):
    """Group instance types by family"""
    families = defaultdict(list)
    for t in sorted(types):
        family_name, size = t.split(".", 1)
        families[family_name].append(size)
    return {f: sorted(sizes) for f, sizes in families.items()}

def render_table(results):
    """Render results as a table with better formatting per AMI"""
    output = []
    
    for idx, result in enumerate(results):
        # AMI header
        output.append("=" * 100)
        output.append(f"AMI #{idx+1}: {result['ami_id']}")
        output.append(f"PAN-OS Version: {result['version']}")
        output.append(f"Product Code: {result['product_code']}")
        output.append(f"Supported Instance Types: {result['count']}")
        
        if result['count'] > 0:
            output.append("-" * 100)
            
            # Group by family for better readability
            families = result.get("families", {})
            if families:
                output.append("By Family:")
                for family in sorted(families.keys()):
                    sizes = families[family]
                    output.append(f"  {family}: {', '.join(sizes)}")
            
            # Show all supported instances if not too many
            instances = result.get("supported_instances", [])
            if instances and len(instances) <= 50:
                output.append("\nAll Supported Types:")
                # Format in columns
                sorted_instances = sorted(instances)
                for i in range(0, len(sorted_instances), 5):
                    line = "  " + "  ".join(f"{inst:15}" for inst in sorted_instances[i:i+5])
                    output.append(line.rstrip())
        else:
            output.append("  No supported instance types found")
        
        # Show rejected if requested
        if result.get("rejected") and len(result["rejected"]) > 0:
            output.append("\nRejected Types (first 10):")
            for inst, reason in list(result["rejected"].items())[:10]:
                output.append(f"  {inst}: {reason}")
    
    output.append("=" * 100)
    return "\n".join(output)

def render_json(results):
    """Render results as JSON"""
    return json.dumps({
        "results": [{
            "panos_version": r["version"],
            "ami_id": r["ami_id"],
            "product_code": r["product_code"],
            "supported_count": r["count"],
            "families": r["families"],
            "supported_instances": r.get("supported_instances", []),
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
    stop_event = threading.Event()
    spinner_thread = None
    
    if args.progress:
        spinner_thread = threading.Thread(target=spinner, args=(stop_event, "Loading instance types"))
        spinner_thread.start()
    
    offered = list_offered_types(ec2c, loc_type, loc_value)
    
    if args.progress:
        stop_event.set()
        spinner_thread.join()
    
    if not offered:
        sys.stderr.write("ERROR: No instance types offered in that AZ\n")
        sys.exit(2)
    
    if args.debug:
        sys.stderr.write(f"DEBUG: Found {len(offered)} instance types in {loc_value}\n")
    
    # Get product code
    product_code = PAN_PRODUCT_CODES.get(args.product)
    if not product_code:
        sys.stderr.write("ERROR: Invalid product type\n")
        sys.exit(3)
    
    # Find AMIs
    if args.progress:
        stop_event = threading.Event()
        spinner_thread = threading.Thread(target=spinner, args=(stop_event, "Finding AMIs"))
        spinner_thread.start()
    
    amis = list_amis(ec2c, product_code, args.version_filter)
    
    if args.progress:
        stop_event.set()
        spinner_thread.join()
    
    if not amis:
        sys.stderr.write("ERROR: No AMIs found. Check product subscription.\n")
        sys.exit(3)
    
    # Limit AMIs if requested
    if args.max_amis and len(amis) > args.max_amis:
        amis = amis[:args.max_amis]
        if args.debug:
            sys.stderr.write(f"DEBUG: Limited to {args.max_amis} AMIs\n")
    
    sys.stderr.write(f"Found {len(amis)} AMIs to process\n")
    
    # Setup validation if requested
    subnet = None
    if args.validate:
        if args.subnet_id:
            try:
                resp = ec2c.describe_subnets(SubnetIds=[args.subnet_id])
                subnet = resp.get("Subnets", [{}])[0]
                if args.debug:
                    sys.stderr.write(f"DEBUG: Using provided subnet {args.subnet_id}\n")
            except Exception as e:
                sys.stderr.write(f"WARN: Invalid subnet ID: {e}\n")
        
        if not subnet:
            subnet = find_subnet_in_az(ec2c, loc_type, loc_value)
            if subnet:
                if args.debug:
                    sys.stderr.write(f"DEBUG: Auto-discovered subnet {subnet['SubnetId']}\n")
            else:
                sys.stderr.write("WARN: No subnet found for validation, using technical filtering only\n")
    
    # Process each AMI
    results = []
    for idx, ami in enumerate(amis):
        ami_id = ami["ImageId"]
        version = extract_version(ami.get("Name", ""))
        product_code = extract_product_code(ami)
        
        # Progress for technical filtering
        if args.progress:
            stop_event = threading.Event()
            msg = f"Processing AMI {idx+1}/{len(amis)} ({version})"
            spinner_thread = threading.Thread(target=spinner, args=(stop_event, msg))
            spinner_thread.start()
        
        # Technical filtering
        candidates = technical_filter(ec2c, offered, ami, args)
        
        if args.progress:
            stop_event.set()
            spinner_thread.join()
        
        supported = candidates
        rejected = {}
        
        # Validation if enabled and subnet available
        if args.validate and subnet and candidates:
            if args.progress:
                stop_event = threading.Event()
                msg = f"Validating {len(candidates)} types for AMI {idx+1}/{len(amis)}"
                spinner_thread = threading.Thread(target=spinner, args=(stop_event, msg))
                spinner_thread.start()
            
            supported, rejected = validate_instances(ec2c, ami_id, candidates, subnet, args)
            
            if args.progress:
                stop_event.set()
                spinner_thread.join()
        
        result = {
            "version": version,
            "ami_id": ami_id,
            "product_code": product_code,
            "count": len(supported),
            "families": format_families(supported),
            "supported_instances": list(supported)
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
        import traceback
        if "--debug" in sys.argv:
            traceback.print_exc()
        sys.exit(1)